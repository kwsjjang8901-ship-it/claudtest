package zeek

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LineEvent carries a log line with its source log type.
type LineEvent struct {
	LogType LogType
	Line    string
}

// Tailer watches a set of Zeek log files and emits new lines.
// It handles log rotation by detecting inode changes or truncation.
type Tailer struct {
	logDir string
	logs   []LogType
	out    chan<- LineEvent
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewTailer(logDir string, logs []LogType, out chan<- LineEvent) *Tailer {
	return &Tailer{
		logDir: logDir,
		logs:   logs,
		out:    out,
		done:   make(chan struct{}),
	}
}

// Start begins tailing all configured log files.
func (t *Tailer) Start() {
	for _, lt := range t.logs {
		t.wg.Add(1)
		go func(lt LogType) {
			defer t.wg.Done()
			t.tailFile(lt)
		}(lt)
	}
}

// Stop signals all tailers to exit and waits for them to finish.
func (t *Tailer) Stop() {
	close(t.done)
	t.wg.Wait()
}

func (t *Tailer) tailFile(lt LogType) {
	path := filepath.Join(t.logDir, string(lt)+".log")

	var (
		file    *os.File
		reader  *bufio.Reader
		lastIno uint64
		offset  int64
	)

	open := func() bool {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return false
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			file = nil
			return false
		}
		lastIno = inode(info)
		// Seek to end on first open so we don't replay history
		if offset == 0 {
			offset, _ = file.Seek(0, io.SeekEnd)
		} else {
			file.Seek(offset, io.SeekStart)
		}
		reader = bufio.NewReaderSize(file, 64*1024)
		return true
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			if file != nil {
				file.Close()
			}
			return

		case <-ticker.C:
			if file == nil {
				if !open() {
					continue
				}
				log.Printf("[tailer] opened %s", path)
			}

			// Check for rotation
			info, err := os.Stat(path)
			if err != nil {
				// File removed – close and wait for re-creation
				file.Close()
				file = nil
				offset = 0
				continue
			}

			if inode(info) != lastIno || info.Size() < offset {
				// Rotated: re-open from start
				file.Close()
				offset = 0
				if !open() {
					continue
				}
				log.Printf("[tailer] rotation detected for %s", path)
			}

			// Read all available lines
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					// Strip newline
					l := line
					if len(l) > 0 && l[len(l)-1] == '\n' {
						l = l[:len(l)-1]
					}
					if len(l) > 0 && l[len(l)-1] == '\r' {
						l = l[:len(l)-1]
					}
					if l != "" {
						select {
						case t.out <- LineEvent{LogType: lt, Line: l}:
						case <-t.done:
							file.Close()
							return
						}
					}
					// Update offset after successful read
					pos, _ := file.Seek(0, io.SeekCurrent)
					offset = pos - int64(reader.Buffered())
				}
				if err != nil {
					if err != io.EOF {
						log.Printf("[tailer] read error on %s: %v", path, err)
					}
					break
				}
			}
		}
	}
}

// logTypeFromPath derives the LogType from a filename like "conn.log".
func logTypeFromPath(path string) (LogType, error) {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]
	switch name {
	case "conn":
		return LogConn, nil
	case "dns":
		return LogDNS, nil
	case "http":
		return LogHTTP, nil
	case "ssl":
		return LogSSL, nil
	case "smb_files":
		return LogSMBFiles, nil
	case "smb_mapping":
		return LogSMBMapping, nil
	case "dce_rpc":
		return LogDCERPC, nil
	case "notice":
		return LogNotice, nil
	default:
		return "", fmt.Errorf("unknown log type: %s", name)
	}
}
