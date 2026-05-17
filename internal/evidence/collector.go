package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kwsjjang8901-ship-it/claudtest/internal/zeek"
)

// Entry is a single log record stored for evidence.
type Entry struct {
	UID     string
	LogType zeek.LogType
	TS      time.Time
	Fields  map[string]string
	Raw     string
}

// Collector buffers recent Zeek log entries keyed by connection UID.
// When a detection fires, the related entries are extracted and persisted.
type Collector struct {
	mu         sync.RWMutex
	bufferByUID map[string][]Entry // uid -> list of entries
	bufferSize  int                // max entries per uid
	outputDir   string
	enabled     bool
}

func NewCollector(outputDir string, bufferSize int, enabled bool) *Collector {
	return &Collector{
		bufferByUID: make(map[string][]Entry),
		bufferSize:  bufferSize,
		outputDir:   outputDir,
		enabled:     enabled,
	}
}

// Add stores a parsed Zeek record in the in-memory evidence buffer.
func (c *Collector) Add(r *zeek.Record) {
	if !c.enabled || r.UID == "" || r.UID == "-" {
		return
	}

	entry := Entry{
		UID:     r.UID,
		LogType: r.Type,
		TS:      r.Timestamp,
		Fields:  r.Fields,
		Raw:     r.Raw,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	list := c.bufferByUID[r.UID]
	list = append(list, entry)
	// Cap buffer per UID to avoid unbounded growth
	if len(list) > c.bufferSize {
		list = list[len(list)-c.bufferSize:]
	}
	c.bufferByUID[r.UID] = list
}

// Collect returns buffered entries for a given UID and persists them to disk.
// Also searches by src/dst IP for broader context when uid is short-lived.
func (c *Collector) Collect(uid, srcIP, dstIP string, detectionTime time.Time) []Entry {
	if !c.enabled {
		return nil
	}

	c.mu.RLock()
	entries := make([]Entry, len(c.bufferByUID[uid]))
	copy(entries, c.bufferByUID[uid])
	c.mu.RUnlock()

	if len(entries) > 0 {
		c.persist(uid, entries, detectionTime)
	}
	return entries
}

// Evict removes stale entries from the buffer (older than maxAge).
func (c *Collector) Evict(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)

	c.mu.Lock()
	defer c.mu.Unlock()

	for uid, entries := range c.bufferByUID {
		var keep []Entry
		for _, e := range entries {
			if e.TS.After(cutoff) {
				keep = append(keep, e)
			}
		}
		if len(keep) == 0 {
			delete(c.bufferByUID, uid)
		} else {
			c.bufferByUID[uid] = keep
		}
	}
}

// StartEviction runs a background goroutine to periodically evict old entries.
func (c *Collector) StartEviction(interval, maxAge time.Duration, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.Evict(maxAge)
			case <-done:
				return
			}
		}
	}()
}

// persist writes the evidence entries to a JSON file on disk.
func (c *Collector) persist(uid string, entries []Entry, detectionTime time.Time) {
	if err := os.MkdirAll(c.outputDir, 0750); err != nil {
		return
	}

	dateDir := filepath.Join(c.outputDir, detectionTime.UTC().Format("2006-01-02"))
	if err := os.MkdirAll(dateDir, 0750); err != nil {
		return
	}

	filename := fmt.Sprintf("evidence_%s_%d.json",
		sanitizeUID(uid), detectionTime.UnixNano())
	path := filepath.Join(dateDir, filename)

	type evidenceFile struct {
		UID           string    `json:"uid"`
		DetectionTime time.Time `json:"detection_time"`
		Entries       []Entry   `json:"entries"`
	}

	ef := evidenceFile{
		UID:           uid,
		DetectionTime: detectionTime,
		Entries:       entries,
	}

	data, err := json.MarshalIndent(ef, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0640)
}

func sanitizeUID(uid string) string {
	out := make([]byte, 0, len(uid))
	for i := 0; i < len(uid); i++ {
		c := uid[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
