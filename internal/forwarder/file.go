package forwarder

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/kwsjjang8901-ship-it/claudtest/internal/config"
)

// FileForwarder writes OCSF events as newline-delimited JSON to a file.
type FileForwarder struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func NewFileForwarder(cfg config.OutputConfig) (*FileForwarder, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("file forwarder: path is required")
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0750); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("opening output file: %w", err)
	}

	return &FileForwarder{file: f, path: cfg.Path}, nil
}

func (f *FileForwarder) Send(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Reopen if file was rotated (inode changed or file removed)
	if err := f.reopen(); err != nil {
		return err
	}

	_, err := f.file.Write(append(data, '\n'))
	return err
}

func (f *FileForwarder) reopen() error {
	info, err := os.Stat(f.path)
	if err != nil || info == nil {
		// File was removed – reopen it
		return f.open()
	}

	fileInfo, err := f.file.Stat()
	if err != nil {
		return f.open()
	}

	if !os.SameFile(info, fileInfo) {
		f.file.Close()
		return f.open()
	}
	return nil
}

func (f *FileForwarder) open() error {
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	f.file = file
	return nil
}

func (f *FileForwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Close()
}
