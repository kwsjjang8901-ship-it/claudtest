package evidence_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeekurity/zeek-bzar-ocsf/internal/evidence"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/zeek"
)

func TestCollectorAddAndCollect(t *testing.T) {
	dir := t.TempDir()
	c := evidence.NewCollector(dir, 100, true)

	rec := &zeek.Record{
		Type:      zeek.LogSMBFiles,
		Timestamp: time.Now(),
		UID:       "Ctest1",
		Fields: map[string]string{
			"path":   `\\server\C$`,
			"action": "SMB::FILE_OPEN",
		},
		Raw: "raw-line-1",
	}

	c.Add(rec)
	c.Add(rec) // Add twice

	entries := c.Collect("Ctest1", "10.0.0.1", "10.0.0.2", time.Now())
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].UID != "Ctest1" {
		t.Errorf("UID: got %q", entries[0].UID)
	}

	// Evidence file should be created
	files, _ := filepath.Glob(filepath.Join(dir, "*", "evidence_Ctest1_*.json"))
	if len(files) == 0 {
		t.Error("expected evidence file to be created on disk")
	}
}

func TestCollectorDisabled(t *testing.T) {
	c := evidence.NewCollector(t.TempDir(), 100, false)

	rec := &zeek.Record{
		Type:  zeek.LogConn,
		UID:   "Cdisabled",
		Fields: map[string]string{},
	}
	c.Add(rec)

	entries := c.Collect("Cdisabled", "", "", time.Now())
	if len(entries) != 0 {
		t.Errorf("disabled collector should return no entries, got %d", len(entries))
	}
}

func TestCollectorBufferCap(t *testing.T) {
	c := evidence.NewCollector(t.TempDir(), 5, true) // buffer=5

	for i := 0; i < 10; i++ {
		c.Add(&zeek.Record{
			Type:   zeek.LogConn,
			UID:    "Ccap1",
			Fields: map[string]string{"n": string(rune('0' + i))},
		})
	}

	entries := c.Collect("Ccap1", "", "", time.Now())
	if len(entries) > 5 {
		t.Errorf("buffer cap should limit to 5, got %d", len(entries))
	}
}

func TestCollectorEvict(t *testing.T) {
	c := evidence.NewCollector(t.TempDir(), 100, true)

	oldRec := &zeek.Record{
		Type:      zeek.LogConn,
		Timestamp: time.Now().Add(-2 * time.Hour),
		UID:       "Cold1",
		Fields:    map[string]string{},
	}
	newRec := &zeek.Record{
		Type:      zeek.LogConn,
		Timestamp: time.Now(),
		UID:       "Cnew1",
		Fields:    map[string]string{},
	}

	c.Add(oldRec)
	c.Add(newRec)

	c.Evict(1 * time.Hour)

	// Old entry should be evicted
	entries := c.Collect("Cold1", "", "", time.Now())
	if len(entries) != 0 {
		t.Errorf("old entry should be evicted, got %d entries", len(entries))
	}

	// New entry should remain
	entries = c.Collect("Cnew1", "", "", time.Now())
	if len(entries) != 1 {
		t.Errorf("new entry should remain, got %d entries", len(entries))
	}
}

func TestCollectorEmptyUID(t *testing.T) {
	c := evidence.NewCollector(t.TempDir(), 100, true)

	// Records with empty UID should not be buffered
	c.Add(&zeek.Record{UID: "", Fields: map[string]string{}})
	c.Add(&zeek.Record{UID: "-", Fields: map[string]string{}})

	// Collecting with empty uid returns nothing
	entries := c.Collect("", "", "", time.Now())
	if len(entries) != 0 {
		t.Errorf("empty UID collect should return 0 entries, got %d", len(entries))
	}

	// No evidence files should be written for empty UIDs
	files, _ := os.ReadDir(t.TempDir())
	if len(files) != 0 {
		t.Error("no files should be written for empty UIDs")
	}
}
