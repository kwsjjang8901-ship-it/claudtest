package forwarder

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/kwsjjang8901-ship-it/claudtest/internal/config"
)

// Forwarder sends serialized OCSF events to one or more destinations.
type Forwarder interface {
	Send(data []byte) error
	Close() error
}

// MultiForwarder fans out to multiple Forwarder implementations.
type MultiForwarder struct {
	forwarders []Forwarder
}

func NewMultiForwarder(outputs []config.OutputConfig) (*MultiForwarder, error) {
	var fwds []Forwarder
	for _, out := range outputs {
		var f Forwarder
		var err error

		switch out.Type {
		case "file":
			f, err = NewFileForwarder(out)
		case "syslog":
			f, err = NewSyslogForwarder(out)
		case "http":
			f, err = NewHTTPForwarder(out)
		default:
			return nil, fmt.Errorf("unknown forwarder type: %s", out.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("creating %s forwarder: %w", out.Type, err)
		}
		fwds = append(fwds, f)
	}
	return &MultiForwarder{forwarders: fwds}, nil
}

// SendEvent marshals any OCSF event to JSON and forwards it.
func (m *MultiForwarder) SendEvent(event interface{}) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[forwarder] marshal error: %v", err)
		return
	}
	for _, f := range m.forwarders {
		if err := f.Send(data); err != nil {
			log.Printf("[forwarder] send error (%T): %v", f, err)
		}
	}
}

// Close shuts down all forwarders.
func (m *MultiForwarder) Close() {
	for _, f := range m.forwarders {
		if err := f.Close(); err != nil {
			log.Printf("[forwarder] close error (%T): %v", f, err)
		}
	}
}
