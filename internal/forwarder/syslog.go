package forwarder

import (
	"fmt"
	"log/syslog"
	"net"
	"sync"
	"time"

	"github.com/zeekurity/zeek-bzar-ocsf/internal/config"
)

// SyslogForwarder sends OCSF events via syslog (UDP or TCP).
type SyslogForwarder struct {
	mu       sync.Mutex
	conn     net.Conn
	addr     string
	proto    string
	maxRetry int
}

func NewSyslogForwarder(cfg config.OutputConfig) (*SyslogForwarder, error) {
	host := cfg.Host
	if host == "" {
		host = "localhost"
	}
	port := cfg.Port
	if port == 0 {
		port = 514
	}
	proto := cfg.Protocol
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		return nil, fmt.Errorf("syslog protocol must be udp or tcp, got %s", proto)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	f := &SyslogForwarder{addr: addr, proto: proto, maxRetry: 3}
	if err := f.connect(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *SyslogForwarder) connect() error {
	var (
		conn net.Conn
		err  error
	)
	for i := 0; i < f.maxRetry; i++ {
		conn, err = net.DialTimeout(f.proto, f.addr, 5*time.Second)
		if err == nil {
			f.conn = conn
			return nil
		}
		time.Sleep(time.Duration(1<<uint(i)) * time.Second)
	}
	return fmt.Errorf("connecting to syslog %s: %w", f.addr, err)
}

func (f *SyslogForwarder) Send(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Format as RFC5424 syslog message (facility=local0, severity=info)
	pri := int(syslog.LOG_LOCAL0 | syslog.LOG_INFO)
	ts := time.Now().UTC().Format(time.RFC3339)
	msg := fmt.Sprintf("<%d>1 %s zeek-bzar-ocsf - - - %s\n", pri, ts, string(data))

	if _, err := fmt.Fprint(f.conn, msg); err != nil {
		// Try to reconnect once
		if err2 := f.connect(); err2 != nil {
			return fmt.Errorf("syslog send failed, reconnect failed: %w", err2)
		}
		_, err = fmt.Fprint(f.conn, msg)
		return err
	}
	return nil
}

func (f *SyslogForwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}
