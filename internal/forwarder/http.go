package forwarder

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/kwsjjang8901-ship-it/claudtest/internal/config"
)

// HTTPForwarder sends OCSF events as JSON to an HTTP endpoint.
type HTTPForwarder struct {
	client  *http.Client
	url     string
	headers map[string]string
	maxRetry int
}

func NewHTTPForwarder(cfg config.OutputConfig) (*HTTPForwarder, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("http forwarder: url is required")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // user-configured
		},
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}

	maxRetry := cfg.MaxRetries
	if maxRetry <= 0 {
		maxRetry = 3
	}

	return &HTTPForwarder{
		client:   client,
		url:      cfg.URL,
		headers:  cfg.Headers,
		maxRetry: maxRetry,
	}, nil
}

func (f *HTTPForwarder) Send(data []byte) error {
	var lastErr error
	for attempt := 0; attempt < f.maxRetry; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}

		req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("creating HTTP request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		for k, v := range f.headers {
			req.Header.Set(k, v)
		}

		resp, err := f.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, f.url)
	}
	return fmt.Errorf("http forwarder: %w after %d attempts", lastErr, f.maxRetry)
}

func (f *HTTPForwarder) Close() error {
	f.client.CloseIdleConnections()
	return nil
}
