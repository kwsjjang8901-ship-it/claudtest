package ocsf_test

import (
	"testing"
	"time"

	"github.com/zeekurity/zeek-bzar-ocsf/internal/bzar"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/evidence"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/ocsf"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/zeek"
)

func newMapper() *ocsf.Mapper {
	return ocsf.NewMapper("zeek-bzar-ocsf", "1.0.0", "https://example.com")
}

func TestFromConn(t *testing.T) {
	m := newMapper()
	conn := &zeek.ConnRecord{
		TS:        time.Now(),
		UID:       "Cconn1",
		OrigH:     "192.168.1.1",
		OrigP:     "54321",
		RespH:     "10.0.0.1",
		RespP:     "443",
		Proto:     "tcp",
		Service:   "ssl",
		ConnState: "SF",
		OrigBytes: "1024",
		RespBytes: "2048",
		OrigPkts:  "10",
		RespPkts:  "12",
	}

	event := m.FromConn(conn)
	if event.ClassUID != ocsf.ClassNetworkActivity {
		t.Errorf("ClassUID: got %d, want %d", event.ClassUID, ocsf.ClassNetworkActivity)
	}
	if event.SrcEndpoint.IP != "192.168.1.1" {
		t.Errorf("SrcEndpoint.IP: got %q", event.SrcEndpoint.IP)
	}
	if event.DstEndpoint.Port != 443 {
		t.Errorf("DstEndpoint.Port: got %d", event.DstEndpoint.Port)
	}
	if event.Traffic == nil {
		t.Error("expected non-nil Traffic")
	}
	if event.Traffic.BytesSent != 1024 {
		t.Errorf("Traffic.BytesSent: got %d", event.Traffic.BytesSent)
	}
}

func TestFromDNS(t *testing.T) {
	m := newMapper()
	dns := &zeek.DNSRecord{
		TS:      time.Now(),
		UID:     "Cdns1",
		OrigH:   "192.168.1.5",
		OrigP:   "45000",
		RespH:   "8.8.8.8",
		RespP:   "53",
		Proto:   "udp",
		Query:   "example.com",
		QType:   "A",
		QClass:  "C_INTERNET",
		RCode:   "NOERROR",
		Answers: "93.184.216.34",
		TTLs:    "3600",
	}

	event := m.FromDNS(dns)
	if event.ClassUID != ocsf.ClassDNSActivity {
		t.Errorf("ClassUID: got %d, want %d", event.ClassUID, ocsf.ClassDNSActivity)
	}
	if event.Query == nil || event.Query.Hostname != "example.com" {
		t.Errorf("Query.Hostname: got %v", event.Query)
	}
	if len(event.Answers) == 0 {
		t.Error("expected answers")
	}
}

func TestFromDetection(t *testing.T) {
	m := newMapper()
	notice := &zeek.NoticeRecord{
		TS:    time.Now(),
		UID:   "Cdet1",
		Note:  "BZAR::ATTACK_TA0008_T1021_002_SMB_Admin_Share",
		Msg:   "Lateral movement via SMB",
		OrigH: "10.0.0.5",
		OrigP: "49200",
		RespH: "10.0.0.10",
		RespP: "445",
		Proto: "tcp",
	}

	det := bzar.Analyze(notice)
	if det == nil {
		t.Fatal("expected detection")
	}

	evList := []evidence.Entry{
		{
			UID:     "Cdet1",
			LogType: zeek.LogSMBFiles,
			TS:      time.Now(),
			Fields:  map[string]string{"path": "\\\\server\\C$", "action": "SMB::FILE_OPEN"},
		},
	}

	event := m.FromDetection(det, evList)
	if event.ClassUID != ocsf.ClassDetectionFinding {
		t.Errorf("ClassUID: got %d, want %d", event.ClassUID, ocsf.ClassDetectionFinding)
	}
	if event.SeverityID != 5 {
		t.Errorf("SeverityID: got %d, want 5", event.SeverityID)
	}
	if len(event.Attacks) == 0 {
		t.Error("expected attacks")
	}
	if event.Attacks[0].Tactic == nil || event.Attacks[0].Tactic.ID != "TA0008" {
		t.Errorf("attack tactic: %+v", event.Attacks[0])
	}
	if len(event.Evidence) < 2 { // at least smb_files + notice
		t.Errorf("expected at least 2 evidence entries, got %d", len(event.Evidence))
	}
	if event.Finding.Title == "" {
		t.Error("finding title should not be empty")
	}
}

func TestFromHTTP(t *testing.T) {
	m := newMapper()
	http := &zeek.HTTPRecord{
		TS:              time.Now(),
		UID:             "Chttp1",
		OrigH:           "10.0.0.1",
		OrigP:           "44000",
		RespH:           "93.184.216.34",
		RespP:           "80",
		Method:          "GET",
		Host:            "example.com",
		URI:             "/index.html",
		UserAgent:       "Mozilla/5.0",
		StatusCode:      "200",
		StatusMsg:       "OK",
		RequestBodyLen:  "0",
		ResponseBodyLen: "1234",
	}

	event := m.FromHTTP(http)
	if event.ClassUID != ocsf.ClassHTTPActivity {
		t.Errorf("ClassUID: got %d, want %d", event.ClassUID, ocsf.ClassHTTPActivity)
	}
	if event.Request == nil || event.Request.Method != "GET" {
		t.Errorf("Request: %+v", event.Request)
	}
	if event.Response == nil || event.Response.Code != 200 {
		t.Errorf("Response: %+v", event.Response)
	}
}
