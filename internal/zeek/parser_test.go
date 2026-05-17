package zeek_test

import (
	"testing"
	"time"

	"github.com/kwsjjang8901-ship-it/claudtest/internal/zeek"
)

func TestParseTSVConn(t *testing.T) {
	p := zeek.NewParser("tsv")

	// Simulate #fields header
	header := "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes"
	rec, err := p.ParseLine(zeek.LogConn, header)
	if err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	if rec != nil {
		t.Error("header line should return nil record")
	}

	line := "1716000000.123456\tCabc123\t192.168.1.10\t54321\t10.0.0.1\t443\ttcp\tssl\t1.5\t1024\t2048\tSF\t-\t-\t0\tShADadfF\t10\t1500\t12\t2500"
	rec, err = p.ParseLine(zeek.LogConn, line)
	if err != nil {
		t.Fatalf("parsing conn line: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil record")
	}

	if rec.UID != "Cabc123" {
		t.Errorf("UID: got %q, want %q", rec.UID, "Cabc123")
	}
	if rec.Fields["id.orig_h"] != "192.168.1.10" {
		t.Errorf("orig_h: got %q, want %q", rec.Fields["id.orig_h"], "192.168.1.10")
	}
	if rec.Fields["conn_state"] != "SF" {
		t.Errorf("conn_state: got %q, want %q", rec.Fields["conn_state"], "SF")
	}

	// Timestamp should be close to the encoded value
	want := time.Unix(1716000000, int64(0.123456*1e9)).UTC()
	if diff := rec.Timestamp.Sub(want).Abs(); diff > time.Millisecond {
		t.Errorf("timestamp diff too large: %v", diff)
	}
}

func TestParseTSVNotice(t *testing.T) {
	p := zeek.NewParser("tsv")

	header := "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfuid\tfile_mime_type\tfile_desc\tproto\tnote\tmsg\tsub\tsrc\tdst\tp\tn\tpeer_descr\tactions\tsuppress_for\tdropped"
	p.ParseLine(zeek.LogNotice, header)

	line := "1716000000.000000\tCxyz\t10.0.0.5\t49200\t10.0.0.10\t445\t-\t-\t-\ttcp\tBZAR::ATTACK_TA0008_T1021_002_SMB_Admin_Share\tLateral movement detected\t-\t10.0.0.5\t10.0.0.10\t445\t-\tzeek\tNotice::ACTION_LOG\t3600.0\tF"
	rec, err := p.ParseLine(zeek.LogNotice, line)
	if err != nil {
		t.Fatalf("parsing notice: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil record")
	}

	notice := zeek.ToNoticeRecord(rec)
	if notice.Note != "BZAR::ATTACK_TA0008_T1021_002_SMB_Admin_Share" {
		t.Errorf("note: got %q", notice.Note)
	}
	if notice.OrigH != "10.0.0.5" {
		t.Errorf("orig_h: got %q", notice.OrigH)
	}
}

func TestParseCommentLine(t *testing.T) {
	p := zeek.NewParser("tsv")
	for _, line := range []string{"#separator \\t", "#set_separator ,", "#empty_field -", "#unset_field -"} {
		rec, err := p.ParseLine(zeek.LogConn, line)
		if err != nil {
			t.Errorf("comment line %q should not return error: %v", line, err)
		}
		if rec != nil {
			t.Errorf("comment line %q should return nil record", line)
		}
	}
}

func TestParseJSONConn(t *testing.T) {
	p := zeek.NewParser("json")
	line := `{"ts":1716000000.5,"uid":"Cjson1","id.orig_h":"172.16.0.1","id.orig_p":12345,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","service":"dns","conn_state":"SF"}`

	rec, err := p.ParseLine(zeek.LogConn, line)
	if err != nil {
		t.Fatalf("parsing JSON: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil record")
	}
	if rec.UID != "Cjson1" {
		t.Errorf("UID: got %q", rec.UID)
	}
	if rec.Fields["proto"] != "udp" {
		t.Errorf("proto: got %q", rec.Fields["proto"])
	}
}
