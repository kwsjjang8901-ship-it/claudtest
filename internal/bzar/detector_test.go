package bzar_test

import (
	"testing"
	"time"

	"github.com/zeekurity/zeek-bzar-ocsf/internal/bzar"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/zeek"
)

func makeNotice(note, msg, origH, respH string) *zeek.NoticeRecord {
	return &zeek.NoticeRecord{
		TS:    time.Now(),
		UID:   "Ctest123",
		Note:  note,
		Msg:   msg,
		OrigH: origH,
		OrigP: "49200",
		RespH: respH,
		RespP: "445",
		Proto: "tcp",
	}
}

func TestAnalyzeBZARNotice(t *testing.T) {
	notice := makeNotice(
		"BZAR::ATTACK_TA0008_T1021_002_SMB_Admin_Share",
		"SMB admin share accessed from 10.0.0.5 to 10.0.0.10",
		"10.0.0.5",
		"10.0.0.10",
	)

	det := bzar.Analyze(notice)
	if det == nil {
		t.Fatal("expected detection, got nil")
	}
	if det.Technique == nil {
		t.Fatal("expected technique mapping")
	}
	if det.Technique.TacticID != "TA0008" {
		t.Errorf("tactic: got %q, want TA0008", det.Technique.TacticID)
	}
	if det.Technique.SubtechniqueID != "T1021.002" {
		t.Errorf("sub-technique: got %q, want T1021.002", det.Technique.SubtechniqueID)
	}
	if det.SrcIP != "10.0.0.5" {
		t.Errorf("srcIP: got %q", det.SrcIP)
	}
	if det.Severity != 5 {
		t.Errorf("severity: got %d, want 5 for lateral movement", det.Severity)
	}
}

func TestAnalyzeNonBZARNotice(t *testing.T) {
	notice := makeNotice("SSL::Invalid_Server_Cert", "Invalid cert", "1.2.3.4", "5.6.7.8")
	det := bzar.Analyze(notice)
	if det != nil {
		t.Errorf("expected nil detection for non-BZAR notice, got %+v", det)
	}
}

func TestIsBZARNotice(t *testing.T) {
	cases := []struct {
		note string
		want bool
	}{
		{"BZAR::ATTACK_TA0008_Lateral_Movement", true},
		{"BZAR::ATTACK_TA0007_Discovery", true},
		{"SSL::Invalid_Cert", false},
		{"", false},
		{"BZAR", false},
		{"BZAR:", false},
		{"BZAR::", true},  // prefix with :: is a valid BZAR notice
	}
	for _, c := range cases {
		got := bzar.IsBZARNotice(c.note)
		if got != c.want {
			t.Errorf("IsBZARNotice(%q) = %v, want %v", c.note, got, c.want)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		tacticID string
		minSev   int
	}{
		{"TA0008", 5}, // Lateral Movement – critical
		{"TA0006", 5}, // Credential Access – critical
		{"TA0002", 4}, // Execution – high
		{"TA0007", 2}, // Discovery – low
	}
	for _, c := range cases {
		sev := bzar.SeverityFromTactic(c.tacticID)
		if sev < c.minSev {
			t.Errorf("tactic %s: severity %d < expected minimum %d", c.tacticID, sev, c.minSev)
		}
	}
}
