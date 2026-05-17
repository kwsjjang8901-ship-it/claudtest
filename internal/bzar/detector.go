package bzar

import (
	"github.com/kwsjjang8901-ship-it/claudtest/internal/zeek"
)

// Detection represents a BZAR-detected threat.
type Detection struct {
	Notice     *zeek.NoticeRecord
	Technique  *MITRETechnique
	Severity   int    // 1 (lowest) to 5 (critical)
	SrcIP      string
	DstIP      string
	SrcPort    string
	DstPort    string
	UID        string
}

// Analyze checks if a Zeek notice record is a BZAR alert.
// Returns nil if the notice is not a BZAR detection.
func Analyze(notice *zeek.NoticeRecord) *Detection {
	if !IsBZARNotice(notice.Note) {
		return nil
	}

	technique, _ := Lookup(notice.Note)
	if technique == nil {
		// Generic BZAR notice without mapped technique
		technique = &MITRETechnique{
			TacticName:    "Unknown",
			TechniqueName: notice.Note,
		}
	}

	// Determine IP addresses from notice fields (src/dst or id.orig_h/resp_h)
	srcIP := notice.Src
	dstIP := notice.Dst
	if srcIP == "" {
		srcIP = notice.OrigH
	}
	if dstIP == "" {
		dstIP = notice.RespH
	}

	uid := notice.UID
	if uid == "" || uid == "-" {
		uid = srcIP + ":" + notice.OrigP + "->" + dstIP + ":" + notice.RespP
	}

	return &Detection{
		Notice:    notice,
		Technique: technique,
		Severity:  SeverityFromTactic(technique.TacticID),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   notice.OrigP,
		DstPort:   notice.RespP,
		UID:       uid,
	}
}
