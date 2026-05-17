package ocsf

import (
	"strconv"
	"strings"

	"github.com/zeekurity/zeek-bzar-ocsf/internal/bzar"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/evidence"
	"github.com/zeekurity/zeek-bzar-ocsf/internal/zeek"
)

// Mapper converts Zeek records into OCSF events.
type Mapper struct {
	metadata Metadata
}

// NewMapper creates a Mapper with the given product metadata.
func NewMapper(name, version, url string) *Mapper {
	return &Mapper{
		metadata: Metadata{
			Version: "1.1.0",
			Product: Product{
				Name:       name,
				Version:    version,
				URLString:  url,
				VendorName: "zeekurity",
			},
		},
	}
}

// FromConn maps a Zeek conn record to a NetworkActivity event.
func (m *Mapper) FromConn(r *zeek.ConnRecord) *NetworkActivity {
	activityID := activityFromConnState(r.ConnState)

	event := &NetworkActivity{
		CategoryUID:  CategoryNetworkActivity,
		CategoryName: "Network Activity",
		ClassUID:     ClassNetworkActivity,
		ClassName:    "Network Activity",
		ActivityID:   activityID,
		ActivityName: networkActivityName(activityID),
		SeverityID:   SeverityIDInformational,
		Severity:     severityName(SeverityIDInformational),
		StatusID:     1,
		Status:       "Success",
		TypeUID:      ClassNetworkActivity*100 + activityID,
		TypeName:     "Network Activity: " + networkActivityName(activityID),
		Time:         TimeToUnixMillis(r.TS),
		Metadata:     m.metadata,
		SrcEndpoint: Endpoint{
			IP:   r.OrigH,
			Port: parseInt(r.OrigP),
		},
		DstEndpoint: Endpoint{
			IP:   r.RespH,
			Port: parseInt(r.RespP),
		},
		Connection: &ConnectionInfo{
			Protocol:    r.Proto,
			ProtocolNum: protocolNum(r.Proto),
		},
	}

	event.Metadata.UID = r.UID

	// Build traffic stats
	origBytes := parseInt64(r.OrigBytes)
	respBytes := parseInt64(r.RespBytes)
	origPkts := parseInt64(r.OrigPkts)
	respPkts := parseInt64(r.RespPkts)
	if origBytes > 0 || respBytes > 0 {
		event.Traffic = &Traffic{
			BytesSent:       origBytes,
			BytesReceived:   respBytes,
			PacketsSent:     origPkts,
			PacketsReceived: respPkts,
		}
	}

	event.RawData = map[string]string{
		"uid":        r.UID,
		"conn_state": r.ConnState,
		"service":    r.Service,
		"duration":   r.Duration,
		"history":    r.History,
	}

	return event
}

// FromDNS maps a Zeek DNS record to a DNSActivity event.
func (m *Mapper) FromDNS(r *zeek.DNSRecord) *DNSActivity {
	event := &DNSActivity{
		CategoryUID:  CategoryNetworkActivity,
		CategoryName: "Network Activity",
		ClassUID:     ClassDNSActivity,
		ClassName:    "DNS Activity",
		ActivityID:   1, // Query
		ActivityName: "Query",
		SeverityID:   SeverityIDInformational,
		Severity:     severityName(SeverityIDInformational),
		TypeUID:      ClassDNSActivity*100 + 1,
		TypeName:     "DNS Activity: Query",
		Time:         TimeToUnixMillis(r.TS),
		Metadata:     m.metadata,
		SrcEndpoint: Endpoint{
			IP:   r.OrigH,
			Port: parseInt(r.OrigP),
		},
		DstEndpoint: Endpoint{
			IP:   r.RespH,
			Port: parseInt(r.RespP),
		},
		Query: &DNSQuery{
			Hostname: r.Query,
			Type:     r.QType,
			Class:    r.QClass,
		},
		RCode: r.RCode,
	}

	event.Metadata.UID = r.UID

	// Parse answers
	if r.Answers != "" && r.Answers != "-" {
		answers := strings.Split(r.Answers, ",")
		ttls := strings.Split(r.TTLs, ",")
		for i, ans := range answers {
			a := DNSAnswer{Value: strings.TrimSpace(ans)}
			if i < len(ttls) {
				a.TTL = parseInt(strings.TrimSpace(ttls[i]))
			}
			event.Answers = append(event.Answers, a)
		}
	}

	event.RawData = map[string]string{
		"uid":   r.UID,
		"query": r.Query,
		"rcode": r.RCode,
	}

	return event
}

// FromHTTP maps a Zeek HTTP record to an HTTPActivity event.
func (m *Mapper) FromHTTP(r *zeek.HTTPRecord) *HTTPActivity {
	statusCode := parseInt(r.StatusCode)
	activityID := 1 // Request
	if statusCode > 0 {
		activityID = 2 // Response
	}

	event := &HTTPActivity{
		CategoryUID:  CategoryNetworkActivity,
		CategoryName: "Network Activity",
		ClassUID:     ClassHTTPActivity,
		ClassName:    "HTTP Activity",
		ActivityID:   activityID,
		ActivityName: httpActivityName(activityID),
		SeverityID:   SeverityIDInformational,
		Severity:     severityName(SeverityIDInformational),
		TypeUID:      ClassHTTPActivity*100 + activityID,
		TypeName:     "HTTP Activity: " + httpActivityName(activityID),
		Time:         TimeToUnixMillis(r.TS),
		Metadata:     m.metadata,
		SrcEndpoint: Endpoint{
			IP:   r.OrigH,
			Port: parseInt(r.OrigP),
		},
		DstEndpoint: Endpoint{
			IP:       r.RespH,
			Port:     parseInt(r.RespP),
			Hostname: r.Host,
		},
		Request: &HTTPRequest{
			Method:    r.Method,
			UserAgent: r.UserAgent,
			BodyLen:   parseInt64(r.RequestBodyLen),
			Referrer:  r.Referrer,
			Version:   r.Version,
			URL: &URL{
				Hostname:  r.Host,
				Path:      r.URI,
				URLString: "http://" + r.Host + r.URI,
			},
		},
	}

	event.Metadata.UID = r.UID

	if statusCode > 0 {
		event.Response = &HTTPResponse{
			Code:    statusCode,
			Message: r.StatusMsg,
			BodyLen: parseInt64(r.ResponseBodyLen),
		}
	}

	event.RawData = map[string]string{
		"uid":         r.UID,
		"method":      r.Method,
		"host":        r.Host,
		"uri":         r.URI,
		"status_code": r.StatusCode,
		"user_agent":  r.UserAgent,
	}

	return event
}

// FromDetection maps a BZAR Detection to a DetectionFinding event.
func (m *Mapper) FromDetection(det *bzar.Detection, evList []evidence.Entry) *DetectionFinding {
	severityID := det.Severity
	if severityID > 5 {
		severityID = 5
	}

	title := det.Notice.Note
	if det.Technique != nil && det.Technique.TechniqueName != "" {
		title = det.Technique.TechniqueName
		if det.Technique.SubtechniqueName != "" {
			title += ": " + det.Technique.SubtechniqueName
		}
	}

	finding := Finding{
		Title:       title,
		Description: det.Notice.Msg,
		Types:       []string{"Threat Detection"},
		CreatedTime: TimeToUnixMillis(det.Notice.TS),
	}

	// Related events from evidence buffer
	for _, ev := range evList {
		finding.RelatedEvents = append(finding.RelatedEvents, RelatedEvent{
			UID:     ev.UID,
			Type:    string(ev.LogType),
			Product: "zeek",
		})
	}

	// Build attacks
	var attacks []Attack
	if det.Technique != nil {
		atk := Attack{}
		if det.Technique.TacticID != "" {
			atk.Tactic = &Tactic{
				ID:   det.Technique.TacticID,
				Name: det.Technique.TacticName,
			}
		}
		techID := det.Technique.TechniqueID
		techName := det.Technique.TechniqueName
		if det.Technique.SubtechniqueID != "" {
			techID = det.Technique.SubtechniqueID
			techName = det.Technique.SubtechniqueName
		}
		if techID != "" {
			atk.Technique = &Technique{
				ID:   techID,
				Name: techName,
			}
		}
		attacks = append(attacks, atk)
	}

	// Build evidence list
	var evidences []Evidence
	for _, ev := range evList {
		evidences = append(evidences, Evidence{
			UID:     ev.UID,
			LogType: string(ev.LogType),
			Data:    ev.Fields,
		})
	}
	// Always include the notice itself as evidence
	evidences = append(evidences, Evidence{
		UID:     det.UID,
		LogType: "notice",
		Data:    det.Notice.Fields(),
	})

	event := &DetectionFinding{
		CategoryUID:  CategoryFindings,
		CategoryName: "Findings",
		ClassUID:     ClassDetectionFinding,
		ClassName:    "Detection Finding",
		ActivityID:   ActivityFindingCreate,
		ActivityName: "Create",
		SeverityID:   severityID,
		Severity:     severityName(severityID),
		StatusID:     1,
		Status:       "New",
		TypeUID:      ClassDetectionFinding*100 + ActivityFindingCreate,
		TypeName:     "Detection Finding: Create",
		Time:         TimeToUnixMillis(det.Notice.TS),
		Message:      det.Notice.Msg,
		Metadata:     m.metadata,
		SrcEndpoint: Endpoint{
			IP:   det.SrcIP,
			Port: parseInt(det.SrcPort),
		},
		DstEndpoint: Endpoint{
			IP:   det.DstIP,
			Port: parseInt(det.DstPort),
		},
		Finding:  finding,
		Attacks:  attacks,
		Evidence: evidences,
		RawData: map[string]string{
			"notice_type": det.Notice.Note,
			"msg":         det.Notice.Msg,
			"sub":         det.Notice.Sub,
			"uid":         det.UID,
		},
	}

	event.Metadata.UID = det.UID
	return event
}

// helpers

func activityFromConnState(state string) int {
	switch state {
	case "SF", "S1", "S2", "S3":
		return ActivityNetworkClose
	case "REJ":
		return ActivityNetworkRefuse
	case "RSTOS0", "RSTRH", "RSTR":
		return ActivityNetworkReset
	case "S0", "SH", "SHR":
		return ActivityNetworkFail
	default:
		return ActivityNetworkOpen
	}
}

func networkActivityName(id int) string {
	switch id {
	case ActivityNetworkOpen:
		return "Open"
	case ActivityNetworkClose:
		return "Close"
	case ActivityNetworkReset:
		return "Reset"
	case ActivityNetworkFail:
		return "Fail"
	case ActivityNetworkRefuse:
		return "Refuse"
	default:
		return "Unknown"
	}
}

func httpActivityName(id int) string {
	switch id {
	case 1:
		return "Request"
	case 2:
		return "Response"
	default:
		return "Unknown"
	}
}

func parseInt(s string) int {
	if s == "" || s == "-" {
		return 0
	}
	v, _ := strconv.Atoi(s)
	return v
}

func parseInt64(s string) int64 {
	if s == "" || s == "-" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
