package ocsf

import "time"

// Class UIDs per OCSF 1.1 specification.
const (
	ClassNetworkActivity  = 4001 // Network Activity
	ClassDetectionFinding = 2004 // Detection Finding
	ClassDNSActivity      = 4003 // DNS Activity
	ClassHTTPActivity     = 4002 // HTTP Activity
)

// Category UIDs.
const (
	CategoryFindings        = 2
	CategoryNetworkActivity = 4
)

// Severity IDs (OCSF).
const (
	SeverityIDUnknown       = 0
	SeverityIDInformational = 1
	SeverityIDLow           = 2
	SeverityIDMedium        = 3
	SeverityIDHigh          = 4
	SeverityIDCritical      = 5
)

// Activity IDs for Network Activity.
const (
	ActivityNetworkUnknown = 0
	ActivityNetworkOpen    = 1
	ActivityNetworkClose   = 2
	ActivityNetworkReset   = 3
	ActivityNetworkFail    = 4
	ActivityNetworkRefuse  = 5
)

// Activity IDs for Detection Finding.
const (
	ActivityFindingCreate = 1
	ActivityFindingUpdate = 2
	ActivityFindingClose  = 3
)

// Metadata describes the source of the event.
type Metadata struct {
	Version   string    `json:"version"`
	Product   Product   `json:"product"`
	EventCode string    `json:"event_code,omitempty"`
	LoggedTime *int64   `json:"logged_time,omitempty"`
	UID       string    `json:"uid,omitempty"`
}

// Product identifies the security product.
type Product struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	URLString  string `json:"url_string,omitempty"`
	VendorName string `json:"vendor_name"`
}

// Endpoint represents a network endpoint.
type Endpoint struct {
	IP        string `json:"ip,omitempty"`
	Port      int    `json:"port,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Interface *NetworkInterface `json:"interface,omitempty"`
}

// NetworkInterface details.
type NetworkInterface struct {
	Name string `json:"name,omitempty"`
}

// ConnectionInfo holds connection-level data.
type ConnectionInfo struct {
	Protocol    string `json:"protocol_name,omitempty"`
	ProtocolNum int    `json:"protocol_num,omitempty"`
	Direction   string `json:"direction,omitempty"`
}

// Traffic holds byte/packet counts.
type Traffic struct {
	BytesSent    int64 `json:"bytes_in,omitempty"`
	BytesReceived int64 `json:"bytes_out,omitempty"`
	PacketsSent  int64 `json:"packets_in,omitempty"`
	PacketsReceived int64 `json:"packets_out,omitempty"`
}

// Finding describes what was found.
type Finding struct {
	Title          string         `json:"title"`
	Description    string         `json:"desc,omitempty"`
	Types          []string       `json:"types,omitempty"`
	RelatedEvents  []RelatedEvent `json:"related_events,omitempty"`
	CreatedTime    int64          `json:"created_time,omitempty"`
}

// RelatedEvent links a detection to underlying log records.
type RelatedEvent struct {
	UID     string `json:"uid,omitempty"`
	Type    string `json:"type,omitempty"`
	Product string `json:"product,omitempty"`
}

// Attack maps to a MITRE ATT&CK entry.
type Attack struct {
	Tactic    *Tactic    `json:"tactic,omitempty"`
	Technique *Technique `json:"technique,omitempty"`
}

// Tactic is a MITRE ATT&CK tactic.
type Tactic struct {
	ID   string `json:"uid"`
	Name string `json:"name"`
}

// Technique is a MITRE ATT&CK technique or sub-technique.
type Technique struct {
	ID   string `json:"uid"`
	Name string `json:"name"`
}

// Evidence holds forensic artifacts supporting a detection.
type Evidence struct {
	UID     string            `json:"uid,omitempty"`
	LogType string            `json:"log_type,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

// DNSQuery holds DNS-specific query data.
type DNSQuery struct {
	Hostname string `json:"hostname,omitempty"`
	Type     string `json:"type,omitempty"`
	Class    string `json:"class,omitempty"`
}

// DNSAnswer holds DNS answer data.
type DNSAnswer struct {
	Hostname string `json:"hostname,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
}

// HTTPRequest holds HTTP request details.
type HTTPRequest struct {
	Method    string `json:"method,omitempty"`
	URL       *URL   `json:"url,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	BodyLen   int64  `json:"length,omitempty"`
	Referrer  string `json:"referrer,omitempty"`
	Version   string `json:"version,omitempty"`
}

// HTTPResponse holds HTTP response details.
type HTTPResponse struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	BodyLen int64  `json:"length,omitempty"`
}

// URL holds URL components.
type URL struct {
	Hostname string `json:"hostname,omitempty"`
	Path     string `json:"path,omitempty"`
	URLString string `json:"url_string,omitempty"`
}

// TLSExtension holds TLS/SSL details.
type TLSExtension struct {
	Version  string `json:"version,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Subject  string `json:"subject,omitempty"`
}

// NetworkActivity is OCSF class 4001.
type NetworkActivity struct {
	// Required OCSF fields
	CategoryUID int       `json:"category_uid"`
	CategoryName string   `json:"category_name"`
	ClassUID    int       `json:"class_uid"`
	ClassName   string    `json:"class_name"`
	ActivityID  int       `json:"activity_id"`
	ActivityName string   `json:"activity_name"`
	SeverityID  int       `json:"severity_id"`
	Severity    string    `json:"severity"`
	StatusID    int       `json:"status_id"`
	Status      string    `json:"status"`
	TypeUID     int       `json:"type_uid"`
	TypeName    string    `json:"type_name"`
	Time        int64     `json:"time"`
	Message     string    `json:"message,omitempty"`

	Metadata   Metadata   `json:"metadata"`
	SrcEndpoint Endpoint  `json:"src_endpoint"`
	DstEndpoint Endpoint  `json:"dst_endpoint"`
	Connection  *ConnectionInfo `json:"connection_info,omitempty"`
	Traffic     *Traffic       `json:"traffic,omitempty"`

	// Extra context
	RawData     map[string]string `json:"raw_data,omitempty"`
}

// HTTPActivity is OCSF class 4002.
type HTTPActivity struct {
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name"`
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity"`
	StatusID     int    `json:"status_id,omitempty"`
	Status       string `json:"status,omitempty"`
	TypeUID      int    `json:"type_uid"`
	TypeName     string `json:"type_name"`
	Time         int64  `json:"time"`

	Metadata    Metadata     `json:"metadata"`
	SrcEndpoint Endpoint     `json:"src_endpoint"`
	DstEndpoint Endpoint     `json:"dst_endpoint"`
	Request     *HTTPRequest `json:"http_request,omitempty"`
	Response    *HTTPResponse `json:"http_response,omitempty"`

	RawData map[string]string `json:"raw_data,omitempty"`
}

// DNSActivity is OCSF class 4003.
type DNSActivity struct {
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name"`
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity"`
	TypeUID      int    `json:"type_uid"`
	TypeName     string `json:"type_name"`
	Time         int64  `json:"time"`

	Metadata    Metadata   `json:"metadata"`
	SrcEndpoint Endpoint   `json:"src_endpoint"`
	DstEndpoint Endpoint   `json:"dst_endpoint"`
	Query       *DNSQuery  `json:"query,omitempty"`
	Answers     []DNSAnswer `json:"answers,omitempty"`
	RCode       string     `json:"rcode,omitempty"`

	RawData map[string]string `json:"raw_data,omitempty"`
}

// DetectionFinding is OCSF class 2004.
type DetectionFinding struct {
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name"`
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity"`
	StatusID     int    `json:"status_id"`
	Status       string `json:"status"`
	TypeUID      int    `json:"type_uid"`
	TypeName     string `json:"type_name"`
	Time         int64  `json:"time"`
	Message      string `json:"message,omitempty"`

	Metadata    Metadata  `json:"metadata"`
	SrcEndpoint Endpoint  `json:"src_endpoint"`
	DstEndpoint Endpoint  `json:"dst_endpoint"`

	Finding   Finding   `json:"finding"`
	Attacks   []Attack  `json:"attacks,omitempty"`
	Evidence  []Evidence `json:"evidences,omitempty"`

	RawData map[string]string `json:"raw_data,omitempty"`
}

// TimeToUnixMillis converts a time.Time to Unix milliseconds.
func TimeToUnixMillis(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}

func severityName(id int) string {
	switch id {
	case 0:
		return "Unknown"
	case 1:
		return "Informational"
	case 2:
		return "Low"
	case 3:
		return "Medium"
	case 4:
		return "High"
	case 5:
		return "Critical"
	default:
		return "Unknown"
	}
}

func protocolNum(proto string) int {
	switch proto {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 0
	}
}
