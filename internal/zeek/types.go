package zeek

import "time"

// LogType identifies which Zeek log a record came from.
type LogType string

const (
	LogConn       LogType = "conn"
	LogDNS        LogType = "dns"
	LogHTTP       LogType = "http"
	LogSSL        LogType = "ssl"
	LogSMBFiles   LogType = "smb_files"
	LogSMBMapping LogType = "smb_mapping"
	LogDCERPC     LogType = "dce_rpc"
	LogNotice     LogType = "notice"
)

// Record is a parsed Zeek log entry with its raw fields.
type Record struct {
	Type      LogType
	Timestamp time.Time
	UID       string
	Fields    map[string]string
	Raw       string
}

// ConnRecord is a parsed conn.log entry.
type ConnRecord struct {
	TS         time.Time
	UID        string
	OrigH      string
	OrigP      string
	RespH      string
	RespP      string
	Proto      string
	Service    string
	Duration   string
	OrigBytes  string
	RespBytes  string
	ConnState  string
	LocalOrig  string
	LocalResp  string
	MissedBytes string
	History    string
	OrigPkts   string
	OrigIPBytes string
	RespPkts   string
	RespIPBytes string
}

// DNSRecord is a parsed dns.log entry.
type DNSRecord struct {
	TS      time.Time
	UID     string
	OrigH   string
	OrigP   string
	RespH   string
	RespP   string
	Proto   string
	TransID string
	RTT     string
	Query   string
	QClass  string
	QType   string
	RCode   string
	AA      string
	TC      string
	RD      string
	RA      string
	Z       string
	Answers string
	TTLs    string
	Rejected string
}

// HTTPRecord is a parsed http.log entry.
type HTTPRecord struct {
	TS             time.Time
	UID            string
	OrigH          string
	OrigP          string
	RespH          string
	RespP          string
	TransDepth     string
	Method         string
	Host           string
	URI            string
	Referrer       string
	Version        string
	UserAgent      string
	Origin         string
	RequestBodyLen string
	ResponseBodyLen string
	StatusCode     string
	StatusMsg      string
	InfoCode       string
	InfoMsg        string
	Tags           string
	Username       string
	Password       string
	ProxiedFrom    string
	OrigFuids      string
	OrigFilenames  string
	OrigMimeTypes  string
	RespFuids      string
	RespFilenames  string
	RespMimeTypes  string
}

// SSLRecord is a parsed ssl.log entry.
type SSLRecord struct {
	TS              time.Time
	UID             string
	OrigH           string
	OrigP           string
	RespH           string
	RespP           string
	Version         string
	Cipher          string
	CurveAlgo       string
	ServerName      string
	Resumed         string
	LastAlert       string
	NextProtocol    string
	Established     string
	CertChainFuids  string
	ClientCertChainFuids string
	Subject         string
	Issuer          string
	ClientSubject   string
	ClientIssuer    string
	ValidationStatus string
}

// SMBFilesRecord is a parsed smb_files.log entry.
type SMBFilesRecord struct {
	TS       time.Time
	UID      string
	OrigH    string
	OrigP    string
	RespH    string
	RespP    string
	FUID     string
	Action   string
	Path     string
	Name     string
	Size     string
	PrevName string
	Times    string
}

// SMBMappingRecord is a parsed smb_mapping.log entry.
type SMBMappingRecord struct {
	TS         time.Time
	UID        string
	OrigH      string
	OrigP      string
	RespH      string
	RespP      string
	Path       string
	Service    string
	NativeFS   string
	ShareType  string
}

// DCERPCRecord is a parsed dce_rpc.log entry.
type DCERPCRecord struct {
	TS           time.Time
	UID          string
	OrigH        string
	OrigP        string
	RespH        string
	RespP        string
	RTTUSEC      string
	NamedPipe    string
	Endpoint     string
	Operation    string
}

// NoticeRecord is a parsed notice.log entry.
// Fields returns the notice as a string map for evidence serialization.
func (n *NoticeRecord) Fields() map[string]string {
	return map[string]string{
		"ts":          n.TS.String(),
		"uid":         n.UID,
		"id.orig_h":   n.OrigH,
		"id.orig_p":   n.OrigP,
		"id.resp_h":   n.RespH,
		"id.resp_p":   n.RespP,
		"note":        n.Note,
		"msg":         n.Msg,
		"sub":         n.Sub,
		"src":         n.Src,
		"dst":         n.Dst,
		"proto":       n.Proto,
		"actions":     n.Actions,
		"peer_descr":  n.PeerDescr,
	}
}

type NoticeRecord struct {
	TS          time.Time
	UID         string
	OrigH       string
	OrigP       string
	RespH       string
	RespP       string
	FUID        string
	FileMime    string
	FileDesc    string
	Proto       string
	Note        string
	Msg         string
	Sub         string
	Src         string
	Dst         string
	P           string
	N           string
	PeerDescr   string
	Actions     string
	SuppressFor string
	Dropped     string
}
