package zeek

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Parser parses Zeek log lines into Records.
type Parser struct {
	format  string // "tsv" or "json"
	headers map[LogType][]string
}

func NewParser(format string) *Parser {
	return &Parser{
		format:  format,
		headers: make(map[LogType][]string),
	}
}

// SetHeaders stores the TSV column headers for a log type (parsed from #fields line).
func (p *Parser) SetHeaders(logType LogType, headers []string) {
	p.headers[logType] = headers
}

// ParseLine parses a single log line. Returns nil if line is a comment/separator.
func (p *Parser) ParseLine(logType LogType, line string) (*Record, error) {
	if line == "" {
		return nil, nil
	}

	if p.format == "json" {
		return p.parseJSON(logType, line)
	}
	return p.parseTSV(logType, line)
}

func (p *Parser) parseTSV(logType LogType, line string) (*Record, error) {
	// Skip comment lines; capture #fields as headers
	if strings.HasPrefix(line, "#") {
		if strings.HasPrefix(line, "#fields") {
			parts := strings.Split(line, "\t")
			if len(parts) > 1 {
				p.headers[logType] = parts[1:]
			}
		}
		return nil, nil
	}

	headers, ok := p.headers[logType]
	if !ok || len(headers) == 0 {
		return nil, fmt.Errorf("no headers known for log type %s", logType)
	}

	parts := strings.Split(line, "\t")
	if len(parts) < len(headers) {
		return nil, fmt.Errorf("field count mismatch: got %d, want %d", len(parts), len(headers))
	}

	fields := make(map[string]string, len(headers))
	for i, h := range headers {
		if i < len(parts) {
			fields[h] = parts[i]
		}
	}

	ts := parseTimestamp(fields["ts"])
	uid := fields["uid"]

	return &Record{
		Type:      logType,
		Timestamp: ts,
		UID:       uid,
		Fields:    fields,
		Raw:       line,
	}, nil
}

func (p *Parser) parseJSON(logType LogType, line string) (*Record, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	strFields := make(map[string]string, len(fields))
	for k, v := range fields {
		switch val := v.(type) {
		case string:
			strFields[k] = val
		case float64:
			strFields[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case bool:
			strFields[k] = strconv.FormatBool(val)
		default:
			b, _ := json.Marshal(v)
			strFields[k] = string(b)
		}
	}

	ts := parseTimestamp(strFields["ts"])
	uid := strFields["uid"]

	return &Record{
		Type:      logType,
		Timestamp: ts,
		UID:       uid,
		Fields:    strFields,
		Raw:       line,
	}, nil
}

func parseTimestamp(s string) time.Time {
	if s == "" || s == "-" {
		return time.Now()
	}
	// Zeek TSV timestamps are Unix epoch with microseconds: "1234567890.123456"
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC()
	}
	// Try RFC3339 for JSON format
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

// ToConnRecord converts a generic Record to a ConnRecord.
func ToConnRecord(r *Record) *ConnRecord {
	f := r.Fields
	return &ConnRecord{
		TS:          r.Timestamp,
		UID:         r.UID,
		OrigH:       f["id.orig_h"],
		OrigP:       f["id.orig_p"],
		RespH:       f["id.resp_h"],
		RespP:       f["id.resp_p"],
		Proto:       f["proto"],
		Service:     f["service"],
		Duration:    f["duration"],
		OrigBytes:   f["orig_bytes"],
		RespBytes:   f["resp_bytes"],
		ConnState:   f["conn_state"],
		LocalOrig:   f["local_orig"],
		LocalResp:   f["local_resp"],
		MissedBytes: f["missed_bytes"],
		History:     f["history"],
		OrigPkts:    f["orig_pkts"],
		OrigIPBytes: f["orig_ip_bytes"],
		RespPkts:    f["resp_pkts"],
		RespIPBytes: f["resp_ip_bytes"],
	}
}

// ToDNSRecord converts a generic Record to a DNSRecord.
func ToDNSRecord(r *Record) *DNSRecord {
	f := r.Fields
	return &DNSRecord{
		TS:       r.Timestamp,
		UID:      r.UID,
		OrigH:    f["id.orig_h"],
		OrigP:    f["id.orig_p"],
		RespH:    f["id.resp_h"],
		RespP:    f["id.resp_p"],
		Proto:    f["proto"],
		TransID:  f["trans_id"],
		RTT:      f["rtt"],
		Query:    f["query"],
		QClass:   f["qclass_name"],
		QType:    f["qtype_name"],
		RCode:    f["rcode_name"],
		AA:       f["AA"],
		TC:       f["TC"],
		RD:       f["RD"],
		RA:       f["RA"],
		Z:        f["Z"],
		Answers:  f["answers"],
		TTLs:     f["TTLs"],
		Rejected: f["rejected"],
	}
}

// ToHTTPRecord converts a generic Record to an HTTPRecord.
func ToHTTPRecord(r *Record) *HTTPRecord {
	f := r.Fields
	return &HTTPRecord{
		TS:              r.Timestamp,
		UID:             r.UID,
		OrigH:           f["id.orig_h"],
		OrigP:           f["id.orig_p"],
		RespH:           f["id.resp_h"],
		RespP:           f["id.resp_p"],
		TransDepth:      f["trans_depth"],
		Method:          f["method"],
		Host:            f["host"],
		URI:             f["uri"],
		Referrer:        f["referrer"],
		Version:         f["version"],
		UserAgent:       f["user_agent"],
		Origin:          f["origin"],
		RequestBodyLen:  f["request_body_len"],
		ResponseBodyLen: f["response_body_len"],
		StatusCode:      f["status_code"],
		StatusMsg:       f["status_msg"],
		InfoCode:        f["info_code"],
		InfoMsg:         f["info_msg"],
		Tags:            f["tags"],
		Username:        f["username"],
		Password:        f["password"],
		ProxiedFrom:     f["proxied"],
		OrigFuids:       f["orig_fuids"],
		OrigFilenames:   f["orig_filenames"],
		OrigMimeTypes:   f["orig_mime_types"],
		RespFuids:       f["resp_fuids"],
		RespFilenames:   f["resp_filenames"],
		RespMimeTypes:   f["resp_mime_types"],
	}
}

// ToSSLRecord converts a generic Record to an SSLRecord.
func ToSSLRecord(r *Record) *SSLRecord {
	f := r.Fields
	return &SSLRecord{
		TS:                   r.Timestamp,
		UID:                  r.UID,
		OrigH:                f["id.orig_h"],
		OrigP:                f["id.orig_p"],
		RespH:                f["id.resp_h"],
		RespP:                f["id.resp_p"],
		Version:              f["version"],
		Cipher:               f["cipher"],
		CurveAlgo:            f["curve"],
		ServerName:           f["server_name"],
		Resumed:              f["resumed"],
		LastAlert:            f["last_alert"],
		NextProtocol:         f["next_protocol"],
		Established:          f["established"],
		CertChainFuids:       f["cert_chain_fuids"],
		ClientCertChainFuids: f["client_cert_chain_fuids"],
		Subject:              f["subject"],
		Issuer:               f["issuer"],
		ClientSubject:        f["client_subject"],
		ClientIssuer:         f["client_issuer"],
		ValidationStatus:     f["validation_status"],
	}
}

// ToSMBFilesRecord converts a generic Record to an SMBFilesRecord.
func ToSMBFilesRecord(r *Record) *SMBFilesRecord {
	f := r.Fields
	return &SMBFilesRecord{
		TS:       r.Timestamp,
		UID:      r.UID,
		OrigH:    f["id.orig_h"],
		OrigP:    f["id.orig_p"],
		RespH:    f["id.resp_h"],
		RespP:    f["id.resp_p"],
		FUID:     f["fuid"],
		Action:   f["action"],
		Path:     f["path"],
		Name:     f["name"],
		Size:     f["size"],
		PrevName: f["prev_name"],
		Times:    f["times"],
	}
}

// ToSMBMappingRecord converts a generic Record to an SMBMappingRecord.
func ToSMBMappingRecord(r *Record) *SMBMappingRecord {
	f := r.Fields
	return &SMBMappingRecord{
		TS:        r.Timestamp,
		UID:       r.UID,
		OrigH:     f["id.orig_h"],
		OrigP:     f["id.orig_p"],
		RespH:     f["id.resp_h"],
		RespP:     f["id.resp_p"],
		Path:      f["path"],
		Service:   f["service"],
		NativeFS:  f["native_file_system"],
		ShareType: f["share_type"],
	}
}

// ToDCERPCRecord converts a generic Record to a DCERPCRecord.
func ToDCERPCRecord(r *Record) *DCERPCRecord {
	f := r.Fields
	return &DCERPCRecord{
		TS:        r.Timestamp,
		UID:       r.UID,
		OrigH:     f["id.orig_h"],
		OrigP:     f["id.orig_p"],
		RespH:     f["id.resp_h"],
		RespP:     f["id.resp_p"],
		RTTUSEC:   f["rtt"],
		NamedPipe: f["named_pipe"],
		Endpoint:  f["endpoint"],
		Operation: f["operation"],
	}
}

// ToNoticeRecord converts a generic Record to a NoticeRecord.
func ToNoticeRecord(r *Record) *NoticeRecord {
	f := r.Fields
	return &NoticeRecord{
		TS:          r.Timestamp,
		UID:         f["uid"],
		OrigH:       f["id.orig_h"],
		OrigP:       f["id.orig_p"],
		RespH:       f["id.resp_h"],
		RespP:       f["id.resp_p"],
		FUID:        f["fuid"],
		FileMime:    f["file_mime_type"],
		FileDesc:    f["file_desc"],
		Proto:       f["proto"],
		Note:        f["note"],
		Msg:         f["msg"],
		Sub:         f["sub"],
		Src:         f["src"],
		Dst:         f["dst"],
		P:           f["p"],
		N:           f["n"],
		PeerDescr:   f["peer_descr"],
		Actions:     f["actions"],
		SuppressFor: f["suppress_for"],
		Dropped:     f["dropped"],
	}
}
