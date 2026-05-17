package bzar

// MITRETechnique holds MITRE ATT&CK technique information.
type MITRETechnique struct {
	TacticID    string
	TacticName  string
	TechniqueID string
	TechniqueName string
	SubtechniqueID   string
	SubtechniqueName string
	Phase       string
}

// BZARNoticeType maps BZAR notice types to MITRE ATT&CK info.
// These correspond to BZAR's notice definitions in bzar_dce-rpc_detect.zeek, etc.
var noticeMapping = map[string]*MITRETechnique{
	// Lateral Movement – TA0008
	"BZAR::ATTACK_TA0008_Lateral_Movement": {
		TacticID:      "TA0008",
		TacticName:    "Lateral Movement",
		TechniqueID:   "T1021",
		TechniqueName: "Remote Services",
	},
	"BZAR::ATTACK_TA0008_T1021_002_SMB_Admin_Share": {
		TacticID:         "TA0008",
		TacticName:       "Lateral Movement",
		TechniqueID:      "T1021",
		TechniqueName:    "Remote Services",
		SubtechniqueID:   "T1021.002",
		SubtechniqueName: "SMB/Windows Admin Shares",
		Phase:            "lateral-movement",
	},
	"BZAR::ATTACK_TA0008_T1021_003_DCE_RPC": {
		TacticID:         "TA0008",
		TacticName:       "Lateral Movement",
		TechniqueID:      "T1021",
		TechniqueName:    "Remote Services",
		SubtechniqueID:   "T1021.003",
		SubtechniqueName: "Distributed Component Object Model",
		Phase:            "lateral-movement",
	},
	"BZAR::ATTACK_TA0008_T1021_006_WinRM": {
		TacticID:         "TA0008",
		TacticName:       "Lateral Movement",
		TechniqueID:      "T1021",
		TechniqueName:    "Remote Services",
		SubtechniqueID:   "T1021.006",
		SubtechniqueName: "Windows Remote Management",
		Phase:            "lateral-movement",
	},
	"BZAR::ATTACK_TA0008_T1570_Lateral_Tool_Transfer": {
		TacticID:      "TA0008",
		TacticName:    "Lateral Movement",
		TechniqueID:   "T1570",
		TechniqueName: "Lateral Tool Transfer",
		Phase:         "lateral-movement",
	},

	// Credential Access – TA0006
	"BZAR::ATTACK_TA0006_Credential_Access": {
		TacticID:    "TA0006",
		TacticName:  "Credential Access",
		TechniqueID: "T1003",
		TechniqueName: "OS Credential Dumping",
	},
	"BZAR::ATTACK_TA0006_T1003_002_SAM": {
		TacticID:         "TA0006",
		TacticName:       "Credential Access",
		TechniqueID:      "T1003",
		TechniqueName:    "OS Credential Dumping",
		SubtechniqueID:   "T1003.002",
		SubtechniqueName: "Security Account Manager",
		Phase:            "credential-access",
	},
	"BZAR::ATTACK_TA0006_T1003_004_LSA": {
		TacticID:         "TA0006",
		TacticName:       "Credential Access",
		TechniqueID:      "T1003",
		TechniqueName:    "OS Credential Dumping",
		SubtechniqueID:   "T1003.004",
		SubtechniqueName: "LSA Secrets",
		Phase:            "credential-access",
	},

	// Execution – TA0002
	"BZAR::ATTACK_TA0002_Execution": {
		TacticID:    "TA0002",
		TacticName:  "Execution",
		TechniqueID: "T1569",
		TechniqueName: "System Services",
	},
	"BZAR::ATTACK_TA0002_T1569_002_Service_Execution": {
		TacticID:         "TA0002",
		TacticName:       "Execution",
		TechniqueID:      "T1569",
		TechniqueName:    "System Services",
		SubtechniqueID:   "T1569.002",
		SubtechniqueName: "Service Execution",
		Phase:            "execution",
	},
	"BZAR::ATTACK_TA0002_T1047_WMI": {
		TacticID:      "TA0002",
		TacticName:    "Execution",
		TechniqueID:   "T1047",
		TechniqueName: "Windows Management Instrumentation",
		Phase:         "execution",
	},
	"BZAR::ATTACK_TA0002_T1059_003_CMD": {
		TacticID:         "TA0002",
		TacticName:       "Execution",
		TechniqueID:      "T1059",
		TechniqueName:    "Command and Scripting Interpreter",
		SubtechniqueID:   "T1059.003",
		SubtechniqueName: "Windows Command Shell",
		Phase:            "execution",
	},

	// Discovery – TA0007
	"BZAR::ATTACK_TA0007_Discovery": {
		TacticID:    "TA0007",
		TacticName:  "Discovery",
		TechniqueID: "T1018",
		TechniqueName: "Remote System Discovery",
	},
	"BZAR::ATTACK_TA0007_T1018_Remote_System_Discovery": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1018",
		TechniqueName: "Remote System Discovery",
		Phase:         "discovery",
	},
	"BZAR::ATTACK_TA0007_T1083_File_Discovery": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1083",
		TechniqueName: "File and Directory Discovery",
		Phase:         "discovery",
	},
	"BZAR::ATTACK_TA0007_T1135_Network_Share_Discovery": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1135",
		TechniqueName: "Network Share Discovery",
		Phase:         "discovery",
	},
	"BZAR::ATTACK_TA0007_T1069_Permission_Groups_Discovery": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1069",
		TechniqueName: "Permission Groups Discovery",
		Phase:         "discovery",
	},
	"BZAR::ATTACK_TA0007_T1087_Account_Discovery": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1087",
		TechniqueName: "Account Discovery",
		Phase:         "discovery",
	},
	"BZAR::ATTACK_TA0007_T1057_Process_Discovery": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1057",
		TechniqueName: "Process Discovery",
		Phase:         "discovery",
	},
	"BZAR::ATTACK_TA0007_T1012_Registry_Query": {
		TacticID:      "TA0007",
		TacticName:    "Discovery",
		TechniqueID:   "T1012",
		TechniqueName: "Query Registry",
		Phase:         "discovery",
	},

	// Collection – TA0009
	"BZAR::ATTACK_TA0009_Collection": {
		TacticID:    "TA0009",
		TacticName:  "Collection",
		TechniqueID: "T1039",
		TechniqueName: "Data from Network Shared Drive",
	},
	"BZAR::ATTACK_TA0009_T1039_Network_Drive_Data": {
		TacticID:      "TA0009",
		TacticName:    "Collection",
		TechniqueID:   "T1039",
		TechniqueName: "Data from Network Shared Drive",
		Phase:         "collection",
	},
}

// Lookup returns the MITRE technique for a BZAR notice type.
// Returns a generic fallback if the specific type is not found but starts with "BZAR::".
func Lookup(noticeType string) (*MITRETechnique, bool) {
	if tech, ok := noticeMapping[noticeType]; ok {
		return tech, true
	}
	// Attempt partial match on tactic prefix
	for k, v := range noticeMapping {
		if len(noticeType) >= len(k) && noticeType[:len(k)] == k {
			return v, true
		}
	}
	return nil, false
}

// IsBZARNotice returns true if the notice type is from BZAR (prefix "BZAR::").
func IsBZARNotice(noticeType string) bool {
	return len(noticeType) >= 6 && noticeType[:6] == "BZAR::"
}

// SeverityFromTactic maps a tactic to a severity score (1-5).
func SeverityFromTactic(tacticID string) int {
	switch tacticID {
	case "TA0006": // Credential Access
		return 5
	case "TA0002": // Execution
		return 4
	case "TA0008": // Lateral Movement
		return 5
	case "TA0009": // Collection
		return 3
	case "TA0007": // Discovery
		return 2
	default:
		return 3
	}
}
