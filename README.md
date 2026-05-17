# zeek-bzar-ocsf

Zeek + BZAR 기반 네트워크 보안 모니터링 및 OCSF 변환 통합 시스템 (Go 구현, Ubuntu Linux)

---

## 개요

| 항목 | 내용 |
|------|------|
| 언어 | Go 1.21+ |
| 대상 OS | Ubuntu Linux (systemd 환경) |
| 입력 | Zeek 로그 (TSV / JSON) + BZAR notice |
| 출력 | OCSF 1.1 형식 JSON → File / Syslog / HTTP |

Zeek가 수집한 네트워크 메타데이터와 BZAR가 탐지한 MITRE ATT&CK 위협을 **OCSF(Open Cybersecurity Schema Framework) 1.1** 형식으로 변환하여 SIEM 등 외부 보안 제품과 연동합니다.  
탐지 발생 시 관련 로그를 증적으로 자동 수집하여 별도 보존합니다.

---

## 프로젝트 구조

```
zeek-bzar-ocsf/
├── cmd/main.go                     # CLI 진입점 (start / install / uninstall)
├── configs/config.yaml             # 설정 파일 예시
├── Makefile                        # 빌드 자동화
├── go.mod / go.sum
└── internal/
    ├── config/config.go            # YAML 설정 로드
    ├── zeek/
    │   ├── types.go                # Zeek 로그 타입 정의
    │   ├── parser.go               # TSV / JSON 파서
    │   ├── tailer.go               # 로그 파일 실시간 감시 (로테이션 대응)
    │   └── inode_linux.go          # Linux inode 기반 로테이션 감지
    ├── bzar/
    │   ├── mitre.go                # MITRE ATT&CK 매핑 테이블
    │   └── detector.go             # BZAR notice → Detection 변환
    ├── ocsf/
    │   ├── types.go                # OCSF 1.1 스키마 타입
    │   └── mapper.go               # Zeek / BZAR → OCSF 변환
    ├── evidence/
    │   └── collector.go            # 증적 버퍼링 및 디스크 보존
    ├── forwarder/
    │   ├── forwarder.go            # 멀티 포워더 오케스트레이터
    │   ├── file.go                 # JSON 파일 출력
    │   ├── syslog.go               # Syslog (UDP / TCP) 전송
    │   └── http.go                 # HTTP / HTTPS SIEM 연동
    └── installer/installer.go      # systemd 서비스 설치 / 제거
```

---

## 주요 기능

### 네트워크 메타데이터 수집

| Zeek 로그 | OCSF 클래스 | class_uid |
|-----------|-------------|-----------|
| conn.log | Network Activity | 4001 |
| dns.log | DNS Activity | 4003 |
| http.log | HTTP Activity | 4002 |
| ssl.log | Network Activity (TLS) | 4001 |

### MITRE ATT&CK 탐지 (BZAR 연동)

BZAR가 `notice.log`에 기록하는 탐지 항목을 파싱하여 OCSF **Detection Finding (class_uid: 2004)** 으로 변환합니다.

| 전술 | 탐지 예시 |
|------|----------|
| TA0008 Lateral Movement | SMB Admin Share, WinRM, DCOM, Lateral Tool Transfer |
| TA0006 Credential Access | SAM 덤프, LSA Secrets |
| TA0002 Execution | 서비스 실행, WMI, CMD |
| TA0007 Discovery | 원격 시스템 탐색, 파일 탐색, 네트워크 공유, 계정 탐색 |
| TA0009 Collection | 네트워크 드라이브 데이터 수집 |

### 탐지 증적 수집

탐지 발생 시 동일 연결 UID의 SMB / DCE-RPC / conn 로그를 자동으로 수집하여 아래 경로에 JSON 파일로 보존합니다.

```
/var/lib/zeek-bzar-ocsf/evidence/
└── YYYY-MM-DD/
    └── evidence_<uid>_<timestamp>.json
```

### OCSF DetectionFinding 구조

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "severity_id": 5,
  "severity": "Critical",
  "time": 1716000000000,
  "finding": {
    "title": "SMB/Windows Admin Shares",
    "desc": "Lateral movement detected via SMB admin share",
    "types": ["Threat Detection"]
  },
  "attacks": [
    {
      "tactic":    { "uid": "TA0008", "name": "Lateral Movement" },
      "technique": { "uid": "T1021.002", "name": "SMB/Windows Admin Shares" }
    }
  ],
  "evidences": [
    { "uid": "Cabc123", "log_type": "smb_files", "data": { "path": "\\\\server\\C$", "action": "SMB::FILE_OPEN" } },
    { "uid": "Cabc123", "log_type": "notice",    "data": { "note": "BZAR::ATTACK_TA0008_T1021_002_SMB_Admin_Share", ... } }
  ],
  "src_endpoint": { "ip": "10.0.0.5", "port": 49200 },
  "dst_endpoint": { "ip": "10.0.0.10", "port": 445 },
  "metadata": { "product": { "name": "zeek-bzar-ocsf", "version": "1.0.0" } }
}
```

### 로그 전송 (포워더)

| 타입 | 설명 |
|------|------|
| `file` | NDJSON 파일 출력 (로테이션 대응) |
| `syslog` | RFC 5424 형식, UDP/TCP 선택 |
| `http` | HTTP/HTTPS POST, 헤더 커스텀, 재시도 |

복수의 출력 대상을 동시에 설정할 수 있습니다.

---

## 빌드 및 설치

### 사전 요구 사항

- Go 1.21 이상
- Zeek (+ BZAR 스크립트 로드)
- Ubuntu Linux (systemd)

### 빌드

```bash
git clone https://github.com/zeekurity/zeek-bzar-ocsf
cd zeek-bzar-ocsf
make build
# 결과: ./build/zeek-bzar-ocsf
```

### 서비스 설치 (root 필요)

```bash
sudo make install
# 또는
sudo ./build/zeek-bzar-ocsf install
```

설치 항목:
- 바이너리: `/opt/zeek-bzar-ocsf/zeek-bzar-ocsf`
- 설정 파일: `/etc/zeek-bzar-ocsf/config.yaml`
- systemd 유닛: `/etc/systemd/system/zeek-bzar-ocsf.service`
- 로그 디렉터리: `/var/log/zeek-bzar-ocsf/`
- 증적 디렉터리: `/var/lib/zeek-bzar-ocsf/evidence/`

### 서비스 시작

```bash
sudo systemctl start zeek-bzar-ocsf
sudo systemctl enable zeek-bzar-ocsf   # 부팅 시 자동 시작
sudo systemctl status zeek-bzar-ocsf
```

### 서비스 제거

```bash
# 설정 파일 유지
sudo ./build/zeek-bzar-ocsf uninstall

# 설정 파일까지 완전 삭제
sudo ./build/zeek-bzar-ocsf uninstall --purge
```

---

## 직접 실행

```bash
./build/zeek-bzar-ocsf start --config configs/config.yaml
```

---

## 설정

설정 파일 위치: `/etc/zeek-bzar-ocsf/config.yaml`

```yaml
zeek:
  log_dir: /opt/zeek/logs/current   # Zeek 현재 로그 디렉터리
  log_format: tsv                    # tsv 또는 json
  logs:
    - conn
    - dns
    - http
    - ssl
    - smb_files
    - smb_mapping
    - dce_rpc
    - notice

bzar:
  enabled: true                      # BZAR 탐지 파싱 활성화

evidence:
  enabled: true
  output_dir: /var/lib/zeek-bzar-ocsf/evidence
  retention_days: 30
  max_size_mb: 1024
  buffer_size: 500

ocsf:
  version: "1.1.0"
  producer:
    name: zeek-bzar-ocsf
    version: "1.0.0"

forwarder:
  outputs:
    - type: file
      path: /var/log/zeek-bzar-ocsf/events.json

    # Syslog 예시
    # - type: syslog
    #   host: 192.168.1.100
    #   port: 514
    #   protocol: udp

    # HTTP/SIEM 예시
    # - type: http
    #   url: https://siem.example.com/api/v1/events
    #   timeout_seconds: 10
    #   max_retries: 3
    #   headers:
    #     Authorization: "Bearer YOUR_TOKEN"

logging:
  level: info        # debug / info / warn / error
  output: stdout     # stdout / stderr / 파일 경로
```

---

## 테스트

```bash
make test            # 전체 단위 테스트
make test-race       # 레이스 컨디션 검사 포함
```

---

## Makefile 주요 타겟

```bash
make build        # 바이너리 빌드
make build-linux  # Linux amd64 크로스 컴파일
make test         # 단위 테스트
make test-race    # 레이스 컨디션 검사
make install      # systemd 서비스 설치 (root)
make uninstall    # 서비스 제거 (root)
make purge        # 서비스 + 설정 완전 삭제 (root)
make clean        # 빌드 결과물 삭제
```
