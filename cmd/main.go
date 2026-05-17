package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kwsjjang8901-ship-it/claudtest/internal/bzar"
	"github.com/kwsjjang8901-ship-it/claudtest/internal/config"
	"github.com/kwsjjang8901-ship-it/claudtest/internal/evidence"
	"github.com/kwsjjang8901-ship-it/claudtest/internal/forwarder"
	"github.com/kwsjjang8901-ship-it/claudtest/internal/installer"
	"github.com/kwsjjang8901-ship-it/claudtest/internal/ocsf"
	"github.com/kwsjjang8901-ship-it/claudtest/internal/zeek"
)

const version = "1.0.0"

func usage() {
	fmt.Fprintf(os.Stderr, `zeek-bzar-ocsf v%s

Usage: zeek-bzar-ocsf <command> [flags]

Commands:
  start      Start the monitoring service
  install    Install as a systemd service
  uninstall  Remove the systemd service
  version    Show version information

Run 'zeek-bzar-ocsf <command> -help' for command-specific flags.
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		runStart(os.Args[2:])
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("zeek-bzar-ocsf version %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// ─── start ───────────────────────────────────────────────────────────────────

func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := fs.String("config", "/etc/zeek-bzar-ocsf/config.yaml", "Path to configuration file")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[main] loading config: %v", err)
	}

	setupLogger(cfg.Logging)
	log.Printf("[main] starting zeek-bzar-ocsf v%s", version)
	log.Printf("[main] watching Zeek logs in: %s", cfg.Zeek.LogDir)

	// Build forwarder
	fwd, err := forwarder.NewMultiForwarder(cfg.Forwarder.Outputs)
	if err != nil {
		log.Fatalf("[main] creating forwarder: %v", err)
	}
	defer fwd.Close()

	// Build OCSF mapper
	mapper := ocsf.NewMapper(
		cfg.OCSF.Producer.Name,
		cfg.OCSF.Producer.Version,
		cfg.OCSF.Producer.URL,
	)

	// Build evidence collector
	evidenceCollector := evidence.NewCollector(
		cfg.Evidence.OutputDir,
		cfg.Evidence.BufferSize,
		cfg.Evidence.Enabled,
	)
	done := make(chan struct{})
	evidenceCollector.StartEviction(5*time.Minute, 30*time.Minute, done)

	// Build log type list
	logTypes := make([]zeek.LogType, 0, len(cfg.Zeek.Logs))
	for _, l := range cfg.Zeek.Logs {
		logTypes = append(logTypes, zeek.LogType(l))
	}

	// Start tailer
	linesCh := make(chan zeek.LineEvent, 4096)
	tailer := zeek.NewTailer(cfg.Zeek.LogDir, logTypes, linesCh)
	tailer.Start()

	// Build parser
	parser := zeek.NewParser(cfg.Zeek.LogFormat)

	// Handle OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Println("[main] running – press Ctrl-C to stop")

	for {
		select {
		case sig := <-sigCh:
			log.Printf("[main] received signal %v, shutting down", sig)
			tailer.Stop()
			close(done)
			return

		case ev := <-linesCh:
			processLine(ev, parser, mapper, evidenceCollector, fwd, cfg)
		}
	}
}

func processLine(
	ev zeek.LineEvent,
	parser *zeek.Parser,
	mapper *ocsf.Mapper,
	ec *evidence.Collector,
	fwd *forwarder.MultiForwarder,
	cfg *config.Config,
) {
	rec, err := parser.ParseLine(ev.LogType, ev.Line)
	if err != nil {
		log.Printf("[processor] parse error (%s): %v", ev.LogType, err)
		return
	}
	if rec == nil {
		return // comment / header line
	}

	// Buffer every record for evidence
	ec.Add(rec)

	switch rec.Type {
	case zeek.LogConn:
		conn := zeek.ToConnRecord(rec)
		event := mapper.FromConn(conn)
		fwd.SendEvent(event)

	case zeek.LogDNS:
		dns := zeek.ToDNSRecord(rec)
		event := mapper.FromDNS(dns)
		fwd.SendEvent(event)

	case zeek.LogHTTP:
		http := zeek.ToHTTPRecord(rec)
		event := mapper.FromHTTP(http)
		fwd.SendEvent(event)

	case zeek.LogNotice:
		if !cfg.BZAR.Enabled {
			return
		}
		notice := zeek.ToNoticeRecord(rec)
		det := bzar.Analyze(notice)
		if det == nil {
			return // not a BZAR alert
		}
		log.Printf("[bzar] detection: %s src=%s dst=%s severity=%d",
			det.Notice.Note, det.SrcIP, det.DstIP, det.Severity)

		// Collect related evidence
		evList := ec.Collect(det.UID, det.SrcIP, det.DstIP, det.Notice.TS)

		event := mapper.FromDetection(det, evList)
		fwd.SendEvent(event)

	// smb_files, smb_mapping, dce_rpc: buffer only (evidence for BZAR alerts)
	case zeek.LogSMBFiles, zeek.LogSMBMapping, zeek.LogDCERPC:
		// No direct OCSF output for these – they are captured as evidence.
	}
}

// ─── install ─────────────────────────────────────────────────────────────────

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	binaryPath := fs.String("binary", "", "Path to binary to install (defaults to current executable)")
	configPath := fs.String("config", "", "Path to config file to install (uses built-in default if empty)")
	fs.Parse(args)

	if err := installer.Install(*binaryPath, *configPath); err != nil {
		log.Fatalf("[install] %v", err)
	}
}

// ─── uninstall ───────────────────────────────────────────────────────────────

func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "Also remove configuration files")
	fs.Parse(args)

	if err := installer.Uninstall(*purge); err != nil {
		log.Fatalf("[uninstall] %v", err)
	}
}

// ─── logging ─────────────────────────────────────────────────────────────────

func setupLogger(cfg config.LoggingConfig) {
	flags := log.LstdFlags | log.Lmicroseconds

	switch cfg.Output {
	case "", "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			log.Printf("[main] cannot open log file %s: %v, falling back to stdout", cfg.Output, err)
		} else {
			log.SetOutput(f)
		}
	}

	log.SetFlags(flags)
}
