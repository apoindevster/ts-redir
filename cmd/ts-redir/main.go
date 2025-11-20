package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/apoindevster/ts-redir/internal/firewall"
	"github.com/apoindevster/ts-redir/internal/ui"
	"github.com/apoindevster/ts-redir/internal/web"
)

var (
	version = "v0.1.0"
	commit  = "none"
	date    = "11/07/2025"
)

func main() {
	var showVersion bool
	var webMode bool
	var listenPort int
	var tsInterface string

	flag.BoolVar(&showVersion, "version", false, "print version information and exit")
	flag.BoolVar(&webMode, "web", false, "run the web UI instead of the terminal UI")
	flag.IntVar(&listenPort, "port", 8080, "port to bind the web UI to when --web is set")
	flag.StringVar(&tsInterface, "ts-interface", defaultTailscaleInterface(), "tailscale network interface for binding the web UI")
	flag.Parse()

	if showVersion {
		fmt.Fprintf(os.Stdout, "ts-redir %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	if webMode {
		runWeb(listenPort, tsInterface)
		return
	}

	runTUI()
}

func runTUI() {
	prog := tea.NewProgram(ui.NewModel(), tea.WithAltScreen())
	if prog == nil {
		log.Fatalf("ts-redir: cannot create Bubble Tea program")
	}
	if _, err := prog.Run(); err != nil {
		log.Fatalf("ts-redir: %v", err)
	}
}

func runWeb(port int, iface string) {
	mgr, err := firewall.NewManager()
	if err != nil {
		log.Fatalf("ts-redir: create firewall manager: %v", err)
	}
	defer mgr.Close()

	server, err := web.NewServer(mgr, iface, port)
	if err != nil {
		log.Fatalf("ts-redir: init web server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Run()
	}()

	select {
	case <-ctx.Done():
		log.Println("ts-redir: shutting down web server")
	case err := <-errCh:
		if err != nil {
			log.Fatalf("ts-redir: web server error: %v", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("ts-redir: graceful shutdown failed: %v", err)
	}
}

func defaultTailscaleInterface() string {
	if _, err := net.InterfaceByName("tailscale0"); err == nil {
		return "tailscale0"
	}
	return "ts0"
}
