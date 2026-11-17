package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kardianos/service"

	"github.com/apoindevster/ts-redir/internal/app"
	"github.com/apoindevster/ts-redir/internal/state"
	"github.com/apoindevster/ts-redir/internal/ui"
	"github.com/apoindevster/ts-redir/internal/web"
)

var (
	version = "v0.1.0"
	commit  = "none"
	date    = "11/07/2025"
)

type program struct {
	path, iface string
	port        int
	webMode     bool
	app         *app.App
	web         *web.Server
	cancel      context.CancelFunc
	workers     sync.WaitGroup
}

func (p *program) Start(_ service.Service) error {
	a, err := app.Open(p.path)
	if err != nil {
		return err
	}
	p.app = a
	a.Start()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.workers.Add(1)
	go func() { defer p.workers.Done(); a.Run(ctx) }()
	if p.webMode {
		p.web, err = web.NewServer(a.Manager, p.iface, p.port)
		if err != nil {
			cancel()
			p.workers.Wait()
			a.Close()
			return err
		}
		p.web.SetApplication(a)
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			for ctx.Err() == nil {
				if err := p.web.RunContext(ctx); err != nil && ctx.Err() == nil {
					log.Printf("Web UI unavailable; retrying in 5 seconds: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}()
	}
	return nil
}

func (p *program) Stop(_ service.Service) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if p.web != nil {
		_ = p.web.Shutdown(ctx)
	}
	p.workers.Wait()
	return p.app.Close()
}

func main() {
	var showVersion, webMode, daemon bool
	var port int
	var iface, path, action string
	flag.BoolVar(&showVersion, "version", false, "print version information and exit")
	flag.BoolVar(&webMode, "web", false, "run the web UI instead of the terminal UI")
	flag.BoolVar(&daemon, "daemon", false, "run DNS, rule restoration and web UI without a terminal")
	flag.IntVar(&port, "port", 8080, "web UI port")
	flag.StringVar(&iface, "ts-interface", defaultTailscaleInterface(), "Tailscale interface for the management UI")
	flag.StringVar(&path, "config", state.DefaultPath(), "persistent configuration file")
	flag.StringVar(&action, "service", "", "service action: install, uninstall, start, stop, restart, status")
	flag.Parse()
	if showVersion {
		fmt.Printf("ts-redir %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	if port < 1 || port > 65535 {
		log.Fatal("web UI port must be between 1 and 65535")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		log.Fatal(err)
	}
	p := &program{path: path, iface: iface, port: port, webMode: webMode || daemon}
	if action != "" || daemon || !service.Interactive() {
		cfg := &service.Config{
			Name: "ts-redir", DisplayName: "ts-redir", Description: "Local DNS overrides and forwarding into a Tailscale tailnet",
			Arguments: []string{"--daemon", "--config", path, "--ts-interface", iface, "--port", fmt.Sprint(port)},
			Option:    service.KeyValue{"Restart": "on-failure", "StartType": "automatic"},
		}
		if runtime.GOOS == "linux" {
			cfg.Dependencies = []string{"Wants=network-online.target tailscaled.service", "After=network-online.target tailscaled.service"}
		}
		if runtime.GOOS == "windows" {
			cfg.Dependencies = []string{"Tailscale", "iphlpsvc"}
		}
		p.webMode = true
		svc, err := service.New(p, cfg)
		if err != nil {
			log.Fatal(err)
		}
		if action == "status" {
			status, err := svc.Status()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("ts-redir service status: %v (1=running, 2=stopped)\n", status)
			return
		}
		if action != "" {
			if err := service.Control(svc, action); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("ts-redir service %s completed\n", action)
			return
		}
		if err := svc.Run(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := p.Start(nil); err != nil {
		log.Fatal(err)
	}
	defer p.Stop(nil)
	if webMode {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		<-ctx.Done()
	} else {
		if _, err := tea.NewProgram(ui.NewModelWithManager(p.app.Manager), tea.WithAltScreen()).Run(); err != nil {
			log.Printf("terminal UI: %v", err)
		}
	}
}

func defaultTailscaleInterface() string {
	if runtime.GOOS == "windows" {
		return "Tailscale"
	}
	if _, err := net.InterfaceByName("tailscale0"); err == nil {
		return "tailscale0"
	}
	return "ts0"
}
