package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/apoindevster/ts-redir/internal/ui"
)

var (
	version = "v0.1.0"
	commit  = "none"
	date    = "11/07/2025"
)

func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version information and exit")
	flag.Parse()

	if showVersion {
		fmt.Fprintf(os.Stdout, "ts-redir %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	prog := tea.NewProgram(ui.NewModel(), tea.WithAltScreen())
	if prog == nil {
		log.Fatalf("ts-redir: cannot create Bubble Tea program")
	}
	if _, err := prog.Run(); err != nil {
		log.Fatalf("ts-redir: %v", err)
	}
}
