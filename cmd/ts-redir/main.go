package main

import (
	"log"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/apoindevster/ts-redir/internal/ui"
)

func main() {
	prog := tea.NewProgram(ui.NewModel(), tea.WithAltScreen())
	if prog == nil {
		log.Fatalf("Failed to allocate new BubbleTea program")
	}
	prog.Run()
}
