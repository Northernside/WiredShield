package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type (
	ErrMsg error
)

type Model struct {
	TextInput textinput.Model
	Err       error
	Output    string
}

type Command struct {
	Key  string
	Desc string
	Fn   func(*Model)
}

var Commands []Command

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			for _, c := range Commands {
				if m.TextInput.Value() == c.Key {
					// exec the cmd & clear input
					c.Fn(&m)
					m.TextInput.SetValue("")
					return m, nil
				}
			}

			// cmd not found
			m.Output += fmt.Sprintf("Unknown command: %s\n", m.TextInput.Value())
			m.TextInput.SetValue("")
		}

	case ErrMsg:
		m.Err = msg
		return m, nil
	}

	m.TextInput, cmd = m.TextInput.Update(msg)
	return m, cmd
}

func InitialModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Type 'help' for a list of commands"
	ti.Focus()
	ti.Width = 128

	return Model{
		TextInput: ti,
		Err:       nil,
		Output:    "",
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) View() string {
	return fmt.Sprintf("%s\n\n%s", strings.TrimSpace(m.Output), m.TextInput.View())
}
