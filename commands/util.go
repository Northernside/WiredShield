package commands

import (
	"fmt"
	"strings"
	"wiredshield/services"

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

var (
	Commands            []Command
	CommandHistory      []string
	CommandHistoryIndex int = 0
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			for _, c := range Commands {
				parts := strings.Split(m.TextInput.Value(), " ")
				if parts[0] == c.Key {
					m.Output += "\n→ " + m.TextInput.Value() + "\n"
					// exec the cmd & clear input
					c.Fn(&m)

					CommandHistory = append(CommandHistory, m.TextInput.Value())
					CommandHistoryIndex = len(CommandHistory)
					m.TextInput.SetValue("")
					return m, nil
				}
			}

			// cmd not found
			m.Output += fmt.Sprintf("Command not found: %s\n", m.TextInput.Value()[0:strings.Index(m.TextInput.Value(), " ")])
			m.TextInput.SetValue("")
		case tea.KeyUp:
			if len(CommandHistory) == 0 {
				break
			}

			if CommandHistoryIndex > 0 {
				CommandHistoryIndex--
			}
			m.TextInput.SetValue(CommandHistory[CommandHistoryIndex])

		case tea.KeyDown:
			if len(CommandHistory) == 0 {
				break
			}

			if CommandHistoryIndex < len(CommandHistory)-1 {
				CommandHistoryIndex++
				m.TextInput.SetValue(CommandHistory[CommandHistoryIndex])
			} else {
				CommandHistoryIndex = len(CommandHistory)
				m.TextInput.SetValue("")
			}
		}
	case ErrMsg:
		m.Err = msg
		return m, nil
	}

	for {
		select {
		case log := <-services.LogsChannel:
			m.Output += log
		default:
			goto done
		}
	}
done:

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
