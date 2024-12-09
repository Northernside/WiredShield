package commands

import "fmt"

func Help(m *Model) {
	m.Output += "Available Commands:\n"
	for _, c := range Commands {
		m.Output += fmt.Sprintf("%s: %s\n", c.Key, c.Desc)
	}
}
