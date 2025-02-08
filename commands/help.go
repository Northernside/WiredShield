package commands

import (
	"fmt"
	"strings"
)

func Help(m *Model) {
	var prefix = "\033[0;37m[\033[0;34mHELP\033[0;37m] →\033[0;37m "
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Available commands:\n"))
	for _, c := range Commands {
		// m.Output += fmt.Sprintf("\t%s: %s\n", c.Key, c.Desc)
		sb.WriteString(fmt.Sprintf(" \033[0;37m- \033[0;34m%s\033[0;37m: %s\n", c.Key, c.Desc))
	}

	m.Output += sb.String()
}
