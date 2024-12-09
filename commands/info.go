package commands

import (
	"fmt"
	"strings"
	"time"
	"wiredshield/services"
)

func Info(model *Model) {
	var sb strings.Builder

	sb.WriteString("Services:\n")
	for _, service := range services.Services {
		sb.WriteString(fmt.Sprintf("  [%s] -> %s\n", service.Name, service.DisplayName))
		sb.WriteString(fmt.Sprintf("    Online Since: %s (%s)\n", time.Unix(service.OnlineSince, 0).Format("2006-01-02 15:04:05 MST"), onlineSince(time.Unix(service.OnlineSince, 0))))
		sb.WriteString("\n")
	}

	model.Output += sb.String()
}

func onlineSince(t time.Time) string {
	d := time.Since(t)
	if d.Seconds() < 60 {
		return fmt.Sprintf("Since %.0fs", d.Seconds())
	}
	if d.Minutes() < 60 {
		return fmt.Sprintf("Since %.0fm", d.Minutes())
	}
	if d.Hours() < 24 {
		return fmt.Sprintf("Since %.0fh", d.Hours())
	}
	return fmt.Sprintf("Since %.0fd", d.Hours()/24)
}
