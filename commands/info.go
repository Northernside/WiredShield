package commands

import (
	"fmt"
	"strings"
	"time"
	"wiredshield/services"
)

func Info(model *Model) {
	var sb strings.Builder

	sb.WriteString("\033[1;34mServices:\033[0m\n")
	for _, service := range services.ServiceRegistry {
		sb.WriteString(fmt.Sprintf("  \033[1;32m[%s]\033[0m -> \033[1;33m%s\033[0m\n", service.Name, service.DisplayName))
		if service.OnlineSince == 0 {
			sb.WriteString("    \033[0;31mOnline Since: Not Online\033[0m\n")
			sb.WriteString("\n")
			continue
		}

		sb.WriteString(fmt.Sprintf("    \033[1;34mOnline Since:\033[0m %s \033[1;36m(%s)\033[0m\n",
			time.Unix(service.OnlineSince, 0).Format("2006-01-02 15:04:05 MST"),
			onlineSince(time.Unix(service.OnlineSince, 0))))
		sb.WriteString("\n")
	}

	model.Output += sb.String()
}

func onlineSince(t time.Time) string {
	d := time.Since(t)
	if d.Seconds() < 60 {
		return fmt.Sprintf("Since \033[1;35m%.0fs\033[0m", d.Seconds())
	}
	if d.Minutes() < 60 {
		return fmt.Sprintf("Since \033[1;35m%.0fm\033[0m", d.Minutes())
	}
	if d.Hours() < 24 {
		return fmt.Sprintf("Since \033[1;35m%.0fh\033[0m", d.Hours())
	}
	return fmt.Sprintf("Since \033[1;35m%.0fd\033[0m", d.Hours()/24)
}
