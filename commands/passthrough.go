package commands

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	ssl "wiredshield/commands/libs"
	"wiredshield/modules/db/passthrough"

	"github.com/fatih/color"
	"github.com/rodaine/table"
)

func Passthrough(model *Model) {
	var prefix = "\033[0;37m[\033[0;34mPASSTHROUGH\033[0;37m] →\033[0;37m "
	var sb strings.Builder

	split := strings.Split(model.TextInput.Value(), " ")
	if len(split) < 2 {
		sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Usage: passthrough <list|set|del> [domain] [path] [target_addr] [target_port] [target_path] [ssl]"))
		return
	}

	switch split[1] {
	case "list":
		passthroughs, _ := passthrough.GetAllPassthroughs()
		if len(passthroughs) == 0 {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "No passthroughs found"))
		} else {
			headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
			columnFmt := color.New(color.FgYellow).SprintfFunc()

			tbl := table.New("ID", "Domain", "Path", "Target Address", "Target Port", "Target Path", "SSL")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for _, passthrough := range passthroughs {
				tbl.AddRow(passthrough.Id, passthrough.Domain, passthrough.Path, passthrough.TargetAddr, passthrough.TargetPort, passthrough.TargetPath, passthrough.Ssl)
			}

			/*
				set table.DefaultWriter to a new writer
				then get the string from the writer
			*/

			var buf bytes.Buffer
			tbl.WithWriter(&buf)

			tbl.Print()
			tableString := buf.String()

			sb.WriteString("\n" + tableString + "\n")
		}
	case "set":
		if len(split) < 8 {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Usage: passthrough set [domain] [path] [target_addr] [target_port] [target_path] [ssl]"))
			break
		}

		targetPort, err := strconv.ParseUint(split[5], 10, 16)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Invalid port: "+err.Error()))
			break
		}

		pt := passthrough.Passthrough{
			Domain:     split[2],
			Path:       split[3],
			TargetAddr: split[4],
			TargetPort: uint16(targetPort),
			TargetPath: split[6],
			Ssl:        split[7] == "true",
		}

		err = passthrough.InsertPassthrough(pt, 0, false)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Failed to set passthrough"))
			break
		}

		if pt.Ssl {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Generating SSL certificate for "+pt.Domain))
			go func() {
				ssl.GenSSL(pt.Domain, false)
			}()
		}

		sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Passthrough set successfully"))
	case "del":
		if len(split) < 3 {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Usage: passthrough del [id]"))
			break
		}

		id, err := strconv.ParseUint(split[2], 10, 64)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Invalid id: "+err.Error()))
			break
		}

		err = passthrough.DeletePassthrough(id, false)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Failed to delete passthrough"))
			break
		}

		sb.WriteString(fmt.Sprintf("%s%s\n", prefix, "Passthrough deleted successfully"))
	}

	model.Output += sb.String()
}
