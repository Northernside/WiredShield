package pages

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"wired/modules/env"
	"wired/modules/logger"
)

type ErrorPageTemplate struct {
	Code     int
	Messages []string
	Html     []byte
	Rerender func(code int, messages []string) []byte
}

var ErrorPages = map[int]ErrorPageTemplate{
	403: {
		Code: 403,
		Messages: []string{
			"You are blocked from accessing this website.",
			"This is a part of Wired's security measures to protect the website from malicious users and bots.",
		},
		Html: nil,
	},
	500: {
		Code: 500,
		Messages: []string{
			"An internal server error has occurred. Please try again later.",
		},
		Html: nil,
	},
	502: {
		Code: 502,
		Messages: []string{
			"The website you're trying to reach is currently not able to handle your request.",
			"This could occur due to a few different reasons, very likely due to the server being offline.",
		},
		Html: nil,
	},
	601: {
		Code: 601,
		Messages: []string{
			"An internal DNS issue has occurred. Please try again later.",
		},
		Html: nil,
	},
	602: {
		Code: 602,
		Messages: []string{
			"The website you're trying to reach is currently not able to handle your request.",
		},
		Html: nil,
	},
	603: {
		Code: 603,
		Messages: []string{
			"You are blocked from accessing this website.",
		},
		Html: nil,
	},
	604: {
		Code: 604,
		Messages: []string{
			"The website you're trying to reach does not exist.",
		},
		Html: nil,
	},
	605: {
		Code: 605,
		Messages: []string{
			"The website you're trying to reach is currently not responding (Timeout exceeded).",
			"This could occur due to a few different reasons, very likely due to the server being offline.",
		},
		Html: nil,
	},
	// Custom
	700: {
		Code:     700,
		Messages: []string{},
		Html:     nil,
		Rerender: func(code int, messages []string) []byte {
			var msgs []string
			msgs = append(msgs, "The application returned with the following error:")
			msgs = append(msgs, messages...)

			return renderHtml(ErrorPageTemplate{
				Code:     code,
				Messages: msgs,
				Html:     nil,
			})
		},
	},
}

var errorBase []byte
var errorBaseLength int

func BuildErrorPages() {
	file, err := os.Open(env.GetEnv("PUBLIC_DIR", "") + "/templates/error.html")
	if err != nil {
		logger.Fatal("Failed to open error.html template file: ", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		logger.Fatal("Failed to get file stat: ", err)
	}

	errorBase = make([]byte, stat.Size())
	errorBaseLength = int(stat.Size())
	_, err = file.Read(errorBase)
	if err != nil {
		logger.Fatal("Failed to read error.html template file: ", err)
	}

	for _, page := range ErrorPages {
		page.Html = renderHtml(page)
		ErrorPages[page.Code] = page
	}
}

func renderHtml(page ErrorPageTemplate) []byte {
	copiedBase := make([]byte, errorBaseLength)
	copy(copiedBase, errorBase)

	copiedBase = bytes.Replace(copiedBase, []byte("{{code}}"), []byte(strconv.Itoa(page.Code)), -1)
	copiedBase = bytes.Replace(copiedBase, []byte("{{info-lines}}"), []byte("<p>"+strings.Join(page.Messages, "<br>")+"</p>"), -1)

	return copiedBase
}
