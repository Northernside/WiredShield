package errorpages

import (
	"bytes"
	"os"
	"strconv"
)

var (
	Error500 = []string{
		"An internal server error has occurred. Please try again later.",
	}
	Error601 = []string{
		"An internal DNS issue has occurred. Please try again later.",
	}
	Error603 = []string{
		"The website you're trying to reach is currently not able to accept any connections.",
		"This could occur due to a few different reasons, very likely due to the server being offline.",
	}
	Error605 = []string{
		"The website you're trying to reach is currently not responding (Timeout exceeded).",
		"This could occur due to a few different reasons, very likely due to the server being offline.",
	}
)

var ErrorBase []byte

type ErrorPage struct {
	Code    int
	Message []string
}

func init() {
	// load from pages/error.html
	file, err := os.Open("pages/error.html")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		panic(err)
	}

	ErrorBase = make([]byte, stat.Size())
	_, err = file.Read(ErrorBase)
	if err != nil {
		panic(err)
	}
}

func (e *ErrorPage) ToHTML() string {
	// replace {{code}} globally with e.Code
	// replace {{info-lines}} globally with e.Message -> <p>{{.}}</p><p>{{.}}</p>...

	copiedBase := make([]byte, len(ErrorBase))
	copy(copiedBase, ErrorBase)

	copiedBase = bytes.Replace(copiedBase, []byte("{{code}}"), []byte(strconv.Itoa(e.Code)), -1)
	copiedBase = bytes.Replace(copiedBase, []byte("{{info-lines}}"), []byte("<p>"+e.Message[0]+"</p>"), -1)

	return string(copiedBase)
}
