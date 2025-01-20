package dashpages

import (
	"os"
	"strings"
	errorpages "wiredshield/pages/error"
)

var DashPages = map[string]string{
	"/.wiredshield/dash":                "domains_overview.html",
	"/.wiredshield/dash/domain/:domain": "domain.html",
	"/.wiredshield/css/global.css":      "global.css",
}

func init() {
	// load from pages/dash/%s.html
	for k, v := range DashPages {
		// load from file

		file, err := os.Open("pages/dash/" + v)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			panic(err)
		}

		content := make([]byte, stat.Size())
		_, err = file.Read(content)
		if err != nil {
			panic(err)
		}

		DashPages[k] = string(content)
	}
}

func PageResponse(path string) (string, int) {
	// remove any # and ? params from the path
	if i := strings.Index(path, "?"); i != -1 {
		path = path[:i]
	}

	if i := strings.Index(path, "#"); i != -1 {
		path = path[:i]
	}

	// return contents of pages[path]
	if v, ok := DashPages[path]; ok {
		return v, 200
	}

	errorPage := errorpages.ErrorPage{
		Code:    604,
		Message: errorpages.Error604,
	}

	return errorPage.ToHTML(), 404
}
