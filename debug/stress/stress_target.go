package stress_target

// basic http server with return 200 "Hello, World!" on port 33032

import (
	"fmt"
	"net/http"
	"wiredshield/services"
)

var service *services.Service

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func Prepare(_service *services.Service) func() {
	service = _service
	return startServer
}

func startServer() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":33032", nil)
}
