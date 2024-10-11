package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
)

var (
	requestsChannel = make(chan *http.Request)
	requestsMade    = new(uint64)
	clientPool      sync.Pool
)

func main() {
	env.LoadEnvFile()
	db.Init()

	clientPool.New = func() interface{} {
		return &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	Init()
}

func Init() {
	http.HandleFunc("/", ProxyHandler)
	port := env.GetEnv("PORT", "80")
	log.Printf("Starting proxy on :%s\n", port)

	go commandHandler()
	go requestsHandler()
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := "http://" + db.GetTarget(formatHost(r.Host))

	req, err := http.NewRequest(r.Method, targetURL+r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, "could not create request", http.StatusInternalServerError)
		return
	}

	req.Header = r.Header
	req.Header.Set("wired-origin-ip", r.RemoteAddr)

	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "error contacting backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.Header().Set("server", "wiredshield")

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	requestsChannel <- req
}

func commandHandler() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err)
			continue
		}

		input = strings.TrimSpace(input)
		args := strings.Split(input, " ")
		if len(args) == 0 || args[0] == "" {
			continue
		}

		switch args[0] {
		case "set":
			if len(args) != 3 {
				log.Println("Usage: set <host> <target>")
				continue
			}

			db.SetTarget(args[1], args[2])
			fmt.Println("Set target for", args[1], "to", args[2])
		case "get":
			if len(args) != 2 {
				log.Println("Usage: get <host>")
				continue
			}
			target := db.GetTarget(formatHost(args[1]))
			fmt.Println(target)

		default:
			log.Println("Unknown command:", args[0])
		}
	}
}

func requestsHandler() {
	for _ = range requestsChannel {
		*requestsMade++
	}
}

func formatHost(host string) string {
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	return host
}
