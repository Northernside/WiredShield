package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	httpVersions := []string{"HTTP/1.1"}
	tlsVersions := []uint16{tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12, tls.VersionTLS12}

	for _, httpVersion := range httpVersions {
		for _, tlsVersion := range tlsVersions {
			fmt.Printf("\nRequesting with %s and TLS %s\n", httpVersion, tlsVersionToString(tlsVersion))

			tlsConfig := &tls.Config{
				MinVersion: tlsVersion,
				MaxVersion: tlsVersion,
			}

			transport := &http.Transport{
				TLSClientConfig: tlsConfig,
			}

			if httpVersion == "HTTP/2.0" {
				transport.TLSClientConfig.NextProtos = []string{"h2"}
			} else if httpVersion != "HTTP/1.2" {
				transport.ForceAttemptHTTP2 = false
			}

			client := &http.Client{
				Transport: transport,
			}

			req, err := http.NewRequest("GET", "https://dawg.pics", nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
				continue
			}
			req.Proto = httpVersion
			req.ProtoMajor, req.ProtoMinor = parseHTTPVersion(httpVersion)

			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Request failed: %v\n", err)
				continue
			}

			_, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
				continue
			}

			if resp.StatusCode == 200 {
				fmt.Printf("success\n")
			} else {
				fmt.Printf("failed\n")
			}
		}
	}
}

func parseHTTPVersion(version string) (major, minor int) {
	switch version {
	case "HTTP/1.0":
		return 1, 0
	case "HTTP/1.1":
		return 1, 1
	case "HTTP/1.2":
		return 1, 2
	case "HTTP/2.0":
		return 2, 0
	default:
		return 1, 1
	}
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}
