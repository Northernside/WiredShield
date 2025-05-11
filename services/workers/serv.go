package workers

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
)

func Start() {
}

func LaunchWorker(id string) error {
	os.Remove(fmt.Sprintf("/tmp/%s.sock", id))

	cmd := exec.Command(
		"deno", "run",
		fmt.Sprintf("--allow-read=./worker,/tmp/%s.sock", id),
		fmt.Sprintf("--allow-write=./worker,/tmp/%s.sock", id),
		"./runtime/executor.ts",
	)

	cmd.Stdout = os.Stdout // for debug, set to nil at some point
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := os.Remove(fmt.Sprintf("/tmp/%s.sock", id)); err != nil {
		return err
	}

	return nil
}

func HandleRequest(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := io.ReadAll(r.Body)
	payload := map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
		"body":   string(reqBody),
	}
	data, _ := json.Marshal(payload)

	conn, err := net.Dial("unix", "/tmp/wiredshield.sock")
	if err != nil {
		http.Error(w, "Worker not reachable", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	conn.Write(data)

	buf := make([]byte, 65536)
	n, _ := conn.Read(buf)
	var res map[string]any
	json.Unmarshal(buf[:n], &res)

	for k, v := range res["headers"].(map[string]any) {
		w.Header().Set(k, v.(string))
	}

	w.WriteHeader(int(res["status"].(float64)))
	w.Write([]byte(res["body"].(string)))
}
