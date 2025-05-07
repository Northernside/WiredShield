package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	_ "embed"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/globals"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pages"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/ssl"
	"wired/modules/types"
	"wired/modules/utils"
	protocol_handler "wired/node/protocol"
	wired_dns "wired/services/dns"
	"wired/services/http"
)

//go:embed version.txt
var version string

//go:embed wirednode.service
var wiredService string

func init() {
	env.LoadEnvFile()
	pages.BuildErrorPages()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "install" {
		systemdInstall()
		return
	}

	pgp.InitKeys()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(globals.ShutdownChannel, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-globals.ShutdownChannel
		logger.Println("Received shutdown signal, shutting down...")
		cancel()
	}()

	go wired_dns.Start(ctx)
	wired_dns.DNSEventBus.Sub(event.Event_DNSServiceInitialized, wired_dns.DNSEventChannel, func() { dnsInitHandler(ctx, wired_dns.DNSEventChannel) })

connectionLoop:
	for {
		select {
		case <-ctx.Done():
			break connectionLoop
		default:
			initNode(ctx)

			select {
			case <-ctx.Done():
				break connectionLoop
			case <-time.After(5 * time.Second):
				logger.Println("Reconnecting to master...")
			}
		}
	}
}

func initNode(ctx context.Context) {
	conn, err := connectToMaster()
	if err != nil {
		logger.Println("Failed to connect to master: ", err)
		return
	}

	protocol.MasterConn = conn

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	handleEncryption(conn)

	logger.Println("Connected to master")

	fileHash, err := utils.GetFileHash(os.Args[0])
	if err != nil {
		logger.Fatal("Failed to get binary hash:", err)
		return
	}

	err = conn.SendPacket(globals.Packet.ID_Login, packet.Login{
		NodeInfo: types.NodeInfo{
			Key:       env.GetEnv("NODE_KEY", "node-key"),
			Arch:      runtime.GOARCH,
			Version:   version,
			Hash:      fileHash,
			PID:       os.Getpid(),
			Listeners: utils.GetListeners(),
			Location:  types.Location{Lon: 0, Lat: 0},
			Modules:   []types.Modules{},
		},
	})
	if err != nil {
		logger.Fatal("Failed to send login packet:", err)
		return
	}

	for {
		p := new(protocol.Packet)
		err := p.Read(conn)
		if err != nil {
			if err == io.EOF {
				logger.Println("Lost connection to master")
				return
			}

			if strings.Contains(err.Error(), "use of closed network connection") {
				logger.Println("Connection closed")
				return
			}

			logger.Fatal("Failed to read packet:", err)
			return
		}

		handler := protocol_handler.GetHandler(p.ID)
		if handler != nil {
			handler.Handle(conn, p)
		} else {
			logger.Println("Unknown packet ID:", p.ID)
		}
	}
}

func connectToMaster() (*protocol.Conn, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:2000", env.GetEnv("GATEWAY", "shepherd.wired.rip")))
	if err != nil {
		return nil, err
	}

	return protocol.NewConn(conn), nil
}

func handleEncryption(conn *protocol.Conn) {
	sharedSecret := utils.RandomBytes(16)
	masterPubKey, err := pgp.LoadPublicKey("keys/master-public.pem")
	if err != nil {
		logger.Fatal("Failed to load master public key:", err)
		return
	}

	buf, err := rsa.EncryptPKCS1v15(rand.Reader, masterPubKey, sharedSecret)
	if err != nil {
		logger.Println("Failed to encrypt shared secret:", err)
		return
	}

	err = conn.SendRawPacket(globals.Packet.ID_SharedSecret, buf)
	if err != nil {
		logger.Fatal("Failed to send shared secret packet:", err)
		return
	}

	err = conn.EnableEncryption(sharedSecret)
	if err != nil {
		logger.Fatal("Failed to enable encryption:", err)
		return
	}
}

func dnsInitHandler(ctx context.Context, eventChan <-chan event.Event) {
	for event := range eventChan {
		_, ok := event.Data.(event_data.DNSServiceInitializedData)
		if !ok {
			fmt.Println("Invalid event data")
			continue
		}

		// convertSingleCertToSAN()
		go http.Start(ctx)
		go ssl.StartRenewalChecker(ctx)
	}
}

func systemdInstall() {
	if runtime.GOOS != "linux" {
		logger.Fatal("Systemd installation is only available on Linux systems")
	}

	cmd := exec.Command("systemctl", "--version")
	err := cmd.Run()
	if err != nil {
		logger.Fatal("Systemd is not available on this system")
	}

	if os.Geteuid() != 0 {
		logger.Fatal("You must be root to install the service")
	}

	err = os.WriteFile("/etc/systemd/system/wirednode.service", formatServiceFile(), 0644)
	if err != nil {
		logger.Fatal("Error writing service file:", err)
	}

	cmd = exec.Command("systemctl", "enable", "--now", "/etc/systemd/system/wirednode.service")
	err = cmd.Run()
	if err != nil {
		logger.Fatal("Error enabling service:", err)
	}

	cmd = exec.Command("systemctl", "start", "wirednode")
	err = cmd.Run()
	if err != nil {
		logger.Fatal("Error starting service:", err)
	}

	logger.Println("Service installed and started")
}

func formatServiceFile() []byte {
	dir, err := os.Getwd()
	if err != nil {
		logger.Fatal("Error getting working directory: ", err)
	}

	bin, err := os.Executable()
	if err != nil {
		logger.Fatal("Error getting executable path: ", err)
	}

	wiredService = strings.ReplaceAll(wiredService, "{WORKINGDIR}", dir)
	wiredService = strings.ReplaceAll(wiredService, "{BINPATH}", bin)
	wiredService = strings.ReplaceAll(wiredService, "{PIDFILE}", dir+"/node.pid")

	return []byte(wiredService)
}
