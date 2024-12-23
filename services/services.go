package services

import (
	"sync"

	"golang.org/x/crypto/openpgp"
)

type networkInfo struct {
	Ip   string
	Port int
}

type Service struct {
	Name        string
	DisplayName string
	OnlineSince int64
	NetworkInfo networkInfo
	Boot        func()
}

type GeoLoc struct {
	Country string
	City    string
}

type Client struct {
	Name      string
	IPAddress string
	GeoLoc    GeoLoc
	Ready     bool
}

var (
	ServiceRegistry    = map[string]*Service{}
	PublicKeys         = make(map[string]*openpgp.Entity)
	ServerPrivateKey   *openpgp.Entity
	ClientName         string
	ClientMap          = make(map[string]Client)
	ProcessAccessToken string
	registryLock       sync.Mutex
	ProcessService     *Service
)

func RegisterService(name, displayName string) *Service {
	registryLock.Lock()
	defer registryLock.Unlock()

	if existingService, ok := ServiceRegistry[name]; ok {
		return existingService
	}

	newService := &Service{
		Name:        name,
		DisplayName: displayName,
		OnlineSince: 0,
	}

	ServiceRegistry[name] = newService
	return newService
}

func (s *Service) InfoLog(message string) {
	logPipeline <- "\033[0;37m[\033[0;34mINFO\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m" + s.DisplayName + "\033[0;37m \033[0;37m→\033[0;37m \033[0;37m" + message + "\033[0m\n"
}

func (s *Service) WarnLog(message string) {
	logPipeline <- "\033[0;37m[\033[0;33mWARN\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m" + s.DisplayName + "\033[0;37m \033[0;37m→\033[0;37m \033[0;37m" + message + "\033[0m\n"
}

func (s *Service) ErrorLog(message string) {
	logPipeline <- "\033[0;37m[\033[0;31mERROR\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m" + s.DisplayName + "\033[0;37m \033[0;37m→\033[0;37m \033[0;37m" + message + "\033[0m\n"
}

func (s *Service) FatalLog(message string) {
	logPipeline <- "\033[0;37m[\033[0;31mERROR\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m" + s.DisplayName + "\033[0;37m \033[0;37m→\033[0;37m \033[0;37m" + message + "\033[0m\n"
	panic(message)
}

var (
	logPipeline = make(chan string, 1024*32)
	LogsChannel = make(chan string)
)

func init() {
	go processLogs()
}

func processLogs() {
	for log := range logPipeline {
		LogsChannel <- log
	}
}
