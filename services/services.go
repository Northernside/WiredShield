package services

import "sync"

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

var (
	ServiceRegistry = map[string]*Service{}
	registryLock    sync.Mutex
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
	PrintToModel(s.DisplayName, "\033[0;37m[\033[0;34mINFO\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m"+s.DisplayName+"\033[0;37m \033[0;37m←\033[0;37m \033[0;37m→\033[0;37m \033[0;37m"+message+"\033[0m\n")
}

func (s *Service) WarnLog(message string) {
	PrintToModel(s.DisplayName, "\033[0;37m[\033[0;33mWARN\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m"+s.DisplayName+"\033[0;37m \033[0;37m←\033[0;37m \033[0;37m→\033[0;37m \033[0;37m"+message+"\033[0m\n")
}

func (s *Service) ErrorLog(message string) {
	PrintToModel(s.DisplayName, "\033[0;37m[\033[0;31mERROR\033[0;37m] \033[0;37m→\033[0;37m \033[0;94m"+s.DisplayName+"\033[0;37m \033[0;37m←\033[0;37m \033[0;37m→\033[0;37m \033[0;37m"+message+"\033[0m\n")
}

func PrintToModel(serviceName string, message string) {

}
