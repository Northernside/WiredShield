package services

type networkInfo struct {
	Ip   string
	Port int
}

type Service struct {
	Name        string
	DisplayName string
	State       bool
	OnlineSince int64
	NetworkInfo networkInfo
	Boot        func()
}

var Services []Service

func RegisterService(name string, displayName string) *Service {
	Services = append(Services, Service{Name: name, DisplayName: displayName})
	return &Services[len(Services)-1]
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
	for i := range Services {
		if Services[i].DisplayName == serviceName {
			// commands.Model.Output += message
		}
	}
}
