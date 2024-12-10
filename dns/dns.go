package wireddns

import (
	"net"
	"time"
	"wiredshield/modules/db"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var (
	service  *services.Service
	shieldIp *net.IP
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)

	if len(r.Question) > 0 {
		question := r.Question[0]
		result, protected, err := db.GetRecord("A", question.Name[:len(question.Name)-1])
		if err != nil {
			service.ErrorLog("failed to get record: " + err.Error())
		}

		var responseIp net.IP
		if protected {
			responseIp = *shieldIp
		} else {
			responseIp = net.ParseIP(result)
		}

		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: responseIp,
		}

		m.Answer = append(m.Answer, rr)
	}

	err := w.WriteMsg(&m)
	if err != nil {
		service.ErrorLog("Failed to write message: " + err.Error())
	}
}

func Prepare(_service *services.Service) func() {
	service = _service

	// get shield ipv4 from main ipv4 in network interface
	ifaces, err := net.Interfaces()
	if err != nil {
		service.FatalLog("failed to get network interfaces: " + err.Error())
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			service.ErrorLog("failed to get addresses: " + err.Error())
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					shieldIp = &ipnet.IP
					break
				}
			}
		}
	}

	return func() {
		addr := "0.0.0.0:53"
		server := &dns.Server{Addr: addr, Net: "udp"}

		dns.HandleFunc(".", handleRequest)

		service.InfoLog("Starting DNS server on " + addr)
		service.OnlineSince = time.Now().Unix()
		err := server.ListenAndServe()
		if err != nil {
			service.ErrorLog("Failed to start DNS server: " + err.Error())
		}
	}
}
