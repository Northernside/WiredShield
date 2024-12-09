package wireddns

import (
	"net"
	"time"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var service *services.Service

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)

	hostname := "northernsi.de"
	ip := "69.69.69.69"

	if len(r.Question) > 0 {
		question := r.Question[0]
		if question.Qtype == dns.TypeA && question.Name == hostname+"." {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(ip),
			}

			m.Answer = append(m.Answer, rr)
		}
	}

	err := w.WriteMsg(&m)
	if err != nil {
		service.ErrorLog("Failed to write message: " + err.Error())
	}
}

var (
	Server *dns.Server
)

func Prepare(_service *services.Service) func() {
	service = _service

	return func() {
		addr := "0.0.0.0:53"
		Server := &dns.Server{Addr: addr, Net: "udp"}

		dns.HandleFunc(".", handleRequest)

		service.InfoLog("Starting DNS server on " + addr)
		service.OnlineSince = time.Now().Unix()
		err := Server.ListenAndServe()
		if err != nil {
			service.ErrorLog("Failed to start DNS server: " + err.Error())
		}
	}
}
