package wireddns

import (
	"net"
	"time"
	"wiredshield/modules/db"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var service *services.Service

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)

	if len(r.Question) > 0 {
		question := r.Question[0]
		result, err := db.GetRecord("A", question.Name[:len(question.Name)-1])
		if err != nil {
			service.ErrorLog("Failed to get record: " + err.Error())
		}

		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP(result),
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
