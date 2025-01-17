package handlers

import (
	wireddns "wiredshield/dns"
	wiredhttps "wiredshield/http"
	"wiredshield/modules/env"
	"wiredshield/services"
)

func PrepareServices() {
	if env.GetEnv("TMP_BYPASS", "false") == "false" {
		httpsService := services.RegisterService("https", "HTTPS Server")
		httpsService.Boot = wiredhttps.Prepare(httpsService)
	} else {
		services.ProcessService.WarnLog("TMP: Bypassing HTTPS service")
	}

	if env.GetEnv("MASTER", "false") == "true" {
		dnsService := services.RegisterService("dns", "DNS Server")
		dnsService.Boot = wireddns.Prepare(dnsService)
	}
}
