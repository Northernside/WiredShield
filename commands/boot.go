package commands

import "wiredshield/services"

func Boot(model *Model) {
	for _, service := range services.ServiceRegistry {
		if service.Boot != nil {
			go service.Boot()
		}
	}

	//model.Output = "All services started\n"
}
