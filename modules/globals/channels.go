package globals

import "os"

var ShutdownChannel = make(chan os.Signal, 1)
