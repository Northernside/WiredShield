package types

type (
	Telemetry struct {
		CPUProgram float64           `json:"cpu_program"`
		MemProgram uint64            `json:"mem_program"`
		CPUSystem  map[int]float64   `json:"cpu_system"`
		MemSystem  SystemMemoryStats `json:"mem_system"`
		Workers    int               `json:"workers"`
	}

	SystemMemoryStats struct {
		Total     uint64 `json:"total"`
		Free      uint64 `json:"free"`
		Available uint64 `json:"available"`
		Buffers   uint64 `json:"buffers"`
		Cached    uint64 `json:"cached"`
		SwapTotal uint64 `json:"swapTotal"`
		SwapFree  uint64 `json:"swapFree"`
	}
)
