package telemetry

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"wired/modules/types"
)

func GetFullTelemetry() (*types.Telemetry, error) {
	var telemetry types.Telemetry
	var err error

	telemetry.CPUProgram, err = GetCPUUsageProgram()
	if err != nil {
		return nil, err
	}

	telemetry.MemProgram = GetMemoryUsageProgram()
	telemetry.CPUSystem, err = GetSystemCPUUsage()
	if err != nil {
		return nil, err
	}

	telemetry.MemSystem, err = GetMemorySystem()

	return &telemetry, err
}

// GetCPUUsageProgram returns the cpu usage of this program
func GetCPUUsageProgram() (float64, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(os.Getpid()), "-o", "%cpu").Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return 0, errors.New("unexpected output from ps command")
	}

	return strconv.ParseFloat(strings.TrimSpace(lines[1]), 64)
}

// GetMemoryUsageProgram returns the memory allocated by this program
func GetMemoryUsageProgram() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	return stats.Alloc / 1024 / 1024
}

func GetMemorySystem() (types.SystemMemoryStats, error) {
	memStats := types.SystemMemoryStats{}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return memStats, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// The second field is the value in kB, and we ignore the unit (kB)
		switch fields[0] {
		case "MemTotal:":
			memStats.Total = value
		case "MemFree:":
			memStats.Free = value
		case "MemAvailable:":
			memStats.Available = value
		case "Buffers:":
			memStats.Buffers = value
		case "Cached:":
			memStats.Cached = value
		case "SwapTotal:":
			memStats.SwapTotal = value
		case "SwapFree:":
			memStats.SwapFree = value
		}
	}

	return memStats, nil
}

// CPU
type cpuStats struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func GetSystemCPUUsage() (map[int]float64, error) {
	prevStats, err := getSystemCPUStats()
	if err != nil {
		return nil, err
	}

	time.Sleep(1 * time.Second)
	currStats, err := getSystemCPUStats()
	if err != nil {
		return nil, err
	}

	return calculateSystemCPUUsage(prevStats, currStats), nil
}

func getSystemCPUStats() (map[int]cpuStats, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	stats := make(map[int]cpuStats)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			fields := strings.Fields(line)
			coreID, err := strconv.Atoi(fields[0][3:]) // Extract core ID from "cpu0", "cpu1", etc.
			if err != nil {
				return nil, err
			}

			user, _ := strconv.ParseUint(fields[1], 10, 64)
			nice, _ := strconv.ParseUint(fields[2], 10, 64)
			system, _ := strconv.ParseUint(fields[3], 10, 64)
			idle, _ := strconv.ParseUint(fields[4], 10, 64)
			iowait, _ := strconv.ParseUint(fields[5], 10, 64)
			irq, _ := strconv.ParseUint(fields[6], 10, 64)
			softirq, _ := strconv.ParseUint(fields[7], 10, 64)
			steal, _ := strconv.ParseUint(fields[8], 10, 64)

			stats[coreID] = cpuStats{user, nice, system, idle, iowait, irq, softirq, steal}
		}
	}

	return stats, scanner.Err()
}

func calculateSystemCPUUsage(prev, curr map[int]cpuStats) map[int]float64 {
	usage := make(map[int]float64)

	for coreID, prevStat := range prev {
		currStat, exists := curr[coreID]
		if !exists {
			continue
		}

		totalDelta := (currStat.user + currStat.nice + currStat.system + currStat.idle +
			currStat.iowait + currStat.irq + currStat.softirq + currStat.steal) - (prevStat.user + prevStat.nice + prevStat.system + prevStat.idle +
			prevStat.iowait + prevStat.irq + prevStat.softirq + prevStat.steal)

		if totalDelta > 0 {
			usage[coreID] = (1.0 - float64((currStat.idle+currStat.iowait)-(prevStat.idle+prevStat.iowait))/float64(totalDelta)) * 100
		}
	}

	return usage
}
