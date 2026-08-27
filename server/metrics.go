package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Lightweight system metrics read straight from /proc - no agent, negligible cost.
type sysMetrics struct {
	CPU        float64 `json:"cpu"`       // percent 0-100
	MemUsedMB  int     `json:"mem_used"`  // MB
	MemTotalMB int     `json:"mem_total"` // MB
	NetKBps    float64 `json:"net_kbps"`  // total rx+tx KB/s
}

var (
	metricsMu   sync.RWMutex
	metricsSnap sysMetrics
)

func currentMetrics() sysMetrics {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return metricsSnap
}

func startMetricsSampler() {
	go func() {
		var lastIdle, lastTotal, lastNet uint64
		var lastTime time.Time
		for {
			idle, total := readCPU()
			net := readNet()
			now := time.Now()

			m := sysMetrics{}
			if lastTotal != 0 && total > lastTotal {
				m.CPU = (1 - float64(idle-lastIdle)/float64(total-lastTotal)) * 100
			}
			if !lastTime.IsZero() {
				if dt := now.Sub(lastTime).Seconds(); dt > 0 {
					m.NetKBps = float64(net-lastNet) / dt / 1024
				}
			}
			m.MemUsedMB, m.MemTotalMB = readMem()

			metricsMu.Lock()
			metricsSnap = m
			metricsMu.Unlock()

			lastIdle, lastTotal, lastNet, lastTime = idle, total, net, now
			time.Sleep(3 * time.Second)
		}
	}()
}

func readCPU() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.SplitN(string(b), "\n", 2)[0] // "cpu  u n s idle iowait ..."
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, 0
	}
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 || i == 5 { // idle + iowait
			idle += v
		}
	}
	return idle, total
}

func readMem() (usedMB, totalMB int) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var total, avail int
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.Atoi(f[1]) // kB
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return (total - avail) / 1024, total / 1024
}

func readNet() (bytes uint64) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if name == "lo" || name == "" {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		bytes += rx + tx
	}
	return bytes
}
