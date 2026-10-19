// Package portprobe provides a bounded TCP connect probe for one registered IP.
// It sends no application data and performs no service fingerprinting.
package portprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	ErrInvalidTarget = errors.New("invalid port probe target")
	ErrInvalidConfig = errors.New("invalid port probe configuration")
)

const (
	PresetCommon          = "common"
	PresetCustom          = "custom"
	PresetCommonAndCustom = "common-and-custom"
	MaxPorts              = 1024
	MaxRanges             = 128
	ProbeTimeout          = 700 * time.Millisecond
	ProbeConcurrency      = 4
)

type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Config struct {
	Preset      string  `json:"preset"`
	Ranges      []Range `json:"ranges,omitempty"`
	Exclusions  []Range `json:"exclusions,omitempty"`
	OpsApproved bool    `json:"opsApproved,omitempty"`
}

// CommonPorts is a curated TCP list for the platform's common Linux web,
// middleware, and database services. The returned slice is a copy.
func CommonPorts() []int {
	return []int{
		22, 80, 443, 1521, 2181, 2888, 3000, 3306, 3888, 5000,
		5236, 5258, 5432, 5672, 6379, 7001, 8000, 8001, 8080, 8081,
		8088, 8443, 8848, 9000, 9090, 9092, 9443, 15672, 9848, 9849,
		54321,
	}
}

// SelectPorts validates a configuration, applies exclusions, and returns a
// sorted list capped at MaxPorts. Ranges are inclusive.
func SelectPorts(config Config) ([]int, error) {
	preset := config.Preset
	if preset == "" {
		preset = PresetCommon
	}
	if len(config.Ranges) > MaxRanges || len(config.Exclusions) > MaxRanges {
		return nil, ErrInvalidConfig
	}
	selected := make(map[int]struct{}, MaxPorts)
	switch preset {
	case PresetCommon:
		if len(config.Ranges) != 0 {
			return nil, ErrInvalidConfig
		}
		for _, port := range CommonPorts() {
			selected[port] = struct{}{}
		}
	case PresetCustom, PresetCommonAndCustom:
		if len(config.Ranges) == 0 {
			return nil, ErrInvalidConfig
		}
		if preset == PresetCommonAndCustom {
			for _, port := range CommonPorts() {
				selected[port] = struct{}{}
			}
		}
		for _, portRange := range config.Ranges {
			if !validRange(portRange) {
				return nil, ErrInvalidConfig
			}
			for port := portRange.Start; port <= portRange.End; port++ {
				selected[port] = struct{}{}
				if len(selected) > MaxPorts {
					return nil, ErrInvalidConfig
				}
			}
		}
	default:
		return nil, ErrInvalidConfig
	}
	if len(selected) == 0 || len(selected) > MaxPorts {
		return nil, ErrInvalidConfig
	}
	for _, exclusion := range config.Exclusions {
		if !validRange(exclusion) {
			return nil, ErrInvalidConfig
		}
		for port := range selected {
			if port >= exclusion.Start && port <= exclusion.End {
				delete(selected, port)
			}
		}
	}
	if len(selected) == 0 {
		return nil, ErrInvalidConfig
	}
	ports := make([]int, 0, len(selected))
	for port := range selected {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func validRange(value Range) bool {
	return value.Start >= 1 && value.Start <= value.End && value.End <= 65535
}

type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Scan validates a numeric IP and probes the provided TCP port list by
// connecting and immediately closing. It never sends protocol data.
func Scan(ctx context.Context, target string, ports []int) ([]int, error) {
	return scanWithDialer(ctx, target, ports, &net.Dialer{})
}

func scanWithDialer(ctx context.Context, target string, ports []int, d dialer) ([]int, error) {
	address, err := netip.ParseAddr(target)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || len(ports) == 0 || len(ports) > MaxPorts || d == nil {
		return nil, ErrInvalidTarget
	}
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, ErrInvalidConfig
		}
		if _, ok := seen[port]; ok {
			return nil, ErrInvalidConfig
		}
		seen[port] = struct{}{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	address = address.Unmap()
	workers := ProbeConcurrency
	if len(ports) < workers {
		workers = len(ports)
	}
	jobs := make(chan int)
	open := make(chan int, len(ports))
	var done sync.WaitGroup
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			for port := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
				conn, err := d.DialContext(probeCtx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
				cancel()
				if conn != nil {
					_ = conn.Close()
				}
				if err == nil {
					open <- port
				}
			}
		}()
	}
	for _, port := range ports {
		select {
		case jobs <- port:
		case <-ctx.Done():
			close(jobs)
			done.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	done.Wait()
	close(open)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]int, 0, len(open))
	for port := range open {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
}
