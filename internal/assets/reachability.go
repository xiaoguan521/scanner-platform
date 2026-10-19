package assets

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"runtime"
	"time"
)

type Reachability struct {
	Status    string `json:"status"`
	CheckedAt string `json:"checkedAt"`
}

type Pinger func(context.Context, string) (bool, error)

func pingArguments(goos, address string) ([]string, bool) {
	switch goos {
	case "windows":
		return []string{"-n", "1", "-w", "1800", address}, true
	case "darwin":
		return []string{"-n", "-c", "1", "-W", "1800", address}, true
	case "linux":
		return []string{"-n", "-c", "1", "-W", "2", address}, true
	default:
		return nil, false
	}
}

func checkIP(ctx context.Context, address, goos string, run func(context.Context, string, ...string) (bool, error)) (bool, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || run == nil {
		return false, ErrInvalid
	}
	args, supported := pingArguments(goos, ip.String())
	if !supported {
		return false, errors.New("ICMP reachability check is unsupported on this platform")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	return run(checkCtx, "ping", args...)
}

func systemPing(ctx context.Context, address string) (bool, error) {
	return checkIP(ctx, address, runtime.GOOS, func(ctx context.Context, name string, args ...string) (bool, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
}
