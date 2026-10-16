//go:build !linux

package workerfence

import (
	"context"
	"errors"
	"os"
)

// Non-Linux platforms cannot claim a kernel-enforced nftables firewall.
type unsupportedConfigurator struct{}

func NewConfigurator(_ string, _ *os.File) Configurator {
	return unsupportedConfigurator{}
}

func (unsupportedConfigurator) Apply(_ context.Context, _ RuleSet) error {
	return errors.New("kernel-enforced worker fence requires Linux isolated network namespace")
}
