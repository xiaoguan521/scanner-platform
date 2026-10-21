package supervisor

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRunUsesBaseDelayAfterSuccessfulCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cycles int
	var delays []time.Duration
	err := Run(ctx, Policy{RestartDelay: 2 * time.Second, MaxBackoff: 10 * time.Second, MaxRestarts: 2}, func(context.Context) (int, error) {
		cycles++
		return 0, nil
	}, func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		if len(delays) == 2 {
			return context.Canceled
		}
		return nil
	}, nil)
	if !errors.Is(err, context.Canceled) || cycles != 2 || !reflect.DeepEqual(delays, []time.Duration{2 * time.Second, 2 * time.Second}) {
		t.Fatalf("run=%v cycles=%d delays=%v", err, cycles, delays)
	}
}

func TestRunBacksOffConsecutiveFailuresAndStopsAtLimit(t *testing.T) {
	ctx := context.Background()
	var delays []time.Duration
	err := Run(ctx, Policy{RestartDelay: time.Second, MaxBackoff: 4 * time.Second, MaxRestarts: 3}, func(context.Context) (int, error) {
		return 7, errors.New("start failed")
	}, func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}, nil)
	if !errors.Is(err, ErrRestartLimit) {
		t.Fatalf("error=%v", err)
	}
	if !reflect.DeepEqual(delays, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("delays=%v", delays)
	}
}

func TestRunRejectsInvalidPolicyAndCancellation(t *testing.T) {
	if err := Run(context.Background(), Policy{RestartDelay: 2 * time.Second, MaxBackoff: time.Second}, func(context.Context) (int, error) { return 0, nil }, Sleep, nil); err == nil {
		t.Fatal("accepted invalid policy")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Policy{}, func(context.Context) (int, error) { return 0, nil }, Sleep, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}
