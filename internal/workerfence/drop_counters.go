package workerfence

import "context"

// DropCounters are kernel counters for the generated default-drop rules.
// They contain no target addresses or packet contents.
type DropCounters struct {
	EgressPackets  uint64
	ForwardPackets uint64
}

// CounterReader is implemented by the Linux nft configurator. It is kept
// separate from Configurator so fake policy installers cannot accidentally
// claim that they observed kernel counters.
type CounterReader interface {
	ReadDropCounters(context.Context) (DropCounters, error)
}
