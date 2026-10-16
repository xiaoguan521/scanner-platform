package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.Error("sec-worker is a Phase 0 scaffold and will not start a scanner")
	os.Exit(2)
}
