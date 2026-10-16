package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.Error("sec-updater is a Phase 0 scaffold and is not configured to start")
	os.Exit(2)
}
