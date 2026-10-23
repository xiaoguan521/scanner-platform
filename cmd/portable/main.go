package main

import (
	"os"

	"scanner-platform/internal/portable"
)

func main() {
	os.Exit(portable.Main(os.Args[1:], os.Stdout, os.Stderr))
}
