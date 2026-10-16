package main

import (
	"os"

	"scanner-platform/internal/bootstrap"
)

func main() {
	os.Exit(bootstrap.RunServer(os.Args[1:], os.Stdout, os.Stderr))
}
