//go:build !linux

package main

import (
	"fmt"
)

func main() {
	// The Linux namespace launcher is intentionally unavailable on other hosts.
	fmt.Println("sec-fence-launcher requires Linux")
}
