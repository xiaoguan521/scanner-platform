//go:build !linux

package main

import "fmt"

func main() {
	fmt.Println("sec-worker-supervisor requires Linux")
}
