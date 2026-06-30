// Package main implements vakta-host-watch, a host overload early-warning
// daemon. See docs/superpowers/specs/2026-06-30-vakta-host-watch-design.md
// in the Taberna repo for the design.
package main

import (
	"log"
	"os"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("vakta-host-watch starting (scaffold)")
	os.Exit(0)
}
