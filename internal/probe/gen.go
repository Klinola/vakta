// Package probe is the kernel-instrumentation layer of vakta.
package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror" probe ./bpf/probe.bpf.c -- -I./bpf/headers
