#!/usr/bin/env bash
# Refresh vendored BPF headers. Run from anywhere.
# vmlinux.h is regenerated from the running kernel (stays at headers root).
# libbpf headers are vendored byte-identical under headers/bpf/ to match
# how libbpf's own headers reference each other (#include <bpf/foo.h>).
set -euo pipefail

LIBBPF_TAG="v1.4.5"
DIR="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

git clone --depth 1 --branch "$LIBBPF_TAG" https://github.com/libbpf/libbpf.git "$TMP/libbpf"
mkdir -p "$DIR/bpf"
for h in bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h; do
    cp "$TMP/libbpf/src/$h" "$DIR/bpf/$h"
done

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$DIR/vmlinux.h"
echo "Headers refreshed. libbpf=$LIBBPF_TAG vmlinux.h=$(uname -r)"
