#!/usr/bin/env bash
# Refresh vendored BPF headers. Run from repo root.
# vmlinux.h is regenerated from the running kernel; the rest come from libbpf.
set -euo pipefail

LIBBPF_TAG="v1.4.5"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

git clone --depth 1 --branch "$LIBBPF_TAG" https://github.com/libbpf/libbpf.git "$TMP/libbpf"
for h in bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h; do
    cp "$TMP/libbpf/src/$h" "$(dirname "$0")/$h"
done

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$(dirname "$0")/vmlinux.h"
echo "Headers refreshed. libbpf=$LIBBPF_TAG vmlinux.h=$(uname -r)"
