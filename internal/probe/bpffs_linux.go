//go:build linux

package probe

import (
	"log/slog"
	"syscall"
)

// bpfFSMagic is the statfs magic identifying the bpf pseudo-filesystem,
// matching <linux/magic.h>:BPF_FS_MAGIC.
const bpfFSMagic = 0xCAFE4A11

// ensureBPFFS makes sure /sys/fs/bpf is a mounted bpf filesystem. On modern
// systemd hosts this is already done at boot, so the common path is a single
// statfs(2) syscall returning nil. Falls back to mount(2) for hosts (or
// stripped containers) where it isn't pre-mounted — requires the calling
// process to hold CAP_SYS_ADMIN, which the vakta agent DaemonSet already
// declares.
func ensureBPFFS() error {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/bpf", &st); err == nil && int64(st.Type) == bpfFSMagic {
		return nil
	}
	if err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return err
	}
	slog.Info("probe: mounted bpffs at /sys/fs/bpf")
	return nil
}
