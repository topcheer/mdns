//go:build linux

package mdns

import "syscall"

// SO_REUSEPORT value on Linux (not always exported by syscall package).
const linuxSoReusePort = 0x0f

// setReusePort enables SO_REUSEPORT on Linux (value 15).
func setReusePort(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, linuxSoReusePort, 1)
}
