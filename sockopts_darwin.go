//go:build darwin

package mdns

import "syscall"

// setReusePort enables SO_REUSEPORT on macOS/BSD (value 0x0200).
func setReusePort(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}
