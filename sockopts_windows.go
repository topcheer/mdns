//go:build windows

package mdns

// setReusePort is a no-op on Windows; SO_REUSEADDR serves a similar purpose.
func setReusePort(fd uintptr) error {
	return nil
}
