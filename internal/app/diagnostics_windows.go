package app

// Windows portproxy is a TCP listener, so it does not require IP forwarding.
func forwardingChecks() []Check { return nil }
