package goloba

import (
	"net"
	"time"
)

// haState indicates the High-Availability state of a VRRP Node.
type haState int

const (
	haUnkown haState = iota
	haBackup
	haDisabled
	haError
	haMaster
	haShutdown
)

func (s haState) String() string {
	switch s {
	case haUnkown:
		return "unknown"
	case haBackup:
		return "backup"
	case haDisabled:
		return "disabled"
	case haError:
		return "error"
	case haMaster:
		return "master"
	case haShutdown:
		return "shutdown"
	}
	return ""
}

// haStatus indicates the High-Availability status for a VRRP Node.
type haStatus struct {
	LastUpdate     time.Time
	State          haState
	Since          time.Time
	Sent           uint64
	Received       uint64
	ReceivedQueued uint64
	Transitions    uint64
}

// haConfig represents the high availability configuration for a node in a
// VRRP cluster.
type haConfig struct {
	Enabled    bool
	LocalAddr  net.IP
	RemoteAddr net.IP
	Priority   uint8
	VRID       uint8
}

// Equal reports whether this HAConfig is equal to the given haConfig.
func (h *haConfig) Equal(other *haConfig) bool {
	return h.Enabled == other.Enabled &&
		h.LocalAddr.Equal(other.LocalAddr) &&
		h.RemoteAddr.Equal(other.RemoteAddr) &&
		h.Priority == other.Priority &&
		h.VRID == other.VRID
}
