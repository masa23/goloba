package vrrp

import (
	"net"
	"time"
)

// HAState indicates the High-Availability state of a Seesaw Node.
type HAState int

const (
	HAUnknown HAState = iota
	HABackup
	HADisabled
	HAError
	HAMaster
	HAShutdown
)

// HAStatus indicates the High-Availability status for a Seesaw Node.
type HAStatus struct {
	LastUpdate     time.Time
	State          HAState
	Since          time.Time
	Sent           uint64
	Received       uint64
	ReceivedQueued uint64
	Transitions    uint64
}

// HAConfig represents the high availability configuration for a node in a
// Seesaw cluster.
type HAConfig struct {
	Enabled    bool
	LocalAddr  net.IP
	RemoteAddr net.IP
	Priority   uint8
	VRID       uint8
}

// Equal reports whether this HAConfig is equal to the given HAConfig.
func (h *HAConfig) Equal(other *HAConfig) bool {
	return h.Enabled == other.Enabled &&
		h.LocalAddr.Equal(other.LocalAddr) &&
		h.RemoteAddr.Equal(other.RemoteAddr) &&
		h.Priority == other.Priority &&
		h.VRID == other.VRID
}
