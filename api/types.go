package api

// Info represents the result of /info API
type Info struct {
	Services []Service `json:"services"`
}

type Service struct {
	Protocol     string        `json:"protocol"`
	Address      string        `json:"address"`
	Port         uint16        `json:"port"`
	Schedule     string        `json:"schedule"`
	Destinations []Destination `json:"destinations"`
}

type Destination struct {
	Address      string `json:"address"`
	Port         uint16 `json:"port"`
	Forward      string `json:"forward"`
	Weight       uint32 `json:"weight"`
	ActiveConn   uint32 `json:"active_conn"`
	InactiveConn uint32 `json:"inactive_conn"`
	Detached     bool   `json:"detached"`
	Locked       bool   `json:"locked"`
}
