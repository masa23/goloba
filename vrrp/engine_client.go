package vrrp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/mdlayher/arp"
)

const engineTimeout = 10 * time.Second

// Engine represents an interface to a Seesaw Engine.
type Engine interface {
	HAConfig() (*HAConfig, error)
	HAState(HAState) error
	HAUpdate(HAStatus) (bool, error)
}

// DummyEngine implements the Engine interface for testing purposes.
type DummyEngine struct {
	Config *HAConfig
}

// HAConfig returns the HAConfig for a DummyEngine.
func (e *DummyEngine) HAConfig() (*HAConfig, error) {
	return e.Config, nil
}

// HAState does nothing.
func (e *DummyEngine) HAState(state HAState) error {
	return nil
}

// HAUpdate does nothing.
func (e *DummyEngine) HAUpdate(status HAStatus) (bool, error) {
	return false, nil
}

// VIPHAConfig represents the high availability configuration for a node in a
// Seesaw cluster.
type VIPHAConfig struct {
	HAConfig
	VIP          net.IP
	VIPNet       *net.IPNet
	VIPInterface *net.Interface
}

// VIPUpdateEngine implements the Engine interface for testing purposes.
type VIPUpdateEngine struct {
	Config *VIPHAConfig

	mu     sync.Mutex
	cancel context.CancelFunc
}

// HAConfig returns the HAConfig for a VIPUpdateEngine.
func (e *VIPUpdateEngine) HAConfig() (*HAConfig, error) {
	return &e.Config.HAConfig, nil
}

// HAState does nothing.
func (e *VIPUpdateEngine) HAState(state HAState) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	c := e.Config
	hasVIP, err := HasAddr(c.VIPInterface, c.VIP)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to check interface has VIP, err=%v", err)
		}).String("interface", c.VIPInterface.Name).Stringer("vip", c.VIP).Stack("")
	}

	if state == HAMaster {
		if hasVIP {
			ltsvlog.Logger.Info().String("msg", "HAState called but already aquired VIP").Sprintf("state", "%v", state).
				String("interface", c.VIPInterface.Name).Stringer("vip", c.VIP).
				Stringer("mask", c.VIPNet.Mask).Log()
		} else {
			err := AddAddr(c.VIPInterface, c.VIP, c.VIPNet, "")
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to add IP address, err=%v", err)
				}).String("interface", c.VIPInterface.Name).Stringer("vip", c.VIP).
					Stringer("mask", c.VIPNet.Mask).Stack("")
			}
		}

		if e.cancel == nil {
			var ctx context.Context
			ctx, e.cancel = context.WithCancel(context.TODO())
			go sendGARPLoop(ctx, c.VIP)
		}
	} else {
		if hasVIP {
			err := DelAddr(c.VIPInterface, c.VIP, c.VIPNet)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to delete IP address, err=%v", err)
				}).String("interface", c.VIPInterface.Name).Stringer("vip", c.VIP).
					Stringer("mask", c.VIPNet.Mask).Stack("")
			}
		} else {
			ltsvlog.Logger.Info().String("msg", "HAState called but already released VIP").Sprintf("state", "%v", state).
				String("interface", c.VIPInterface.Name).Stringer("vip", c.VIP).
				Stringer("mask", c.VIPNet.Mask).Log()
			return nil
		}
		if e.cancel != nil {
			e.cancel()
		}
	}
	ltsvlog.Logger.Info().String("msg", "HAState updated").Sprintf("state", "%v", state).
		String("interface", c.VIPInterface.Name).Stringer("vip", c.VIP).
		Stringer("mask", c.VIPNet.Mask).Log()
	return nil
}

func sendGARPLoop(ctx context.Context, vip net.IP) {
	intf, err := InterfaceByIP(vip)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("interface not found for VIP")
		}).Stringer("vip", vip).Stack(""))
		return
	}

	c, err := arp.Dial(intf)
	if err != nil {
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to dial for arp")
		}).String("interface", intf.Name).Stack(""))
		return
	}
	defer c.Close()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := SendGARP(c, intf, vip)
			if err != nil {
				ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to send GARP, err=%v", err)
				}).Stringer("vip", vip).Stack(""))
			}
			ltsvlog.Logger.Info().String("msg", "sent GARP").Stringer("vip", vip).Log()
		case <-ctx.Done():
			ltsvlog.Logger.Info().String("msg", "exiting sendGARPLoop").Stringer("vip", vip).Log()
			return
		}
	}
}

// HAUpdate does nothing.
func (e *VIPUpdateEngine) HAUpdate(status HAStatus) (bool, error) {
	return false, nil
}
