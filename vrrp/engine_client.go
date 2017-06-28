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

// VIPsHAConfig represents the high availability configuration for a node in a
// vrrp cluster.
type VIPsHAConfig struct {
	HAConfig
	VIPInterface *net.Interface
	VIPs         []*VIPsHAConfigVIP
}

type VIPsHAConfigVIP struct {
	IP    net.IP
	IPNet *net.IPNet
}

// VIPsUpdateEngine implements the Engine interface for testing purposes.
type VIPsUpdateEngine struct {
	Config *VIPsHAConfig

	mu     sync.Mutex
	cancel context.CancelFunc
}

// HAConfig returns the HAConfig for a VIPsUpdateEngine.
func (e *VIPsUpdateEngine) HAConfig() (*HAConfig, error) {
	return &e.Config.HAConfig, nil
}

// HAState does nothing.
func (e *VIPsUpdateEngine) HAState(state HAState) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	c := e.Config
	for _, vipCfg := range c.VIPs {
		err := e.updateHAStateForVIP(state, vipCfg)
		if err != nil {
			// 1つのVIPの追加・削除に失敗しても他のVIPの追加・削除は行いたいので
			// ログ出力はするがエラーでも抜けずにループを継続する。
			ltsvlog.Logger.Err(err)
		}
	}
	return nil
}

func (e *VIPsUpdateEngine) updateHAStateForVIP(state HAState, vipCfg *VIPsHAConfigVIP) error {
	c := e.Config
	hasVIP, err := HasAddr(c.VIPInterface, vipCfg.IP)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to check interface has VIP, err=%v", err)
		}).String("interface", c.VIPInterface.Name).Stringer("vip", vipCfg.IP).Stack("")
	}

	if state == HAMaster {
		if hasVIP {
			ltsvlog.Logger.Info().String("msg", "HAState called but already aquired VIP").Sprintf("state", "%v", state).
				String("interface", c.VIPInterface.Name).Stringer("vip", vipCfg.IP).
				Stringer("mask", vipCfg.IPNet.Mask).Log()
		} else {
			err := AddAddr(c.VIPInterface, vipCfg.IP, vipCfg.IPNet, "")
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to add IP address, err=%v", err)
				}).String("interface", c.VIPInterface.Name).Stringer("vip", vipCfg.IP).
					Stringer("mask", vipCfg.IPNet.Mask).Stack("")
			}
		}

		if e.cancel == nil {
			var ctx context.Context
			ctx, e.cancel = context.WithCancel(context.TODO())
			go sendGARPLoop(ctx, c.VIPInterface, vipCfg.IP)
		}
	} else {
		if hasVIP {
			err := DelAddr(c.VIPInterface, vipCfg.IP, vipCfg.IPNet)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to delete IP address, err=%v", err)
				}).String("interface", c.VIPInterface.Name).Stringer("vip", vipCfg.IP).
					Stringer("mask", vipCfg.IPNet.Mask).Stack("")
			}
		} else {
			ltsvlog.Logger.Info().String("msg", "HAState called but already released VIP").Sprintf("state", "%v", state).
				String("interface", c.VIPInterface.Name).Stringer("vip", vipCfg.IP).
				Stringer("mask", vipCfg.IPNet.Mask).Log()
			return nil
		}
		if e.cancel != nil {
			e.cancel()
		}
	}
	ltsvlog.Logger.Info().String("msg", "HAState updated").Sprintf("state", "%v", state).
		String("interface", c.VIPInterface.Name).Stringer("vip", vipCfg.IP).
		Stringer("mask", vipCfg.IPNet.Mask).Log()
	return nil
}

func sendGARPLoop(ctx context.Context, intf *net.Interface, vip net.IP) {
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
func (e *VIPsUpdateEngine) HAUpdate(status HAStatus) (bool, error) {
	return false, nil
}
