package goloba

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/hnakamur/netutil"
)

// haEngineConfig represents the high availability configuration for a node in a
// VRRP cluster.
type haEngineConfig struct {
	haConfig
	sendGARPInterval time.Duration
	vipInterface     *net.Interface
	vips             []*haEngineVIPConfig
}

type haEngineVIPConfig struct {
	ip    net.IP
	ipNet *net.IPNet

	cancel context.CancelFunc
}

// haEngine implements the Engine interface for testing purposes.
type haEngine struct {
	config *haEngineConfig
}

func (e *haEngine) HAState(state haState) error {
	c := e.config
	for i, vipCfg := range c.vips {
		ltsvlog.Logger.Info().String("msg", "before updateHAStateForVIP").Int("i", i).Fmt("vipCfg", "%+v", vipCfg).Log()
		err := e.updateHAStateForVIP(state, vipCfg)
		if err != nil {
			// 1つのVIPの追加・削除に失敗しても他のVIPの追加・削除は行いたいので
			// ログ出力はするがエラーでも抜けずにループを継続する。
			ltsvlog.Logger.Err(err)
		}
	}
	return nil
}

func (e *haEngine) updateHAStateForVIP(state haState, vipCfg *haEngineVIPConfig) error {
	c := e.config
	hasVIP, err := netutil.HasAddr(c.vipInterface, vipCfg.ip)
	if err != nil {
		return ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to check interface has VIP, err=%v", err)
		}).String("interface", c.vipInterface.Name).Stringer("vip", vipCfg.ip).Stack("")
	}

	if state == haMaster {
		if hasVIP {
			ltsvlog.Logger.Info().String("msg", "HAState called but already acquired VIP").Fmt("state", "%v", state).
				String("interface", c.vipInterface.Name).Stringer("vip", vipCfg.ip).
				Stringer("mask", vipCfg.ipNet.Mask).Log()
		} else {
			err := netutil.AddAddr(c.vipInterface, vipCfg.ip, vipCfg.ipNet, "")
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to add IP address, err=%v", err)
				}).String("interface", c.vipInterface.Name).Stringer("vip", vipCfg.ip).
					Stringer("mask", vipCfg.ipNet.Mask).Stack("")
			}
		}

		if vipCfg.cancel == nil {
			var ctx context.Context
			ctx, vipCfg.cancel = context.WithCancel(context.TODO())
			ltsvlog.Logger.Info().String("msg", "before go sendGARPLoop").Stringer("vip", vipCfg.ip).Log()
			go e.sendGARPLoop(ctx, c.vipInterface, vipCfg.ip)
		}
	} else {
		if hasVIP {
			err := netutil.DelAddr(c.vipInterface, vipCfg.ip, vipCfg.ipNet)
			if err != nil {
				return ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to delete IP address, err=%v", err)
				}).String("interface", c.vipInterface.Name).Stringer("vip", vipCfg.ip).
					Stringer("mask", vipCfg.ipNet.Mask).Stack("")
			}
		} else {
			ltsvlog.Logger.Info().String("msg", "HAState called but already released VIP").Fmt("state", "%v", state).
				String("interface", c.vipInterface.Name).Stringer("vip", vipCfg.ip).
				Stringer("mask", vipCfg.ipNet.Mask).Log()
			return nil
		}
		if vipCfg.cancel != nil {
			vipCfg.cancel()
		}
	}
	ltsvlog.Logger.Info().String("msg", "HAState updated").Fmt("state", "%v", state).
		String("interface", c.vipInterface.Name).Stringer("vip", vipCfg.ip).
		Stringer("mask", vipCfg.ipNet.Mask).Log()
	return nil
}

func (e *haEngine) sendGARPLoop(ctx context.Context, intf *net.Interface, vip net.IP) {
	ticker := time.NewTicker(e.config.sendGARPInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := netutil.SendGARP(intf, vip)
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
