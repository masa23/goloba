package goloba

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hnakamur/ltsvlog"
)

// advertisement represents a VRRPv3 advertisement packet.  Field names and sizes are per RFC 5798.
type advertisement struct {
	VersionType  uint8
	VRID         uint8
	Priority     uint8
	CountIPAddrs uint8
	AdvertInt    uint16
	Checksum     uint16
}

const (
	// vrrpAdvertSize is the expected number of bytes in the Advertisement struct.
	vrrpAdvertSize = 8

	// vrrpAdvertType is the type of VRRP advertisements to send and receive.
	vrrpAdvertType = uint8(1)

	// vrrpVersion is the VRRP version this module implements.
	vrrpVersion = uint8(3)

	// vrrpVersionType represents the version and Advertisement type of VRRP
	// packets that this module supports.
	vrrpVersionType = vrrpVersion<<4 | vrrpAdvertType

	// vrrpPort is the port for VRRP
	vrrpPort = 112
)

// haNodeConfig specifies the configuration for a Node.
type haNodeConfig struct {
	haConfig
	MasterAdvertInterval time.Duration
	Preempt              bool
}

// haNode represents one member of a high availability cluster.
type haNode struct {
	haNodeConfig
	conn                 *ipHAConn
	engine               *haEngine
	statusLock           sync.RWMutex
	haStatus             haStatus
	sendCount            uint64
	receiveCount         uint64
	masterDownInterval   time.Duration
	lastMasterAdvertTime time.Time
	errChannel           chan error
	recvChannel          chan *advertisement
	stopSenderChannel    chan haState
}

// newHANode creates a new Node with the given NodeConfig and haConn.
func newHANode(cfg haNodeConfig, conn *ipHAConn, eng *haEngine) *haNode {
	n := &haNode{
		haNodeConfig:         cfg,
		conn:                 conn,
		engine:               eng,
		lastMasterAdvertTime: time.Now(),
		errChannel:           make(chan error),
		recvChannel:          make(chan *advertisement, 20),
		stopSenderChannel:    make(chan haState),
	}
	n.setState(haBackup)
	n.resetMasterDownInterval(cfg.MasterAdvertInterval)
	return n
}

// resetMasterDownInterval calculates masterDownInterval per RFC 5798.
func (n *haNode) resetMasterDownInterval(advertInterval time.Duration) {
	skewTime := (time.Duration((256 - int(n.Priority))) * (advertInterval)) / 256
	masterDownInterval := 3*(advertInterval) + skewTime
	if masterDownInterval != n.masterDownInterval {
		n.masterDownInterval = masterDownInterval
		if ltsvlog.Logger.DebugEnabled() {
			ltsvlog.Logger.Debug().String("msg", "resetMasterDownInterval").Fmt("skewTime", "%v", skewTime).Fmt("masterDownInterval", "%v", masterDownInterval).Log()
		}
	}
}

// state returns the current HA state for this node.
func (n *haNode) state() haState {
	n.statusLock.RLock()
	defer n.statusLock.RUnlock()
	return n.haStatus.State
}

// setState changes the HA state for this node.
func (n *haNode) setState(s haState) {
	n.statusLock.Lock()
	defer n.statusLock.Unlock()
	if n.haStatus.State != s {
		n.haStatus.State = s
		n.haStatus.Since = time.Now()
		n.haStatus.Transitions++
	}
}

// newAdvertisement creates a new Advertisement with this Node's VRID and priority.
func (n *haNode) newAdvertisement() *advertisement {
	return &advertisement{
		VersionType: vrrpVersionType,
		VRID:        n.VRID,
		Priority:    n.Priority,
		AdvertInt:   uint16(n.MasterAdvertInterval / time.Millisecond / 10), // AdvertInt is in centiseconds
	}
}

// run sends and receives advertisements, changes this Node's state in response to incoming
// advertisements, and periodically notifies the engine of the current state. run does not return
// until Shutdown is called or an unrecoverable error occurs.
func (n *haNode) run(ctx context.Context) error {
	go n.receiveAdvertisements()

	for n.state() != haShutdown {
		if err := n.runOnce(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (n *haNode) runOnce(ctx context.Context) error {
	switch s := n.state(); s {
	case haBackup:
		switch newState := n.doBackupTasks(ctx); newState {
		case haBackup:
			// do nothing
		case haMaster:
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "received advertisements").Uint64("receiveCount", atomic.LoadUint64(&n.receiveCount)).Int("recvChannelLen", len(n.recvChannel)).Log()
				ltsvlog.Logger.Debug().String("msg", "Last master Advertisement dequeued").String("dequeuedAt", n.lastMasterAdvertTime.Format(time.StampMilli)).Log()
			}
			n.becomeMaster()
		case haShutdown:
			n.becomeShutdown()
		default:
			return ltsvlog.Err(fmt.Errorf("runOnce: Can't handle transition from %v to %v", s, newState)).Stack("")
		}

	case haMaster:
		switch newState := n.doMasterTasks(ctx); newState {
		case haMaster:
			// do nothing
		case haBackup:
			n.becomeBackup()
		case haShutdown:
			n.becomeShutdown()
		default:
			return ltsvlog.Err(fmt.Errorf("runOnce: Can't handle transition from %v to %v", s, newState)).Stack("")
		}

	default:
		return ltsvlog.Err(fmt.Errorf("runOnce: Invalid state - %v", s)).Stack("")
	}
	return nil
}

func (n *haNode) becomeMaster() {
	ltsvlog.Logger.Info().String("msg", "Node.becomeMaster").Log()
	if err := n.engine.HAState(haMaster); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(fmt.Errorf("Failed to notify engine: %v", err)).Stack(""))
	}

	go n.sendAdvertisements()
	n.setState(haMaster)
}

func (n *haNode) becomeBackup() {
	ltsvlog.Logger.Info().String("msg", "Node.becomeBackup").Log()
	if err := n.engine.HAState(haBackup); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(fmt.Errorf("Failed to notify engine: %v", err)).Stack(""))
	}

	n.stopSenderChannel <- haBackup
	n.setState(haBackup)
}

func (n *haNode) becomeShutdown() {
	ltsvlog.Logger.Info().String("msg", "Node.becomeShutdown").Log()
	if err := n.engine.HAState(haShutdown); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(fmt.Errorf("Failed to notify engine: %v", err)).Stack(""))
	}

	if n.state() == haMaster {
		n.stopSenderChannel <- haShutdown
		// Sleep for a moment so sendAdvertisements() has a chance to send the shutdown advertisement.
		time.Sleep(500 * time.Millisecond)
	}
	n.setState(haShutdown)
}

func (n *haNode) doMasterTasks(ctx context.Context) haState {
	select {
	case advert := <-n.recvChannel:
		if advert.VersionType != vrrpVersionType {
			// Ignore
			return haMaster
		}
		if advert.VRID != n.VRID {
			ltsvlog.Logger.Info().String("msg", "doMasterTasks: ignoring Advertisement").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
			return haMaster
		}
		if advert.Priority == n.Priority {
			// TODO(angusc): RFC 5798 says we should compare IP addresses at this point.
			ltsvlog.Logger.Info().String("msg", "doMasterTasks: ignoring Advertisement with my priority").Uint8("peerPriority", advert.Priority).Log()
			return haMaster
		}
		if advert.Priority > n.Priority {
			ltsvlog.Logger.Info().String("msg", "doMasterTasks: peer priority > my priority - becoming BACKUP").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
			n.lastMasterAdvertTime = time.Now()
			return haBackup
		}

	case <-ctx.Done():
		ltsvlog.Logger.Info().String("msg", "got ctx.Done(), returning haShutdown from doMasterTasks").Log()
		return haShutdown

	case err := <-n.errChannel:
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("doMasterTasks: %v", err)
		}))
		return haError
	}
	// no change
	return haMaster
}

func (n *haNode) doBackupTasks(ctx context.Context) haState {
	deadline := n.lastMasterAdvertTime.Add(n.masterDownInterval)
	remaining := deadline.Sub(time.Now())
	timeout := time.After(remaining)
	select {
	case advert := <-n.recvChannel:
		return n.backupHandleAdvertisement(advert)

	case <-ctx.Done():
		ltsvlog.Logger.Info().String("msg", "got ctx.Done(), returning haShutdown from doBackupTasks").Log()
		return haShutdown

	case err := <-n.errChannel:
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("doBackupTasks: %v", err)
		}))
		return haError

	case <-timeout:
		ltsvlog.Logger.Info().String("msg", "doBackupTasks: timed out waiting for Advertisement").Stringer("remaining", remaining).Log()
		select {
		case advert := <-n.recvChannel:
			ltsvlog.Logger.Info().String("msg", "doBackupTasks: found Advertisement queued for processing")
			return n.backupHandleAdvertisement(advert)
		default:
			ltsvlog.Logger.Info().String("msg", "doBackupTasks: becoming MASTER")
			return haMaster
		}
	}
}

func (n *haNode) backupHandleAdvertisement(advert *advertisement) haState {
	switch {
	case advert.VersionType != vrrpVersionType:
		// Ignore
		return haBackup

	case advert.VRID != n.VRID:
		ltsvlog.Logger.Info().String("msg", "backupHandleAdvertisement: ignoring Advertisement").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
		return haBackup

	case advert.Priority == 0:
		ltsvlog.Logger.Info().String("msg", "backupHandleAdvertisement: peer priority is 0 - becoming MASTER")
		return haMaster

	case n.Preempt && advert.Priority < n.Priority:
		ltsvlog.Logger.Info().String("msg", "backupHandleAdvertisement: peer priority < my priority - becoming MASTER").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
		return haMaster
	}

	// Per RFC 5798, set the masterDownInterval based on the advert interval received from the
	// current master.  AdvertInt is in centiseconds.
	n.resetMasterDownInterval(time.Millisecond * time.Duration(10*advert.AdvertInt))
	n.lastMasterAdvertTime = time.Now()
	return haBackup
}

func (n *haNode) queueAdvertisement(advert *advertisement) {
	if queueLen := len(n.recvChannel); queueLen > 0 {
		ltsvlog.Logger.Info().String("msg", "queueAdvertisement: advertisements already queued").Int("queueLen", queueLen).Log()
	}
	select {
	case n.recvChannel <- advert:
	default:
		n.errChannel <- ltsvlog.Err(errors.New("queueAdvertisement: recvChannel is full")).Stack("")
	}
}

func (n *haNode) sendAdvertisements() {
	ticker := time.NewTicker(n.MasterAdvertInterval)
	for {
		// TODO(angusc): figure out how to make the timing-related logic here, and throughout, clockjump
		// safe.
		select {
		case <-ticker.C:
			if err := n.conn.send(n.newAdvertisement(), n.MasterAdvertInterval); err != nil {
				select {
				case n.errChannel <- err:
				default:
					ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("sendAdvertisements: Unable to write to errChannel. Error was: %v", err)
					}).Stack(""))
					os.Exit(1)
				}
				break
			}

			sendCount := atomic.AddUint64(&n.sendCount, 1)
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "sendAdvertisements: Sent advertisements").Uint64("sendCount", sendCount).Log()
			}

		case newState := <-n.stopSenderChannel:
			ticker.Stop()
			if newState == haShutdown {
				advert := n.newAdvertisement()
				advert.Priority = 0
				if err := n.conn.send(advert, time.Second); err != nil {
					ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("sendAdvertisements: Failed to send shutdown Advertisement, %v", err)
					}).Stack(""))
				}
			}
			return
		}
	}
}

func (n *haNode) receiveAdvertisements() {
	for {
		if advert, err := n.conn.receive(); err != nil {
			select {
			case n.errChannel <- err:
			default:
				ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("receiveAdvertisements: Unable to write to errChannel. Error was: %v", err)
				}).Stack(""))
				os.Exit(1)
			}
		} else if advert != nil {
			receiveCount := atomic.AddUint64(&n.receiveCount, 1)
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "receiveAdvertisements: Received advertisements").Uint64("receveCount", receiveCount).Log()
			}
			n.queueAdvertisement(advert)
		}
	}
}
