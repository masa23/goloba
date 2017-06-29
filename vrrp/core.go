package vrrp

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hnakamur/ltsvlog"
)

// HAConn represents an HA connection for sending and receiving advertisements between two Nodes.
type HAConn interface {
	send(advert *advertisement, timeout time.Duration) error
	receive() (*advertisement, error)
}

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

// NodeConfig specifies the configuration for a Node.
type NodeConfig struct {
	HAConfig
	MasterAdvertInterval time.Duration
	Preempt              bool
}

// Node represents one member of a high availability cluster.
type Node struct {
	NodeConfig
	conn                 HAConn
	engine               Engine
	statusLock           sync.RWMutex
	haStatus             HAStatus
	sendCount            uint64
	receiveCount         uint64
	masterDownInterval   time.Duration
	lastMasterAdvertTime time.Time
	errChannel           chan error
	recvChannel          chan *advertisement
	stopSenderChannel    chan HAState
	shutdownChannel      chan bool
}

// NewNode creates a new Node with the given NodeConfig and HAConn.
func NewNode(cfg NodeConfig, conn HAConn, engine Engine) *Node {
	n := &Node{
		NodeConfig:           cfg,
		conn:                 conn,
		engine:               engine,
		lastMasterAdvertTime: time.Now(),
		errChannel:           make(chan error),
		recvChannel:          make(chan *advertisement, 20),
		stopSenderChannel:    make(chan HAState),
		shutdownChannel:      make(chan bool),
	}
	n.setState(HABackup)
	n.resetMasterDownInterval(cfg.MasterAdvertInterval)
	return n
}

// resetMasterDownInterval calculates masterDownInterval per RFC 5798.
func (n *Node) resetMasterDownInterval(advertInterval time.Duration) {
	skewTime := (time.Duration((256 - int(n.Priority))) * (advertInterval)) / 256
	masterDownInterval := 3*(advertInterval) + skewTime
	if masterDownInterval != n.masterDownInterval {
		n.masterDownInterval = masterDownInterval
		if ltsvlog.Logger.DebugEnabled() {
			ltsvlog.Logger.Debug().String("msg", "resetMasterDownInterval").Sprintf("skewTime", "%v", skewTime).Sprintf("masterDownInterval", "%v", masterDownInterval).Log()
		}
	}
}

// state returns the current HA state for this node.
func (n *Node) state() HAState {
	n.statusLock.RLock()
	defer n.statusLock.RUnlock()
	return n.haStatus.State
}

// setState changes the HA state for this node.
func (n *Node) setState(s HAState) {
	n.statusLock.Lock()
	defer n.statusLock.Unlock()
	if n.haStatus.State != s {
		n.haStatus.State = s
		n.haStatus.Since = time.Now()
		n.haStatus.Transitions++
	}
}

// newAdvertisement creates a new Advertisement with this Node's VRID and priority.
func (n *Node) newAdvertisement() *advertisement {
	return &advertisement{
		VersionType: vrrpVersionType,
		VRID:        n.VRID,
		Priority:    n.Priority,
		AdvertInt:   uint16(n.MasterAdvertInterval / time.Millisecond / 10), // AdvertInt is in centiseconds
	}
}

// Run sends and receives advertisements, changes this Node's state in response to incoming
// advertisements, and periodically notifies the engine of the current state. Run does not return
// until Shutdown is called or an unrecoverable error occurs.
func (n *Node) Run() error {
	go n.receiveAdvertisements()

	for n.state() != HAShutdown {
		if err := n.runOnce(); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown puts this Node in SHUTDOWN state and causes Run() to return.
func (n *Node) Shutdown() {
	n.shutdownChannel <- true
}

func (n *Node) runOnce() error {
	switch s := n.state(); s {
	case HABackup:
		switch newState := n.doBackupTasks(); newState {
		case HABackup:
			// do nothing
		case HAMaster:
			if ltsvlog.Logger.DebugEnabled() {
				ltsvlog.Logger.Debug().String("msg", "received advertisements").Uint64("receiveCount", atomic.LoadUint64(&n.receiveCount)).Int("recvChannelLen", len(n.recvChannel)).Log()
				ltsvlog.Logger.Debug().String("msg", "Last master Advertisement dequeued").String("dequeuedAt", n.lastMasterAdvertTime.Format(time.StampMilli)).Log()
			}
			n.becomeMaster()
		case HAShutdown:
			n.becomeShutdown()
		default:
			return ltsvlog.Err(fmt.Errorf("runOnce: Can't handle transition from %v to %v", s, newState)).Stack("")
		}

	case HAMaster:
		switch newState := n.doMasterTasks(); newState {
		case HAMaster:
			// do nothing
		case HABackup:
			n.becomeBackup()
		case HAShutdown:
			n.becomeShutdown()
		default:
			return ltsvlog.Err(fmt.Errorf("runOnce: Can't handle transition from %v to %v", s, newState)).Stack("")
		}

	default:
		return ltsvlog.Err(fmt.Errorf("runOnce: Invalid state - %v", s)).Stack("")
	}
	return nil
}

func (n *Node) becomeMaster() {
	ltsvlog.Logger.Info().String("msg", "Node.becomeMaster").Log()
	if err := n.engine.HAState(HAMaster); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(fmt.Errorf("Failed to notify engine: %v", err)).Stack(""))
	}

	go n.sendAdvertisements()
	n.setState(HAMaster)
}

func (n *Node) becomeBackup() {
	ltsvlog.Logger.Info().String("msg", "Node.becomeBackup").Log()
	if err := n.engine.HAState(HABackup); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(fmt.Errorf("Failed to notify engine: %v", err)).Stack(""))
	}

	n.stopSenderChannel <- HABackup
	n.setState(HABackup)
}

func (n *Node) becomeShutdown() {
	ltsvlog.Logger.Info().String("msg", "Node.becomeShutdown").Log()
	if err := n.engine.HAState(HAShutdown); err != nil {
		ltsvlog.Logger.Err(ltsvlog.Err(fmt.Errorf("Failed to notify engine: %v", err)).Stack(""))
	}

	if n.state() == HAMaster {
		n.stopSenderChannel <- HAShutdown
		// Sleep for a moment so sendAdvertisements() has a chance to send the shutdown advertisment.
		time.Sleep(500 * time.Millisecond)
	}
	n.setState(HAShutdown)
}

func (n *Node) doMasterTasks() HAState {
	select {
	case advert := <-n.recvChannel:
		if advert.VersionType != vrrpVersionType {
			// Ignore
			return HAMaster
		}
		if advert.VRID != n.VRID {
			ltsvlog.Logger.Info().String("msg", "doMasterTasks: ignoring Advertisement").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
			return HAMaster
		}
		if advert.Priority == n.Priority {
			// TODO(angusc): RFC 5798 says we should compare IP addresses at this point.
			ltsvlog.Logger.Info().String("msg", "doMasterTasks: ignoring Advertisement with my priority").Uint8("peerPriority", advert.Priority).Log()
			return HAMaster
		}
		if advert.Priority > n.Priority {
			ltsvlog.Logger.Info().String("msg", "doMasterTasks: peer priority > my priority - becoming BACKUP").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
			n.lastMasterAdvertTime = time.Now()
			return HABackup
		}

	case <-n.shutdownChannel:
		return HAShutdown

	case err := <-n.errChannel:
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("doMasterTasks: %v", err)
		}))
		return HAError
	}
	// no change
	return HAMaster
}

func (n *Node) doBackupTasks() HAState {
	deadline := n.lastMasterAdvertTime.Add(n.masterDownInterval)
	remaining := deadline.Sub(time.Now())
	timeout := time.After(remaining)
	select {
	case advert := <-n.recvChannel:
		return n.backupHandleAdvertisement(advert)

	case <-n.shutdownChannel:
		return HAShutdown

	case err := <-n.errChannel:
		ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("doBackupTasks: %v", err)
		}))
		return HAError

	case <-timeout:
		ltsvlog.Logger.Info().String("msg", "doBackupTasks: timed out waiting for Advertisement").Stringer("remaing", remaining).Log()
		select {
		case advert := <-n.recvChannel:
			ltsvlog.Logger.Info().String("msg", "doBackupTasks: found Advertisement queued for processing")
			return n.backupHandleAdvertisement(advert)
		default:
			ltsvlog.Logger.Info().String("msg", "doBackupTasks: becoming MASTER")
			return HAMaster
		}
	}
}

func (n *Node) backupHandleAdvertisement(advert *advertisement) HAState {
	switch {
	case advert.VersionType != vrrpVersionType:
		// Ignore
		return HABackup

	case advert.VRID != n.VRID:
		ltsvlog.Logger.Info().String("msg", "backupHandleAdvertisement: ignoring Advertisement").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
		return HABackup

	case advert.Priority == 0:
		ltsvlog.Logger.Info().String("msg", "backupHandleAdvertisement: peer priority is 0 - becoming MASTER")
		return HAMaster

	case n.Preempt && advert.Priority < n.Priority:
		ltsvlog.Logger.Info().String("msg", "backupHandleAdvertisement: peer priority < my priority - becoming MASTER").Uint8("peerVRID", advert.VRID).Uint8("myVRID", n.VRID).Log()
		return HAMaster
	}

	// Per RFC 5798, set the masterDownInterval based on the advert interval received from the
	// current master.  AdvertInt is in centiseconds.
	n.resetMasterDownInterval(time.Millisecond * time.Duration(10*advert.AdvertInt))
	n.lastMasterAdvertTime = time.Now()
	return HABackup
}

func (n *Node) queueAdvertisement(advert *advertisement) {
	if queueLen := len(n.recvChannel); queueLen > 0 {
		ltsvlog.Logger.Info().String("msg", "queueAdvertisement: advertisements already queued").Int("queueLen", queueLen).Log()
	}
	select {
	case n.recvChannel <- advert:
	default:
		n.errChannel <- ltsvlog.Err(fmt.Errorf("queueAdvertisement: recvChannel is full")).Stack("")
	}
}

func (n *Node) sendAdvertisements() {
	ticker := time.NewTicker(n.MasterAdvertInterval)
	for {
		// TODO(angusc): figure out how to make the timing-related logic here, and thoughout, clockjump
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
			if newState == HAShutdown {
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

func (n *Node) receiveAdvertisements() {
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
			ltsvlog.Logger.Info().String("msg", "receiveAdvertisements: Received advertisements").Uint64("receveCount", receiveCount).Log()
			n.queueAdvertisement(advert)
		}
	}
}
