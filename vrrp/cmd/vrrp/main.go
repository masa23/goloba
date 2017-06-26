// Copyright 2012 Google Inc.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: angusc@google.com (Angus Cameron)

// The seesaw_ha binary implements HA peering between Seesaw nodes.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/hnakamur/ltsvlog"
	"github.com/masa23/keepalivego/vrrp"
)

var (
	configCheckInterval = flag.Duration("config_check_interval", 15*time.Second,
		"How frequently to poll the engine for HAConfig changes")

	configCheckMaxFailures = flag.Int("config_check_max_failures", 3,
		"The maximum allowable number of consecutive config check failures")

	configCheckRetryDelay = flag.Duration("config_check_retry_delay", 2*time.Second,
		"Time between config check retries")

	initConfigRetryDelay = flag.Duration("init_config_retry_delay", 5*time.Second,
		"Time between retries when retrieving the initial HAConfig from the engine")

	masterAdvertInterval = flag.Duration("master_advert_interval", 500*time.Millisecond,
		"How frequently to send advertisements when this node is master")

	preempt = flag.Bool("preempt", false,
		"If true, a higher priority node will preempt the mastership of a lower priority node")

	statusReportInterval = flag.Duration("status_report_interval", 3*time.Second,
		"How frequently to report the current HAStatus to the engine")

	statusReportMaxFailures = flag.Int("status_report_max_failures", 3,
		"The maximum allowable number of consecutive status report failures")

	statusReportRetryDelay = flag.Duration("status_report_retry_delay", 2*time.Second,
		"Time between status report retries")

	testLocalAddr = flag.String("local_addr", "",
		"Local IP Address")

	testVIP = flag.String("vip", "",
		"Virtual IP Address")

	testVIPDev = flag.String("vip_dev", "",
		"Virtual IP network interface")

	testPriority = flag.Int("priority", 100,
		"Priority")

	testRemoteAddr = flag.String("remote_addr", "224.0.0.18",
		"Remote IP Address")

	testVRID = flag.Int("vrid", 100,
		"VRID")
)

// config reads the HAConfig from the engine. It does not return until it
// successfully retrieves an HAConfig that has HA peering enabled.
func config(e vrrp.Engine) *vrrp.HAConfig {
	for {
		c, err := e.HAConfig()
		switch {
		case err != nil:
			ltsvlog.Logger.Err(ltsvlog.WrapErr(err, func(err error) error {
				return fmt.Errorf("config: Failed to retrieve HAConfig: %v", err)
			}).Stack(""))

		case !c.Enabled:
			ltsvlog.Logger.Info().String("msg", "config: HA peering is currently disabled for this node").Log()

		default:
			return c
		}
		time.Sleep(*initConfigRetryDelay)
	}
}

func engine() vrrp.Engine {
	ltsvlog.Logger.Info().String("msg", "Using command-line flags for config").Log()
	vip, vipNet, err := net.ParseCIDR(*testVIP)
	if err != nil {
		log.Fatal(err)
	}
	vipDev, err := net.InterfaceByName(*testVIPDev)
	if err != nil {
		log.Fatal(err)
	}
	config := vrrp.VIPHAConfig{
		HAConfig: vrrp.HAConfig{
			Enabled:    true,
			LocalAddr:  net.ParseIP(*testLocalAddr),
			RemoteAddr: net.ParseIP(*testRemoteAddr),
			Priority:   uint8(*testPriority),
			VRID:       uint8(*testVRID),
		},
		VIP:          vip,
		VIPNet:       vipNet,
		VIPInterface: vipDev,
	}
	return &vrrp.VIPUpdateEngine{Config: &config}
}

func main() {
	flag.Parse()

	ltsvlog.Logger.Info().String("msg", "Starting up")
	engine := engine()
	config := config(engine)
	ltsvlog.Logger.Info().String("msg", "Received HAConfig").Sprintf("haConfig", "%v", config).Log()
	conn, err := vrrp.NewIPHAConn(config.LocalAddr, config.RemoteAddr)
	if err != nil {
		ltsvlog.Logger.Err(err)
		os.Exit(1)
	}
	nc := vrrp.NodeConfig{
		HAConfig:                *config,
		ConfigCheckInterval:     *configCheckInterval,
		ConfigCheckMaxFailures:  *configCheckMaxFailures,
		ConfigCheckRetryDelay:   *configCheckRetryDelay,
		MasterAdvertInterval:    *masterAdvertInterval,
		Preempt:                 *preempt,
		StatusReportInterval:    *statusReportInterval,
		StatusReportMaxFailures: *statusReportMaxFailures,
		StatusReportRetryDelay:  *statusReportRetryDelay,
	}
	n := vrrp.NewNode(nc, conn, engine)
	vrrp.ShutdownHandler(n)

	if err = n.Run(); err != nil {
		ltsvlog.Logger.Err(err)
		os.Exit(1)
	}
}
