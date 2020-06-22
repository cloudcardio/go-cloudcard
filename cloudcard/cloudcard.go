// Copyright (C) 2018 go-cloudcard authors
//
// This file is part of the go-cloudcard library.
//
// the go-cloudcard library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of t1he License, or
// (at your option) any later version.
//
// the go-cloudcard library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-cloudcard library.  If not, see <http://www.gnu.org/licenses/>.
//
package cloudcard

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/account"
	"cloudcard.pro/cloudcardio/go-cloudcard/consensus/psec"
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	"cloudcard.pro/cloudcardio/go-cloudcard/metrics"
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/rpc"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	csync "cloudcard.pro/cloudcardio/go-cloudcard/sync"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/pprof"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"sync"
	"time"
)

// cloudcard
type cloudcard struct {
	networkId uint64

	config         *config.Config
	chain          *core.BlockChain
	engine         core.Consensus
	accountManager core.AccountManager
	chainDb        cdb.Storage
	netService     network.Service
	rpcServer      rpc.GRPCServer
	syncService    core.Synchronize
	pprof          *pprof.Pprof

	mu sync.RWMutex

	quitChan chan bool
	running  bool
}

// Newcloudcard
func Newcloudcard(cloudcardConf *config.Config) (*cloudcard, error) {
	if cloudcardConf == nil {
		logging.CLog().Error("Failed to load config file")
		return nil, nil
	}

	// cloudcard
	app := &cloudcard{
		config:   cloudcardConf,
		quitChan: make(chan bool),
	}

	//pprof
	pprofConf := pprof.GetPprofConfig(cloudcardConf)
	pprof := &pprof.Pprof{
		Config: pprofConf,
	}
	// try enable profile.
	pprof.StartProfiling()
	app.pprof = pprof

	return app, nil
}

// Setup
func (c *cloudcard) Setup() {
	var err error
	logging.CLog().Info("Setuping cloudcard...")

	//db
	c.chainDb, err = cdb.NewDB(c.config)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to open disk storage.")
	}

	if c.accountManager, err = account.NewAccountManager(c.config, c.chainDb); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to new account manager.")
	}

	// net
	c.netService, err = network.NewcloudcardService(c.config)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup net service.")
	}

	c.chain, err = core.NewBlockChain(c.config, c.netService, c.chainDb)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup blockchain.")
	}

	// consensus
	c.engine = psec.NewPsec(c.chainDb)
	if c.engine == nil {
		logging.CLog().Fatal("Failed to new psec.")
	}

	if err := c.chain.Setup(c); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup blockchain.")
	}

	if err := c.engine.Setup(c); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to setup consensus.")
	}

	// sync
	c.syncService = csync.NewService(c.chain, c.netService)
	c.chain.SetSyncEngine(c.syncService)

	// rpc
	c.rpcServer = rpc.NewServer(c)

	logging.CLog().Info("Setuped cloudcard.")
}

// StartPprof start pprof http listen
func (c *cloudcard) StartPprof(listen string) error {
	if len(listen) > 0 {
		conn, err := net.DialTimeout("tcp", listen, time.Second*1)
		if err == nil {
			logging.CLog().WithFields(logrus.Fields{
				"listen": listen,
				"err":    err,
			}).Error("Failed to start pprof")
			_ = conn.Close()
			return err
		}

		go func() {
			logging.CLog().WithFields(logrus.Fields{
				"listen": listen,
			}).Info("Starting pprof...")
			_ = http.ListenAndServe(listen, nil)
		}()
	}
	return nil
}

// Run
func (c *cloudcard) Run() {
	c.mu.Lock()
	defer c.mu.Unlock()

	logging.CLog().Info("Starting cloudcard...")

	if c.running {
		logging.CLog().WithFields(logrus.Fields{
			"err": "cloudcard is already running",
		}).Fatal("Failed to start cloudcard.")
	}
	c.running = true

	//metrics
	statscfg := metrics.GetStatsConfig(c.config)
	if statscfg.EnableMetrics {
		metrics.Start(c.config)
	}
	// net
	if err := c.netService.Start(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to start net service.")
	}
	//rpc
	if err := c.rpcServer.Start(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to start api server.")
	}
	//gateway
	if err := c.rpcServer.RunGateway(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to start api gateway.")
	}

	c.chain.Start()
	c.engine.Start()
	c.chain.BlockPool().Start()
	c.chain.TxPool().Start()
	c.syncService.Start()
	c.engine.Start()

	//netcfg := network.GetNetConfig(c.config)
	//if len(netcfg.Seed) > 0 {
	//	c.BlockChain().StartActiveSync()
	//}

	select {
	case <-c.quitChan:
		logging.CLog().Info("Stopped cloudcard...")
	}
}

// Stop stops the services of the cloudcard.
func (c *cloudcard) Stop() {

	logging.CLog().Info("Stopping cloudcard...")

	// try Stop Profiling.
	if c.pprof != nil {
		c.pprof.StopProfiling()
		c.pprof = nil
	}

	//sync
	if c.syncService != nil {
		c.syncService.Stop()
		c.syncService = nil
	}

	if c.chain != nil {

		c.chain.BlockPool().Stop()
		c.chain.Stop()
		c.chain = nil
	}

	//rpc
	if c.rpcServer != nil {
		c.rpcServer.Stop()
		c.rpcServer = nil
	}
	//net
	if c.netService != nil {
		c.netService.Stop()
		c.netService = nil
	}
	//metrics
	statscfg := metrics.GetStatsConfig(c.config)
	if statscfg.EnableMetrics {
		metrics.Stop()
	}

	c.accountManager = nil

	c.running = false

	logging.CLog().Info("Stopped cloudcard.")
	c.quitChan <- true
}

func (c *cloudcard) BlockChain() *core.BlockChain        { return c.chain }
func (c *cloudcard) AccountManager() core.AccountManager { return c.accountManager }
func (c *cloudcard) Consensus() core.Consensus           { return c.engine }
func (c *cloudcard) Config() *config.Config              { return c.config }
func (c *cloudcard) Storage() cdb.Storage                { return c.chainDb }
func (c *cloudcard) NetService() network.Service         { return c.netService }
