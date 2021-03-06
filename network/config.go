// Copyright (C) 2018 go-cloudcard authors
//
// This file is part of the go-cloudcard library.
//
// the go-cloudcard library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
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

package network

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/conf"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"fmt"
	"github.com/multiformats/go-multiaddr"
	"time"
)

// const
const (
	InitBucketCapacity         = 64
	InitRoutingTableMaxLatency = 10
	InitPrivateKeyPath         = "conf/network/key"
	InitMaxSyncNodes           = 64
	InitChainID                = 1
	InitMaxStreamNum           = 210
	InitReservedStreamNum      = 20
	MajorNetworkID             = 1
	RTNTNetworkID              = 2
	Thirty                     = 30 * time.Second
	ThreeMinutes               = 3 * 60 * time.Second
	Network                    = "network"
)

// Default Configuration in P2P network
var (
	DefaultListen = []string{"0.0.0.0:8888"}

	RouteTableSyncLoopInterval     = Thirty
	RouteTableSaveToDiskInterval   = ThreeMinutes
	RouteTableCacheFileName        = "routetable.cache"
	RouteTableInternalNodeFileName = "conf/internal.txt"

	MaxPeersCountForSyncResp = 32
)

type Config struct {
	NetworkID            uint32
	BucketSize           int
	Latency              time.Duration
	BootNodes            []multiaddr.Multiaddr
	PrivateKeyPath       string
	Listen               []string
	MaxSyncNodes         int
	ChainID              uint32
	RoutingTableDir      string
	StreamLimits         uint32
	ReservedStreamLimits uint32
}

type NetConfig struct {
	Seed                    []string `yaml:"seed"`
	Listen                  []string `yaml:"listen"`
	NetworkId               uint32   `yaml:"network_id"`
	PrivateKey              string   `yaml:"private_key"`
	StreamLimits            uint32   `yaml:"stream_limits"`
	ReservedStreamLimits    uint32   `yaml:"reserved_stream_limits"`
	RouteTableCacheFileName string   `yaml:"route_table_cache_filename"`
}

func GetNetConfig(conf *config.Config) *NetConfig {
	netcfg := new(NetConfig)
	conf.GetObject(Network, netcfg)
	return netcfg
}

func SetNetConfig(conf *config.Config, netCfg *NetConfig) {
	conf.Set(Network, netCfg)
}

// NewP2PConfig return new config object.
func NewP2PConfig(cfg *config.Config) *Config {
	netcfg := GetNetConfig(cfg)
	if netcfg == nil {
		panic("Failed to find network p2pConfig in p2pConfig file.")
	}
	chaincfg := conf.GetChainConfig(cfg)
	if chaincfg == nil {
		panic("Failed to find chain p2pConfig in p2pConfig file.")
	}
	p2pConfig := NewConfigFromDefaults()

	// listen.
	if len(netcfg.Listen) == 0 {
		panic("Missing network.listen p2pConfig.")
	}
	if err := verifyListenAddress(netcfg.Listen); err != nil {
		panic(fmt.Sprintf("Invalid network.listen p2pConfig: err is %s, p2pConfig value is %s.", err, netcfg.Listen))
	}
	p2pConfig.Listen = netcfg.Listen

	// private key path.
	if checkPathConfig(netcfg.PrivateKey) == false {
		panic(fmt.Sprintf("The network private key path %s is not exist.", netcfg.PrivateKey))
	}
	p2pConfig.PrivateKeyPath = netcfg.PrivateKey

	// Chain ID.
	p2pConfig.ChainID = chaincfg.ChainId

	// routing table dir.
	if checkPathConfig(chaincfg.Datadir) == false {
		panic(fmt.Sprintf("The chain data directory %s is not exist.", chaincfg.Datadir))
	}
	p2pConfig.RoutingTableDir = chaincfg.Datadir

	// seed server address.
	seeds := netcfg.Seed
	// set networkId
	if netcfg.NetworkId > 0 {
		p2pConfig.NetworkID = netcfg.NetworkId
	}
	// fixed seed nodes
	defaultSeeds := []string{
		"/ip4/47.94.36.171/tcp/8880/ipfs/12D3KooWB78qtKkxWcqpLsX1cQ7sgD23gnauzupkrrNcMACyjegf",
		"/ip4/8.208.15.78/tcp/8880/ipfs/12D3KooWT1cmbPRW6qq9W3BE9R3aoYt5wzWJwNUuRqr9cB8XrR7C",
	}

	p2pConfig.BootNodes = make([]multiaddr.Multiaddr, 0)

	// write fixed seed nodes
	for _, seed := range defaultSeeds {
		addr, err := multiaddr.NewMultiaddr(seed)
		if err != nil {
			panic(fmt.Sprintf("Invalid seed address p2pConfig: err is %s, p2pConfig value is %s.", err, seed))
		}
		p2pConfig.BootNodes = append(p2pConfig.BootNodes, addr)
	}

	if len(seeds) > 0 {
		// p2pConfig.BootNodes = make([]multiaddr.Multiaddr, len(seeds))
		for _, v := range seeds {
			addr, err := multiaddr.NewMultiaddr(v)
			if err != nil {
				panic(fmt.Sprintf("Invalid seed address p2pConfig: err is %s, p2pConfig value is %s.", err, v))
			}
			p2pConfig.BootNodes = append(p2pConfig.BootNodes, addr)
		}
	}
	// max stream limits
	if netcfg.StreamLimits > 0 {
		p2pConfig.StreamLimits = netcfg.StreamLimits
	}

	if netcfg.ReservedStreamLimits > 0 {
		p2pConfig.ReservedStreamLimits = netcfg.ReservedStreamLimits
	}

	return p2pConfig
}

// NewConfigFromDefaults return new config from defaults.
func NewConfigFromDefaults() *Config {
	return &Config{
		MajorNetworkID,
		InitBucketCapacity,
		InitRoutingTableMaxLatency,
		[]multiaddr.Multiaddr{},
		InitPrivateKeyPath,
		DefaultListen,
		InitMaxSyncNodes,
		InitChainID,
		"",
		InitMaxStreamNum,
		InitReservedStreamNum,
	}
}
