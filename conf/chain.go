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

package conf

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
)

const (
	DefaultChainID = 1
	DefaultDataDIR = "data"
	DefaultKeyDir  = "keydir"

	Chain = "chain"
)

type ChainConfig struct {
	ChainId  uint32 `yaml:"chain_id"`
	Datadir  string `yaml:"datadir"`
	Keydir   string `yaml:"keydir"`
	Coinbase string `yaml:"coinbase"`
	Genesis  string `yaml:"genesis"`
}

func GetChainConfig(conf *config.Config) *ChainConfig {
	chaincfg := new(ChainConfig)
	conf.GetObject(Chain, chaincfg)
	if chaincfg.ChainId <= 0 {
		chaincfg.ChainId = DefaultChainID
	}
	if chaincfg.Datadir == "" {
		chaincfg.Datadir = DefaultDataDIR
	}
	if chaincfg.Keydir == "" {
		chaincfg.Keydir = chaincfg.Datadir + "/" + DefaultKeyDir
	}
	return chaincfg
}

func SetChainConfig(conf *config.Config, chainCfg *ChainConfig) {
	conf.Set(Chain, chainCfg)
}
