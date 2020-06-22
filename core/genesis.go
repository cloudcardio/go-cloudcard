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

package core

import (
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/core/state"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"math/big"
)

const (
	DefaultGenesisPath = "conf/genesis.yaml"
)

// Genesis Block Hash
var (
	GenesisHash        = []byte("990c9490a8fe664c1da047c9447da525c37b345bc5058b5d08d939b54a799882")
	GenesisTimestamp   = int64(1561615240)
	GenesisCoinbase, _ = NewAddressFromPublicKey(make([]byte, PublicKeyDataLength))
)

//
type Genesis struct {
	ChainId                uint32                      `yaml:"chain_id"`
	SuperNodes             []*corepb.TokenDistribution `yaml:"super_nodes"`
	StandbyNodes           []*corepb.TokenDistribution `yaml:"standby_nodes"`
	Foundation             *corepb.TokenDistribution   `yaml:"foundation"`
	FoundingTeam           *corepb.TokenDistribution   `yaml:"founding_team"`
	NodeDeployment         *corepb.TokenDistribution   `yaml:"node_deployment"`
	EcologicalConstruction *corepb.TokenDistribution   `yaml:"ecological_construction"`
	FoundingCommunity      *corepb.TokenDistribution   `yaml:"founding_community"`
}

//
func LoadGenesisConf(filePath string) (*corepb.Genesis, error) {
	in, err := ioutil.ReadFile(filePath)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to read the genesis config file.")
		return nil, err
	}
	genesis := new(Genesis)
	err = yaml.Unmarshal(in, genesis)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to parse genesis file.")
		return nil, err
	}

	return &corepb.Genesis{
		ChainId:                genesis.ChainId,
		SuperNodes:             genesis.SuperNodes,
		StandbyNodes:           genesis.StandbyNodes,
		Foundation:             genesis.Foundation,
		FoundingTeam:           genesis.FoundingTeam,
		NodeDeployment:         genesis.NodeDeployment,
		FoundingCommunity:      genesis.FoundingCommunity,
		EcologicalConstruction: genesis.EcologicalConstruction,
	}, nil
}

// NewGenesis
func NewGenesis(cfg *corepb.Genesis, chain *BlockChain) (*Block, error) {
	if cfg == nil || chain == nil {
		return nil, ErrNilArgument
	}

	worldState, err := state.NewWorldState(chain.db)
	if err != nil {
		return nil, err
	}

	genesisBlock := &Block{
		header: &BlockHeader{
			chainId:       cfg.ChainId,
			hash:          GenesisHash,
			parentHash:    nil,
			timestamp:     GenesisTimestamp,
			coinbase:      GenesisCoinbase,
			height:        1,
			sign:          &corepb.Signature{},
			extra:         []byte("create genesis block"),
		},
		transactions: make([]*Transaction, 0),
		txPool:       chain.txPool,
		blkPool:      chain.bkPool,
		db:           chain.db,
		worldState:   worldState,
		sealed:       false,
	}

	if err := genesisBlock.Begin(); err != nil {
		return nil, err
	}

	for _, superNode := range cfg.SuperNodes {
		if err := processingDistributionFund(superNode, genesisBlock); err != nil {
			genesisBlock.RollBack()
			return nil, err
		}
	}

	standbyNodes := make([]string, 0, len(cfg.StandbyNodes))

	for _, standbyNode := range cfg.StandbyNodes {
		err := processingDistributionFund(standbyNode, genesisBlock)
		if err != nil {
			genesisBlock.RollBack()
			return nil, err
		}
		standbyNodes = append(standbyNodes, standbyNode.Address)
	}

	pbStandby := &corepb.StandByNodes{
		StandbyNodes: standbyNodes,
	}
	data, err := proto.Marshal(pbStandby)
	if err != nil {
		return nil, err
	}
	if err = chain.db.Put([]byte(StandbyNodes), data); err != nil { // store standby nodes to db
		return nil, err
	}

	if err := processingDistributionFund(cfg.Foundation, genesisBlock); err != nil {
		genesisBlock.RollBack()
		return nil, err
	}
	if err := processingDistributionFund(cfg.FoundingTeam, genesisBlock); err != nil {
		genesisBlock.RollBack()
		return nil, err
	}
	if err := processingDistributionFund(cfg.NodeDeployment, genesisBlock); err != nil {
		genesisBlock.RollBack()
		return nil, err
	}
	if err := processingDistributionFund(cfg.EcologicalConstruction, genesisBlock); err != nil {
		genesisBlock.RollBack()
		return nil, err
	}
	if err := processingDistributionFund(cfg.FoundingCommunity, genesisBlock); err != nil {
		genesisBlock.RollBack()
		return nil, err
	}

	declaration := fmt.Sprintf("%s\n%s\n", "www.cloudcard.pro", "This is the genesis of cloudcard.")
	genesisTx, err := NewTransaction(GenesisCoinbase, GenesisCoinbase, big.NewInt(1), 1, chain.ChainId(), PriorityNormal, TransferTx, []byte(declaration))
	if err != nil {
		return nil, err
	}

	genesisTx.timestamp = GenesisTimestamp

	hash, err := genesisTx.CalcHash()
	if err != nil {
		return nil, err
	}
	genesisTx.hash = hash

	pbTx, err := genesisTx.ToProto()
	if err != nil {
		return nil, err
	}

	txBytes, err := proto.Marshal(pbTx)
	if err != nil {
		return nil, err
	}

	genesisBlock.transactions = append(genesisBlock.transactions, genesisTx)
	if err := genesisBlock.worldState.PutTx(genesisTx.hash, txBytes); err != nil {
		return nil, err
	}

	genesisBlock.Commit()

	genesisBlock.header.stateRoot = genesisBlock.WorldState().AccountsRoot()
	genesisBlock.header.txsRoot = genesisBlock.WorldState().TxsRoot()
	genesisBlock.header.consensusRoot = genesisBlock.WorldState().WitnessRoot()

	return genesisBlock, nil
}

//
func processingDistributionFund(token *corepb.TokenDistribution, gBlock *Block) error {
	addr, err := AddressParse(token.Address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"address": token.Address,
			"err":     err,
		}).Error("Found invalid address in genesis .")
		return err
	}
	acc, err := gBlock.worldState.GetOrCreateAccount(addr.address)
	if err != nil {
		return err
	}
	txsBalance, status := new(big.Int).SetString(token.Value, 10)
	if !status {
		return ErrInvalidAmount
	}
	err = acc.AddBalance(txsBalance)
	if err != nil {
		return err
	}

	return nil
}

//
func CheckGenesisBlock(block *Block) bool {
	if block == nil {
		return false
	}

	if block.Hash().Equals(GenesisHash) {
		return true
	}
	return false
}

//
func CheckGenesisTx(coinbase *Address, tx *Transaction) bool {
	if tx == nil {
		return false
	}

	if tx.from.Equals(coinbase) {
		return true
	}
	return false
}
