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
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"time"
)

// ConsensusEngine
type Consensus interface {
	Setup(cloudcard cloudcard) error
	Start()
	Stop()
	EnableMining()
	DisableMining()
	IsEnable() bool
	TermId() uint64
	SetTermId(in uint64)
	ResumeMining()
	SuspendMining()
	IsSuspend() bool
	VerifyBlock(*Block) error
	HandleFork() error
	UpdateFixedBlock()
	Coinbase() *Address
	Paxos() Paxos
	IsValidStandbyNode(string) bool
}

// Synchronize interface of sync service
type Synchronize interface {
	Start()
	Stop()
	StartActiveSync() bool
	StopActiveSync()
	WaitingForFinish()
	IsActiveSyncing() bool
}

type AccountManager interface {
	NewAccount(passphrase []byte) (*Address, string, error)
	UpdateAccount(address *Address, oldPassphrase, newPassphrase []byte) error
	GetAllAddress() []*Address
	AddressIsValid(address string) (*Address, error)
	UnLock(address *Address, passphrase []byte, duration time.Duration) error
	Lock(address *Address) error
	ImportAccount(priKey, passphrase []byte) (*Address, error)
	Sign(address *Address, hash []byte) ([]byte, error)
	SignBlock(address *Address, block *Block) error
	SignTx(addr *Address, tx *Transaction) error
	Verify(addr *Address, message, sig []byte) (bool, error)
}

type cloudcard interface {
	BlockChain() *BlockChain
	NetService() network.Service
	AccountManager() AccountManager
	Consensus() Consensus
	Config() *config.Config
	Storage() cdb.Storage
	Stop()
}

// WorldState needed by core
type WorldState interface {
	GetOrCreateAccount(addr byteutils.Hash) (state.Account, error)
	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	Reset(addr byteutils.Hash, isResetChangeLog bool) error

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)

	Witnesses() ([]byteutils.Hash, error)
	WitnessRoot() byteutils.Hash
}

type Paxos interface {
	Propose(proposalId uint64) (*corepb.Propose, error)
	NotifyNoBlockArrive()
	NotifyNotEnoughWitness()
	NotifyRecvConsensusBlock()
}
