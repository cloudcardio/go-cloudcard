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
package state

import (
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"errors"
	"math/big"
)

// Errors
var (
	ErrBalanceInsufficient    = errors.New("cannot subtract a value which is bigger than current balance")
	ErrFrozenFundInsufficient = errors.New("cannot subtract a value which is bigger than frozen fund")
	ErrPledgeFundInsufficient = errors.New("cannot subtract a value which is bigger than pledge fund")
	ErrAccountNotFound        = errors.New("cannot found account in storage")
)

// Iterator Variables in Account Storage
type Iterator interface {
	Next() (bool, error)
	Value() []byte
}

// Account Interface
type Account interface {
	Address() byteutils.Hash

	Balance() *big.Int
	FrozenFund() *big.Int
	PledgeFund() *big.Int
	Nonce() uint64
	CreditIndex() *big.Int
	VarsHash() byteutils.Hash
	Permissions() []*corepb.Permission
	DoEvils() uint32
	GetProduction() uint32
	ClearProduction()

	Copy() (Account, error)

	ToBytes() ([]byte, error)
	FromBytes(bytes []byte, storage cdb.Storage) error

	IncreaseNonce()
	AddBalance(value *big.Int) error
	SubBalance(value *big.Int) error
	AddFrozenFund(value *big.Int) error
	SubFrozenFund(value *big.Int) error
	AddPledgeFund(value *big.Int) error
	SubPledgeFund(value *big.Int) error
	SetCreditIndex(value *big.Int) error
	AddCreditIndex(value *big.Int) error
	SubCreditIndex(value *big.Int) error

	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	Iterator(prefix []byte) (Iterator, error)
}

// AccountState Interface
type AccountState interface {
	RootHash() byteutils.Hash
	Flush() error
	Abort() error
	DirtyAccounts() ([]Account, error)
	Accounts() ([]Account, error)
	Copy() (AccountState, error)
	Replay(AccountState) error
	GetOrCreateAccount(byteutils.Hash) (Account, error)
}

// ConsensusState interface of consensus state
type ConsensusState interface {
	RootHash() byteutils.Hash
	String() string
	Copy() (ConsensusState, error)
	Replay(ConsensusState) error

	Proposer() byteutils.Hash

	TermId() uint64
	CurrentWitnesses(uint64) ([]*corepb.Group, error)

	Witnesses() ([]byteutils.Hash, error)
	WitnessRoot() byteutils.Hash
	PutWitnesses(wts *corepb.WitnessState) error
}

// WorldState interface of world state
type WorldState interface {
	Begin() error
	Commit() error
	RollBack() error

	Prepare(interface{}) (TxWorldState, error)
	Reset(addr byteutils.Hash, isResetChangeLog bool) error
	Flush() error
	Abort() error

	LoadAccountsRoot(byteutils.Hash) error
	LoadTxsRoot(byteutils.Hash) error
	LoadWitnessRoot(root byteutils.Hash) error

	Copy() (WorldState, error)

	AccountsRoot() byteutils.Hash
	TxsRoot() byteutils.Hash
	//ConsensusRoot() byteutils.Hash

	Accounts() ([]Account, error)
	GetOrCreateAccount(addr byteutils.Hash) (Account, error)

	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	Witnesses() ([]byteutils.Hash, error)
	WitnessRoot() byteutils.Hash
	CurrentWitnesses(uint64) ([]*corepb.Group, error)
	PutWitnesses(*corepb.WitnessState) error

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)
}

// TxWorldState is the world state of a single transaction
type TxWorldState interface {
	AccountsRoot() byteutils.Hash
	TxsRoot() byteutils.Hash

	CheckAndUpdate() ([]interface{}, error)
	Reset(addr byteutils.Hash, isResetChangeLog bool) error
	Close() error

	Accounts() ([]Account, error)
	GetOrCreateAccount(addr byteutils.Hash) (Account, error)

	GetTx(txHash byteutils.Hash) ([]byte, error)
	PutTx(txHash byteutils.Hash, txBytes []byte) error

	Witnesses() ([]byteutils.Hash, error)
	WitnessRoot() byteutils.Hash

	GetBlockHashByHeight(height uint64) ([]byte, error)
	GetBlock(txHash byteutils.Hash) ([]byte, error)
}
