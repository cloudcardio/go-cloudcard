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
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/trie"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"fmt"
	"math/big"
)

// accountState manages accounts state in Block.
type accountState struct {
	stateTrie    *trie.Trie
	dirtyAccount map[byteutils.HexHash]Account
	storage      cdb.Storage
}

// NewAccountState create a new account state
func NewAccountState(root byteutils.Hash, storage cdb.Storage) (AccountState, error) {
	stateTrie, err := trie.NewTrie(root, storage, false)
	if err != nil {
		return nil, err
	}

	return &accountState{
		stateTrie:    stateTrie,
		dirtyAccount: make(map[byteutils.HexHash]Account),
		storage:      storage,
	}, nil
}

func (accState *accountState) Flush() error {
	for addr, acc := range accState.dirtyAccount {
		bytes, err := acc.ToBytes()
		if err != nil {
			return err
		}
		key, err := addr.Hash()
		if err != nil {
			return err
		}
		_, _ = accState.stateTrie.Put(key, bytes)
	}
	accState.dirtyAccount = make(map[byteutils.HexHash]Account)
	return nil
}

func (accState *accountState) Abort() error {
	accState.dirtyAccount = make(map[byteutils.HexHash]Account)
	return nil
}

// RootHash return root hash of account state
func (accState *accountState) RootHash() byteutils.Hash {
	return accState.stateTrie.RootHash()
}

func (accState *accountState) Accounts() ([]Account, error) {
	var accounts []Account
	iter, err := accState.stateTrie.Iterator(nil)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err != nil {
		return accounts, nil
	}
	exist, err := iter.Next()
	if err != nil {
		return nil, err
	}
	for exist {
		acc := new(account)
		err = acc.FromBytes(iter.Value(), accState.storage)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
		exist, err = iter.Next()
		if err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

// DirtyAccounts return all changed accounts
func (accState *accountState) DirtyAccounts() ([]Account, error) {
	var accounts []Account
	for _, account := range accState.dirtyAccount {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// Relay merge the done account state
func (accState *accountState) Replay(done AccountState) error {
	state := done.(*accountState)
	for addr, acc := range state.dirtyAccount {
		accState.dirtyAccount[addr] = acc
	}
	return nil
}

// Clone an accountState
func (accState *accountState) Copy() (AccountState, error) {
	stateTrie, err := accState.stateTrie.Clone()
	if err != nil {
		return nil, err
	}

	dirtyAccount := make(map[byteutils.HexHash]Account)
	for addr, acc := range accState.dirtyAccount {
		dirtyAccount[addr], err = acc.Copy()
		if err != nil {
			return nil, err
		}
	}

	return &accountState{
		stateTrie:    stateTrie,
		dirtyAccount: dirtyAccount,
		storage:      accState.storage,
	}, nil
}

// GetOrCreateAccount according to the addr
func (accState *accountState) GetOrCreateAccount(addr byteutils.Hash) (Account, error) {
	acc, err := accState.getAccount(addr)
	if err != nil && err != ErrAccountNotFound {
		return nil, err
	}
	if err == ErrAccountNotFound {
		acc, err = accState.newAccount(addr)
		if err != nil {
			return nil, err
		}
		return acc, nil
	}
	return acc, nil
}

func (accState *accountState) String() string {
	return fmt.Sprintf("AccountState %p {RootHash:%s; dirtyAccount:%v; Storage:%p}",
		accState,
		byteutils.Hex(accState.stateTrie.RootHash()),
		accState.dirtyAccount,
		accState.storage,
	)
}

func (accState *accountState) newAccount(addr byteutils.Hash) (Account, error) {
	newTrie, err := trie.NewTrie(nil, accState.storage, false)
	if err != nil {
		return nil, err
	}

	acc := &account{
		address:     addr,
		balance:     big.NewInt(0),
		frozenFund:  big.NewInt(0),
		pledgeFund:  big.NewInt(0),
		nonce:       0,
		variables:   newTrie,
		products:    0,
		doEvils:     0,
		creditIndex: big.NewInt(0),
	}
	accState.recordToDirty(addr, acc)
	return acc, nil
}

func (accState *accountState) recordToDirty(addr byteutils.Hash, acc Account) {
	accState.dirtyAccount[addr.Hex()] = acc
}

func (accState *accountState) getAccount(addr byteutils.Hash) (Account, error) {
	// search in dirty account
	if acc, ok := accState.dirtyAccount[addr.Hex()]; ok {
		return acc, nil
	}
	// search in storage
	bytes, err := accState.stateTrie.Get(addr)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err == nil {
		acc := new(account)
		err = acc.FromBytes(bytes, accState.storage)
		if err != nil {
			return nil, err
		}
		accState.recordToDirty(addr, acc)
		return acc, nil
	}
	return nil, ErrAccountNotFound
}
