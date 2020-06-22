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
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/mvccdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/trie"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
)

type states struct {
	accState     AccountState
	txsState     *trie.Trie
	witnessState *trie.Trie
	superNodes   *trie.Trie
	standByNodes *trie.Trie
	changelog *mvccdb.MVCCDB
	stateDB   *mvccdb.MVCCDB
	innerDB   cdb.Storage
	txid      interface{}
}

func (s *states) GetOrCreateAccount(addr byteutils.Hash) (Account, error) {
	acc, err := s.accState.GetOrCreateAccount(addr)
	if err != nil {
		return nil, err
	}
	return s.recordAccount(acc)
}

func (s *states) GetTx(txHash byteutils.Hash) ([]byte, error) {
	bytes, err := s.txsState.Get(txHash)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (s *states) PutTx(txHash byteutils.Hash, txBytes []byte) error {
	_, err := s.txsState.Put(txHash, txBytes)
	if err != nil {
		return err
	}
	return nil
}

func (s *states) Witnesses() ([]byteutils.Hash, error) {
	return nil, nil
}

func (s *states) WitnessRoot() byteutils.Hash {
	return s.witnessState.RootHash()
}

func (s *states) Reset(addr byteutils.Hash, isResetChangeLog bool) error {
	if err := s.stateDB.Reset(); err != nil {
		return err
	}
	if err := s.Abort(); err != nil {
		return err
	}
	if isResetChangeLog {
		if err := s.changelog.Reset(); err != nil {
			return err
		}
		if addr != nil {
			// record dependency
			if err := s.changelog.Put(addr, addr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *states) GetBlockHashByHeight(height uint64) ([]byte, error) {
	bytes, err := s.innerDB.Get(byteutils.FromUint64(height))
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (s *states) GetBlock(hash byteutils.Hash) ([]byte, error) {
	bytes, err := s.innerDB.Get(hash)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (s *states) Close() error {
	if err := s.changelog.Close(); err != nil {
		return err
	}
	if err := s.stateDB.Close(); err != nil {
		return err
	}
	if err := s.Abort(); err != nil {
		return err
	}

	return nil
}

func (s *states) Flush() error {
	return s.accState.Flush()
}

func (s *states) Replay(done *states) error {
	err := s.accState.Replay(done.accState)
	if err != nil {
		return err
	}
	_, err = s.txsState.Replay(done.txsState)
	if err != nil {
		return err
	}
	return nil
}

func (s *states) Copy() (*states, error) {
	changelog, err := newChangeLog()
	if err != nil {
		return nil, err
	}
	stateDB, err := newStateDB(s.innerDB)
	if err != nil {
		return nil, err
	}

	accState, err := NewAccountState(s.accState.RootHash(), stateDB)
	if err != nil {
		return nil, err
	}

	txsState, err := trie.NewTrie(s.txsState.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	witnessState, err := trie.NewTrie(s.witnessState.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	superNodes, err := trie.NewTrie(s.superNodes.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	standByNodes, err := trie.NewTrie(s.standByNodes.RootHash(), stateDB, false)
	if err != nil {
		return nil, err
	}

	return &states{
		accState:     accState,
		txsState:     txsState,
		witnessState: witnessState,
		superNodes:   superNodes,
		standByNodes: standByNodes,
		changelog:    changelog,
		stateDB:      stateDB,
		innerDB:      s.innerDB,
		txid:         s.txid,
	}, nil
}

func (s *states) Begin() error {
	if err := s.changelog.Begin(); err != nil {
		return err
	}
	if err := s.stateDB.Begin(); err != nil {
		return err
	}
	return nil
}

func (s *states) Commit() error {
	if err := s.Flush(); err != nil {
		return err
	}
	// changelog is used to check conflict temporarily
	// we should rollback it when the transaction is over
	if err := s.changelog.RollBack(); err != nil {
		return err
	}
	if err := s.stateDB.Commit(); err != nil {
		return err
	}

	return nil
}

func (s *states) RollBack() error {
	if err := s.Abort(); err != nil {
		return err
	}
	if err := s.changelog.RollBack(); err != nil {
		return err
	}
	if err := s.stateDB.RollBack(); err != nil {
		return err
	}

	return nil
}

func (s *states) Prepare(txid interface{}) (*states, error) {
	changelog, err := s.changelog.Prepare(txid)
	if err != nil {
		return nil, err
	}
	stateDB, err := s.stateDB.Prepare(txid)
	if err != nil {
		return nil, err
	}

	// Flush all changes in world state into merkle trie make a snapshot of world state
	if err := s.Flush(); err != nil {
		return nil, err
	}

	accState, err := NewAccountState(s.AccountsRoot(), stateDB)
	if err != nil {
		return nil, err
	}

	txsState, err := trie.NewTrie(s.TxsRoot(), stateDB, true)
	if err != nil {
		return nil, err
	}

	witnessState, err := trie.NewTrie(s.WitnessRoot(), stateDB, false)
	if err != nil {
		return nil, err
	}

	return &states{
		accState:     accState,
		txsState:     txsState,
		witnessState: witnessState,
		changelog:    changelog,
		stateDB:      stateDB,
		innerDB:      s.innerDB,
		txid:         txid,
	}, nil
}

func (s *states) CheckAndUpdateTo(parent *states) ([]interface{}, error) {
	dependency, err := s.changelog.CheckAndUpdate()
	if err != nil {
		return nil, err
	}
	_, err = s.stateDB.CheckAndUpdate()
	if err != nil {
		return nil, err
	}
	if err := parent.Replay(s); err != nil {
		return nil, err
	}
	return dependency, nil
}

func (s *states) Abort() error {
	return s.accState.Abort()
}

func (s *states) AccountsRoot() byteutils.Hash {
	return s.accState.RootHash()
}

func (s *states) TxsRoot() byteutils.Hash {
	return s.txsState.RootHash()
}

//func (s *states) ConsensusRoot() byteutils.Hash {
//	return s.witnessState.RootHash()
//}

func (s *states) Accounts() ([]Account, error) {
	return s.accState.Accounts()
}

func (s *states) LoadAccountsRoot(root byteutils.Hash) error {
	accState, err := NewAccountState(root, s.stateDB)
	if err != nil {
		return err
	}
	s.accState = accState
	return nil
}

func (s *states) LoadWitnessRoot(root byteutils.Hash) error {
	witnessState, err := trie.NewTrie(root, s.stateDB, false)
	if err != nil {
		return err
	}
	s.witnessState = witnessState
	return nil
}

func (s *states) LoadTxsRoot(root byteutils.Hash) error {
	txsState, err := trie.NewTrie(root, s.stateDB, false)
	if err != nil {
		return err
	}
	s.txsState = txsState
	return nil
}

func (s *states) recordAccount(acc Account) (Account, error) {
	if err := s.changelog.Put(acc.Address(), acc.Address()); err != nil {
		return nil, err
	}
	return acc, nil
}

func newStates(storage cdb.Storage) (*states, error) {
	changelog, err := newChangeLog()
	if err != nil {
		return nil, err
	}
	stateDB, err := newStateDB(storage)
	if err != nil {
		return nil, err
	}

	accState, err := NewAccountState(nil, stateDB)
	if err != nil {
		return nil, err
	}

	txsState, err := trie.NewTrie(nil, stateDB, false)
	if err != nil {
		return nil, err
	}

	superNodesState, err := trie.NewTrie(nil, stateDB, false)
	if err != nil {
		return nil, err
	}

	standByNodesState, err := trie.NewTrie(nil, stateDB, false)
	if err != nil {
		return nil, err
	}

	witnessState, err := trie.NewTrie(nil, stateDB, false)
	if err != nil {
		return nil, err
	}

	return &states{
		accState:     accState,
		txsState:     txsState,
		superNodes:   superNodesState,
		standByNodes: standByNodesState,
		witnessState: witnessState,
		changelog:    changelog,
		stateDB:      stateDB,
		innerDB:      storage,
		txid:         nil,
	}, nil
}

func newChangeLog() (*mvccdb.MVCCDB, error) {
	mem, err := cdb.NewMemoryStorage()
	if err != nil {
		return nil, err
	}
	db, err := mvccdb.NewMVCCDB(mem, false)
	if err != nil {
		return nil, err
	}

	db.SetStrictGlobalVersionCheck(true)
	return db, nil
}

func newStateDB(storage cdb.Storage) (*mvccdb.MVCCDB, error) {
	return mvccdb.NewMVCCDB(storage, true)
}
