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

package cdb

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"github.com/dgraph-io/badger"
	"sync"
)

type BadgerDB struct {
	badgerDB    *badger.DB
	enableBatch bool
	filename    string
	mutex       sync.Mutex
	batchOpts   map[string]*batchOpt
}

func NewBadgerDB(dbcfg *DbConfig) (*BadgerDB, error) {
	opts := badger.DefaultOptions
	opts.Dir = dbcfg.DbDir
	opts.ValueDir = dbcfg.DbDir
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerDB{
		badgerDB:    db,
		enableBatch: dbcfg.EnableBatch,
		filename:    dbcfg.DbDir,
		batchOpts:   make(map[string]*batchOpt),
	}, nil
}

func (db *BadgerDB) Close() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	return db.badgerDB.Close()
}

func (db *BadgerDB) Has(key []byte) (bool, error) {
	err := db.badgerDB.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err != nil && err == badger.ErrKeyNotFound {
			return ErrKeyNotFound
		}
		return err
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (db *BadgerDB) Get(key []byte) ([]byte, error) {
	txn := db.badgerDB.NewTransaction(false) // read-only
	defer txn.Discard()
	var err error
	if item, err := txn.Get(key); err == nil {
		if value, err := item.Value(); err == nil {
			return value, nil
		}
	}
	if err == badger.ErrKeyNotFound {
		return nil, ErrKeyNotFound
	}
	return nil, err
}

func (db *BadgerDB) Put(key, value []byte) error {
	if db.enableBatch {
		db.mutex.Lock()
		defer db.mutex.Unlock()

		db.batchOpts[byteutils.Hex(key)] = &batchOpt{
			key:     key,
			value:   value,
			deleted: false,
		}

		return nil
	}

	txn := db.badgerDB.NewTransaction(true) // write-read
	defer txn.Discard()
	if err := txn.Set(key, value); err != nil {
		return err
	} else {
		return txn.Commit(nil)
	}
}

func (db *BadgerDB) Delete(key []byte) error {
	if db.enableBatch {
		db.mutex.Lock()
		defer db.mutex.Unlock()

		db.batchOpts[byteutils.Hex(key)] = &batchOpt{
			key:     key,
			deleted: true,
		}
		return nil
	}

	txn := db.badgerDB.NewTransaction(true)
	defer txn.Discard()
	if err := txn.Delete(key); err != nil {
		return err
	}
	return txn.Commit(nil)
}

func (db *BadgerDB) EnableBatch() {
	db.enableBatch = true
}

func (db *BadgerDB) DisableBatch() {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.batchOpts = make(map[string]*batchOpt)
	db.enableBatch = false
}

func (db *BadgerDB) ValueSize() int {
	if db.batchOpts == nil {
		return 0
	}
	return len(db.batchOpts)
}

func (db *BadgerDB) Flush() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if !db.enableBatch {
		return nil
	}

	txn := db.badgerDB.NewTransaction(true)
	for _, opt := range db.batchOpts {
		if opt.deleted {
			if err := txn.Delete(opt.key); err != nil {
				return err
			}
		} else {
			if err := txn.Set(opt.key, opt.value); err == nil {
				return err
			}
		}
	}
	db.batchOpts = make(map[string]*batchOpt)

	return txn.Commit(nil)
}
