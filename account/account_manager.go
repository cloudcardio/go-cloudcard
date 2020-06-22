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
package account

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	"cloudcard.pro/cloudcardio/go-cloudcard/core/address"
	"cloudcard.pro/cloudcardio/go-cloudcard/core/state"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

const (
	DefaultAddressUnlockedDuration = time.Second * 60
)

var (
	ErrInitDBError       = errors.New("Failure of database initialization")
	WorldStateIsNil      = errors.New("world state is nil")
	ErrPrivateHasExisted = errors.New("private key has existed")
)

type AccountManager struct {
	addrManger *address.AddressManager
	db         cdb.Storage
	mutex      sync.Mutex
}

func (am *AccountManager) GetAddrManager() *address.AddressManager { return am.addrManger }

func NewAccountManager(config *config.Config, db cdb.Storage) (*AccountManager, error) {
	if config == nil || db == nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": core.ErrInvalidArgument,
		}).Error("Failed to init AccountManager")
		return nil, core.ErrInvalidArgument
	}
	accMgr := new(AccountManager)
	var err error
	accMgr.addrManger, err = address.NewAddressManager(config)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to create address manager")
		return nil, err
	}

	accMgr.db = db

	if accMgr.db == nil {
		logging.CLog().WithFields(logrus.Fields{}).Error("Failed to init db")
		return nil, ErrInitDBError
	}

	return accMgr, nil
}

func (am *AccountManager) AddressManager() *address.AddressManager {
	return am.addrManger
}

//return address,mnemonicWord
func (am *AccountManager) NewAccount(passphrase []byte) (*core.Address, string, error) {
	add, err := am.addrManger.NewAddress(passphrase)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to new account")
		return nil, "", err
	}
	memo, err := am.addrManger.GetMnemonic(add, passphrase)
	if err != nil {
		return nil, "", err
	}
	return add, memo, nil
}

func (am *AccountManager) AddressIsValid(address string) (*core.Address, error) {
	addr, err := core.AddressParse(address)
	if err != nil {
		return nil, err
	}
	return addr, err
}

func (am *AccountManager) UpdateAccount(address *core.Address, oldPassphrase, newPassphrase []byte) error {
	addr, err := am.AddressIsValid(address.String())
	if err != nil {
		return err
	}
	return am.addrManger.UpdatePassphrase(addr, oldPassphrase, newPassphrase)
}

func (am *AccountManager) ImportAccount(priKey, passphrase []byte) (*core.Address, error) {
	err := am.CheckRepeated(priKey)
	if err != nil {
		return nil, err
	}
	addr, err := am.addrManger.ImportByPrivateKey(priKey, passphrase)
	if err != nil {
		return nil, err
	}
	return addr, err
}

func (am *AccountManager) GetAllAddress() []*core.Address {
	return am.addrManger.Accounts()
}

func (am *AccountManager) Sign(address *core.Address, hash []byte) ([]byte, error) {
	signResult, err := am.addrManger.SignHash(address, hash)
	if err != nil {
		return nil, err
	}
	return signResult.GetData(), nil
}

func (am *AccountManager) SignBlock(address *core.Address, block *core.Block) error {
	return am.addrManger.SignBlock(address, block)
}

func (am *AccountManager) SignTx(addr *core.Address, tx *core.Transaction) error {
	return am.addrManger.SignTx(addr, tx)
}

func (am *AccountManager) Verify(addr *core.Address, message, sig []byte) (bool, error) {
	return am.addrManger.VerifySign(addr, sig, message)
}

func (am *AccountManager) UnLock(address *core.Address, passphrase []byte, duration time.Duration) error {
	if duration == 0 {
		duration = DefaultAddressUnlockedDuration
	}
	return am.addrManger.Unlock(address, passphrase, duration)
}

func (am *AccountManager) Lock(address *core.Address) error {
	return am.addrManger.Lock(address)
}

func GetAccountByAddress(address string, worldState state.WorldState) (state.Account, error) {
	if worldState == nil {
		return nil, WorldStateIsNil
	}
	addr, err := core.AddressParse(address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"address": address,
			"error":   err,
		}).Debug("address parse error")
		return nil, err
	}
	account, err := worldState.GetOrCreateAccount(addr.Bytes())
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"address": address,
			"error":   err,
		}).Debug("get account by address error")
		return nil, err
	}
	return account, nil
}

func (am *AccountManager) CheckRepeated(privKey []byte) error {
	key, err := crypto.NewPrivateKey(privKey)
	if err != nil {
		return err
	}
	pubKey, err := key.PublicKey().Encoded()
	if err != nil {
		return err
	}
	addr, err := core.NewAddressFromPublicKey(pubKey)
	if err != nil {
		return err
	}
	contains := am.addrManger.Contains(addr)
	if contains {
		return ErrPrivateHasExisted
	}
	return nil
}
