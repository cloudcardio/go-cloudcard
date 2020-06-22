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
	"cloudcard.pro/cloudcardio/go-cloudcard/trie"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"math/big"
)

// account info in state Trie
type account struct {
	address byteutils.Hash

	nonce    uint64
	doEvils  uint32
	products uint32

	balance     *big.Int
	frozenFund  *big.Int
	pledgeFund  *big.Int
	creditIndex *big.Int

	variables *trie.Trie

	permissions []*corepb.Permission
}

// ToBytes converts domain Account to bytes
func (acc *account) ToBytes() ([]byte, error) {
	pbAccount := &corepb.Account{
		Address:     acc.address,
		Balance:     acc.balance.Bytes(),
		FrozenFund:  acc.frozenFund.Bytes(),
		PledgeFund:  acc.pledgeFund.Bytes(),
		Nonce:       acc.nonce,
		DoEvils:     acc.doEvils,
		Products:    acc.products,
		VarsHash:    acc.variables.RootHash(),
		CreditIndex: acc.creditIndex.Bytes(),
		Permissions: acc.permissions,
	}
	bytes, err := proto.Marshal(pbAccount)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// FromBytes converts bytes to Account
func (acc *account) FromBytes(bytes []byte, storage cdb.Storage) error {
	pbAccount := &corepb.Account{}
	var err error
	if err = proto.Unmarshal(bytes, pbAccount); err != nil {
		return err
	}
	acc.address = pbAccount.Address
	acc.balance = new(big.Int).SetBytes(pbAccount.Balance)
	acc.frozenFund = new(big.Int).SetBytes(pbAccount.FrozenFund)
	acc.pledgeFund = new(big.Int).SetBytes(pbAccount.PledgeFund)
	acc.nonce = pbAccount.Nonce
	acc.doEvils = pbAccount.DoEvils
	acc.products = pbAccount.Products
	if acc.variables, err = trie.NewTrie(pbAccount.VarsHash, storage, false); err != nil {
		return err
	}
	acc.creditIndex = new(big.Int).SetBytes(pbAccount.CreditIndex)
	return nil
}

// DoEvils
func (acc *account) DoEvils() uint32 {
	return acc.doEvils
}

// GetProduction
func (acc *account) GetProduction() uint32 {
	return acc.products
}

//
func (acc *account) ClearProduction() {
	acc.products = uint32(0)
}

// Address return account's address.
func (acc *account) Address() byteutils.Hash { return acc.address }

// Balance return account's balance.
func (acc *account) Balance() *big.Int { return acc.balance }

// FrozenFund return account's frozen fund.
func (acc *account) FrozenFund() *big.Int { return acc.frozenFund }

// PledgeFund return account's pledge fund.
func (acc *account) PledgeFund() *big.Int { return acc.pledgeFund }

// Nonce return account's nonce.
func (acc *account) Nonce() uint64 { return acc.nonce }

// CreditIndex return account's credit index.
func (acc *account) CreditIndex() *big.Int { return acc.creditIndex }

// VarsHash return account's variables hash.
func (acc *account) VarsHash() byteutils.Hash { return acc.variables.RootHash() }

// Permissions return account's permissions.
func (acc *account) Permissions() []*corepb.Permission { return acc.permissions }

// IncreaseNonce increases nonce by 1.
func (acc *account) IncreaseNonce() { acc.nonce++ }

// Copy copies account.
func (acc *account) Copy() (Account, error) {
	variables, err := acc.variables.Clone()
	if err != nil {
		return nil, err
	}

	return &account{
		address:     acc.address,
		balance:     acc.balance,
		frozenFund:  acc.frozenFund,
		pledgeFund:  acc.pledgeFund,
		creditIndex: acc.creditIndex,
		nonce:       acc.nonce,
		doEvils:     acc.doEvils,
		variables:   variables,
		products:    acc.products,
		permissions: acc.permissions,
	}, nil
}

// AddBalance adds balance to an account.
func (acc *account) AddBalance(value *big.Int) error {
	balance := new(big.Int).Add(acc.balance, value)
	acc.balance = balance
	return nil
}

// SubBalance subtracts balance to an account.
func (acc *account) SubBalance(value *big.Int) error {
	if acc.balance.Cmp(value) < 0 {
		return ErrBalanceInsufficient
	}
	balance := new(big.Int).Sub(acc.balance, value)
	acc.balance = balance
	return nil
}

// AddFrozenFund freezes funds to an account.
func (acc *account) AddFrozenFund(value *big.Int) error {
	frozenFund := new(big.Int).Add(acc.frozenFund, value)
	acc.frozenFund = frozenFund
	return nil
}

// SubFrozenFund subtracts frozen funds to an account.
func (acc *account) SubFrozenFund(value *big.Int) error {
	if acc.frozenFund.Cmp(value) < 0 {
		return ErrFrozenFundInsufficient
	}
	frozenFund := new(big.Int).Sub(acc.frozenFund, value)
	acc.frozenFund = frozenFund
	return nil
}

// AddPledgeFund adds pledge funds to an account.
func (acc *account) AddPledgeFund(value *big.Int) error {
	pledgeFund := new(big.Int).Add(acc.pledgeFund, value)
	acc.pledgeFund = pledgeFund
	return nil
}

// SubPledgeFund subtracts pledge funds to an account.
func (acc *account) SubPledgeFund(value *big.Int) error {
	if acc.pledgeFund.Cmp(value) < 0 {
		return ErrPledgeFundInsufficient
	}
	pledgeFund := new(big.Int).Sub(acc.pledgeFund, value)
	acc.pledgeFund = pledgeFund
	return nil
}

// AddCreditIndex adds credit index to an account.
func (acc *account) AddCreditIndex(value *big.Int) error {
	acc.creditIndex = new(big.Int).Add(acc.creditIndex, value)
	return nil
}

// SetCreditIndex
func (acc *account) SetCreditIndex(value *big.Int) error {
	acc.creditIndex = new(big.Int).Set(value)
	return nil
}

// SubCreditIndex subtracts index to an account.
func (acc *account) SubCreditIndex(value *big.Int) error {
	acc.creditIndex = new(big.Int).Sub(acc.creditIndex, value)
	return nil
}

// Put into account's storage.
func (acc *account) Put(key []byte, value []byte) error {
	_, err := acc.variables.Put(key, value)
	return err
}

// Get from account's storage.
func (acc *account) Get(key []byte) ([]byte, error) {
	return acc.variables.Get(key)
}

// Del from account's storage.
func (acc *account) Delete(key []byte) error {
	if _, err := acc.variables.Del(key); err != nil {
		return err
	}
	return nil
}

// Iterator map var from account's storage.
func (acc *account) Iterator(prefix []byte) (Iterator, error) {
	return acc.variables.Iterator(prefix)
}

func (acc *account) String() string {
	return fmt.Sprintf("Account %p {Address: %v, Balance:%v, FrozenFund:%v, PledgeFund:%v, CreditIndex:%v; Nonce:%v; DoEvils:%v; VarsHash:%v; ProductNum:%v}",
		acc,
		byteutils.Hex(acc.address),
		acc.balance.String(),
		acc.frozenFund.String(),
		acc.pledgeFund.String(),
		acc.creditIndex,
		acc.nonce,
		acc.doEvils,
		byteutils.Hex(acc.variables.RootHash()),
		acc.products,
	)
}
