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

import "math/big"

// ContractSet
type ContractSet struct {
	normalCons       uint64
	templateCons     uint64
	templateConsRefs uint64
}

func (cs *ContractSet) NormalContracts() uint64       { return cs.normalCons }
func (cs *ContractSet) TemplateContracts() uint64     { return cs.templateCons }
func (cs *ContractSet) TemplateContractsRefs() uint64 { return cs.templateConsRefs }
func (cs *ContractSet) Value() *big.Int {
	sum := new(big.Int).SetUint64(cs.normalCons)
	tempCons := new(big.Int).SetUint64(cs.templateCons)
	tempConRefs := new(big.Int).SetUint64(cs.templateConsRefs)
	sum.Add(sum, tempCons)
	sum.Add(sum, tempConRefs)
	return sum
}

// TransactionSet
type TransactionSet struct {
	normalTxs   uint64
	contractTxs uint64
}

func (ts *TransactionSet) NormalTxs() uint64   { return ts.normalTxs }
func (ts *TransactionSet) ContractTxs() uint64 { return ts.contractTxs }
func (ts *TransactionSet) Value() *big.Int {
	sum := new(big.Int).SetUint64(ts.normalTxs)
	conTxs := new(big.Int).SetUint64(ts.contractTxs)
	sum.Add(sum, conTxs)
	return sum
}
