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
	"math/big"
)

// CreditScore
type HandledData struct {
	prevRoundProductions int
	winningTimes         uint64
	handledContracts     *ContractSet
	handledTxs           *TransactionSet
}

func (hd *HandledData) PrevRoundProductions() int      { return hd.prevRoundProductions }
func (hd *HandledData) WinningTimes() uint64           { return hd.winningTimes }
func (hd *HandledData) HandledContracts() *ContractSet { return hd.handledContracts }
func (hd *HandledData) HandledTxs() *TransactionSet    { return hd.handledTxs }

func (hd *HandledData) Value() *big.Int {
	sum := new(big.Int)
	sum.Add(sum, hd.handledContracts.Value())
	sum.Add(sum, hd.handledTxs.Value())
	sum.Add(sum, new(big.Int).SetUint64(hd.winningTimes))
	sum.Add(sum, new(big.Int).SetInt64(int64(hd.prevRoundProductions)))

	return sum
}

// Voter
type Voter struct {
	address     Address
	handedData  *HandledData
	pledge      *big.Int
	creditIndex *big.Int
	deduction   *big.Int
}

func (v *Voter) Address() Address          { return v.address }
func (v *Voter) Pledge() *big.Int          { return v.pledge }
func (v *Voter) HandledData() *HandledData { return v.handedData }
func (v *Voter) Index() *big.Int           { return v.creditIndex }
func (v *Voter) calcIndex() {
	pledgeScore := new(big.Int).Div(v.pledge, new(big.Int).SetUint64(10000))
	productionScore := new(big.Int).Add(new(big.Int).SetUint64(uint64(v.handedData.prevRoundProductions)), new(big.Int).SetUint64(v.handedData.winningTimes))

	index := new(big.Int)
	allTxs := v.handedData.handledTxs
	txScore1 := new(big.Int).Mul(new(big.Int).SetUint64(allTxs.normalTxs), new(big.Int).SetUint64(6))   // normal txs * 6
	txScore2 := new(big.Int).Mul(new(big.Int).SetUint64(allTxs.contractTxs), new(big.Int).SetUint64(4)) // template txs * 4
	txScore1.Add(txScore1, txScore2)

	allCons := v.handedData.handledContracts
	conScore1 := new(big.Int).Mul(new(big.Int).SetUint64(allCons.normalCons), new(big.Int).SetUint64(4))   // normal contracts * 4
	conScore2 := new(big.Int).Mul(new(big.Int).SetUint64(allCons.templateCons), new(big.Int).SetUint64(5)) // template contracts * 5
	conScore3 := new(big.Int).SetUint64(allCons.templateConsRefs)                                          // template contracts reference * 1
	conScore1.Add(conScore1, conScore2)
	conScore1.Add(conScore1, conScore3)

	index.Add(txScore1, conScore1)
	index.Add(index, productionScore)
	index.Add(index, pledgeScore)
	index.Sub(index, v.deduction)

	v.creditIndex = new(big.Int).Set(index)
}
