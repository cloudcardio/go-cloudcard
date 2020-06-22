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
package psec

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	"math/big"
)

type Term struct {
	start     int64
	witnesses []*core.Witness
}

func (term *Term) Witnesses() []*core.Witness             { return term.witnesses }
func (term *Term) SetTimestamp(time int64)                { term.start = time }
func (term *Term) SetWitnesses(witnesses []*core.Witness) { term.witnesses = witnesses }

type SortableVoters []*core.Voter

func (sv SortableVoters) Len() int { return len(sv) }

func (sv SortableVoters) Swap(i, j int) { sv[i], sv[j] = sv[j], sv[i] }

func (sv SortableVoters) Less(i, j int) bool {
	vi := new(big.Int).Set(sv[i].Index())
	vj := new(big.Int).Set(sv[j].Index())
	if vi.Cmp(vj) < 0 {
		return false
	} else if vi.Cmp(vj) > 0 {
		return true
	} else {
		addri := sv[i].Address()
		addrj := sv[i].Address()
		return addri.String() < addrj.String()
	}
}

func (sv SortableVoters) Data() []*core.Voter {
	voters := make([]*core.Voter, sv.Len())
	copy(voters, sv)
	return voters
}
