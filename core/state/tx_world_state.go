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

import "cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"

// txWorldState
type txWorldState struct {
	*states
	txid   interface{}
	parent *worldState
}

func (tws *txWorldState) CheckAndUpdate() ([]interface{}, error) {
	dependencies, err := tws.states.CheckAndUpdateTo(tws.parent.states)
	if err != nil {
		return nil, err
	}
	tws.parent = nil
	return dependencies, nil
}

func (tws *txWorldState) Reset(addr byteutils.Hash, isResetChangeLog bool) error {
	if err := tws.states.Reset(addr, isResetChangeLog); err != nil {
		return err
	}
	return nil
}

func (tws *txWorldState) Close() error {
	if err := tws.states.Close(); err != nil {
		return err
	}
	tws.parent = nil
	return nil
}

func (tws *txWorldState) TxID() interface{} {
	return tws.txid
}
