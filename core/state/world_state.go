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
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
)

// WorldState manages all current states in Blockchain.
type worldState struct {
	*states
	snapshot *states
}

// NewWorldState create a new empty WorldState
func NewWorldState(storage cdb.Storage) (WorldState, error) {
	states, err := newStates(storage)
	if err != nil {
		return nil, err
	}
	return &worldState{
		states:   states,
		snapshot: nil,
	}, nil
}

// Clone a new WorldState
func (ws *worldState) Copy() (WorldState, error) {
	s, err := ws.states.Copy()
	if err != nil {
		return nil, err
	}
	return &worldState{
		states:   s,
		snapshot: nil,
	}, nil
}

//
func (ws *worldState) Begin() error {
	snapshot, err := ws.states.Copy()
	if err != nil {
		return err
	}
	if err := ws.states.Begin(); err != nil {
		return err
	}
	ws.snapshot = snapshot
	return nil
}

//
func (ws *worldState) Commit() error {
	if err := ws.states.Commit(); err != nil {
		return err
	}
	ws.snapshot = nil
	return nil
}

//
func (ws *worldState) RollBack() error {
	if err := ws.states.RollBack(); err != nil {
		return err
	}
	ws.states = ws.snapshot
	ws.snapshot = nil
	return nil
}

//
func (ws *worldState) Prepare(txid interface{}) (TxWorldState, error) {
	s, err := ws.states.Prepare(txid)
	if err != nil {
		return nil, err
	}
	txState := &txWorldState{
		states: s,
		txid:   txid,
		parent: ws,
	}
	return txState, nil
}

//
func (ws *worldState) CurrentWitnesses(termId uint64) ([]*corepb.Group, error) {
	key := byteutils.FromUint64(termId)
	data, err := ws.states.witnessState.Get(key)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"term_id":      termId,
			"witness_root": ws.WitnessRoot().String(),
			"err":          err,
		}).Debug("[Get Witness] error")
		return nil, err
	}

	pbWitnesses := new(corepb.WitnessState)
	if err := proto.Unmarshal(data, pbWitnesses); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"term_id":      termId,
			"witness_root": ws.WitnessRoot().String(),
			"err":          err,
		}).Debug("[Get Witness] error")
		return nil, err
	}

	return pbWitnesses.Witnesses, nil
}

//
func (ws *worldState) PutWitnesses(wts *corepb.WitnessState) error {
	data, err := proto.Marshal(wts)
	if err != nil {
		return err
	}
	key := byteutils.FromUint64(wts.TermId)
	_, err = ws.states.witnessState.Put(key, data)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"term_id":      wts.TermId,
			"witness_root": ws.WitnessRoot().String(),
			"err":          err,
		}).Debug("[Put Witness] error")
		return err
	}
	return nil
}
