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
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/core/state"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/trie"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"fmt"
)

// TermState
type PsecState struct {
	timestamp   int64
	proposer    byteutils.Hash
	witnessTrie *trie.Trie
	chain       *core.BlockChain
	consensus   core.Consensus
}

// NewState creates a new psec state.
func (psec *Psec) NewState(root *corepb.ConsensusRoot, db cdb.Storage, needChangeLog bool) (state.ConsensusState, error) {
	var witnessRoot byteutils.Hash
	if root != nil {
		witnessRoot = root.WitnessRoot
	}
	witnessTrie, err := trie.NewTrie(witnessRoot, db, needChangeLog)
	if err != nil {
		return nil, err
	}

	return &PsecState{
		timestamp:   root.Timestamp,
		proposer:    root.Proposer,
		witnessTrie: witnessTrie,
		chain:       psec.chain,
		consensus:   psec,
	}, nil
}

//
func (ps *PsecState) RootHash() *corepb.ConsensusRoot {
	return &corepb.ConsensusRoot{
		WitnessRoot: ps.witnessTrie.RootHash(),
		Timestamp:   ps.Timestamp(),
		Proposer:    ps.Proposer(),
	}
}

//
func (ps *PsecState) String() string {
	proposer := ""
	if ps.proposer != nil {
		proposer = ps.proposer.String()
	}
	return fmt.Sprintf(`{"timestamp:%d", "proposer:%s", "witness":%s}`, ps.timestamp, proposer, byteutils.Hex(ps.witnessTrie.RootHash()))
}

//
func (ps *PsecState) Copy() (state.ConsensusState, error) {
	witnessTrie, err := ps.witnessTrie.Clone()
	if err != nil {
		return nil, ErrCloneWitnessTrie
	}
	return &PsecState{
		timestamp:   ps.timestamp,
		proposer:    ps.proposer,
		witnessTrie: witnessTrie,
		chain:       ps.chain,
		consensus:   ps.consensus,
	}, nil
}

//
func (ps *PsecState) Replay(done state.ConsensusState) error {
	state := done.(*PsecState)
	if _, err := ps.witnessTrie.Replay(state.witnessTrie); err != nil {
		return err
	}
	return nil
}

func (ps *PsecState) Term() ([]byteutils.Hash, error) { return TraverseTerm(ps.witnessTrie) }
func (ps *PsecState) TermRoot() byteutils.Hash        { return ps.witnessTrie.RootHash() }
func (ps *PsecState) Proposer() byteutils.Hash        { return ps.proposer }
func (ps *PsecState) Timestamp() int64                { return ps.timestamp }

func (ps *PsecState) GenesisConsensusState(chain *core.BlockChain)(state.ConsensusState, error) {
	return nil,nil
}

func (ps *PsecState) NextConsensusState(elapsedSecond int64, worldState state.WorldState) (state.ConsensusState, error) {
	elapsedSecondInMs := elapsedSecond * OneSecond
	if elapsedSecondInMs <= 0 || elapsedSecondInMs%BlockInterval != 0 {
		return nil, ErrNotBlockMintTime
	}
	return nil, nil
}


//
func FindProposer(now int64, miners []byteutils.Hash) (proposer byteutils.Hash, err error) {
	nowInMs := now * OneSecond
	offsetInMs := nowInMs % TermInterval
	if (offsetInMs % BlockInterval) != 0 {
		return nil, ErrNotBlockMintTime
	}
	offset := offsetInMs / BlockInterval
	offset %= WitnessesSize

	if offset >= 0 && int(offset) < len(miners) {
		proposer = miners[offset]
	} else {
		return nil, ErrFoundNilProposer
	}
	return proposer, nil
}

//
func TraverseTerm(trie *trie.Trie) ([]byteutils.Hash, error) {
	var members []byteutils.Hash
	itr, err := trie.Iterator(nil)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err != nil {
		return members, nil
	}
	exist, err := itr.Next()
	for exist {
		members = append(members, itr.Value())
		exist, err = itr.Next()
	}
	return members, nil
}
