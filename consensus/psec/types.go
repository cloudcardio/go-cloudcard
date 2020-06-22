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
	"errors"
)

const (
	MaxMiningDuration = int64(10 * 365 * 24 * 60 * 60)
)

var (
	ErrInvalidBlockWitness        = errors.New("invalid block witness")
	ErrAppendNewBlockFailed       = errors.New("failed to append new block to real chain")
	ErrCannotMintWhenDisable      = errors.New("cannot mint block now, waiting for enable it again")
	ErrCannotMintWhenPending      = errors.New("cannot mint block now, waiting for cancel suspended again")
	ErrWaitingBlockInLastSlot     = errors.New("cannot mint block now, waiting for last block")
	ErrGenerateNextConsensusState = errors.New("failed to generate next consensus state")
	ErrInvalidBlockProposer       = errors.New("invalid block proposer")
	ErrCloneWitnessTrie           = errors.New("failed to clone witness trie")
	ErrNotBlockMintTime           = errors.New("now is not time to mint block")
	ErrFoundNilProposer           = errors.New("found a nil proposer")
	ErrInvalidWitnesses           = errors.New("the size of initial witness in genesis block is invalid, should be equal ")
	ErrBlockMintedInNextSlot      = errors.New("cannot mint block now, there is a block minted in current slot")
	ErrGetTerm                    = errors.New("failed to get term with current genesis and term")
	ErrInvalidProtoToTerm         = errors.New("protobuf message cannot be converted into Term")

	ErrVerifyPreprepareMsgError = errors.New("verify preprepare msg sign error")
	ErrSeqIdIsTooLow            = errors.New("msg seq id is too low")
	ErrWrongMiner               = errors.New("wrong miner")
)
