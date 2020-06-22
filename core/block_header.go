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
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"github.com/gogo/protobuf/proto"
	"math/big"
)

// BlockHeader
type BlockHeader struct {
	chainId       uint32
	height        uint64
	timestamp     int64
	termId        uint64
	witnessReward *big.Int
	coinbase      *Address

	parentHash byteutils.Hash
	hash       byteutils.Hash

	stateRoot     byteutils.Hash
	txsRoot       byteutils.Hash
	consensusRoot byteutils.Hash

	sign  *corepb.Signature
	extra []byte
}

func (h *BlockHeader) SetParentHash(hash []byte)           { h.hash = hash }
func (h *BlockHeader) SetTimestamp(t int64)                { h.timestamp = t }
func (h *BlockHeader) SetHeight(height uint64)             { h.height = height }
func (h *BlockHeader) SetCoinbase(addr Address)            { h.coinbase = &addr }
func (h *BlockHeader) SetWitnessReward(reward int64)       { h.witnessReward = big.NewInt(reward) }
func (h *BlockHeader) SetChainId(id uint32)                { h.chainId = id }
func (h *BlockHeader) SetHash(hash byteutils.Hash)         { h.hash = hash }
func (h *BlockHeader) SetAccountsRoot(hash byteutils.Hash) { h.stateRoot = hash }
func (h *BlockHeader) SetTxsRoot(hash byteutils.Hash)      { h.txsRoot = hash }

func (h *BlockHeader) TxsRoot() []byte         { return h.txsRoot }
func (h *BlockHeader) ParentHash() []byte      { return h.parentHash }
func (h *BlockHeader) Timestamp() int64        { return h.timestamp }
func (h *BlockHeader) WitnessReward() *big.Int { return h.witnessReward }
func (h *BlockHeader) ChainId() uint32         { return h.chainId }
func (h *BlockHeader) Coinbase() *Address      { return h.coinbase }
func (h *BlockHeader) Extra() []byte           { return h.extra }
func (h *BlockHeader) Sign() *corepb.Signature { return h.sign }
func (h *BlockHeader) Hash() []byte            { return h.hash }
func (h *BlockHeader) Height() uint64          { return h.height }

// FromProto converts proto BlockHeader to domain BlockHeader
func (h *BlockHeader) FromProto(msg proto.Message) error {
	if msg, ok := msg.(*corepb.BlockHeader); ok {
		if msg != nil {
			h.chainId = msg.ChainId
			coinbase, err := AddressParseFromBytes(msg.Coinbase)
			if err != nil {
				return ErrInvalidProtoToBlockHeader
			}
			h.coinbase = coinbase
			h.stateRoot = msg.StateRoot
			h.txsRoot = msg.TxsRoot
			h.consensusRoot = msg.WitnessRoot
			h.parentHash = msg.ParentHash
			h.height = msg.Height
			h.termId = msg.TermId
			h.timestamp = msg.Timestamp
			h.hash = msg.Hash
			h.sign = msg.Sign
			h.extra = msg.Extra
			return nil
		}
		return ErrInvalidProtoToBlockHeader
	}
	return ErrInvalidProtoToBlockHeader
}

// ToProto converts domain BlockHeader to proto BlockHeader
func (h *BlockHeader) ToProto() (proto.Message, error) {
	return &corepb.BlockHeader{
		Hash:          h.hash,
		ParentHash:    h.parentHash,
		Coinbase:      h.coinbase.address,
		ChainId:       h.chainId,
		Timestamp:     h.timestamp,
		Height:        h.height,
		TermId:        h.termId,
		StateRoot:     h.stateRoot,
		TxsRoot:       h.txsRoot,
		WitnessRoot:   h.consensusRoot,
		Sign:          h.sign,
		Extra:         h.extra,
	}, nil

}
