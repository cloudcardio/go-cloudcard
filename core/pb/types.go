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

package corepb

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"errors"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/crypto/sha3"
)

const (
	OpConsensus = "Consensus"
	OpTxVerify  = "TxVerify"
	OpIgnore    = "ignore"
)

var (
	ErrNoMaster     = errors.New("no master in group")
	ErrWrongGroup   = errors.New("wrong group")
	ErrGetGroupNext = errors.New("get next error")
)

func NewPropose(num uint64) *Propose {
	return &Propose{
		Num: num,
	}
}

func (p *Propose) CalcHash() []byte {
	hasher := sha3.New256()
	hasher.Write(byteutils.FromUint64(p.Num))
	if p.Value != nil {
		hasher.Write(p.Value)
	}
	return hasher.Sum(nil)
}

func (p *Propose) ToProto() (proto.Message, error) {
	prop := &Propose{
		Num:   p.Num,
		Value: p.Value,
	}
	return prop, nil
}

func (p *Propose) FromProto(msg proto.Message) error {
	p.Num = msg.(*Propose).Num
	p.Value = msg.(*Propose).Value
	return nil
}

func (prepreMsg *PreprepareMsg) ToProto() (proto.Message, error) {
	return &PreprepareMsg{
		Type:   prepreMsg.Type,
		ViewId: prepreMsg.ViewId,
		SeqId:  prepreMsg.SeqId,
		Hash:   prepreMsg.Hash,
		Block:  prepreMsg.Block,
		Sign:   prepreMsg.Sign,
	}, nil
}

func (prepreMsg *PreprepareMsg) FromProto(msg proto.Message) error {
	pm := msg.(*PreprepareMsg)
	prepreMsg.Type = pm.Type
	prepreMsg.Block = pm.Block
	prepreMsg.ViewId = pm.ViewId
	prepreMsg.Hash = pm.Hash
	prepreMsg.Sign = pm.Sign
	prepreMsg.SeqId = pm.SeqId

	return nil
}

func (pbftMsg *PreprepareMsg) CalcHash() []byte {
	hasher := sha3.New256()
	hasher.Write(byteutils.FromUint32(pbftMsg.Type))
	hasher.Write([]byte(pbftMsg.ViewId))
	hasher.Write(pbftMsg.Block.Hash)
	hasher.Write(byteutils.FromUint64(pbftMsg.SeqId))

	hash := hasher.Sum(nil)
	pbftMsg.Hash = hash

	return hash
}

func (voteMsg *VoteMsg) ToProto() (proto.Message, error) {
	return &VoteMsg{
		Type:   voteMsg.Type,
		ViewId: voteMsg.ViewId,
		SeqId:  voteMsg.SeqId,
		Hash:   voteMsg.Hash,
		Sign:   voteMsg.Sign,
	}, nil
}

func (voteMsg *VoteMsg) FromProto(msg proto.Message) error {
	pm := msg.(*VoteMsg)
	voteMsg.Type = pm.Type
	voteMsg.ViewId = pm.ViewId
	voteMsg.Hash = pm.Hash
	voteMsg.Sign = pm.Sign
	voteMsg.SeqId = pm.SeqId

	return nil
}

func (voteMsg *VoteMsg) CalcHash() []byte {
	hasher := sha3.New256()
	hasher.Write(byteutils.FromUint32(voteMsg.Type))
	hasher.Write([]byte(voteMsg.ViewId))
	hasher.Write(byteutils.FromUint64(voteMsg.SeqId))

	hash := hasher.Sum(nil)
	voteMsg.Hash = hash

	return hash
}

//
func (group *Group) ToSlice() ([]string, error) {
	if group.Master == "" {
		return nil, ErrNoMaster
	}

	if len(group.Members) == 0 {
		res := make([]string, 1)
		res = append(res, group.Master)
		return res, nil
	}

	if len(group.Members) == 3 {
		res := make([]string, 4)
		res[0] = group.Master
		res[1] = group.Members[0]
		res[2] = group.Members[1]
		res[3] = group.Members[2]
		return res, nil
	}

	return nil, ErrWrongGroup
}

//
func (group *Group) Next(miner string) (string, error) {
	if group.Master == "" {
		return "", ErrNoMaster
	}

	if len(group.Members) == 0 {
		return group.Master, nil
	}

	if len(group.Members) == 3 {
		res, err := group.ToSlice()
		if err != nil {
			return "", err
		}

		for i, w := range res {
			if w == miner {
				if i == len(res)-1 {
					return res[0], nil
				} else {
					return res[i+1], nil
				}
			}
		}
	}

	return "", ErrGetGroupNext
}
