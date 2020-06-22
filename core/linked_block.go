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
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/sirupsen/logrus"
)

type linkedBlock struct {
	block       *Block
	chain       *BlockChain
	hash        byteutils.Hash
	parentHash  byteutils.Hash
	parentBlock *linkedBlock
	childBlocks map[byteutils.HexHash]*linkedBlock
}

func newLinkedBlock(block *Block, chain *BlockChain) *linkedBlock {
	return &linkedBlock{
		block:       block,
		chain:       chain,
		hash:        block.Hash(),
		parentHash:  block.ParentHash(),
		parentBlock: nil,
		childBlocks: make(map[byteutils.HexHash]*linkedBlock),
	}
}

func (lb *linkedBlock) LinkParent(parentBlock *linkedBlock) {
	lb.parentBlock = parentBlock
	parentBlock.childBlocks[lb.hash.Hex()] = lb
}

// Dispose dispose linkedBlock
func (lb *linkedBlock) Dispose() {
	// clear pointer
	lb.block = nil
	lb.chain = nil
	// cut the relationship with children
	for _, v := range lb.childBlocks {
		v.parentBlock = nil
	}
	lb.childBlocks = nil
	// cut the relationship whit parent
	if lb.parentBlock != nil {
		delete(lb.parentBlock.childBlocks, lb.hash.Hex())
		lb.parentBlock = nil
	}
}

func (lb *linkedBlock) travelToLinkAndReturnAllValidBlocks(parentBlock *Block) ([]*Block, []*Block, error) {
	if err := lb.block.LinkParentBlock(lb.chain, parentBlock); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"parent": parentBlock,
			"block":  lb.block,
			"err":    err,
		}).Error("Failed to link the block with its parent.")
		return nil, nil, err
	}

	if err := lb.block.VerifyExecution(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": lb.block,
			"err":   err,
		}).Error("Failed to execute block.")
		return nil, nil, err
	}

	allBlocks := []*Block{lb.block}
	var tailBlocks []*Block

	if len(lb.childBlocks) == 0 {
		tailBlocks = append(tailBlocks, lb.block)
	}

	for _, clb := range lb.childBlocks {
		a, b, err := clb.travelToLinkAndReturnAllValidBlocks(lb.block)
		if err == nil {
			allBlocks = append(allBlocks, a...)
			tailBlocks = append(tailBlocks, b...)
		}
	}

	return allBlocks, tailBlocks, nil
}
