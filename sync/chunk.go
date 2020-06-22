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

package sync

import (
	"bytes"
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	syncpb "cloudcard.pro/cloudcardio/go-cloudcard/sync/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/trie"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/sirupsen/logrus"
)

// Chunk packs some blocks
type Chunk struct {
	blockChain *core.BlockChain
	chunksTrie *trie.Trie
}

// NewChunk return a new chunk
func NewChunk(blockChain *core.BlockChain) *Chunk {
	return &Chunk{
		blockChain: blockChain,
		chunksTrie: nil,
	}
}

func verifyChunkHeaders(chunkHeaders *syncpb.ChunkHeaders) (bool, error) {
	if len(chunkHeaders.ChunkHeaders) == 0 && len(chunkHeaders.Root) == 0 {
		// fast quit.
		return true, nil
	}

	stor, err := cdb.NewMemoryStorage()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create memory storage")
		return false, err
	}

	chunksTrie, err := trie.NewTrie(nil, stor, false)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create merkle tree")
		return false, err
	}

	for _, chunkHeader := range chunkHeaders.ChunkHeaders {
		blocksTrie, err := trie.NewTrie(nil, stor, false)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("Failed to create merkle tree")
			return false, err
		}

		for _, blockHash := range chunkHeader.Headers {
			_, _ = blocksTrie.Put(blockHash, blockHash)
		}

		_, _ = chunksTrie.Put(blocksTrie.RootHash(), blocksTrie.RootHash())
	}

	return bytes.Compare(chunksTrie.RootHash(), chunkHeaders.Root) == 0, nil
}

func verifyChunkData(chunkHeader *syncpb.ChunkHeader, chunkData *syncpb.ChunkData) (bool, error) {
	stor, err := cdb.NewMemoryStorage()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create memory storage")
		return false, err
	}

	blocksTrie, err := trie.NewTrie(nil, stor, false)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create merkle tree")
		return false, err
	}

	if len(chunkHeader.Headers) != len(chunkData.Blocks) {
		logging.VLog().WithFields(logrus.Fields{
			"chunkData.size":   len(chunkData.Blocks),
			"chunkHeader.size": len(chunkHeader.Headers),
			"err":              ErrWrongChunkDataSize,
		}).Debug("Wrong chunk data size.")
		return false, ErrWrongChunkDataSize
	}

	for k, block := range chunkData.Blocks {
		hash := chunkHeader.Headers[k]
		calculated, err := core.HashPbBlock(block)
		if err != nil {
			return false, err
		}
		if bytes.Compare(calculated, block.Header.Hash) != 0 {
			logging.VLog().WithFields(logrus.Fields{
				"index":                k,
				"chunkData.size":       len(chunkData.Blocks),
				"chunkHeader.size":     len(chunkHeader.Headers),
				"data.header.hash":     byteutils.Hex(block.Header.Hash),
				"data.calculated.hash": byteutils.Hex(calculated),
				"err":                  ErrInvalidBlockHashInChunk,
			}).Debug("Invalid block hash.")
			return false, ErrInvalidBlockHashInChunk
		}
		if bytes.Compare(hash, block.Header.Hash) != 0 {
			logging.VLog().WithFields(logrus.Fields{
				"index":            k,
				"chunkData.size":   len(chunkData.Blocks),
				"chunkHeader.size": len(chunkHeader.Headers),
				"data.hash":        byteutils.Hex(block.Header.Hash),
				"header.hash":      byteutils.Hex(hash),
				"err":              ErrWrongBlockHashInChunk,
			}).Debug("Wrong block hash.")
			return false, ErrWrongBlockHashInChunk
		}
		_, _ = blocksTrie.Put(block.Header.Hash, block.Header.Hash)
	}

	if bytes.Compare(blocksTrie.RootHash(), chunkHeader.Root) != 0 {
		logging.VLog().WithFields(logrus.Fields{
			"size":                len(chunkData.Blocks),
			"localChunkRootHash":  byteutils.Hex(blocksTrie.RootHash()),
			"chunkHeader":         chunkHeader,
			"chunkHeaderRootHash": byteutils.Hex(chunkHeader.Root),
		}).Debug("Wrong chunk header root hash.")
		return false, ErrWrongChunkDataRootHash
	}

	return true, nil
}

func (c *Chunk) generateChunkData(chunkHeader *syncpb.ChunkHeader) (*syncpb.ChunkData, error) {
	stor, err := cdb.NewMemoryStorage()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create memory storage")
		return nil, err
	}

	blocksTrie, err := trie.NewTrie(nil, stor, false)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create merkle tree")
		return nil, err
	}

	var blocks []*corepb.Block
	for k, v := range chunkHeader.Headers {
		block := c.blockChain.GetBlockOnCanonicalChainByHash(v)
		if block == nil {
			logging.VLog().WithFields(logrus.Fields{
				"index": k,
				"hash":  byteutils.Hex(v),
				"err":   ErrCannotFindBlockByHash,
			}).Debug("Failed to find the block on canonical chain.")
			return nil, ErrCannotFindBlockByHash
		}
		pbBlock, err := block.ToProto()
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"block": block,
				"err":   err,
			}).Debug("Failed to serialize block.")
			return nil, err
		}
		blocks = append(blocks, pbBlock.(*corepb.Block))
		_, _ = blocksTrie.Put(block.Hash(), block.Hash())
	}

	if bytes.Compare(blocksTrie.RootHash(), chunkHeader.Root) != 0 {
		logging.VLog().WithFields(logrus.Fields{
			"size":                len(blocks),
			"localChunkRootHash":  byteutils.Hex(blocksTrie.RootHash()),
			"chunkHeader":         chunkHeader,
			"chunkHeaderRootHash": byteutils.Hex(chunkHeader.Root),
		}).Debug("Wrong chunk header root hash.")
		return nil, ErrWrongChunkHeaderRootHash
	}

	logging.VLog().WithFields(logrus.Fields{
		"size": len(blocks),
	}).Debug("Succeed to generate chunk.")

	return &syncpb.ChunkData{Blocks: blocks, Root: blocksTrie.RootHash()}, nil
}

func (c *Chunk) processChunkData(chunk *syncpb.ChunkData) error {
	for k, v := range chunk.Blocks {
		block := new(core.Block)
		if err := block.FromProto(v); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"index": k,
				"hash":  byteutils.Hex(v.Header.Hash),
				"err":   err,
			}).Debug("Failed to recover a block from proto data.")
			return err
		}
		if err := c.blockChain.BlockPool().Add(block); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"index": k,
				"hash":  byteutils.Hex(v.Header.Hash),
				"err":   err,
			}).Debug("Failed to push a block into block pool.")
			return err
		}
	}

	logging.VLog().WithFields(logrus.Fields{
		"size": len(chunk.Blocks),
	}).Debug("Succeed to process chunk.")
	return nil
}
