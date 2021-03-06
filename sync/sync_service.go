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
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	net "cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	syncpb "cloudcard.pro/cloudcardio/go-cloudcard/sync/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/trie"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"errors"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

// Errors
var (
	ErrInvalidChainSyncMessageData     = errors.New("invalid ChainSync message data")
	ErrInvalidChainGetChunkMessageData = errors.New("invalid ChainGetChunk message data")
	ErrInvalidProposeMessageData       = errors.New("invalid Propose message data")
	ErrInvalidPropose                  = errors.New("invalid Propose")
)

// Service manage sync tasks
type Service struct {
	blockChain *core.BlockChain
	netService net.Service
	chunk      *Chunk
	quitCh     chan bool
	messageCh  chan net.Message

	activeTask      *Task
	proposeTask     *ProposeTask
	activeTaskMutex sync.Mutex
}

// NewService return new Service.
func NewService(blockChain *core.BlockChain, netService net.Service) *Service {
	return &Service{
		blockChain:  blockChain,
		netService:  netService,
		chunk:       NewChunk(blockChain),
		quitCh:      make(chan bool, 1),
		activeTask:  nil,
		proposeTask: nil,
		messageCh:   make(chan net.Message, 128),
	}
}

// Start start sync service.
func (ss *Service) Start() {
	logging.VLog().Info("Starting Sync Service.")

	// register the network handler.
	netService := ss.netService
	netService.Register(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkHeadersRequest, net.MessageWeightZero))
	netService.Register(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkHeadersResponse, net.MessageWeightChainChunks))
	netService.Register(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkDataRequest, net.MessageWeightZero))
	netService.Register(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkDataResponse, net.MessageWeightChainChunkData))
	netService.Register(net.NewSubscriber(ss, ss.messageCh, false, net.ProposeLearnRequest, net.MessageWeightZero))
	netService.Register(net.NewSubscriber(ss, ss.messageCh, false, net.ProposeLearnResponse, net.MessageWeightPropose))

	// start loop().
	go ss.startLoop()
}

func (ss *Service) startLoop() {
	logging.CLog().Info("Started Sync Service.")
	timerChan := time.NewTicker(time.Second).C

	for {
		select {
		case <-timerChan:
			metricsCachedSync.Update(int64(len(ss.messageCh)))
		case <-ss.quitCh:
			if ss.activeTask != nil {
				ss.activeTask.Stop()
			}
			if ss.proposeTask != nil {
				ss.proposeTask.Stop()
			}
			logging.CLog().Info("Stopped Sync Service.")
			return
		case message := <-ss.messageCh:
			switch message.MessageType() {
			case net.ChunkHeadersRequest:
				ss.onChunkHeadersRequest(message)
			case net.ChunkHeadersResponse:
				ss.onChunkHeadersResponse(message)
			case net.ChunkDataRequest:
				ss.onChunkDataRequest(message)
			case net.ChunkDataResponse:
				ss.onChunkDataResponse(message)
			case net.ProposeLearnRequest:
				ss.onProposeLearnRequest(message)
			case net.ProposeLearnResponse:
				ss.onProposeLearnResponse(message)
			default:
				logging.VLog().WithFields(logrus.Fields{
					"messageName": message.MessageType(),
				}).Warn("Received unknown message.")
			}
		}
	}
}

// IsActiveSyncing return if there is active task now
func (ss *Service) IsActiveSyncing() bool {
	if ss.activeTask == nil {
		return false
	}

	return true
}

func (ss *Service) onChunkHeadersRequest(message net.Message) {
	if ss.IsActiveSyncing() {
		return
	}

	// handle ChunkHeadersRequest message.
	chunkSync := new(syncpb.Sync)
	err := proto.Unmarshal(message.Data(), chunkSync)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"pid": message.MessageFrom(),
		}).Debug("Invalid ChunkHeadersRequest message data.")
		ss.netService.ClosePeer(message.MessageFrom(), ErrInvalidChainSyncMessageData)
		return
	}

	// generate ChunkHeaders message.
	chunks, err := ss.chunk.generateChunkHeaders(chunkSync.TailBlockHash)
	if err != nil && err != ErrTooSmallGapToSync {
		logging.VLog().WithFields(logrus.Fields{
			"err":  err,
			"pid":  message.MessageFrom(),
			"hash": byteutils.Hex(chunkSync.TailBlockHash),
		}).Debug("Failed to generate chunk headers.")
		return
	}

	ss.chunkHeadersResponse(message.MessageFrom(), chunks)
}

func (c *Chunk) generateChunkHeaders(syncpointHash byteutils.Hash) (*syncpb.ChunkHeaders, error) {
	syncpoint := c.blockChain.GetBlockOnCanonicalChainByHash(syncpointHash)
	if syncpoint == nil {
		logging.VLog().WithFields(logrus.Fields{
			"syncpointHash": syncpointHash.Hex(),
		}).Debug("Failed to find the block on canonical chain")
		return nil, ErrCannotFindBlockByHash
	}
	tail := c.blockChain.TailBlock()
	if int(tail.Height())-int(syncpoint.Height()) <= core.ChunkSize {
		logging.VLog().WithFields(logrus.Fields{
			"err": ErrTooSmallGapToSync,
		}).Debug("Failed to generate sync blocks meta info")
		return &syncpb.ChunkHeaders{}, ErrTooSmallGapToSync
	}

	chunkHeaders, chunksTrieRootHash, err := getChunHeaders(c, syncpoint, tail)
	if err != nil {
		return nil, err
	}
	return &syncpb.ChunkHeaders{ChunkHeaders: chunkHeaders, Root: chunksTrieRootHash}, nil
}

func (ss *Service) chunkHeadersResponse(peerID string, chunks *syncpb.ChunkHeaders) {
	data, err := proto.Marshal(chunks)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to marshal syncpb.ChunkHeaders.")
		return
	}

	_ = ss.netService.SendMessageToPeer(net.ChunkHeadersResponse, data, net.MessagePriorityLow, peerID)
}

func (ss *Service) onChunkHeadersResponse(message net.Message) {
	if ss.activeTask == nil {
		return
	}

	ss.activeTask.processChunkHeaders(message)
}

func (ss *Service) onChunkDataRequest(message net.Message) {
	if ss.IsActiveSyncing() {
		return
	}

	// handle ChunkDataRequest message.
	chunkHeader := new(syncpb.ChunkHeader)
	err := proto.Unmarshal(message.Data(), chunkHeader)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"pid": message.MessageFrom(),
		}).Debug("Invalid ChainGetChunk message data.")
		ss.netService.ClosePeer(message.MessageFrom(), ErrInvalidChainGetChunkMessageData)
		return
	}

	chunkData, err := ss.chunk.generateChunkData(chunkHeader)
	if err != nil {
		if err == ErrWrongChunkHeaderRootHash {
			ss.netService.ClosePeer(message.MessageFrom(), err)
		}
		return
	}

	ss.chunkDataResponse(message.MessageFrom(), chunkData)
}

func (ss *Service) chunkDataResponse(peerID string, chunkData *syncpb.ChunkData) {
	data, err := proto.Marshal(chunkData)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to marshal syncpb.ChunkData.")
		return
	}

	_ = ss.netService.SendMessageToPeer(net.ChunkDataResponse, data, net.MessagePriorityLow, peerID)
}

func (ss *Service) onChunkDataResponse(message net.Message) {
	if ss.activeTask == nil {
		return
	}

	ss.activeTask.processChunkData(message)
}

func (ss *Service) onProposeLearnRequest(message net.Message) {
	if ss.proposeTask == nil {
		return
	}
	propose := new(corepb.Propose)
	err := proto.Unmarshal(message.Data(), propose)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"pid": message.MessageFrom(),
		}).Debug("Invalid propose message data.")
		ss.netService.ClosePeer(message.MessageFrom(), ErrInvalidProposeMessageData)
		return
	}

	if ss.proposeTask.latestPropose.Num > propose.Num {
		ss.proposeLearnResponse(message.MessageFrom(), ss.proposeTask.latestPropose)
	}
}

func (ss *Service) proposeLearnResponse(peerID string, propose *corepb.Propose) {
	data, err := proto.Marshal(propose)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to marshal corepb.Propose.")
		return
	}

	_ = ss.netService.SendMessageToPeer(net.ProposeLearnResponse, data, net.MessagePriorityHigh, peerID)
}

func (ss *Service) onProposeLearnResponse(message net.Message) {
	if ss.proposeTask == nil {
		return
	}

	ss.proposeTask.processProposeLearn(message)
}

// StartActiveSync starts an active sync task
func (ss *Service) StartActiveSync() bool {
	// lock.
	ss.activeTaskMutex.Lock()
	defer ss.activeTaskMutex.Unlock()

	if ss.IsActiveSyncing() {
		return false
	}

	ss.activeTask = NewTask(ss.blockChain, ss.netService, ss.chunk)
	ss.activeTask.Start()

	logging.CLog().WithFields(logrus.Fields{
		"syncpoint": ss.activeTask.syncPointBlock,
	}).Info("Started Active Sync Task.")

	ss.proposeTask = NewProposeTask(ss.blockChain, ss.netService)
	ss.proposeTask.Start()

	logging.CLog().WithFields(logrus.Fields{
		"propose_num": ss.proposeTask.latestPropose.Num,
	}).Info("Started Propose Sync Task.")
	return true
}

// Stop stop sync service.
func (ss *Service) Stop() {
	// deregister the network handler.
	netService := ss.netService
	netService.Deregister(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkHeadersRequest, net.MessageWeightZero))
	netService.Deregister(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkHeadersResponse, net.MessageWeightChainChunks))
	netService.Deregister(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkDataRequest, net.MessageWeightZero))
	netService.Deregister(net.NewSubscriber(ss, ss.messageCh, false, net.ChunkDataResponse, net.MessageWeightChainChunkData))
	netService.Deregister(net.NewSubscriber(ss, ss.messageCh, false, net.ProposeLearnRequest, net.MessageWeightZero))
	netService.Deregister(net.NewSubscriber(ss, ss.messageCh, false, net.ProposeLearnResponse, net.MessageWeightPropose))

	ss.StopActiveSync()

	ss.quitCh <- true
}

// StopActiveSync stops current sync task
func (ss *Service) StopActiveSync() {
	if ss.activeTask != nil {
		ss.activeTask.Stop()
		ss.activeTask = nil
	}
	if ss.proposeTask != nil {
		ss.proposeTask.Stop()
		ss.proposeTask = nil
	}

}

// WaitingForFinish wait for finishing current sync task
func (ss *Service) WaitingForFinish() {
	if ss.activeTask == nil {
		return
	}

	<-ss.activeTask.statusCh

	logging.CLog().WithFields(logrus.Fields{
		"tail": ss.blockChain.TailBlock(),
	}).Info("Active Sync Task Finished.")

	ss.activeTask = nil
}

func getChunHeaders(c *Chunk, startBlock *core.Block, tailBlock *core.Block) ([]*syncpb.ChunkHeader, []byte, error) {
	var chunkHeaders []*syncpb.ChunkHeader
	stor, err := cdb.NewMemoryStorage()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create memory storage")
		return nil, nil, err
	}
	chunksTrie, err := trie.NewTrie(nil, stor, false)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to create merkle tree")
		return nil, nil, err
	}

	startChunk := (startBlock.Height() - 1) / core.ChunkSize
	endChunk := (tailBlock.Height() - 1) / core.ChunkSize
	curChunk := startChunk
	for curChunk < endChunk && curChunk-startChunk < MaxChunkPerSyncRequest {
		var headers [][]byte
		blocksTrie, err := trie.NewTrie(nil, stor, false)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("Failed to create merkle tree")
			return nil, nil, err
		}

		startHeight := curChunk*core.ChunkSize + 2
		endHeight := (curChunk+1)*core.ChunkSize + 2
		curHeight := startHeight
		for curHeight < endHeight {
			block := c.blockChain.GetBlockOnCanonicalChainByHeight(curHeight)
			if block == nil {
				logging.VLog().WithFields(logrus.Fields{
					"height": curHeight + 1,
				}).Debug("Failed to find the block on canonical chain.")
				return nil, nil, ErrCannotFindBlockByHeight
			}
			headers = append(headers, block.Hash())
			_, _ = blocksTrie.Put(block.Hash(), block.Hash())
			curHeight++
		}
		chunkHeaders = append(chunkHeaders, &syncpb.ChunkHeader{Headers: headers, Root: blocksTrie.RootHash()})
		_, _ = chunksTrie.Put(blocksTrie.RootHash(), blocksTrie.RootHash())

		curChunk++
	}

	logging.VLog().WithFields(logrus.Fields{
		"syncpoint": startBlock,
		"start":     startChunk,
		"end":       endChunk,
		"limit":     MaxChunkPerSyncRequest,
		"synced":    len(chunkHeaders),
	}).Debug("Succeed to generate chunks meta info.")
	return chunkHeaders, chunksTrie.RootHash(), nil
}
