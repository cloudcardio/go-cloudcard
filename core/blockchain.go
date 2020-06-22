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
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-cloudcard library.  If not, see <http://www.gnu.org/licenses/>.
//
package core

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/conf"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"errors"
	"github.com/gogo/protobuf/proto"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"time"
)

var (
	ContractAddressIsNilError  = errors.New("contract address is nil")
	TxHashLengthNotMatchError  = errors.New("tx hash is not 64")
	TransactionNotFoundInBlock = errors.New("transaction not found in block")
)

const (
	// ChunkSize is the size of blocks in a chunk
	ChunkSize = 32
	// Tail Key in storage
	Tail = "blockchain_tail"
	// Fixed in storage
	Fixed = "blockchain_fixed"
	// Latest Propose in storage
	Propose = "consensus_propose"
	// standby nodes
	StandbyNodes = "standby_nodes"
	// transaction's block height
	TxBlockHeight = "height"
	//
	TermID = "term_id"
)

// BlockChain
type BlockChain struct {
	chainId   uint32
	consensus Consensus
	sync      Synchronize

	config  *config.Config
	db      cdb.Storage
	genesis *corepb.Genesis

	tailBlock    *Block
	fixedBlock   *Block
	genesisBlock *Block

	txPool *TxPool
	bkPool *BlockPool

	cachedBlocks       *lru.Cache
	detachedTailBlocks *lru.Cache

	latestPropose *corepb.Propose
	quitCh        chan int
}

func (bc *BlockChain) LatestPropose() *corepb.Propose {
	return bc.latestPropose
}

//
func (bc *BlockChain) LoadTermIdFromStorage() uint64 {
	data, err := bc.db.Get([]byte(TermID))
	if err != nil {
		return 0
	}
	id := byteutils.Uint64(data)
	return id
}

//
func (bc *BlockChain) StoreTermIdToStorage(id uint64) {
	_ = bc.db.Put([]byte(TermID), byteutils.FromUint64(id))
}

func (bc *BlockChain) LoadStandbyNodesFromStorage() []string {
	data, err := bc.db.Get([]byte(StandbyNodes))
	if err != nil {
		return nil
	}
	pbNodes := &corepb.StandByNodes{}
	if err = proto.Unmarshal(data, pbNodes); err != nil {
		return nil
	}

	return pbNodes.StandbyNodes
}

func (bc *BlockChain) SetLatestPropose(latestPropose *corepb.Propose) {
	bc.latestPropose = latestPropose
}

// NewBlockChain
func NewBlockChain(config *config.Config, net network.Service, db cdb.Storage) (*BlockChain, error) {
	blockPool, err := NewBlockPool(128)
	if err != nil {
		return nil, err
	}

	chaincfg := conf.GetChainConfig(config)
	txPool := NewTxPool()

	chain := &BlockChain{
		chainId: chaincfg.ChainId,
		config:  config,
		db:      db,
		bkPool:  blockPool,
		txPool:  txPool,
		genesis: &corepb.Genesis{},
		quitCh:  make(chan int),
	}

	blockPool.RegisterInNetwork(net)
	txPool.RegisterInNetwork(net)

	chain.cachedBlocks, err = lru.New(128)
	if err != nil {
		return nil, err
	}

	chain.detachedTailBlocks, err = lru.New(128)
	if err != nil {
		return nil, err
	}
	propose, err := chain.LoadLatestProposeFromStorage()
	if err != nil {
		return nil, err
	}
	chain.SetLatestPropose(propose)

	chain.bkPool.setBlockChain(chain)
	chain.txPool.setBlockChain(chain)

	return chain, nil
}

func (bc *BlockChain) Setup(cloudcard cloudcard) error {
	bc.consensus = cloudcard.Consensus()

	var err error

	bc.genesis, err = LoadGenesisConf(DefaultGenesisPath)
	if err != nil {
		return err
	}

	bc.genesisBlock, err = bc.LoadGenesisFromStorage()
	if err != nil {
		return err
	}

	bc.tailBlock, err = bc.LoadTailFromStorage()
	if err != nil {
		return err
	}
	logging.CLog().WithFields(logrus.Fields{
		"tail": bc.tailBlock,
	}).Info("Tail Block.")

	bc.fixedBlock, err = bc.LoadFixedFromStorage()
	if err != nil {
		return err
	}
	logging.CLog().WithFields(logrus.Fields{
		"block": bc.fixedBlock,
	}).Info("Latest Permanent Block.")

	return nil
}

// LoadLatestProposeFromStorage load latest propose
func (bc *BlockChain) LoadLatestProposeFromStorage() (*corepb.Propose, error) {
	value, err := bc.db.Get([]byte(Propose))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	} else if err == cdb.ErrKeyNotFound {
		return corepb.NewPropose(0), nil
	}
	propose := new(corepb.Propose)
	if err = proto.Unmarshal(value, propose); err != nil {
		return nil, err
	}
	return propose, nil
}

// StoreLatestProposeFromStorage store latest propose to Storage
func (bc *BlockChain) StoreLatestProposeFromStorage(propose *corepb.Propose) error {
	value, err := proto.Marshal(propose)
	if err == nil {
		return bc.db.Put([]byte(Propose), value)
	}
	return err
}

// LoadGenesisFromStorage load genesis
func (bc *BlockChain) LoadGenesisFromStorage() (*Block, error) { // ToRefine, remove or ?
	genesis, err := LoadBlockFromStorage(GenesisHash, bc)
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err == cdb.ErrKeyNotFound {
		genesis, err = NewGenesis(bc.genesis, bc)
		if err != nil {
			return nil, err
		}
		if err := bc.StoreBlockToStorage(genesis); err != nil {
			return nil, err
		}
		heightKey := byteutils.FromUint64(genesis.Height())
		if err := bc.db.Put(heightKey, genesis.Hash()); err != nil {
			return nil, err
		}
	}

	return genesis, nil
}

// LoadTailFromStorage load tail block
func (bc *BlockChain) LoadTailFromStorage() (*Block, error) {
	hash, err := bc.db.Get([]byte(Tail))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}
	if err == cdb.ErrKeyNotFound {
		genesis, err := bc.LoadGenesisFromStorage()
		if err != nil {
			return nil, err
		}

		if err := bc.StoreTailHashToStorage(genesis); err != nil {
			return nil, err
		}

		return genesis, nil
	}

	return LoadBlockFromStorage(hash, bc)
}

func (bc *BlockChain) StoreTailHashToStorage(block *Block) error {

	return bc.db.Put([]byte(Tail), block.Hash())
}

// LoadFixedFromStorage load FIXED
func (bc *BlockChain) LoadFixedFromStorage() (*Block, error) {
	hash, err := bc.db.Get([]byte(Fixed))
	if err != nil && err != cdb.ErrKeyNotFound {
		return nil, err
	}

	if err == cdb.ErrKeyNotFound {
		if err := bc.StoreFixedHashToStorage(bc.genesisBlock); err != nil {
			return nil, err
		}
		return bc.genesisBlock, nil
	}

	return LoadBlockFromStorage(hash, bc)
}

// StoreFIXEDHashToStorage store FIXED block hash
func (bc *BlockChain) StoreFixedHashToStorage(block *Block) error {
	return bc.db.Put([]byte(Fixed), block.Hash())
}

func (bc *BlockChain) ChainId() uint32      { return bc.chainId }
func (bc *BlockChain) Storage() cdb.Storage { return bc.db }

func (bc *BlockChain) SetTailBlock(newTail *Block) error {
	if newTail == nil {
		return ErrNilArgument
	}

	if err := bc.buildIndexByBlockHeight(newTail); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"newtail": newTail,
		}).Debug("Failed to build index by block height.")
	}

	//remove transactions in block from tx poll
	go bc.removeTxsInBlockFromTxPool(newTail)

	if err := bc.StoreTailHashToStorage(newTail); err != nil {
		return err
	}

	bc.tailBlock = newTail

	return nil
}

func (bc *BlockChain) GetTransactionByHash(txHash string) (*TransactionReceipt, error) {
	if txHash == "" || len(txHash) != 64 {
		return nil, TxHashLengthNotMatchError
	}
	txHashBytes, err := byteutils.FromHex(txHash)
	if err != nil {
		return nil, err
	}
	txBytes, err := bc.db.Get(txHashBytes)
	if txBytes == nil {
		return nil, err
	}
	pbTx := new(corepb.Transaction)
	if err = proto.Unmarshal(txBytes, pbTx); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"txHash": txHash,
			"err":    err,
		}).Error("unmarshal corepb.Transaction error")
		return nil, err
	}
	tx := new(Transaction)
	err = tx.FromProto(pbTx)
	if err != nil {
		return nil, err
	}

	blockHeight, err := bc.GetTransactionHeight(txHashBytes)
	if err != nil {
		return nil, err
	}

	block := bc.GetBlockOnCanonicalChainByHeight(blockHeight)
	if block == nil {
		return nil, TransactionNotFoundInBlock
	}

	txReceipt := &TransactionReceipt{
		BlockHash:   block.Hash().String(),
		BlockHeight: blockHeight,
		Tx:          tx,
	}

	return txReceipt, nil
}

func (bc *BlockChain) GetTransactionByContractAddress(contrctAddress *Address) (*TransactionReceipt, error) {
	if contrctAddress == nil {
		return nil, ContractAddressIsNilError
	}
	//TODO brady 2019/7/9 get tx by contract address
	return nil, nil
}

// GetBlockOnCanonicalChainByHash check if a block is on canonical chain
func (bc *BlockChain) GetBlockOnCanonicalChainByHash(blockHash byteutils.Hash) *Block {
	blockByHash := bc.GetBlock(blockHash)
	if blockByHash == nil {
		logging.VLog().WithFields(logrus.Fields{
			"hash": blockHash.Hex(),
			"tail": bc.tailBlock,
			"err":  "cannot find block with the given hash in local storage",
		}).Debug("Failed to check a block on canonical chain.")
		return nil
	}
	blockByHeight := bc.GetBlockOnCanonicalChainByHeight(blockByHash.Height())
	if blockByHeight == nil {
		logging.VLog().WithFields(logrus.Fields{
			"height": blockByHash.Height(),
			"tail":   bc.tailBlock,
			"err":    "cannot find block with the given height in local storage",
		}).Debug("Failed to check a block on canonical chain.")
		return nil
	}
	if !blockByHeight.Hash().Equals(blockByHash.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"blockByHash":   blockByHash,
			"blockByHeight": blockByHeight,
			"tail":          bc.tailBlock,
			"err":           "block with the given hash isn't on canonical chain",
		}).Debug("Failed to check a block on canonical chain.")
		return nil
	}
	return blockByHeight
}

// GetBlock return block of given hash from local storage and detachedBlocks.
func (bc *BlockChain) GetBlock(hash byteutils.Hash) *Block {
	v, _ := bc.cachedBlocks.Get(hash.Hex())
	if v == nil {
		block, err := LoadBlockFromStorage(hash, bc)
		if err != nil {
			return nil
		}
		return block
	}

	block := v.(*Block)
	return block
}

// GetTransactionHeight return transaction's block height
func (bc *BlockChain) GetTransactionHeight(hash byteutils.Hash) (uint64, error) {
	bytes, err := bc.db.Get(append(hash, []byte(TxBlockHeight)...))
	if err != nil {
		return 0, err
	}

	if len(bytes) == 0 {
		// for empty value (history txs), height = 0
		return 0, nil
	}

	return byteutils.Uint64(bytes), nil
}

// GetBlockOnCanonicalChainByHeight return block in given height
func (bc *BlockChain) GetBlockOnCanonicalChainByHeight(height uint64) *Block {
	if height > bc.tailBlock.Height() {
		return nil
	}

	blockHash, err := bc.db.Get(byteutils.FromUint64(height))
	if err != nil {
		return nil
	}
	return bc.GetBlock(blockHash)
}

//
func (bc *BlockChain) GetBlocksByHeight(height uint64) []*Block {
	res := make([]*Block, 0)
	b := bc.GetBlockOnCanonicalChainByHeight(height)
	if b == nil {
		return nil
	}
	res = append(res, b)
	return res
}

func (bc *BlockChain) removeTxsInBlockFromTxPool(block *Block) {
	for _, tx := range block.transactions {
		bc.txPool.removeTransaction(tx)
	}
}

//
func (bc *BlockChain) GetIndexAndHashesByHeight(height uint64) (int, []byteutils.Hash) {
	index := 0
	res := make([]byteutils.Hash, 0)
	b := bc.GetBlockOnCanonicalChainByHeight(height)
	if b == nil {
		return -1, nil
	}
	res = append(res, b.Hash())
	return index, res
}

//
func (bc *BlockChain) DetachedTailBlocks() []*Block {
	ret := make([]*Block, 0)
	for _, k := range bc.detachedTailBlocks.Keys() {
		v, _ := bc.detachedTailBlocks.Get(k)
		if v != nil {
			block := v.(*Block)
			ret = append(ret, block)
		}
	}
	return ret
}

// PutVerifiedNewBlocks put verified new blocks and tails.
func (bc *BlockChain) putVerifiedNewBlocks(parent *Block, allBlocks, tailBlocks []*Block) error {
	for _, v := range allBlocks {
		bc.cachedBlocks.Add(v.Hash().Hex(), v)
		if err := bc.StoreBlockToStorage(v); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"block": v,
				"err":   err,
			}).Debug("Failed to store the verified block.")
			return err
		}

		logging.VLog().WithFields(logrus.Fields{
			"block": v,
		}).Info("Accepted the new block on chain")

		//metricsBlockOnchainTimer.Update(time.Duration(time.Now().Unix() - v.Timestamp()))
		//for _, tx := range v.transactions {
		//	metricsTxOnchainTimer.Update(time.Duration(time.Now().Unix() - tx.Timestamp()))
		//}
	}
	for _, v := range tailBlocks {
		bc.detachedTailBlocks.Add(v.Hash().Hex(), v)
	}

	bc.detachedTailBlocks.Remove(parent.Hash().Hex())

	return nil
}

// StoreBlockToStorage store block
func (bc *BlockChain) StoreBlockToStorage(block *Block) error {
	pbBlock, err := block.ToProto()
	if err != nil {
		return err
	}
	value, err := proto.Marshal(pbBlock)
	if err != nil {
		return err
	}
	err = bc.db.Put(block.Hash(), value)
	if err != nil {
		return err
	}

	// store block's txs to storage
	for _, tx := range block.transactions {
		pbTx, err := tx.ToProto()
		if err != nil {
			continue
		}

		txBytes, err := proto.Marshal(pbTx)
		if err != nil {
			continue
		}

		_ = bc.db.Put(tx.Hash(), txBytes)
	}

	return nil
}

func (bc *BlockChain) BlockPool() *BlockPool { return bc.bkPool }
func (bc *BlockChain) TxPool() *TxPool       { return bc.txPool }
func (bc *BlockChain) Consensus() Consensus  { return bc.consensus }
func (bc *BlockChain) TailBlock() *Block     { return bc.tailBlock }

func (bc *BlockChain) GenesisBlock() *Block { return bc.genesisBlock }
func (bc *BlockChain) FixedBlock() *Block   { return bc.fixedBlock }

func (bc *BlockChain) SetFixedBlock(block *Block) { bc.fixedBlock = block }

func (bc *BlockChain) LoadBlockFromStorage(blockHash byteutils.Hash) *Block {
	value, err := bc.db.Get(blockHash)
	if err != nil {
		return nil
	}
	pbBlock := new(corepb.Block)
	block := new(Block)
	if err = proto.Unmarshal(value, pbBlock); err != nil {
		return nil
	}
	if err = block.FromProto(pbBlock); err != nil {
		return nil
	}
	return block
}

// StartActiveSync start active sync task
func (bc *BlockChain) StartActiveSync() bool {
	if bc.sync.StartActiveSync() {
		bc.consensus.SuspendMining()
		go func() {
			bc.sync.WaitingForFinish()
			bc.consensus.ResumeMining()
		}()
		return true
	}
	return false
}

// IsActiveSyncing returns true if being syncing
func (bc *BlockChain) IsActiveSyncing() bool {
	return bc.sync.IsActiveSyncing()
}

// SetSyncEngine set sync engine
func (bc *BlockChain) SetSyncEngine(syncEngine Synchronize) {
	bc.sync = syncEngine
}

// Start start loop.
func (bc *BlockChain) Start() {
	logging.CLog().Info("Starting BlockChain...")
	go bc.loop()
}

func (bc *BlockChain) loop() {
	logging.CLog().Info("Started BlockChain.")
	timerChan := time.NewTicker(5 * time.Second).C
	for {
		select {
		case <-bc.quitCh:
			logging.CLog().Info("Stopped BlockChain.")
			return
		case <-timerChan:
			bc.Consensus().UpdateFixedBlock()
		}
	}
}

func (bc *BlockChain) buildMappingByTxHashWithBlockHeight(block *Block) {
	for _, v := range block.transactions {
		bc.db.Put(append(v.hash, []byte(TxBlockHeight)...), byteutils.FromUint64(block.Height()))
	}
}

// Stop stop loop.
func (bc *BlockChain) Stop() {
	logging.CLog().Info("Stopping BlockChain...")
	bc.quitCh <- 0
}

func (bc *BlockChain) buildIndexByBlockHeight(tail *Block) error {
	err := bc.db.Put(byteutils.FromUint64(tail.Height()), tail.Hash())
	if err != nil {
		return err
	}
	go bc.buildMappingByTxHashWithBlockHeight(tail)
	return nil
}
