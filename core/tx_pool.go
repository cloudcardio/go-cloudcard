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
	"container/heap"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/sorted"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"sync"
)

const (
	// transaction pool
	pledgeSize  = 2048
	pendingSize = 4096
	poolSize    = 8192

	//
	defaultLimit = 10
	maxLimit     = 50
	pageNumber   = 1
)

var (
	ErrNoData   = errors.New("the page size no data")
	ErrPoolFull = errors.New("tx pool is full")
)

// TxPool
type TxPool struct {
	pending   timeHeap
	pledgeTxs timeHeap

	all     map[string]*Transaction
	addrTxs map[string]*sorted.Slice

	chain *BlockChain
	ns    network.Service

	quitCh chan int
	recvCh chan network.Message
	mu     sync.RWMutex
}

// NewTxPool
func NewTxPool() *TxPool {
	return &TxPool{
		pending:   make(timeHeap, 0, pendingSize),
		pledgeTxs: make(timeHeap, 0, pledgeSize),
		quitCh:    make(chan int),
		recvCh:    make(chan network.Message, poolSize),
		all:       make(map[string]*Transaction),
		addrTxs:   make(map[string]*sorted.Slice),
		mu:        sync.RWMutex{},
	}
}

// RegisterInNetwork
func (pool *TxPool) RegisterInNetwork(ns network.Service) {
	ns.Register(network.NewSubscriber(pool, pool.recvCh, true, MessageTypeNewTx, network.MessageWeightNewTx))
	pool.ns = ns
}

//
func (pool *TxPool) loop() {
	for {
		select {
		case <-pool.quitCh:
			logging.CLog().WithFields(logrus.Fields{}).Info("Stopped transaction pool")
			return
		case msg := <-pool.recvCh:
			if msg.MessageType() != MessageTypeNewTx {
				logging.VLog().WithFields(logrus.Fields{
					"messageType": msg.MessageType(),
					"message":     msg,
					"err":         "not new tx msg",
				}).Debug("Received unregistered message")
				continue
			}
			tx := new(Transaction)
			pbTx := new(corepb.Transaction)
			if err := proto.Unmarshal(msg.Data(), pbTx); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"msgType": msg.MessageType(),
					"msg":     msg,
					"err":     err,
				}).Debug("Failed to unmarshal data")
				continue
			}
			if err := tx.FromProto(pbTx); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"msgType": msg.MessageType(),
					"msg":     msg,
					"err":     err,
				}).Debug("Failed to recover a transaction from proto data")
				continue
			}
			if err := pool.AddAndRelay(tx); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"func":        "TxPool.loop",
					"messageType": msg.MessageType(),
					"transaction": tx,
					"err":         err,
				}).Debug("Failed to add a transaction into transaction pool")
				continue
			}
		}
	}
}

//
func (pool *TxPool) setBlockChain(bc *BlockChain) {
	pool.chain = bc
}

// Start starts tx pool loop.
func (pool *TxPool) Start() {
	logging.CLog().Info("Start Transaction Pool...")
	go pool.loop()
}

// Stop stops tx pool loop.
func (pool *TxPool) Stop() {
	logging.CLog().Info("Stop Transaction Pool...")
	pool.quitCh <- 0
}

//
func (pool *TxPool) PendingIsEmpty() bool {
	return len(pool.pending) == 0
}

//
func (pool *TxPool) PledgeIsEmpty() bool {
	return len(pool.pledgeTxs) == 0
}

//
func (pool *TxPool) removeTransaction(tx *Transaction) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	nonce := tx.Nonce()
	var oldTx *Transaction
	if slice, ok := pool.addrTxs[tx.From().String()]; ok && slice.Len() > 0 {
		for true {
			if slice.Len() == 0 {
				break
			}
			if slice.Left().(*Transaction).nonce <= nonce {
				oldTx = slice.PopLeft().(*Transaction)
				delete(pool.all, oldTx.From().String())
				logging.VLog().WithFields(logrus.Fields{
					"txHash":  tx.Hash(),
					"txNonce": tx.Nonce(),
				}).Debug("Remove had packaged transactions")
				continue
			}
			break
		}
	}
	delete(pool.all, tx.Hash().String())
}

//
func (pool *TxPool) GetTxsNumByAddr(addr string) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	slice := pool.addrTxs[addr]
	if slice == nil {
		return 0
	}

	return pool.addrTxs[addr].Len()
}

// GetPendingTransactionsByPage
func (pool *TxPool) GetPendingTransactionsByPage(pageNum uint, limit uint) ([]*Transaction, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if limit == 0 {
		limit = defaultLimit
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	if pageNum == 0 {
		pageNum = pageNumber
	}
	start := (pageNum - 1) * limit
	num := int64(uint(len(pool.pending)) - 1 - start)
	if num < 0 {
		return nil, ErrNoData
	}

	//handle tail page not enough limit size
	if uint(num) < limit {
		limit = uint(num) + 1
	}

	txs := make([]*Transaction, limit)
	index := 0
	for i := uint(0); i < limit; i++ {
		index = int(start + i)
		txs[i] = pool.pending[index]
	}
	return txs, nil
}

// GetPendingTxSize
func (pool *TxPool) GetPendingTxSize() uint {
	if pool == nil {
		logging.VLog().Debug("transaction pool is nil")
		return 0
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return uint(len(pool.all))
}

// TakeTransaction
func (pool *TxPool) TakeTransferTransaction(isPledgeTx bool) *Transaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if isPledgeTx {
		if pool.PledgeIsEmpty() {
			return nil
		}
	} else {
		if pool.PendingIsEmpty() {
			return nil
		}
	}

	var tx *Transaction
	var slice *sorted.Slice
	ok := false

	for true {
		if isPledgeTx {
			if pool.PledgeIsEmpty() {
				return nil
			}
			tx = heap.Pop(&pool.pledgeTxs).(*Transaction)
		} else {
			if pool.PendingIsEmpty() {
				return nil
			}
			tx = heap.Pop(&pool.pending).(*Transaction)
		}

		slice, ok = pool.addrTxs[tx.From().String()]
		if !ok || slice.Len() == 0 {
			logging.VLog().WithFields(logrus.Fields{
				"transaction": tx,
				"from":        tx.From(),
			}).Error("addrTxs has not the tx")
			continue
		}
		nonce := slice.Left().(*Transaction).Nonce()
		//Ignore lower nonce transactions
		if tx.Nonce() < nonce {
			delete(pool.all, tx.Hash().String())
			continue
		}
		break
	}

	var equalNonceMaxPriorityTx *Transaction
	nonce := uint64(0)
	for true {
		if slice.Len() == 0 {
			break
		}
		nonce = slice.Left().(*Transaction).Nonce()
		if nonce != tx.Nonce() {
			break
		}
		//Ignore lower priority transactions with the same nonce
		equalNonceMaxPriorityTx = slice.PopLeft().(*Transaction)
		//delete from all tx pool
		delete(pool.all, equalNonceMaxPriorityTx.Hash().String())
	}
	return equalNonceMaxPriorityTx
}

//
func (pool *TxPool) TakePledgeTransaction() *Transaction {
	if pool.PledgeIsEmpty() {
		return nil
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	tx := heap.Pop(&pool.pledgeTxs).(*Transaction)

	return tx
}

//
func (pool *TxPool) ClearPledgeTransactions() {
	logging.CLog().Info("clear vote transactions")
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.pledgeTxs = make(timeHeap, 0, pledgeSize)
}

// AddAndBroadcast adds a tx into pool and broadcast it.
func (pool *TxPool) AddAndBroadcast(tx *Transaction) error {
	if err := pool.Add(tx); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx.Hash(),
			"err": err,
		}).Debug("Failed to add transaction")
		return err
	}

	pool.ns.Broadcast(MessageTypeNewTx, tx, network.MessagePriorityNormal)

	return nil
}

//
func (pool *TxPool) Add(tx *Transaction) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if _, ok := pool.all[tx.Hash().String()]; ok {
		return nil
	}
	if len(pool.all) == poolSize {
		return ErrTxPoolFull
	}

	if err := tx.VerifyIntegrity(pool.chain.ChainId()); err != nil {
		return err
	}

	switch tx.Type() {
	case PledgeTx:
		pool.AddPledgeTransaction(tx)
	case TransferTx:
		pool.AddTransferTransaction(tx)
	}

	return nil
}

// AddAndRelay adds a tx into pool and relay it.
func (pool *TxPool) AddAndRelay(tx *Transaction) error {
	if err := pool.Add(tx); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx.Hash(),
			"err": err,
		}).Debug("Failed to add transaction")
		return err
	}

	pool.ns.Relay(MessageTypeNewTx, tx, network.MessagePriorityNormal)

	return nil
}

// AddTransferTransaction
func (pool *TxPool) AddTransferTransaction(tx *Transaction) {
	if len(pool.pending) == pendingSize {
		logging.CLog().Debug("pending pool is full")
	}

	// add tx into addrTxs
	from := tx.From().String()
	addrTxsMap, ok := pool.addrTxs[from]
	if !ok {
		addrTxsMap = sorted.NewSlice(noncePriorityCmp)
		pool.addrTxs[from] = addrTxsMap
	}

	addrTxsMap.Push(tx)

	// add tx to pending
	heap.Push(&pool.pending, tx)

	// add tx to all
	pool.all[tx.Hash().String()] = tx
}

// AddPledgeTransaction
func (pool *TxPool) AddPledgeTransaction(tx *Transaction) {
	if len(pool.pledgeTxs) == pledgeSize {
		return
	}

	// add tx into addrTxs
	from := tx.From().String()
	addrTxsMap, ok := pool.addrTxs[from]
	if !ok {
		addrTxsMap = sorted.NewSlice(noncePriorityCmp)
		pool.addrTxs[from] = addrTxsMap
	}

	addrTxsMap.Push(tx)

	// add tx to voteTxs
	heap.Push(&pool.pledgeTxs, tx)

	// add tx to all
	pool.all[tx.Hash().String()] = tx
}

func noncePriorityCmp(a interface{}, b interface{}) int {
	txa := a.(*Transaction)
	txb := b.(*Transaction)
	if txa.Nonce() < txb.Nonce() {
		return -1
	} else if txa.Nonce() > txb.Nonce() {
		return 1
	}

	//Nonce equal
	if txa.Priority() < txb.Priority() {
		return -1
	} else if txa.Priority() > txb.Priority() {
		return 1
	}
	logging.VLog().WithFields(logrus.Fields{
		"txa": txa,
		"txb": txb,
	}).Error("tx nonce equal and priority equal")
	return 0
}
