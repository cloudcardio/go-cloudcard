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
	"cloudcard.pro/cloudcardio/go-cloudcard/core/state"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/ed25519"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/keystore"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/sorted"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"math/big"
	"time"
)

const (
	MiningReward = int64(1000000000)

	WitnessNum = 4
	AllNum     = WitnessNum * 4
)

// Block
type Block struct {
	header       *BlockHeader
	transactions []*Transaction //
	sealed       bool
	txPool       *TxPool
	blkPool      *BlockPool
	worldState   state.WorldState
	db           cdb.Storage
}

//
type creditIndex struct {
	tx    *Transaction
	addr  string
	index int64
}

//
func cmp2(a interface{}, b interface{}) int {
	if a.(*creditIndex).index > b.(*creditIndex).index {
		return 1
	} else if a.(*creditIndex).index < b.(*creditIndex).index {
		return -1
	} else {
		return 0
	}
}

// NewBlock
func NewBlock(chainID uint32, coinbase *Address, parent *Block) (*Block, error) {
	ws, err := parent.worldState.Copy()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Debug("copy parent's world state error")
		return nil, err
	}

	block := &Block{
		header: &BlockHeader{
			chainId:       chainID,
			coinbase:      coinbase,
			parentHash:    parent.Hash(),
			height:        parent.Height() + 1,
			timestamp:     time.Now().Unix(),
		},
		sealed:       false,
		transactions: make([]*Transaction, 0),
		txPool:       parent.txPool,
		blkPool:      parent.blkPool,
		db:           parent.db,
		worldState:   ws,
	}

	if err := block.Begin(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Debug("new block's world state begins error")
		return nil, err
	}

	if err := block.rewardForMining(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Debug("reward for mining error")
		return nil, err
	}

	return block, nil
}

// CalcHash
func (block *Block) CalcHash() error {
	h, err := block.calcHash()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Calc block hash error")
		return err
	}
	block.header.hash = h
	return nil
}

func (block *Block) Header() *BlockHeader          { return block.header }
func (block *Block) Hash() byteutils.Hash          { return block.header.hash }
func (block *Block) Extra() byteutils.Hash         { return block.header.extra }
func (block *Block) Txs() []*Transaction           { return block.transactions }
func (block *Block) Timestamp() int64              { return block.header.Timestamp() }
func (block *Block) Height() uint64                { return block.header.Height() }
func (block *Block) Sealed() bool                  { return block.sealed }
func (block *Block) TermId() uint64                { return block.header.termId }
func (block *Block) SetTermId(id uint64)           { block.header.termId = id }
func (block *Block) SetHeight(height uint64)       { block.header.height = height }
func (block *Block) SetTimestamp(time int64)       { block.header.timestamp = time }
func (block *Block) SetParent(hash byteutils.Hash) { block.header.parentHash = hash }

//
func (block *Block) SetWorldState(parent *Block) {
	ws, err := parent.WorldState().Copy()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to set world state.")
		return
	}

	block.worldState = ws
}

//
func (block *Block) PutBackTxs() {
	for _, tx := range block.transactions {
		_ = block.txPool.Add(tx)
	}
}

//
func (block *Block) putBackTxsWhenPackError(txs []*Transaction) {
	for _, tx := range txs {
		_ = block.txPool.Add(tx)
	}
}

//
func (block *Block) PackTransactions(deadline int64) {
	if !block.CanElect() {
		block.packTransactions(deadline, false)
	} else {
		block.packTransactions(deadline, true)
	}
}

//
func (block *Block) CanElect() bool {
	if block.Height() == 2 {
		return true
	}

	if (block.Height()-2)%(WitnessNum*WitnessNum) == 0 {
		return true
	}

	return false
}

//
func (block *Block) packTransactions(deadline int64, isPledgeTx bool) {
	logging.CLog().Debug("Start packing transfer transactions....")
	txs := make([]*Transaction, 0)
	failedTxs := make([]*Transaction, 0)
	elapse := deadline - time.Now().Unix()
	logging.VLog().WithFields(logrus.Fields{
		"elapse": elapse,
	}).Debug("Time to pack transfer transactions")

	if elapse <= 0 {
		logging.CLog().Debug("pack transactions elapse less than 0")
		return
	}

	pool := block.txPool
	timer := time.NewTimer(time.Duration(elapse) * time.Second)
	over := false

	// collect txs in tx pool
	go func() {
		for {
			if over {
				return
			}
			tx := pool.TakeTransferTransaction(isPledgeTx)
			if tx == nil {
				continue
			}

			// 1. prepare execution environment
			if over {
				failedTxs = append(failedTxs, tx)
				return
			}
			txws, err := block.WorldState().Prepare(tx.Hash().String())
			if err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"block": block,
					"tx":    tx,
					"err":   err,
				}).Debug("Prepare transfer transaction error")
				failedTxs = append(failedTxs, tx)
				continue
			}

			if over {
				failedTxs = append(failedTxs, tx)
				return
			}

			// 2. execute transaction
			if _, err = block.ExecuteTransaction(tx, txws); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"block": block,
					"tx":    tx,
					"err":   err,
				}).Debug("Execute transfer transaction error")
				failedTxs = append(failedTxs, tx)
				continue
			}

			// 3. check and update transaction
			if over {
				failedTxs = append(failedTxs, tx)
				return
			}
			if _, err = txws.CheckAndUpdate(); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"block": block,
					"tx":    tx,
					"err":   err,
				}).Debug("CheckAndUpdate invalid transfer transaction")
				failedTxs = append(failedTxs, tx)
				continue
			}
			txs = append(txs, tx)
		}
	}()

	select {
	case <-timer.C:
		block.transactions = txs
		over = true
		logging.CLog().WithFields(logrus.Fields{
			"txs_amount": len(txs),
		}).Info("Finished to pack transfer transactions")
	}

	if len(failedTxs) > 0 {
		logging.VLog().Debug("back failed txs")
		go block.putBackTxsWhenPackError(failedTxs)
	}

	if isPledgeTx {
		if err := block.calcCreditIndex(txs); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("Calc credit index error")
		}
	}
}

//
func (block *Block) calcCreditIndex(txs []*Transaction) error {
	allAddrs := block.blkPool.termAllAddrsNum()
	allTxs := block.blkPool.termAllTxsNum()
	allCons := block.blkPool.termAllConsNum()
	avgTxPerAddr := allTxs / allAddrs
	avgConPerAddr := allCons / allAddrs
	res := sorted.NewSlice(cmp2)

	sum := big.NewInt(0)
	for _, tx :=range txs {
		sum.Add(sum, tx.value)
	}

	for _, tx := range txs {
		var ts, cs int
		var doEvils, deduction, production int64
		term := (block.Height()-2) / (WitnessNum*WitnessNum)

		t := block.blkPool.addrsTxs[tx.From().String()]
		if t >= avgTxPerAddr {
			ts = 20
		} else {
			ts = 20 * t / avgTxPerAddr
		}

		cons := block.blkPool.addrsCons[tx.From().String()]
		if cons >= avgConPerAddr {
			cs = 30
		} else {
			cs = 30 * cons / avgConPerAddr
		}

		acc, _ := block.worldState.GetOrCreateAccount(tx.From().address)
		if acc != nil {
			doEvils = int64(acc.DoEvils())
			if term%5 != 0 {
				remain := term % 5
				for j := 1; j <= int(remain); j++ {
					production += int64(acc.GetProduction())
				}
			}
		}

		if doEvils == 0 {
			deduction = 0
		} else if doEvils == 1 {
			deduction = 20
		} else {
			deduction = 20 * (2 << uint64(doEvils-1))
		}

		contribution := block.blkPool.contractContribution(tx.From().String())
		a := big.NewInt(int64(ts+cs) + contribution + production - deduction)
		b := new(big.Int).Div(new(big.Int).Mul(tx.value, big.NewInt(100)), sum)
		index := new(big.Int).Add(a, b)

		res.Push(&creditIndex{
			tx:    tx,
			addr:  tx.From().String(),
			index: index.Int64(),
		})

		//if acc != nil {
		//	_ = acc.AddCreditIndex(index)
		//}

		logging.VLog().WithFields(logrus.Fields{
			"tx_from":      tx.From().String(),
			"credit_index": index.String(),
		}).Info("Finished calc a tx's index")
	}

	electedTxs := make([]*Transaction, 0)
	if res.Len() >= WitnessNum && res.Len() < AllNum {
		for i := 0; i < WitnessNum; i++ {
			cr := res.PopRight().(*creditIndex)
			electedTxs = append(electedTxs, cr.tx)
			logging.VLog().WithFields(logrus.Fields{
				"tx_from":      cr.tx.From().String(),
				"credit_index": cr.index,
			}).Info("Elect a transaction")
		}
	} else if res.Len() >= AllNum {
		for i := 0; i < AllNum; i++ {
			cr := res.PopRight().(*creditIndex)
			electedTxs = append(electedTxs, cr.tx)
			logging.VLog().WithFields(logrus.Fields{
				"tx_from":      cr.tx.From().String(),
				"credit_index": cr.index,
			}).Info("Elect a transaction")
		}
	}

	block.transactions = make([]*Transaction, 0, len(electedTxs))
	block.transactions = append(block.transactions, electedTxs...)

	wts := new(corepb.WitnessState)
	wts.TermId = block.txPool.chain.Consensus().TermId() + 1
	switch len(electedTxs) {
	case WitnessNum:
		wts.Witnesses = make([]*corepb.Group, WitnessNum)
		for i, tx := range electedTxs {
			group := &corepb.Group{}
			group.Master = tx.From().String()
			wts.Witnesses[i] = group
		}

	case AllNum:
		wts.Witnesses = make([]*corepb.Group, AllNum)
		for i, tx := range electedTxs {
			group := &corepb.Group{}
			group.Master = tx.From().String()
			group.Members = make([]string, 3)
			group.Members[0] = electedTxs[i*3+WitnessNum].From().String()
			group.Members[1] = electedTxs[i*3+WitnessNum+1].From().String()
			group.Members[2] = electedTxs[i*3+WitnessNum+2].From().String()
			wts.Witnesses[i] = group
		}
	}

	if err := block.WorldState().PutWitnesses(wts); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[Calc Index] error")
		return err
	}

	block.txPool.chain.consensus.SetTermId(wts.TermId)
	block.header.consensusRoot = block.WorldState().WitnessRoot()
	block.blkPool.ClearCacheForCreditIndex()

	return nil
}

//
func (block *Block) Seal() error {
	if block.sealed {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
		}).Debug("Cannot seal a block twice")
		return errors.New("cannot seal a block twice")
	}

	defer block.RollBack()

	if err := block.WorldState().Flush(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Debug("Flush block's world state error when seal")
		return err
	}

	block.header.stateRoot = block.WorldState().AccountsRoot()
	block.header.txsRoot = block.WorldState().TxsRoot()
	block.header.consensusRoot = block.WorldState().WitnessRoot()

	hash, err := block.calcHash()
	if err != nil {
		return err
	}

	block.header.hash = hash
	block.sealed = true

	logging.VLog().WithFields(logrus.Fields{
		"block": block,
	}).Info("Sealed Block")

	return nil
}

// LoadBlockFromStorage return a block from storage
func LoadBlockFromStorage(hash byteutils.Hash, chain *BlockChain) (*Block, error) {
	if chain == nil {
		return nil, ErrNilArgument
	}

	value, err := chain.db.Get(hash)
	if err != nil {
		return nil, err
	}
	pbBlock := new(corepb.Block)
	block := new(Block)
	if err = proto.Unmarshal(value, pbBlock); err != nil {
		return nil, err
	}
	if err = block.FromProto(pbBlock); err != nil {
		return nil, err
	}

	block.worldState, err = state.NewWorldState(chain.db)
	if err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadAccountsRoot(block.StateRoot()); err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadTxsRoot(block.TxsRoot()); err != nil {
		return nil, err
	}
	if err := block.WorldState().LoadWitnessRoot(block.WitnessRoot()); err != nil {
		return nil, err
	}

	block.db = chain.db
	block.txPool = chain.txPool
	block.blkPool = chain.bkPool

	return block, nil
}

// ToProto converts domain Block into proto Block
func (block *Block) ToProto() (proto.Message, error) {
	header, err := block.header.ToProto()
	if err != nil {
		return nil, err
	}
	if header, ok := header.(*corepb.BlockHeader); ok {
		txs := make([]*corepb.Transaction, len(block.transactions))
		for idx, v := range block.transactions {
			tx, err := v.ToProto()
			if err != nil {
				return nil, err
			}
			if tx, ok := tx.(*corepb.Transaction); ok {
				txs[idx] = tx
			} else {
				return nil, ErrInvalidProtoToTransaction
			}
		}
		return &corepb.Block{
			Hash:   block.Hash(),
			Header: header,
			Body:   txs,
		}, nil
	}
	return nil, ErrInvalidProtoToBlock
}

// HashPbBlock return the hash of pb block.
func HashPbBlock(pbBlock *corepb.Block) (byteutils.Hash, error) {
	block := new(Block)
	if err := block.FromProto(pbBlock); err != nil {
		return nil, err
	}
	return block.calcHash()
}

// CalcHash calculate the hash of block.
func (block *Block) calcHash() (byteutils.Hash, error) {
	hasher := sha3.New256()
	hasher.Write(block.ParentHash())
	hasher.Write(block.Coinbase().Bytes())
	hasher.Write(byteutils.FromUint32(block.header.chainId))
	hasher.Write(byteutils.FromInt64(block.header.timestamp))
	hasher.Write(block.StateRoot())
	hasher.Write(block.TxsRoot())
	hasher.Write(block.header.extra)

	for _, tx := range block.transactions {
		hasher.Write(tx.Hash())
	}

	return hasher.Sum(nil), nil
}

// FromProto converts proto Block to domain Block
func (block *Block) FromProto(msg proto.Message) error {
	if msg, ok := msg.(*corepb.Block); ok {
		if msg != nil {
			block.header = new(BlockHeader)
			if err := block.header.FromProto(msg.Header); err != nil {
				return err
			}
			block.transactions = make(Transactions, len(msg.Body))
			for idx, v := range msg.Body {
				if v != nil {
					tx := new(Transaction)
					if err := tx.FromProto(v); err != nil {
						return err
					}
					block.transactions[idx] = tx
				} else {
					return ErrInvalidProtoToTransaction
				}
			}
			return nil
		}
		return ErrInvalidProtoToBlock
	}
	return ErrInvalidProtoToBlock
}

// VerifyIntegrity verify block's hash, txs' integrity and consensus acceptable.
func (block *Block) VerifyIntegrity(chainId uint32, consensus Consensus) error {
	if consensus == nil {
		//metricsInvalidBlock.Inc(1)
		return ErrNilArgument
	}

	// check ChainID.
	if block.header.chainId != chainId {
		logging.VLog().WithFields(logrus.Fields{
			"expect": chainId,
			"actual": block.header.chainId,
		}).Info("Failed to check chain id")
		//metricsInvalidBlock.Inc(1)
		return ErrInvalidBlockHeaderChainID
	}

	// verify transactions integrity.
	for _, tx := range block.transactions {
		if err := tx.VerifyIntegrity(block.header.chainId); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"tx":  tx,
				"err": err,
			}).Info("Failed to verify tx's integrity")
			//metricsInvalidBlock.Inc(1)
			return err
		}
	}

	// verify block hash.
	wantedHash, err := block.calcHash()
	if err != nil {
		return err
	}
	if !wantedHash.Equals(block.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": wantedHash,
			"actual": block.Hash(),
			"err":    err,
		}).Info("Failed to check block's hash")
		//metricsInvalidBlock.Inc(1)
		return ErrInvalidBlockHash
	}

	sign := new(ed25519.Signature)
	result, err := sign.Verify(block.Hash(), block.header.sign)
	if !result {
		logging.VLog().WithFields(logrus.Fields{
			"blockHash": wantedHash,
			"sign":      byteutils.Hex(block.header.sign.Data),
			"pubKey":    byteutils.Hex(block.header.sign.Signer),
			"err":       err,
		}).Info("Failed to check block's signature")
		return ErrInvalidBlockSign
	}

	//verify the block is acceptable by consensus.
	if err := consensus.VerifyBlock(block); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Info("Failed to verify block")
		metricsInvalidBlock.Inc(1)
		return err
	}

	return nil
}

// LinkParentBlock link parent block, return true if hash is the same; false otherwise.
func (block *Block) LinkParentBlock(chain *BlockChain, parentBlock *Block) error {
	if !block.ParentHash().Equals(parentBlock.Hash()) {
		return ErrLinkToWrongParentBlock
	}

	var err error
	if block.worldState, err = parentBlock.WorldState().Copy(); err != nil {
		return ErrCloneAccountState
	}

	block.header.height = parentBlock.header.height + 1
	block.db = parentBlock.db
	block.txPool = parentBlock.txPool
	block.blkPool = parentBlock.blkPool
	return nil
}

// ExecuteTx
func (block *Block) ExecuteTransaction(tx *Transaction, ws WorldState) (bool, error) {
	var (
		giveback bool
		err      error
	)

	if giveback, err = CheckTransaction(tx, ws); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx,
			"err": err,
		}).Info("Failed to check transaction")
		return giveback, err
	}

	if giveback, err := VerifyExecution(tx, block, ws); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx,
			"err": err,
		}).Info("Failed to verify transaction execution")
		return giveback, err
	}

	if giveback, err := AcceptTransaction(tx, ws); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx":  tx,
			"err": err,
		}).Info("Failed to accept transaction")
		return giveback, err
	}

	return false, nil
}

// VerifyExecution execute the block and verify the execution result.
func (block *Block) VerifyExecution() error {
	if err := block.Begin(); err != nil {
		return err
	}

	if err := block.execute(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Debug("execute block error")
		block.RollBack()
		return err
	}

	if err := block.verifyState(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Debug("verify block's state error")
		block.RollBack()
		return err
	}

	block.Commit()

	logging.VLog().WithFields(logrus.Fields{
		"block": block,
		"txs":   len(block.Transactions()),
	}).Info("Verify txs succeed")

	return nil
}

func (block *Block) rewardForMining() error {
	coinbase := block.Coinbase().Bytes()
	acc, err := block.WorldState().GetOrCreateAccount(coinbase)
	if err != nil {
		return err
	}

	if err = acc.AddBalance(big.NewInt(MiningReward)); err != nil {
		return err
	}

	return nil
}

// Execute block and return result.
func (block *Block) execute() error {
	if err := block.rewardForMining(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("reward for mining error")
		return err
	}

	for _, tx := range block.transactions {
		txws, err := block.WorldState().Prepare(tx.Hash().String())
		if err != nil {
			continue
		}

		if _, err := block.ExecuteTransaction(tx, txws); err != nil {
			continue
		}

		if _, err := txws.CheckAndUpdate(); err != nil {
			continue
		}
	}

	// pledge tx
	if len(block.transactions) > 0 && block.transactions[0].Type() == PledgeTx {
		txs := block.transactions
		txLen := len(txs)
		termId := block.header.termId + 1
		block.txPool.chain.consensus.SetTermId(termId)
		pbWitnessState := new(corepb.WitnessState)
		pbWitnessState.TermId = termId

		switch txLen {
		case WitnessNum:
			witnesses := make([]*corepb.Group, 0, WitnessNum)
			for i := 0; i < WitnessNum; i++ {
				group := new(corepb.Group)
				group.Master = txs[i].From().String()
				witnesses = append(witnesses, group)
			}
			pbWitnessState.Witnesses = witnesses

		case AllNum:
			witnesses := make([]*corepb.Group, 0, AllNum)
			for i := 0; i < AllNum; i++ {
				group := new(corepb.Group)
				group.Master = txs[i].From().String()
				group.Members[0] = txs[i*3+WitnessNum].From().String()
				group.Members[1] = txs[i*3+WitnessNum+1].From().String()
				group.Members[2] = txs[i*3+WitnessNum+2].From().String()
				witnesses = append(witnesses, group)
			}
			pbWitnessState.Witnesses = witnesses
		}

		if err := block.WorldState().PutWitnesses(pbWitnessState); err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"witness_num": len(pbWitnessState.Witnesses),
				"err":         err,
			}).Debug("Put witnesses error when execute")
			return err
		}

		block.header.consensusRoot = block.WorldState().WitnessRoot()
		//block.calcCreditIndex(txs)

	}

	if err := block.WorldState().Flush(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("flush state error when execute block's transactions")
		return err
	}

	return nil
}

// RollBack a batch task
func (block *Block) RollBack() {
	if err := block.WorldState().RollBack(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to rollback the block")
	}
}

// verifyState return state verify result.
func (block *Block) verifyState() error {
	// verify state root.
	if !byteutils.Equal(block.WorldState().AccountsRoot(), block.StateRoot()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": block.StateRoot(),
			"actual": block.WorldState().AccountsRoot(),
		}).Info("Failed to verify account state")
		return ErrInvalidBlockStateRoot
	}

	// verify transaction root.
	if !byteutils.Equal(block.WorldState().TxsRoot(), block.TxsRoot()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": block.TxsRoot(),
			"actual": block.WorldState().TxsRoot(),
		}).Info("Failed to verify txs state")
		return ErrInvalidBlockTxsRoot
	}

	return nil
}

// Commit a batch task
func (block *Block) Commit() {
	if err := block.WorldState().Commit(); err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Fatal("Failed to commit the block")
	}
}

//
func (block *Block) PutWitnesses(wts *corepb.WitnessState) error {
	return block.WorldState().PutWitnesses(wts)
}

// Begin a batch task
func (block *Block) Begin() error {
	return block.WorldState().Begin()
}

// WorldState return the world state of the block
func (block *Block) WorldState() state.WorldState {
	return block.worldState
}

// StateRoot return state root hash.
func (block *Block) StateRoot() byteutils.Hash {
	return block.header.stateRoot
}

// TxsRoot return txs root hash.
func (block *Block) TxsRoot() byteutils.Hash {
	return block.header.txsRoot
}

func (block *Block) WitnessRoot() byteutils.Hash {
	return block.header.consensusRoot
}

// ConsensusRoot returns block's consensus root.
func (block *Block) ConsensusRoot() byteutils.Hash {
	return block.header.consensusRoot
}

// ParentHash return parent hash.
func (block *Block) ParentHash() byteutils.Hash {
	return block.header.parentHash
}

// Coinbase return coinbase
func (block *Block) Coinbase() *Address {
	return block.header.coinbase
}

// Transactions returns block transactions
func (block *Block) Transactions() Transactions {
	return block.transactions
}

// Signature return block's signature
func (block *Block) Signature() *corepb.Signature {
	return block.header.sign
}

// SignHash return block's sign hash
func (block *Block) SignHash() byteutils.Hash {
	return block.header.sign.GetData()
}

func (block *Block) Sign(signature keystore.Signature) error {
	if signature == nil {
		return ErrNilArgument
	}
	sign, err := signature.Sign(block.header.hash)
	if err != nil {
		return err
	}
	block.header.sign = &corepb.Signature{
		Signer: sign.GetSigner(),
		Data:   sign.GetData(),
	}
	return nil
}
