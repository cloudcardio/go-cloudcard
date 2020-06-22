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
	"cloudcard.pro/cloudcardio/go-cloudcard/account"
	"cloudcard.pro/cloudcardio/go-cloudcard/conf"
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/core/state"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/ed25519"
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/storage/cdb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"math/big"
	"sync"
	"time"
)

// Psec
type Psec struct {
	coinbase  *core.Address
	termId    uint64
	db        cdb.Storage
	am        core.AccountManager
	ns        network.Service
	chain     *core.BlockChain
	messageCh chan network.Message

	// paxos
	fixedStandbyNodes map[string]string
	standbyPeers      *sync.Map
	paxos             *Paxos
	standby           bool

	// pbft
	pbft *PBFT

	// mine flag
	hasVoted bool
	enable   bool
	suspend  bool

	// quit channel
	quitCh        chan bool
	quitStandby   chan bool
	quitBlockLoop chan bool
}

//
func NewPsec(db cdb.Storage) *Psec {
	return &Psec{
		db:                db,
		enable:            false,
		suspend:           false,
		hasVoted:          false,
		standby:           false,
		standbyPeers:      new(sync.Map),
		fixedStandbyNodes: make(map[string]string),
		messageCh:         make(chan network.Message, 128),
		quitCh:            make(chan bool),
		quitStandby:       make(chan bool),
		quitBlockLoop:     make(chan bool),
	}
}

//
func (psec *Psec) IsValidStandbyNode(addr string) bool {
	if _, ok := psec.fixedStandbyNodes[addr]; !ok {
		return false
	}
	return true
}

//
func (psec *Psec) StandbyCount() int {
	count := 0
	psec.standbyPeers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

//
func (psec *Psec) StandbyPeers() map[string]string {
	mp := make(map[string]string)
	psec.standbyPeers.Range(func(key, value interface{}) bool {
		mp[key.(string)] = value.(string)
		return true
	})
	return mp
}

//
func (psec *Psec) Setup(cloudcard core.cloudcard) error {
	var err error
	psec.chain = cloudcard.BlockChain()
	psec.ns = cloudcard.NetService()
	psec.am = cloudcard.AccountManager()
	psec.pbft = NewPbft(psec, psec.ns, psec.chain)

	psec.termId = psec.chain.LoadTermIdFromStorage()

	if psec.coinbase, err = core.AddressParse(conf.GetChainConfig(cloudcard.Config()).Coinbase); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Info("Failed to get coinbase from configure.")
	}

	if psec.coinbase != nil {
		nodes := psec.chain.LoadStandbyNodesFromStorage()
		psec.standbyPeers.Store(psec.coinbase.String(), psec.ns.Node().ID())

		for _, addr := range nodes {
			if psec.coinbase.String() == addr {
				psec.standby = true
			}

			psec.fixedStandbyNodes[addr] = addr
		}
	}

	if psec.standby {
		psec.paxos = NewPaxos(psec, psec.ns, psec.chain)
		// register message
		psec.ns.Register(network.NewSubscriber(psec, psec.messageCh, false, network.StandBy, network.MessageWeightStandby))
		// regiter paxos message
		psec.paxos.ns.Register(network.NewSubscriber(psec.paxos, psec.paxos.messageCh, false, network.ProposalID, network.MessageWeightStandby))
		psec.paxos.ns.Register(network.NewSubscriber(psec.paxos, psec.paxos.messageCh, false, network.Promise, network.MessageWeightStandby))
		psec.paxos.ns.Register(network.NewSubscriber(psec.paxos, psec.paxos.messageCh, false, network.Accept, network.MessageWeightStandby))
		psec.paxos.ns.Register(network.NewSubscriber(psec.paxos, psec.paxos.messageCh, false, network.Accepted, network.MessageWeightStandby))
		psec.paxos.ns.Register(network.NewSubscriber(psec.paxos, psec.paxos.messageCh, false, network.LatestPropose, network.MessageWeightStandby))
		return nil
	}

	// register pbft message
	psec.pbft.ns.Register(network.NewSubscriber(psec.pbft, psec.pbft.messageCh, false, network.PbftPreprepare, network.MessageWeightStandby))
	psec.pbft.ns.Register(network.NewSubscriber(psec.pbft, psec.pbft.messageCh, false, network.PbftPrepare, network.MessageWeightStandby))
	psec.pbft.ns.Register(network.NewSubscriber(psec.pbft, psec.pbft.messageCh, false, network.PbftCommit, network.MessageWeightStandby))

	return nil
}

// disable mining and exit consensus
func (psec *Psec) Stop() {
	logging.CLog().Info("Stopping Psec Consensus...")
	psec.DisableMining()
	psec.quitBlockLoop <- true

}

func (psec *Psec) IsEnable() bool          { return psec.enable }
func (psec *Psec) IsSuspend() bool         { return psec.suspend }
func (psec *Psec) IsStandby() bool         { return psec.standby }
func (psec *Psec) Coinbase() *core.Address { return psec.coinbase }

func (psec *Psec) SetCoinbase(addr *core.Address) { psec.coinbase = addr }
func (psec *Psec) EnableMining()                  { psec.enable = true }
func (psec *Psec) DisableMining()                 { psec.enable = false }
func (psec *Psec) SuspendMining()                 { psec.suspend = true }
func (psec *Psec) ResumeMining()                  { psec.suspend = false }

func (psec *Psec) TermId() uint64      { return psec.termId }
func (psec *Psec) SetTermId(id uint64) { psec.termId = id }

//
func (psec *Psec) UpdateFixedBlock() {
	fixed := psec.chain.FixedBlock()
	tail := psec.chain.TailBlock()

	if tail != nil && fixed != nil && tail.Height() >= fixed.Height() {
		if err := psec.chain.StoreFixedHashToStorage(tail); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"err": err,
			}).Error("Failed to store fixed to storage.")
		}
		psec.chain.SetFixedBlock(tail)
	}
}

// start psec service
func (psec *Psec) Start() {
	logging.CLog().Info("Starting Psec Consensus...")
	if psec.standby {
		// standby mine
		go psec.StartStandBy()
	}
}

//
func (psec *Psec) StartMining() {
	if psec.standby {
		psec.startStandbyMining()
	} else {
		psec.startNormalMining()
	}
}

//
func (psec *Psec) startNormalMining() {
	if psec.standby {
		return
	}

	psec.EnableMining()
	go psec.blockLoop()
}


func (psec *Psec) Paxos() core.Paxos {
	return psec.paxos
}

func (psec *Psec) startStandbyMining() {
	psec.EnableMining()
	logging.CLog().Info("Starting standby mining...")

	//tail := psec.chain.TailBlock()
	//if psec.Coinbase().String() == "C11123XcqLiX3AUC4zRjyr9Bnhg9L9Zx5U866" {
	//	psec.mineBlock(tail, time.Now().Unix()+2)
	//}

	if psec.paxos.running {
		return
	}
	// send standby node message
	addrManager := psec.am.(*account.AccountManager).GetAddrManager()
	_, err := addrManager.GetKeyStore().GetUnlocked(psec.coinbase.String())
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get unlocked private key.")
		return
	}

	if psec.paxos == nil {
		psec.paxos = NewPaxos(psec, psec.ns, psec.chain)
	}
	go psec.paxos.Run()
}

func (psec *Psec) StartStandBy() {
	logging.CLog().Info("Starting standby...")
	ticker := time.NewTicker(time.Second * 5)

	for {
		select {
		case <-psec.quitStandby:
			return
		case <-ticker.C:
			// send
			addrManager := psec.am.(*account.AccountManager).AddressManager()
			signResult, err := addrManager.SignHash(psec.coinbase, []byte("standby"))
			if err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("Failed to get unlocked private key.")
				continue
			}

			signpb := &corepb.Signature{
				Signer: signResult.GetSigner(),
				Data:   signResult.GetData(),
			}

			pbData, err := proto.Marshal(signpb)
			_ = psec.ns.SendMessageToPeers(network.StandBy, pbData, network.MessagePriorityLow, new(network.ChainSyncPeersFilter))

		case msg := <-psec.messageCh:
			psec.handleStandby(msg)

		default:
		}
	}
}

func (psec *Psec) handleStandby(msg network.Message) {
	signature := new(corepb.Signature)
	err := proto.Unmarshal(msg.Data(), signature)
	msg.MessageFrom()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"pid": msg.MessageFrom(),
		}).Debug("failed to unmarshal signature.")
	}

	sign := new(ed25519.Signature)
	if ok, err := sign.Verify([]byte("standby"), signature); err == nil && ok {
		address, _ := core.NewAddressFromPublicKey(signature.Signer)
		if psec.chain.Consensus().IsValidStandbyNode(address.String()) {
			psec.standbyPeers.Store(address.String(), msg.MessageFrom())
		}
	}
}

//
func (psec *Psec) HandleFork() error {
	chain := psec.chain
	tail := chain.TailBlock()
	detachedTails := chain.DetachedTailBlocks()
	newTail := tail

	for _, v := range detachedTails {
		if less(tail, v) {
			newTail = v
		}
	}

	if newTail.Hash().Equals(tail.Hash()) {
		logging.VLog().WithFields(logrus.Fields{
			"old tail": tail,
			"new tail": newTail,
		}).Debug("Current tail is best, no need to change.")
		return nil
	}

	err := chain.SetTailBlock(newTail)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"new tail": newTail,
			"old tail": tail,
			"err":      err,
		}).Debug("Failed to set new tail block.")
		return err
	}

	logging.VLog().WithFields(logrus.Fields{
		"new tail": newTail,
		"old tail": tail,
	}).Info("change to new tail.")
	return nil
}

// AutoVote
func (psec *Psec) AutoVote(addr *core.Address, amount *big.Int) {
	timeCh := time.NewTicker(time.Second * 21 * 18 * 5).C
	for {
		select {
		case <-timeCh:
			if err := psec.Vote(addr, amount); err != nil {
				logging.CLog().WithFields(logrus.Fields{
					"err": err,
				}).Error("Failed to vote")
			}
		}
	}
}

// Vote
func (psec *Psec) Vote(addr *core.Address, amount *big.Int) error {
	if psec.hasVoted {
		logging.CLog().Info("You have voted")
		return nil
	}
	// check argument
	_, err := psec.am.AddressIsValid(addr.String())
	if err != nil || amount.Cmp(big.NewInt(0)) < 0 {
		return err
	}
	// get all accounts
	accounts, err := psec.chain.TailBlock().WorldState().Accounts()
	if err != nil {
		return err
	}

	var acc state.Account
	// check whether the account is exist.
	for _, a := range accounts {
		if a.Address().Equals(addr.Bytes()) {
			acc = a
			break
		}
	}

	if acc != nil {
		// check
		if acc.PledgeFund().Cmp(big.NewInt(0)) > 0 {
			return errors.New("You have pledged fund")
		}
		bal := acc.Balance()
		if bal.Cmp(amount) < 0 {
			return errors.New("Insufficient funds")
		}
		// new vote tx
		tx, err := core.NewPledgeTransaction(addr, amount, acc.Nonce()+1, psec.chain.ChainId(), core.PriorityNormal, core.PledgeTx, nil)
		if err != nil {
			return err
		}
		// sign tx
		if err := psec.am.SignTx(addr, tx); err != nil {
			return err
		}
		psec.hasVoted = true
		// add tx to TxPool
		psec.chain.TxPool().AddPledgeTransaction(tx)
	}

	return nil
}

// CancelVote
func (psec *Psec) CancelVote(addr *core.Address, amount *big.Int) error {
	if !psec.hasVoted {
		logging.CLog().Info("You haven't voted, cannot cancel vote")
		return nil
	}
	_, err := psec.am.AddressIsValid(addr.String())
	if err != nil || amount.Cmp(big.NewInt(0)) < 0 {
		return err
	}
	accounts, err := psec.chain.TailBlock().WorldState().Accounts()
	if err != nil {
		return err
	}

	var acc state.Account

	// check whether the account is exist.
	for _, a := range accounts {
		if a.Address().Equals(addr.Bytes()) {
			acc = a
			break
		}
	}

	if acc != nil {
		pledge := acc.PledgeFund()
		if pledge.Cmp(amount) < 0 {
			return errors.New("invalid amount")
		}
		if err := acc.SubPledgeFund(amount); err != nil {
			return err
		}
		if err := acc.AddBalance(pledge); err != nil {
			return err
		}
	}

	return nil
}

//
func (psec *Psec) blockLoop() {
	timeChan := time.NewTicker(time.Second)
	geneTime := psec.chain.GenesisBlock().Timestamp()
	for {
		select {
		case now := <-timeChan.C:
			tail := psec.chain.TailBlock()
			termId := psec.TermId()
			if (tail.Height()-2)%(core.WitnessNum*core.WitnessNum) == 0 {
				psec.chain.StoreTermIdToStorage(termId)
			}
			groups, err := tail.WorldState().CurrentWitnesses(termId)
			if err != nil {
				logging.CLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("Get witness error when mining")
				continue
			}

			var flag bool
			var group *corepb.Group
			for _, g := range groups {
				if g.Master == psec.Coinbase().String() {
					flag = true
					group = g
					break
				}
			}

			elapse := now.Unix() - geneTime
			if elapse%5 == 0 && groups[(elapse/5-1)%core.WitnessNum].Master == psec.coinbase.String() {
				if flag {
					var blk *core.Block
					if tail.Height() <= core.WitnessNum+1 {
						err := psec.mineBlock(tail, now.Unix()+2)
						if err != nil {
							logging.CLog().WithFields(logrus.Fields{
								"err": err,
							}).Debug("Mine new block error")
						}
					} else {
						blk = psec.chain.GetBlockOnCanonicalChainByHeight(tail.Height() + 1 - core.WitnessNum)
						if blk.Coinbase().String() == psec.Coinbase().String() {
							err := psec.mineBlock(tail, now.Unix()+2)
							if err != nil {
								logging.CLog().WithFields(logrus.Fields{
									"err": err,
								}).Debug("Mine new block error")
							}
						} else {
							newMiner, err := group.Next(psec.Coinbase().String())
							if err != nil || newMiner == "" {
								logging.CLog().WithFields(logrus.Fields{
									"err": err,
								}).Debug("Get next error in group")
								continue
							}

							if psec.Coinbase().String() == newMiner {
								err := psec.mineBlock(tail, now.Unix()+2)
								if err != nil {
									logging.CLog().WithFields(logrus.Fields{
										"err": err,
									}).Debug("Mine new block error")
								}
							}
						}
					}
				}
			}

		case <-psec.quitBlockLoop:
			logging.CLog().Info("Stopped Mining...")
			return
		}
	}
}

//
func (psec *Psec) mineBlock(tail *core.Block, deadline int64) error {
	if !psec.IsEnable() {
		return ErrCannotMintWhenDisable
	}
	if psec.IsSuspend() {
		return ErrCannotMintWhenPending
	}

	if tail == nil {
		err := errors.New("tail block is nil")
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Tail block is nil")
		return err
	}

	if psec.coinbase == nil {
		err := errors.New("coinbase is nil")
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Coinbase is nil")
		return err
	}

	block, err := psec.newBlock(tail, psec.coinbase, deadline)
	if err != nil {
		return err
	}

	if err := psec.pbft.Preprepare(block); err != nil {
		go block.PutBackTxs()
		return err
	}

	//_ = psec.pbft.consensus.(*Psec).addAndBroadcast(tail, block)

	return nil
}

//
func (psec *Psec) addAndBroadcast(tail *core.Block, block *core.Block) error {
	if err := psec.chain.BlockPool().AddAndBroadcast(block); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"tail":  tail,
			"block": block,
			"err":   err,
		}).Error("Failed to push new minted block into block pool")
		return err
	}

	if !psec.chain.TailBlock().Hash().Equals(block.Hash()) {
		return ErrAppendNewBlockFailed
	}

	logging.CLog().WithFields(logrus.Fields{
		"tail":  tail,
		"block": block,
	}).Info("Broadcasted new block")
	return nil
}

//
func (psec *Psec) newBlock(tail *core.Block, coinbase *core.Address, deadline int64) (*core.Block, error) {
	block, err := core.NewBlock(psec.chain.ChainId(), coinbase, tail)
	if err != nil {
		return nil, err
	}

	block.SetTermId(psec.termId)

	block.PackTransactions(deadline)

	if err = block.Seal(); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"block": block,
			"err":   err,
		}).Error("Failed to seal new block")
		go block.PutBackTxs()
		return nil, err
	}

	if err := psec.am.SignBlock(psec.coinbase, block); err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"miner": psec.coinbase,
			"err":   err,
		}).Error("Failed to sign new block.")

		go block.PutBackTxs()

		return nil, err
	}

	logging.CLog().Info("-----⚒️mined new block----- ", " Height:", block.Height(), " timestamp:", deadline, " Proposer:", psec.coinbase.String())

	return block, nil
}

func (psec *Psec) VerifyBlock(*core.Block) error {

	return nil
}

//
func less(a *core.Block, b *core.Block) bool {
	if a.Height() != b.Height() {
		return a.Height() < b.Height()
	}
	return byteutils.Less(a.Hash(), b.Hash())
}


