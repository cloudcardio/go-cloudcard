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
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/ed25519"
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"sort"
	"sync"
	"time"
)

const (
	STANDBYNUM = 5

	NoBlockArrive = iota
	NotEnoughWitness
	RecvConsensusBlock

	five = int64(5)
)

var (
	StandbyNodesMapIsEmptyError = errors.New("standby nodes map is empty")
	StandbyNodeNotFoundError    = errors.New("the standby node not found")
	StandbyNodeSignError        = errors.New("the standby node sign failed")

	PBFTSignMessageError = errors.New("PBFT sign msg error")
)

type Paxos struct {
	running bool

	consensus     core.Consensus
	ns            network.Service
	latestPropose *corepb.Propose
	chain         *core.BlockChain
	mu            *sync.RWMutex

	// paxos
	maxRound          uint64 //
	promisedNo        uint64 //
	acceptRequestSent bool
	consensusSuccess  bool
	promiseValue      map[uint64][]*corepb.Propose
	acceptValue       map[uint64]*corepb.Propose   // phrase 1 accept
	acceptedValue     map[uint64][]*corepb.Propose // phrase 2 send

	messageCh  chan network.Message
	majorityCh chan bool
	startCh    chan int
	quitCh     chan bool

	switchTimer *time.Timer
	//switch standby node times,default = 1
	switchTimes         int64
	latestProposeArrive chan bool
}

func NewPaxos(consensus core.Consensus, ns network.Service, chain *core.BlockChain) *Paxos {
	paxos := &Paxos{
		quitCh:              make(chan bool),
		startCh:             make(chan int, 128),
		majorityCh:          make(chan bool),
		latestProposeArrive: make(chan bool, 3),

		messageCh:     make(chan network.Message, 128),
		promiseValue:  make(map[uint64][]*corepb.Propose),
		acceptValue:   make(map[uint64]*corepb.Propose),
		acceptedValue: make(map[uint64][]*corepb.Propose),
		ns:            ns,
		chain:         chain,
		consensus:     consensus,
		running:       false,
		maxRound:      0,
		mu:            &sync.RWMutex{},
		latestPropose: chain.LatestPropose(),

		switchTimes: 1,
	}
	if paxos.latestPropose != nil && paxos.latestPropose.Num > paxos.maxRound {
		paxos.maxRound = paxos.latestPropose.Num
	}
	return paxos
}

func (paxos *Paxos) Run() {
	logging.CLog().Info("Start running paxos...")

	if paxos.running {
		return
	}
	paxos.running = true

	for {
		time.Sleep(time.Duration(3 * time.Second))
		if paxos.consensus.(*Psec).StandbyCount() >= (STANDBYNUM / 2) {
			break
		}
	}
	go paxos.SendMessage()
	go paxos.HandleMessage()

	select {
	case <-paxos.quitCh:
		logging.VLog().Info("quit paxos ............")
	}
}

func (paxos *Paxos) Stop() {
	paxos.quitCh <- true
}

//
func (paxos *Paxos) SendMessage() {
	logging.CLog().Info("Start sending paxos message...")
	paxos.switchTimer = time.NewTimer(time.Duration(100 * int64(time.Second)))
	paxos.switchTimer.Stop()
	for {
		select {
		case msg := <-paxos.startCh:
			if !paxos.consensus.IsEnable() {
				continue
			}
			switch msg {
			case RecvConsensusBlock:
			case NoBlockArrive:
				//init switch standby node timer
				paxos.switchStandbyNodeTimer()
				paxos.continuePropose()
				paxos.ProposeID("")
			default:
			}
		case <-paxos.latestProposeArrive:
			logging.VLog().WithFields(logrus.Fields{
				"block height": paxos.chain.TailBlock().Height(),
				"Num":          paxos.latestPropose.Num,
			}).Debug("latest Propose Arrive, stop switch timer")
			paxos.switchTimer.Stop()
			paxos.acceptValue = make(map[uint64]*corepb.Propose)
			paxos.switchTimes = 1
		case <-paxos.switchTimer.C:
			paxos.switchTimes++
			paxos.switchStandbyNodeTimer()
			myCoinBase := paxos.chain.Consensus().Coinbase().String()
			if paxos.checkProposer(myCoinBase) {
				paxos.ProposeID(myCoinBase)
			}
		default:

		}
	}

}

//
func (paxos *Paxos) ProposeID(proposer string) {
	//clear the previous consensus status
	paxos.Clear()
	if paxos.latestPropose.Num == 0 && paxos.switchTimes == 1 {
		logging.VLog().Debug("first propose id...")
		psec := paxos.consensus.(*Psec)
		orderStandbyArray, _ := getIncreasingOrderStandbyArray(psec)
		proposer = orderStandbyArray[0]
	}
	if len(proposer) > 0 && proposer == paxos.consensus.Coinbase().String() {
		if paxos.latestPropose.Num > paxos.maxRound {
			paxos.maxRound = paxos.latestPropose.Num
		}
		if paxos.promisedNo > paxos.maxRound {
			paxos.maxRound = paxos.promisedNo
		}

		paxos.maxRound++
		proposal := &corepb.Propose{
			Num:   paxos.maxRound,
			Value: nil,
		}
		data, err := proto.Marshal(proposal)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("failed to marshal proposal in ProposeID...")
		}
		paxos.broadcastMsgToStandbyNodes(network.ProposalID, data, "")
	}
}

func (paxos *Paxos) HandleMessage() {
	logging.CLog().Info("Start handling paxos message...")
	for {
		select {
		case msg := <-paxos.messageCh:
			if !paxos.consensus.IsEnable() {
				continue
			}
			switch msg.MessageType() {
			case network.ProposalID:
				if !paxos.checkSender(msg.MessageFrom()) {
					logging.VLog().WithFields(logrus.Fields{
						"paxos.checkSender()": msg.MessageFrom(),
					}).Debug("[ProposalID] sender is not standby node")
					continue
				}
				proposal := corepb.Propose{}
				err := proto.Unmarshal(msg.Data(), &proposal)
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("unmarshal proposal error.")
					continue
				}
				if proposal.Num <= paxos.promisedNo {
					logging.VLog().WithFields(logrus.Fields{
						"proposal.Num":     proposal.Num,
						"paxos.promisedNo": paxos.promisedNo,
					}).Debug("proposal.Num <= paxos.promisedNo.")
					continue
				}
				paxos.promisedNo = proposal.Num
				pbResp := paxos.maxAcceptNumberPropose()
				if pbResp == nil {
					pbResp = &corepb.Propose{
						Num: 0,
					}
				}
				err = paxos.SignPropose(pbResp)
				if err != nil {
					continue
				}
				promise := &corepb.Promise{
					ProposalId:         proposal.Num,
					MaxAcceptedPropose: pbResp,
				}

				data, err := proto.Marshal(promise) // marshal response
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("marshal proposalID response error.")
					continue
				}

				// send response
				_ = paxos.ns.SendMessageToPeer(network.Promise, data, network.MessagePriorityHigh, msg.MessageFrom())
				logging.VLog().WithFields(logrus.Fields{
					"to":               msg.MessageFrom(),
					"paxos.promisedNo": paxos.promisedNo,
					"paxos.maxRound":   paxos.maxRound,
				}).Debug("send promise to proposer...")
			case network.Promise:
				if !paxos.checkSender(msg.MessageFrom()) {
					logging.VLog().WithFields(logrus.Fields{
						"paxos.checkSender()": msg.MessageFrom(),
					}).Debug("[Promise] sender is not standby node")
					continue
				}
				if paxos.acceptRequestSent {
					logging.VLog().WithFields(logrus.Fields{
						"maxRound": paxos.maxRound,
					}).Debug("[Promise] accept request had broadcast")
					continue
				}
				pbPromise := &corepb.Promise{}
				err := proto.Unmarshal(msg.Data(), pbPromise)
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("[Promise] unmarshal pbPromise error.")
					continue
				}

				if pbPromise.ProposalId != paxos.maxRound {
					logging.VLog().WithFields(logrus.Fields{
						"promise proposal id": pbPromise.ProposalId,
						"my ProposalID":       paxos.maxRound,
					}).Debug("promise proposal id is not equal maxRound")
					continue
				}

				pbPropose := pbPromise.MaxAcceptedPropose
				if pbPropose.Num >= paxos.maxRound {
					logging.VLog().WithFields(logrus.Fields{
						"promise num":   pbPropose.Num,
						"my ProposalID": paxos.maxRound,
					}).Debug("id of the response is greater than or equal to the proposal id ")
					continue
				}

				result := verifyPropose(pbPropose)
				if !result {
					continue
				}

				if _, ok := paxos.promiseValue[pbPropose.Num]; !ok {
					paxos.promiseValue[pbPropose.Num] = make([]*corepb.Propose, 0)
				}
				paxos.promiseValue[pbPropose.Num] = append(paxos.promiseValue[pbPropose.Num], pbPropose) // append value

				promiseCount := countPromiseValueNum(paxos.promiseValue)
				if promiseCount >= STANDBYNUM/2 {
					promiseMaxNumberPropose := paxos.maxPromiseNumberValue()
					newPropose := new(corepb.Propose)
					if promiseMaxNumberPropose.Value == nil {
						propose, err := paxos.Propose(paxos.maxRound)
						if err != nil {
							logging.VLog().WithFields(logrus.Fields{
								"err": err,
							}).Debug("propose new block error.")
							continue
						}
						newPropose = propose
						logging.VLog().WithFields(logrus.Fields{
							"Num":             newPropose.Num,
							"nextBlockHeight": paxos.chain.TailBlock().Height() + 1,
						}).Debug("promise max number propose is nil")
					} else {
						newPropose.Num = paxos.maxRound
						newPropose.Value = promiseMaxNumberPropose.Value
						logging.VLog().WithFields(logrus.Fields{
							"Num":             newPropose.Num,
							"nextBlockHeight": paxos.chain.TailBlock().Height() + 1,
						}).Debug("promise max number propose is not nil")
					}

					data, err := proto.Marshal(newPropose)
					if err != nil {
						logging.VLog().WithFields(logrus.Fields{
							"err": err,
						}).Debug("marshal pbPropose error.")
						continue
					}
					//broadcast propose to standby nodes
					paxos.broadcastMsgToStandbyNodes(network.Accept, data, "")
					paxos.acceptRequestSent = true
				}
			case network.Accept:
				if !paxos.checkSender(msg.MessageFrom()) {
					logging.VLog().WithFields(logrus.Fields{
						"paxos.checkSender()": msg.MessageFrom(),
					}).Debug("[Accept] sender is not standby node")
					continue
				}
				pbPropose := &corepb.Propose{}
				err := proto.Unmarshal(msg.Data(), pbPropose)
				if err != nil {
					continue
				}
				if pbPropose.Num < paxos.promisedNo {
					logging.VLog().WithFields(logrus.Fields{
						"Propose.Num":      pbPropose.Num,
						"paxos promisedNo": paxos.promisedNo,
					}).Debug("Propose Num < paxos promisedNo")
					continue
				}
				// verify pbpropose
				result := verifyPropose(pbPropose)
				if !result {
					continue
				}

				paxos.promisedNo = pbPropose.Num
				// accept response
				pbAcceptResp := &corepb.Propose{
					Num:   pbPropose.Num,
					Value: pbPropose.Value,
				}

				err = paxos.SignPropose(pbAcceptResp)
				if err != nil {
					continue
				}

				// send accept response
				data, err := proto.Marshal(pbAcceptResp)
				if err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Error("marshal acceptResp error.")
					continue
				}
				_ = paxos.ns.SendMessageToPeer(network.Accepted, data, network.MessagePriorityHigh, msg.MessageFrom())
				logging.VLog().WithFields(logrus.Fields{
					"to": msg.MessageFrom(),
				}).Debug("send accepted to sender...")

				// record accept propose
				paxos.acceptValue[pbPropose.Num] = pbPropose
			case network.Accepted:
				if !paxos.checkSender(msg.MessageFrom()) {
					logging.VLog().WithFields(logrus.Fields{
						"paxos.checkSender()": msg.MessageFrom(),
					}).Debug("[Accepted] sender is not standby node")
					continue
				}

				if paxos.consensusSuccess {
					logging.VLog().WithFields(logrus.Fields{
						"maxRound": paxos.maxRound,
					}).Debug("[Accepted] consensus result had broadcast")
					continue
				}
				pbAccepted := &corepb.Propose{}
				if err := proto.Unmarshal(msg.Data(), pbAccepted); err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("unmarshal propose error.")
					continue
				}
				if pbAccepted.Num != paxos.maxRound {
					logging.VLog().WithFields(logrus.Fields{
						"pbAccepted.Num": pbAccepted.Num,
						"paxos.maxRound": paxos.maxRound,
					}).Debug("pbAccepted.Num != paxos.maxRound")
					continue
				}
				// verify value
				result := verifyPropose(pbAccepted)
				if !result {
					continue
				}

				logging.VLog().WithFields(logrus.Fields{
					"from":             msg.MessageFrom(),
					"Num":              paxos.maxRound,
					"paxos.promisedNo": paxos.promisedNo,
				}).Debug("[Accepted] master proposer accepted consensus result")

				if _, ok := paxos.acceptedValue[pbAccepted.Num]; !ok {
					paxos.acceptedValue[pbAccepted.Num] = make([]*corepb.Propose, 0)
				}
				paxos.acceptedValue[pbAccepted.Num] = append(paxos.acceptedValue[pbAccepted.Num], pbAccepted)
				if len(paxos.acceptedValue[pbAccepted.Num]) >= STANDBYNUM/2 {
					paxos.consensusSuccess = true
					pbBlock := new(corepb.Block)
					if err := proto.Unmarshal(pbAccepted.Value, pbBlock); err == nil {
						block := new(core.Block)
						err = block.FromProto(pbBlock)
						if err != nil {
							logging.VLog().WithFields(logrus.Fields{
								"err": err,
							}).Debug("block from pbBlock error")
							continue
						}
						paxos.updateLatestPropose(pbAccepted)
						//update latestPropose
						paxos.latestProposeArrive <- true
						tailBlock := paxos.chain.TailBlock()
						//broadcast block
						paxos.consensus.(*Psec).addAndBroadcast(tailBlock, block)
						logging.VLog().Debug("send new block to proposer...")
						recvBlockCh := paxos.chain.BlockPool().RecvBlockCh()
						//notify myself to reset timer
						myId := paxos.ns.Node().ID()
						newBlockMsg := network.NewBaseMessage(core.MessageTypeNewBlock, myId, pbAccepted.Value)
						recvBlockCh <- newBlockMsg

						paxos.acceptValue = make(map[uint64]*corepb.Propose)
						paxos.Clear()
					}
				}
			case network.LatestPropose:
				start := time.Now().Unix()
				logging.VLog().Debug(paxos.ns.Node().ID() + ": accept latestPropose")

				if !paxos.checkSender(msg.MessageFrom()) {
					logging.VLog().WithFields(logrus.Fields{
						"paxos.checkSender()": msg.MessageFrom(),
					}).Debug("[Accepted] sender is not standby node")
					continue
				}
				pbLatestPropose := &corepb.Propose{}
				if err := proto.Unmarshal(msg.Data(), pbLatestPropose); err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("[LatestPropose] unmarshal propose error.")
					continue
				}
				if paxos.latestPropose != nil && paxos.latestPropose.Num >= pbLatestPropose.Num {
					logging.VLog().WithFields(logrus.Fields{
						"form":                 msg.MessageFrom(),
						"preLatestPropose.Num": paxos.latestPropose.Num,
						"pbLatestPropose.Num":  pbLatestPropose.Num,
					}).Debug("preLatestPropose.Num >= paxos pbLatestPropose.Num")
					continue
				}
				if pbLatestPropose.Num < paxos.promisedNo {
					logging.VLog().WithFields(logrus.Fields{
						"pbLatestPropose.Num": pbLatestPropose.Num,
						"paxos promisedNo":    paxos.promisedNo,
					}).Debug("pbLatestPropose.Num < paxos promisedNo")
					continue
				}

				// verify value
				result := verifyPropose(pbLatestPropose)
				if !result {
					continue
				}

				err := paxos.chain.StoreLatestProposeFromStorage(pbLatestPropose)
				if err != nil {
					logging.VLog().Error("store latest propose error")
				}
				paxos.mu.Lock()
				paxos.latestPropose = pbLatestPropose
				paxos.promisedNo = pbLatestPropose.Num
				paxos.maxRound = pbLatestPropose.Num
				paxos.mu.Unlock()
				paxos.latestProposeArrive <- true

				end := time.Now().Unix()
				logging.CLog().WithFields(logrus.Fields{
					"spend": end - start,
				}).Debug("handle latestPropose time")
				logging.VLog().Debug(paxos.ns.Node().ID() + ": update and store latestPropose success.")
			}
		default:
		}
	}
}

func (paxos *Paxos) checkSender(sender string) bool {
	standbyNodesMap := paxos.consensus.(*Psec).standbyPeers
	isStandByNode := false
	standbyNodesMap.Range(func(key, value interface{}) bool {
		if value == sender {
			isStandByNode = true
			return false
		}
		return true
	})
	return isStandByNode
}

func (paxos *Paxos) maxAcceptNumberPropose() *corepb.Propose {
	i := uint64(0)
	for k, _ := range paxos.acceptValue {
		if k > i {
			i = k
		}
	}
	return paxos.acceptValue[i]
}

func (paxos *Paxos) maxPromiseNumberValue() *corepb.Propose {
	i := uint64(0)
	for k, _ := range paxos.promiseValue {
		if k > i {
			i = k
		}
	}
	return paxos.promiseValue[i][0]
}

func (paxos *Paxos) Propose(proposalId uint64) (*corepb.Propose, error) {
	tailBlock := paxos.chain.TailBlock()
	coinbase := paxos.consensus.Coinbase()
	psec := paxos.consensus.(*Psec)

	block, err := psec.newBlock(tailBlock, coinbase, time.Now().Unix()) // new block
	if err != nil {
		return nil, err
	}
	pbBlock, err := block.ToProto()

	data, err := proto.Marshal(pbBlock)
	if err != nil {
		return nil, err
	}

	// propose
	pbPropose := &corepb.Propose{
		Num:   proposalId,
		Value: data,
	}

	err = paxos.SignPropose(pbPropose)
	if err != nil {
		return nil, err
	}

	return pbPropose, nil
}

func (paxos *Paxos) SignPropose(pbPropose *corepb.Propose) error {
	coinbase := paxos.consensus.Coinbase()
	hash := pbPropose.CalcHash()
	addrManager := paxos.consensus.(*Psec).am.(*account.AccountManager).GetAddrManager()
	signResult, err := addrManager.SignHash(coinbase, hash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"coinbase": coinbase.String(),
			"hash":     byteutils.Hex(hash),
			"err":      err,
		}).Debug("[SignPropose] sign propose error")
		return StandbyNodeSignError
	}

	sign := &corepb.Signature{
		Signer: signResult.GetSigner(),
		Data:   signResult.GetData(),
	}
	pbPropose.Sign = sign
	return nil
}

func (paxos *Paxos) NotifyNoBlockArrive() {
	if paxos.consensus.(*Psec).IsValidStandbyNode(paxos.consensus.Coinbase().String()) {
		paxos.startCh <- NoBlockArrive
	}
}

func (paxos *Paxos) NotifyNotEnoughWitness()   { paxos.startCh <- NotEnoughWitness }
func (paxos *Paxos) NotifyRecvConsensusBlock() { paxos.startCh <- RecvConsensusBlock }

func (paxos *Paxos) getProposerByHeight(blockHeight uint64) (*core.Address, error) {
	psec := paxos.consensus.(*Psec)
	orderStandbyArray, err := getIncreasingOrderStandbyArray(psec)
	if err != nil {
		return nil, err
	}

	//calculate standy node by block height
	index := blockHeight % uint64(len(orderStandbyArray))
	return psec.am.AddressIsValid(orderStandbyArray[index])
}

func (paxos *Paxos) getProposerByFailedNode(failedNode string) (*core.Address, error) {
	psec := paxos.consensus.(*Psec)
	_, err := psec.am.AddressIsValid(failedNode)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"failedNode": failedNode,
		}).Error("parse address failed")
		return nil, err
	}

	orderStandbyArray, err := getIncreasingOrderStandbyArray(psec)
	if err != nil {
		return nil, err
	}
	endIndex := len(orderStandbyArray) - 1
	for index, addr := range orderStandbyArray {
		if addr != failedNode {
			continue
		}
		if index == endIndex {
			//The next node of the failed node is the first
			return psec.am.AddressIsValid(orderStandbyArray[0])
		}
		return psec.am.AddressIsValid(orderStandbyArray[index+1])
	}
	return nil, StandbyNodeNotFoundError
}

func getIncreasingOrderStandbyArray(psec *Psec) ([]string, error) {
	standbyNodesMap := psec.fixedStandbyNodes
	if len(standbyNodesMap) < 1 {
		logging.VLog().WithFields(logrus.Fields{
			"standByNum": len(standbyNodesMap),
		}).Error("standby nodes map is empty")
		return nil, StandbyNodesMapIsEmptyError
	}
	standbyNodes := make([]string, 0)
	for k := range standbyNodesMap {
		standbyNodes = append(standbyNodes, k)
	}
	sort.Strings(standbyNodes)
	return standbyNodes, nil
}

func verifyPropose(pbPropose *corepb.Propose) bool {
	// calc hash
	hash := pbPropose.CalcHash()
	// verify response sign
	sign := new(ed25519.Signature)
	if ok, err := sign.Verify(hash, pbPropose.Sign); err != nil || !ok {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("verify response sign error.")
		return false
	}

	//no value when the proposal first requests acceptor
	if pbPropose.Num == 0 && pbPropose.Value == nil {
		return true
	}
	if pbPropose.Value == nil {
		logging.VLog().WithFields(logrus.Fields{}).Debug("[verifyPropose] propose value is nil")
		return false
	}

	pbBockBytes := pbPropose.Value
	pbBlock := &corepb.Block{}
	err := proto.Unmarshal(pbBockBytes, pbBlock)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[verifyPropose] unmarshal pbblock error")
		return false
	}
	block := new(core.Block)
	err = block.FromProto(pbBlock)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[verifyPropose] block.FromProto error")
		return false
	}

	sourceBlockHash := block.Hash()
	err = block.CalcHash()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[verifyPropose] block.FromProto error at promise")
		return false
	}
	if !block.Hash().Equals(sourceBlockHash) {
		logging.VLog().WithFields(logrus.Fields{
			"sourceBlockHash": byteutils.Hex(sourceBlockHash),
			"CalcBlockHash":   byteutils.Hex(block.Hash()),
		}).Debug("[verifyPropose] calc block hash is not equal source block hash")
		return false
	}

	// verify response sign
	if ok, err := sign.Verify(sourceBlockHash, block.Signature()); err != nil || !ok {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[verifyPropose] verify pbPropose sign error.")
		return false
	}

	return true
}

func countPromiseValueNum(promiseValue map[uint64][]*corepb.Propose) int {
	count := 0
	for _, arr := range promiseValue {
		count += len(arr)
	}
	return count
}

func (paxos *Paxos) broadcastMsgToStandbyNodes(msgName string, msg []byte, exclude string) {
	peers := paxos.consensus.(*Psec).StandbyPeers()
	myPid := paxos.ns.Node().ID()
	for _, pid := range peers {
		if pid == myPid {
			continue
		}
		if len(exclude) > 0 && pid == exclude {
			continue
		}
		logging.VLog().WithFields(logrus.Fields{
			"Num":              paxos.maxRound,
			"paxos.promisedNo": paxos.promisedNo,
		}).Debug("send " + msgName + " msg to " + pid)

		_ = paxos.ns.SendMessageToPeer(msgName, msg, network.MessagePriorityHigh, pid)
	}
}

func (paxos *Paxos) Clear() {
	if len(paxos.promiseValue) > 0 {
		paxos.promiseValue = make(map[uint64][]*corepb.Propose)
	}
	if len(paxos.acceptedValue) > 0 {
		paxos.acceptedValue = make(map[uint64][]*corepb.Propose)
	}

	paxos.consensusSuccess = false
	paxos.acceptRequestSent = false
}

func (paxos *Paxos) updateLatestPropose(pbPropose *corepb.Propose) {
	lastesPropose := &corepb.Propose{
		Num:   pbPropose.Num,
		Value: pbPropose.Value,
	}
	err := paxos.SignPropose(lastesPropose)
	data, _ := proto.Marshal(lastesPropose)
	if err == nil {
		paxos.broadcastMsgToStandbyNodes(network.LatestPropose, data, "")
		err = paxos.chain.StoreLatestProposeFromStorage(lastesPropose)
		if err != nil {
			logging.VLog().Error("store latest propose error")
		}
		paxos.mu.Lock()
		paxos.latestPropose = lastesPropose
		paxos.promisedNo = lastesPropose.Num
		paxos.maxRound = lastesPropose.Num
		paxos.mu.Unlock()
	}
}

func (paxos *Paxos) switchStandbyNodeTimer() {
	tailBlockCreateTimestamp := paxos.chain.TailBlock().Timestamp()
	nextBlockFinalTimestamp := tailBlockCreateTimestamp + core.StandbyWaitTime + five*paxos.switchTimes
	nowTimestamp := time.Now().Unix()
	timerValue := nextBlockFinalTimestamp - nowTimestamp
	if paxos.chain.TailBlock().Height() == 1 {
		timerValue = five
	}
	if timerValue <= 0 {
		logging.CLog().Debug("timer value must be greater than 0")
		timerValue = five
	}
	if paxos.switchTimer == nil {
		paxos.switchTimer = time.NewTimer(time.Duration(timerValue * int64(time.Second)))

		logging.VLog().WithFields(logrus.Fields{
			"timerValue": timerValue,
		}).Debug("paxos.switchTimer is nil")
		return
	}
	paxos.switchTimer.Reset(time.Duration(timerValue * int64(time.Second)))
	logging.VLog().WithFields(logrus.Fields{
		"resetTimes": paxos.switchTimes,
		"timerValue": timerValue,
	}).Debug("reset standby node timer")
}

func (paxos *Paxos) checkProposer(miner string) bool {
	var failedAddress *core.Address
	var failedNode string
	var err error
	psec := paxos.consensus.(*Psec)
	orderStandbyArray, err := getIncreasingOrderStandbyArray(psec)
	if paxos.chain.TailBlock().Height() == 1 {
		failedNode = orderStandbyArray[0]
	} else {
		failedAddress, err = core.NewAddressFromPublicKey(paxos.latestPropose.Sign.Signer)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("[checkProposer] " + err.Error())
			return false
		}
		failedNode = failedAddress.String()
	}

	if failedNode == miner && paxos.switchTimes == 1 {
		return true
	}

	logging.VLog().WithFields(logrus.Fields{
		"orderStandbyArray": orderStandbyArray,
		"failedNode":        failedNode,
		"switchTimes":       paxos.switchTimes,
		"miner":             miner,
	}).Debug("[checkProposer] orderStandbyArray and switchTimes")

	standbyIndex := -1
	for index, addr := range orderStandbyArray {
		if addr == failedNode {
			standbyIndex = index
			break
		}
	}
	if standbyIndex < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"err": StandbyNodeNotFoundError,
		}).Debug("[checkProposer] " + StandbyNodeNotFoundError.Error())
		return false
	}
	offset := (paxos.switchTimes - 1) % int64(len(orderStandbyArray))
	newStandbyNodeArray := make([]string, 0, len(orderStandbyArray))
	newStandbyNodeArray = append(newStandbyNodeArray, orderStandbyArray[standbyIndex:]...)
	newStandbyNodeArray = append(newStandbyNodeArray, orderStandbyArray[:standbyIndex]...)
	return newStandbyNodeArray[offset] == miner
}

func (paxos *Paxos) continuePropose() {
	if paxos.latestPropose.Num == 0 {
		return
	}
	if addr, _ := core.NewAddressFromPublicKey(paxos.latestPropose.Sign.Signer); addr != nil {
		if addr.String() != paxos.consensus.Coinbase().String() {
			logging.VLog().Debug("latest proposer is not me...")
			return
		}
		paxos.maxRound++
		pbPropose, err := paxos.Propose(paxos.maxRound)
		if err != nil {
			logging.VLog().Debug("propose error...")
			return
		}
		data, err := proto.Marshal(pbPropose)
		if err != nil {
			logging.VLog().Debug("marshal pbPropose error...")
			return
		}
		paxos.Clear()
		paxos.broadcastMsgToStandbyNodes(network.Accept, data, "")
		paxos.acceptRequestSent = true
	}
}
