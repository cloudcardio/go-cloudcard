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
	"github.com/sirupsen/logrus"
	"strconv"
	"time"
)

const (
	f = 1

	MsgPreprepare = iota + 100
	MsgPrepare
	MsgCommit
)

const (
	StagePreprepared = iota + 200
	StagePrepared
	StageCommitted
)

//
type PbftState struct {
	viewId        string
	timestamp     int64
	seqId         uint64
	stage         uint32
	preprepareMsg *corepb.PreprepareMsg
	prepareMsgs   map[string]*corepb.VoteMsg
	flagPrepared  bool
	committedMsgs map[string]*corepb.VoteMsg
	flagCommitted bool
}

// Pbft
type PBFT struct {
	consensus core.Consensus
	chain     *core.BlockChain
	ns        network.Service
	lastSeqId uint64
	msgBuffer map[string]*PbftState
	messageCh chan network.Message
}

// NewPbft
func NewPbft(consensus core.Consensus, ns network.Service, chain *core.BlockChain) *PBFT {
	pbft := &PBFT{
		consensus: consensus,
		chain:     chain,
		ns:        ns,
		lastSeqId: uint64(0),
		messageCh: make(chan network.Message, 128),
		msgBuffer: make(map[string]*PbftState),
	}

	go pbft.handleMsg()
	//go pbft.timeout()

	return pbft
}

//
func (pbft *PBFT) timeout() {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			for k, v := range pbft.msgBuffer {
				if v.timestamp+10 < time.Now().Unix() {
					delete(pbft.msgBuffer, k)
				}
			}
		}
	}
}

//
func (pbft *PBFT) Preprepare(block *core.Block) error {
	if block.Height() <= pbft.lastSeqId {
		return ErrSeqIdIsTooLow
	}

	pbBlock, err := block.ToProto()
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[PBFT Preprepare] convert block to pb error")
		return err
	}

	coinbase := pbft.consensus.Coinbase().String()
	preprepareMsg := &corepb.PreprepareMsg{
		Timestamp: time.Now().Unix(),
		Type:      MsgPreprepare,
		ViewId:    coinbase,
		SeqId:     block.Height(),
		Block:     pbBlock.(*corepb.Block),
	}

	if err := pbft.SignPreprepareMsg(preprepareMsg); err != nil { // sign message
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[PBFT Preprepare] sign preprepare msg error")
		return err
	}

	// record msg
	key := preprepareMsg.ViewId + strconv.FormatUint(preprepareMsg.SeqId, 10)
	msgBuff := &PbftState{
		timestamp:     preprepareMsg.Timestamp,
		stage:         StagePreprepared,
		viewId:        preprepareMsg.ViewId,
		seqId:         preprepareMsg.SeqId,
		preprepareMsg: preprepareMsg,
		prepareMsgs:   make(map[string]*corepb.VoteMsg),
		committedMsgs: make(map[string]*corepb.VoteMsg),
		flagCommitted: false,
		flagPrepared:  false,
	}
	pbft.msgBuffer[key] = msgBuff

	// send prepare msg
	pbft.ns.Broadcast(network.PbftPreprepare, preprepareMsg, network.MessagePriorityHigh)

	return nil
}

// handleMsg
func (pbft *PBFT) handleMsg() {
	for {
		select {
		case msg := <-pbft.messageCh:
			if !pbft.consensus.IsEnable() {
				continue
			}
			switch msg.MessageType() {
			case network.PbftPreprepare:
				if err := pbft.handlePreprepare(msg); err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("[PBFT handleMsg] unmarshal preprepare msg error")
					continue
				}
			case network.PbftPrepare:
				if err := pbft.handlePrepare(msg); err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("[PBFT handleMsg] unmarshal prepare msg error")
					continue
				}
			case network.PbftCommit:
				if err := pbft.handleCommit(msg); err != nil {
					logging.VLog().WithFields(logrus.Fields{
						"err": err,
					}).Debug("[PBFT handleMsg] unmarshal commit msg error")
					continue
				}
			}
		}
	}
}

//
func (pbft *PBFT) handlePreprepare(msg network.Message) error {
	pbPreprepare := new(corepb.PreprepareMsg)
	data := msg.Data()
	err := proto.Unmarshal(data, pbPreprepare) // unmarshal
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[PBFT handlePreprepare] unmarshal preprepare msg error")
		return err
	}

	if !pbft.verifyPreprepare(pbPreprepare) { // verify msg
		return ErrVerifyPreprepareMsgError
	}

	if pbPreprepare.SeqId <= pbft.lastSeqId {
		return ErrSeqIdIsTooLow
	}

	key := pbPreprepare.ViewId + strconv.FormatUint(pbPreprepare.SeqId, 10)
	if _, ok := pbft.msgBuffer[key]; !ok {
		state := &PbftState{
			viewId:        pbPreprepare.ViewId,
			timestamp:     pbPreprepare.Timestamp,
			seqId:         pbPreprepare.SeqId,
			stage:         StagePreprepared,
			preprepareMsg: pbPreprepare,
			prepareMsgs:   make(map[string]*corepb.VoteMsg),
			committedMsgs: make(map[string]*corepb.VoteMsg),
			flagCommitted: false,
			flagPrepared:  false,
		}
		pbft.msgBuffer[key] = state

		prepareMsg := &corepb.VoteMsg{
			Type:   MsgPrepare,
			ViewId: pbPreprepare.ViewId,
			SeqId:  pbPreprepare.SeqId,
		}

		if err := pbft.SignVoteMsg(prepareMsg); err != nil { // sign
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("[PBFT handlePreprepare] sign prepare msg error")
			return err
		}
		coinbase := pbft.consensus.Coinbase().String()
		keyFrom := coinbase + strconv.FormatUint(pbPreprepare.SeqId, 10)
		pbft.msgBuffer[key].prepareMsgs[keyFrom] = prepareMsg

		// broad prepare msg
		pbft.ns.Broadcast(network.PbftPrepare, prepareMsg, network.MessagePriorityHigh)
	}

	// relay preprepare msg
	pbft.ns.Relay(network.PbftPreprepare, pbPreprepare, network.MessagePriorityHigh)

	return nil
}

//
func (pbft *PBFT) handlePrepare(msg network.Message) error {
	pbPrepare := new(corepb.VoteMsg)
	data := msg.Data()
	err := proto.Unmarshal(data, pbPrepare) // unmarshal
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[PBFT handlePrepare] unmarshal prepare msg error")
		return err
	}
	key := pbPrepare.ViewId + strconv.FormatUint(pbPrepare.SeqId, 10)
	if _, ok := pbft.msgBuffer[key]; !ok {
		return nil
	}
	if pbft.msgBuffer[key].flagPrepared {
		logging.VLog().WithFields(logrus.Fields{
			"key": key,
		}).Debug("[PBFT handlePrepare] the prepare message has been enough")
		return nil
	}
	if !pbft.verifyVoteMsg(pbPrepare) { // verify sign
		return ErrVerifyPreprepareMsgError
	}

	if pbPrepare.SeqId <= pbft.lastSeqId {
		return ErrSeqIdIsTooLow
	}

	if state, ok := pbft.msgBuffer[key]; ok {
		from, err := core.NewAddressFromPublicKey(pbPrepare.Sign.Signer)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("[PBFT handlePrepare] get addr from prepare msg error")
			return err
		}

		keyFrom := from.String() + strconv.FormatUint(pbPrepare.SeqId, 10)
		pbft.msgBuffer[key].prepareMsgs[keyFrom] = pbPrepare

		logging.VLog().WithFields(logrus.Fields{
			"from":    from.String(),
			"view_id": pbPrepare.ViewId,
			"seq_id":  pbPrepare.SeqId,
		}).Debug("[PBFT handlePrepare] store prepare msg.")

		if len(pbft.msgBuffer[key].prepareMsgs) >= 2*f {
			logging.VLog().Debug("[PBFT handlePrepare] reached pbft prepare majority")
			state.stage = StagePrepared
			pbft.msgBuffer[key].flagPrepared = true

			commitMsg := &corepb.VoteMsg{
				Type:   MsgCommit,
				ViewId: pbPrepare.ViewId,
				SeqId:  pbPrepare.SeqId,
			}

			if err := pbft.SignVoteMsg(commitMsg); err != nil { // sign
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("[PBFT handlePrepare] sign commit msg error")
				return err
			}

			// add my commit msg
			pbft.msgBuffer[key].committedMsgs[key] = commitMsg

			// broad commit msg
			pbft.ns.Broadcast(network.PbftCommit, commitMsg, network.MessagePriorityHigh)
		}
	}

	// relay prepare msg
	pbft.ns.Relay(network.PbftPrepare, pbPrepare, network.MessagePriorityHigh)

	return nil
}

//
func (pbft *PBFT) handleCommit(msg network.Message) error {
	pbCommit := new(corepb.VoteMsg)
	data := msg.Data()
	err := proto.Unmarshal(data, pbCommit)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("[PBFT handleCommit] unmarshal commit msg error")
		return err
	}
	key := pbCommit.ViewId + strconv.FormatUint(pbCommit.SeqId, 10)
	if _, ok := pbft.msgBuffer[key]; !ok {
		return nil
	}
	if pbft.msgBuffer[key].flagCommitted {
		logging.VLog().WithFields(logrus.Fields{
			"key": key,
		}).Debug("[PBFT handleCommit] the commit message has been enough")
		return nil
	}

	if !pbft.verifyVoteMsg(pbCommit) {
		return ErrVerifyPreprepareMsgError
	}

	if pbCommit.SeqId <= pbft.lastSeqId {
		return ErrSeqIdIsTooLow
	}

	if state, ok := pbft.msgBuffer[key]; ok {
		from, err := core.NewAddressFromPublicKey(pbCommit.Sign.Signer)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"err": err,
			}).Debug("[PBFT handleCommit] get addr from commit msg error")
			return err
		}

		keyFrom := from.String() + strconv.FormatUint(pbCommit.SeqId, 10)
		pbft.msgBuffer[key].committedMsgs[keyFrom] = pbCommit

		logging.VLog().WithFields(logrus.Fields{
			"from":    from.String(),
			"view_id": pbCommit.ViewId,
			"seq_id":  pbCommit.SeqId,
		}).Debug("[PBFT handleCommit] store commit msg.")

		if len(pbft.msgBuffer[key].committedMsgs) >= 2*f+1 {
			logging.VLog().Debug("[PBFT handleCommit] reached pbft commit majority")

			state.stage = StageCommitted
			pbft.msgBuffer[key].flagCommitted = true

			tailBlock := pbft.chain.TailBlock()

			// get block from pb
			block := new(core.Block)
			if err := block.FromProto(pbft.msgBuffer[key].preprepareMsg.Block); err != nil {
				logging.VLog().WithFields(logrus.Fields{
					"err": err,
				}).Debug("[PBFT handleCommit] get block error")
				return err
			}

			// broadcast new block
			_ = pbft.consensus.(*Psec).addAndBroadcast(tailBlock, block)

			//
			pbft.lastSeqId = pbCommit.SeqId

			// delete the committed
			delete(pbft.msgBuffer, key)
		}
	}

	// relay msg
	pbft.ns.Relay(network.PbftCommit, pbCommit, network.MessagePriorityHigh)

	return nil
}

//
func (pbft *PBFT) verifyPreprepare(msg *corepb.PreprepareMsg) bool {
	targetHash := msg.CalcHash()
	sign := new(ed25519.Signature)
	if ok, err := sign.Verify(targetHash, msg.Sign); err != nil || !ok {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("verify response sign error.")
		return false
	}

	return true
}

//
func (pbft *PBFT) verifyVoteMsg(msg *corepb.VoteMsg) bool {
	targetHash := msg.CalcHash()
	sign := new(ed25519.Signature)
	if ok, err := sign.Verify(targetHash, msg.Sign); err != nil || !ok {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("verify response sign error.")
		return false
	}

	return true
}

//
func (pbft *PBFT) SignPreprepareMsg(msg *corepb.PreprepareMsg) error {
	coinbase := pbft.consensus.Coinbase()
	hash := msg.CalcHash()
	addrManager := pbft.consensus.(*Psec).am.(*account.AccountManager).GetAddrManager()
	signResult, err := addrManager.SignHash(coinbase, hash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"coinbase": coinbase.String(),
			"hash":     byteutils.Hex(hash),
			"err":      err,
		}).Debug("[PBFT] sign pre-prepare message error")
		return PBFTSignMessageError
	}

	sign := &corepb.Signature{
		Signer: signResult.GetSigner(),
		Data:   signResult.GetData(),
	}

	msg.Sign = sign

	return nil
}

//
func (pbft *PBFT) SignVoteMsg(msg *corepb.VoteMsg) error {
	coinbase := pbft.consensus.Coinbase()
	hash := msg.CalcHash()
	addrManager := pbft.consensus.(*Psec).am.(*account.AccountManager).GetAddrManager()
	signResult, err := addrManager.SignHash(coinbase, hash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"hash": byteutils.Hex(hash),
			"err":  err,
		}).Debug("[PBFT] sign vote message error")
		return PBFTSignMessageError
	}

	sign := &corepb.Signature{
		Signer: signResult.GetSigner(),
		Data:   signResult.GetData(),
	}

	msg.Sign = sign
	return nil
}
