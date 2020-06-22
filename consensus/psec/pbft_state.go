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
	"github.com/pkg/errors"
	"log"
	"time"
)

type Stage int

const (
	faultNum = 1

	StageIdle Stage = 1000 + iota
	StagePrePrepared
	StagePrepared
	StageCommitted
)

// PbftState
type State struct {
	ViewId       int64
	MsgLogs      *MessageLogs
	LastSeqId    int64
	CurrentStage Stage
}

//  MessageLogs
type MessageLogs struct {
	ReqMsg      *RequestMessage
	PrepareMsgs map[string]*InternalMessage
	CommitMsgs  map[string]*InternalMessage
}

// NewState
func NewState(viewId int64, lastSeq int64) *State {
	return &State{
		ViewId:       viewId,
		LastSeqId:    lastSeq,
		CurrentStage: StageIdle,
		MsgLogs: &MessageLogs{
			PrepareMsgs: make(map[string]*InternalMessage),
			CommitMsgs:  make(map[string]*InternalMessage),
		},
	}
}

// Start
func (state *State) Start(reqMsg *RequestMessage) (*PrePrepareMessage, error) {
	seqId := time.Now().UnixNano()
	if state.LastSeqId != -1 {
		for seqId <= state.LastSeqId {
			seqId++
		}
	}
	reqMsg.SeqId = seqId          // assign a new sequence id to the reqMsg.
	state.MsgLogs.ReqMsg = reqMsg // save the reqMsg to its records.
	digest, err := digest(reqMsg) // get the digest.
	if err != nil {
		log.Println(err)
		return nil, err
	}
	state.CurrentStage = StagePrePrepared // change the stage to pre-prepared.
	return &PrePrepareMessage{
		ViewId: state.ViewId,
		SeqId:  seqId,
		Digest: digest,
		ReqMsg: reqMsg,
	}, nil
}

// PrePrepare
func (state *State) PrePrepare(prePrepareMsg *PrePrepareMessage) (*InternalMessage, error) {
	state.MsgLogs.ReqMsg = prePrepareMsg.ReqMsg // get RequestMsg and save it to its records like the primary.
	if !state.verifyMessage(prePrepareMsg.ViewId, prePrepareMsg.SeqId, prePrepareMsg.Digest) {
		return nil, errors.New("invalid pre-prepare message")
	}
	state.CurrentStage = StagePrePrepared // change the stage to pre-prepared.
	return &InternalMessage{
		ViewId:  state.ViewId,
		SeqId:   prePrepareMsg.SeqId,
		Digest:  prePrepareMsg.Digest,
		MsgType: MsgTypePrepare,
	}, nil
}

// Prepare
func (state *State) Prepare(prepareMsg *InternalMessage) (*InternalMessage, error) {
	if !state.verifyMessage(prepareMsg.ViewId, prepareMsg.SeqId, prepareMsg.Digest) {
		return nil, errors.New("invalid prepare message")
	}
	state.MsgLogs.PrepareMsgs[prepareMsg.NodeId] = prepareMsg
	if state.prepared() {
		state.CurrentStage = StagePrepared
		return &InternalMessage{
			ViewId:  state.ViewId,
			SeqId:   prepareMsg.SeqId,
			Digest:  prepareMsg.Digest,
			MsgType: MsgTypeCommit,
		}, nil
	}

	return nil, nil
}

// Commit
func (state *State) Commit(commitMsg *InternalMessage) (*ResponseMessage, *RequestMessage, error) {
	if !state.verifyMessage(commitMsg.ViewId, commitMsg.SeqId, commitMsg.Digest) {
		return nil, nil, errors.New("invalid commit message")
	}
	state.MsgLogs.CommitMsgs[commitMsg.NodeId] = commitMsg
	if state.committed() {
		result := "passed"
		state.CurrentStage = StageCommitted
		return &ResponseMessage{
			ViewId:    state.ViewId,
			Timestamp: state.MsgLogs.ReqMsg.Timestamp,
			Result:    result,
		}, state.MsgLogs.ReqMsg, nil
	}

	return nil, nil, nil
}

// Response
func (state *Stage) Response(msg *ResponseMessage) error {

	return nil
}

// verifyMessage
func (state *State) verifyMessage(viewId, seqId int64, digGot string) bool {
	if state.ViewId != viewId {
		return false
	}
	if state.LastSeqId != -1 {
		if seqId <= state.LastSeqId {
			return false
		}
	}
	dig, err := digest(state.MsgLogs.ReqMsg)
	if err != nil {
		log.Println(err)
		return false
	}
	if dig != digGot {
		return false
	}

	return true
}

// prepared
func (state *State) prepared() bool {
	if state.MsgLogs.ReqMsg == nil {
		return false
	}
	if len(state.MsgLogs.PrepareMsgs) < 2*faultNum {
		return false
	}
	return true
}

// committed
func (state *State) committed() bool {
	if !state.prepared() {
		return false
	}
	if len(state.MsgLogs.CommitMsgs) < 2*faultNum {
		return false
	}
	return true
}

func digest(object interface{}) (string, error) {

	return "", nil
}
