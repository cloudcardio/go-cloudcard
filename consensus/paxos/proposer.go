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
package paxos

import (
	"log"
	"strconv"
)

func NewProposer(id string, val string, acceptors []string) *proposer {
	pro := proposer{id: id, proposeVal: val, seq: 0}
	pro.acceptors = make(map[string]message, len(acceptors))
	log.Println("proposer has ", len(acceptors), " acceptors, val:", pro.proposeVal)
	for _, acceptor := range acceptors {
		pro.acceptors[acceptor] = message{}
	}
	return &pro
}

type proposer struct {
	id         string
	seq        int
	proposeNum int
	proposeVal string
	acceptors  map[string]message
	nt         nodeNetwork
}

//Detail process for Proposer.
func (p *proposer) Run() {
	log.Println("Proposer start run... val:", p.proposeVal)
	//Stage1: Proposer send prepare message to acceptor to reach accept from majority.
	for !p.MajorityReached() {
		log.Println("[Proposer:Prepare]")
		outMsgs := p.Prepare()
		log.Println("[Proposer: prepare ", len(outMsgs), "msg")
		for _, msg := range outMsgs {
			p.nt.send(msg)
			log.Println("[Proposer: send", msg)
		}

		log.Println("[Proposer: prepare recv..")
		m := p.nt.recv()
		if m == nil {
			log.Println("[Proposer: no msg... ")
			continue
		}
		log.Println("[Proposer: recv", m)
		switch m.typ {
		case Promise:
			log.Println(" proposer recv a promise from ", m.from)
			p.CheckRecvPromise(*m)
		default:
			panic("Unsupported message.")
		}
	}

	log.Println("[Proposer:Propose]")
	//Stage2: Proposer send propose value to acceptor to learn.
	log.Println("Proposer propose seq:", p.GetProposeNum(), " value:", p.proposeVal)
	proposeMsgs := p.Propose()
	for _, msg := range proposeMsgs {
		p.nt.send(msg)
	}
}

// After receipt the promise from acceptor and reach majority.
// Proposer will propose value to those acceptors and let them know the consensus already ready.
func (p *proposer) Propose() []message {
	sendMsgCount := 0
	var msgList []message
	log.Println("proposer: propose msg:", len(p.acceptors))
	for acceptId, acceptMsg := range p.acceptors {
		log.Println("check promise id:", acceptMsg.getProposeSeq(), p.GetProposeNum())
		if acceptMsg.getProposeSeq() == p.GetProposeNum() {
			msg := message{from: p.id, to: acceptId, typ: Propose, seq: p.GetProposeNum()}
			msg.val = p.proposeVal
			log.Println("Propose val:", msg.val)
			msgList = append(msgList, msg)
		}
		sendMsgCount++
		if sendMsgCount > p.Majority() {
			break
		}
	}
	log.Println(" proposer propose msg list:", msgList)
	return msgList
}

// Stage 1:
// Prepare will prepare message to send to majority of acceptors.
// According to spec, we only send our prepare msg to the "majority" not all acceptors.
func (p *proposer) Prepare() []message {
	p.seq++

	sendMsgCount := 0
	var msgList []message
	log.Println("proposer: prepare major msg:", len(p.acceptors))
	for acceptId := range p.acceptors {
		msg := message{from: p.id, to: acceptId, typ: Prepare, seq: p.GetProposeNum(), val: p.proposeVal}
		msgList = append(msgList, msg)
		sendMsgCount++
		if sendMsgCount > p.Majority() {
			break
		}
	}
	return msgList
}

func (p *proposer) CheckRecvPromise(promise message) {
	previousPromise := p.acceptors[promise.from]
	log.Println(" prevMsg:", previousPromise, " promiseMsg:", promise)
	log.Println(previousPromise.getProposeSeq(), promise.getProposeSeq())
	if previousPromise.getProposeSeq() < promise.getProposeSeq() {
		log.Println("Proposer:", p.id, " get new promise:", promise)
		p.acceptors[promise.from] = promise
		if promise.getProposeSeq() > p.GetProposeNum() {
			p.proposeNum = promise.getProposeSeq()
			p.proposeVal = promise.getProposeVal()
		}
	}
}

func (p *proposer) Majority() int {
	return len(p.acceptors)/2 + 1
}

func (p *proposer) GetRecvPromiseCount() int {
	recvCount := 0
	for _, acepMsg := range p.acceptors {
		log.Println(" proposer has total ", len(p.acceptors), " acceptor ", acepMsg, " current Num:", p.GetProposeNum(), " msgNum:", acepMsg.getProposeSeq())
		if acepMsg.getProposeSeq() == p.GetProposeNum() {
			log.Println("recv ++", recvCount)
			recvCount++
		}
	}
	log.Println("Current proposer recv promise count=", recvCount)
	return recvCount
}

func (p *proposer) MajorityReached() bool {
	return p.GetRecvPromiseCount() > p.Majority()
}

func (p *proposer) GetProposeNum() int {
	id, _ := strconv.Atoi(p.id)
	p.proposeNum = p.seq<<4 |id
	return p.proposeNum
}
