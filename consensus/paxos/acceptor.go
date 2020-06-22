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

import "log"

//Create a acceptor and also assign learning IDs into acceptor.
//Acceptor:
// Will response request from proposer, promise the first and largest seq number propose.
// After proposer reach the majority promise.  Acceptor will pass the proposal value to learner to confirm and choose.
func NewAcceptor(id string, nt nodeNetwork, learners ...string) acceptor {
	newAcceptor := acceptor{id: id, nt: nt}
	newAcceptor.learners = learners
	return newAcceptor
}

type acceptor struct {
	id         string
	learners   []string
	acceptMsg  message
	promiseMsg message
	nt         nodeNetwork
}

//Acceptor process detail logic.
func (a *acceptor) run() {
	for {
		//	log.Println("acceptor:", a.id, " wait to recv msg")
		m := a.nt.recv()
		if m == nil {
			continue
		}

		//	log.Println("acceptor:", a.id, " recv message ", *m)
		switch m.typ {
		case Prepare:
			promiseMsg := a.recvPrepare(*m)
			a.nt.send(*promiseMsg)
			continue
		case Propose:
			accepted := a.recvPropose(*m)
			if accepted {
				for _, lId := range a.learners {
					m.from = a.id
					m.to = lId
					m.typ = Accept
					a.nt.send(*m)
				}
			}
		default:
			log.Fatalln("Unsupported message in acceptor ID:", a.id)
		}
	}
}

//After acceptor receive prepare message.
//It will check  prepare number and return acceptor if it is bigest one.
func (a *acceptor) recvPrepare(prepare message) *message {
	if a.promiseMsg.getProposeSeq() >= prepare.getProposeSeq() {
		log.Println("ID:", a.id, "Already accept bigger one")
		return nil
	}
	log.Println("ID:", a.id, " Promise")
	prepare.to = prepare.from
	prepare.from = a.id
	prepare.typ = Promise
	a.acceptMsg = prepare
	return &prepare
}

//RecvPropose only check if acceptor already accept bigger propose before.
//Otherwise, will just forward this message out and change its type to "Accept" to learning later.
func (a *acceptor) recvPropose(proposeMsg message) bool {
	//Already accept message is identical with previous promise message
	log.Println("accept:check propose. ", a.acceptMsg.getProposeSeq(), proposeMsg.getProposeSeq())
	if a.acceptMsg.getProposeSeq() > proposeMsg.getProposeSeq() || a.acceptMsg.getProposeSeq() < proposeMsg.getProposeSeq() {
		log.Println("ID:", a.id, " acceptor not take propose:", proposeMsg.val)
		return false
	}
	log.Println("ID:", a.id, " Accept")
	return true
}
