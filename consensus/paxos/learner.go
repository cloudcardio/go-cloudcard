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

type learner struct {
	id           int
	acceptedMsgs map[string]message
	nt           nodeNetwork
}

//Initialize learner and prepare message pool.
func NewLearner(id int, nt nodeNetwork, acceptorIDs ...string) *learner {
	newLearner := &learner{id: id, nt: nt}
	newLearner.acceptedMsgs = make(map[string]message)
	for _, acceptId := range acceptorIDs {
		newLearner.acceptedMsgs[acceptId] = message{}
	}
	return newLearner
}

//Run learner process and will return learn value if reach majority.
func (l *learner) run() string {

	for {
		m := l.nt.recv()
		if m == nil {
			continue
		}

		log.Println("Learner: recv msg:", *m)
		l.handleRecvAccept(*m)
		learnMsg, isLearn := l.chosen()
		if isLearn == false {
			continue
		}
		return learnMsg.getProposeVal()
	}
}

//Check acceptor message and compare with local accepted proposal to make sure it is most updated.
func (l *learner) handleRecvAccept(acceptMsg message) {
	hasAcceptedMsg := l.acceptedMsgs[acceptMsg.from]
	if hasAcceptedMsg.getProposeSeq() < acceptMsg.getProposeSeq() {
		//get bigger num will replace it to keep it updated.
		l.acceptedMsgs[acceptMsg.from] = acceptMsg
	}
}

//Every acceptor might send different proposal ID accept message to learner.
//Learner only chosen if the accept count reach majority.
func (l *learner) chosen() (message, bool) {
	acceptCount := make(map[int]int)
	acceptMsgMap := make(map[int]message)

	//Separate each acceptor message according their proposal ID and count it
	for _, msg := range l.acceptedMsgs {
		proposalNum := msg.getProposeSeq()
		acceptCount[proposalNum]++
		acceptMsgMap[proposalNum] = msg
	}

	//Check count if reach majority will return as chosen value.
	for chosenNum, chosenMsg := range acceptMsgMap {
		if acceptCount[chosenNum] > l.majority() {
			return chosenMsg, true
		}
	}
	return message{}, false
}

//Count for majority, need initialize the count at constructor.
func (l *learner) majority() int {
	return len(l.acceptedMsgs)/2 + 1
}
