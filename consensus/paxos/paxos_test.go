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
	"testing"
	"time"
)

func TestBasicNetwork(t *testing.T) {
	log.Println("TestBasicNetwork........................")
	nt := CreateNetwork(1, 3, 5, 2, 4)
	go func() {
		recvFrom(5)
		recvFrom(1)
		recvFrom(3)
		recvFrom(2)
		m := recvFrom(4)
		if m == nil {
			t.Errorf("No message detected.")
		}
	}()

	m1 := Message{from: 3, to: 1, typ: Prepare, seq: 1, preSeq: 0, val: "m1"}
	sendTo(m1)
	m2 := Message{from: 5, to: 3, typ: Accept, seq: 2, preSeq: 1, val: "m2"}
	sendTo(m2)
	m3 := Message{from: 4, to: 2, typ: Promise, seq: 3, preSeq: 2, val: "m3"}
	sendTo(m3)
	time.Sleep(time.Second)
}

func TestSingleProposer(t *testing.T) {
	log.Println("TestProposerFunction........................")
	//Three acceptor and one proposer
	network := CreateNetwork(100, 1, 2, 3, 200)

	//Create acceptors
	var acceptors []Acceptor
	aId := 1
	for aId <= 3 {
		acctor := NewAcceptor(aId, getNodeNetwork(aId), 200)
		acceptors = append(acceptors, acctor)
		aId++
	}

	//Create proposer
	proposer := NewProposer(100, "value1", getNodeNetwork(100), 1, 2, 3)

	//Run proposer and acceptors
	go Run()

	for index := range acceptors {
		go Run()
	}

	//Create learner and learner will wait until reach majority.
	learner := NewLearner(200, getNodeNetwork(200), 1, 2, 3)
	learnValue := Run()
	if learnValue != "value1" {
		t.Errorf("Learner learn wrong proposal.")
	}
}

func TestTwoProposers(t *testing.T) {
	log.Println("TestProposerFunction........................")
	//Three acceptor and one proposer
	network := CreateNetwork(100, 1, 2, 3, 200, 101)

	//Create acceptors
	var acceptors []Acceptor
	aId := 1
	for aId <= 3 {
		acceptor := NewAcceptor(aId, getNodeNetwork(aId), 200)
		acceptors = append(acceptors, acceptor)
		aId++
	}

	//Create proposer 1
	proposer1 := NewProposer(100, "ExpectValue", getNodeNetwork(100), 1, 2, 3)
	//Run proposer and acceptors
	go Run()

	//Need sleep to make sure first proposer reach majority
	time.Sleep(time.Millisecond)

	//Create proposer 2
	proposer2 := NewProposer(101, "WrongValue", getNodeNetwork(101), 1, 2, 3)
	//Run proposer and acceptors
	go Run()

	for index := range acceptors {
		go Run()
	}

	//Create learner and learner will wait until reach majority.
	learner := NewLearner(200, getNodeNetwork(200), 1, 2, 3)
	learnValue := Run()
	if learnValue != "ExpectValue" {
		t.Errorf("Learner learn wrong proposal. Expect:'ExpectValue'")
	}
}
