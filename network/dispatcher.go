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

package network

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/metrics"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

var (
	metricsDispatcherCached     = metrics.NewGauge("cloudcard.net.dispatcher.cached")
	metricsDispatcherDuplicated = metrics.NewMeter("cloudcard.net.dispatcher.duplicated")
)

// Dispatcher a message dispatcher service.
type Dispatcher struct {
	subscribersMap     *sync.Map
	quitCh             chan bool
	receivedMessageCh  chan Message
	dispatchedMessages *lru.Cache
	filters            map[string]bool
}

// NewDispatcher create Dispatcher instance.
func NewDispatcher() *Dispatcher {
	dp := &Dispatcher{
		subscribersMap:    new(sync.Map),
		quitCh:            make(chan bool, 10),
		receivedMessageCh: make(chan Message, 65536),
		filters:           make(map[string]bool),
	}

	dp.dispatchedMessages, _ = lru.New(51200)

	return dp
}

// Register register subscribers.
func (dp *Dispatcher) Register(subscribers ...*Subscriber) {
	for _, v := range subscribers {
		mt := v.MessageType()
		m, _ := dp.subscribersMap.LoadOrStore(mt, new(sync.Map))
		m.(*sync.Map).Store(v, true)
		dp.filters[mt] = v.DoFilter()
	}
}

// Deregister deregister subscribers.
func (dp *Dispatcher) Deregister(subscribers ...*Subscriber) {
	for _, v := range subscribers {
		mt := v.MessageType()
		m, _ := dp.subscribersMap.Load(mt)
		if m == nil {
			continue
		}
		m.(*sync.Map).Delete(v)
		delete(dp.filters, mt)
	}
}

func (dp *Dispatcher) loop() {
	logging.CLog().Info("Started cloudcardService Dispatcher.")

	timerChan := time.NewTicker(time.Second).C
	for {
		select {
		case <-timerChan:
			metricsDispatcherCached.Update(int64(len(dp.receivedMessageCh)))
		case <-dp.quitCh:
			logging.CLog().Info("Stoped cloudcardService Dispatcher.")
			return
		case msg := <-dp.receivedMessageCh:
			msgType := msg.MessageType()

			v, _ := dp.subscribersMap.Load(msgType)
			if v == nil {
				continue
			}
			m, _ := v.(*sync.Map)

			m.Range(func(key, value interface{}) bool {
				select {
				case key.(*Subscriber).msgChan <- msg:
				default:
					logging.VLog().WithFields(logrus.Fields{
						"msgType": msgType,
					}).Warn("timeout to dispatch message.")
				}
				return true
			})
		}
	}
}

// Start start message dispatch goroutine.
func (dp *Dispatcher) Start() {
	logging.CLog().Info("Starting cloudcardService Dispatcher...")
	go dp.loop()
}

// Stop stop goroutine.
func (dp *Dispatcher) Stop() {
	logging.CLog().Info("Stopping cloudcardService Dispatcher...")

	dp.quitCh <- true
}

// PutMessage put new message to chan, then subscribers will be notified to process.
func (dp *Dispatcher) PutMessage(msg Message) {

	hash := msg.Hash()
	if dp.filters[msg.MessageType()] {
		if exist, _ := dp.dispatchedMessages.ContainsOrAdd(hash, hash); exist == true {
			// duplicated message, ignore.
			metricsDuplicatedMessage(msg.MessageType())
			return
		}
	}

	dp.receivedMessageCh <- msg
}

func metricsDuplicatedMessage(messageName string) {
	metricsDispatcherDuplicated.Mark(int64(1))
	meter := metrics.NewMeter(fmt.Sprintf("cloudcard.net.dispatcher.duplicated.%s", messageName))
	meter.Mark(int64(1))
}
