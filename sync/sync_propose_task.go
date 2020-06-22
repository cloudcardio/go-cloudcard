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

package sync

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/ed25519"
	net "cloudcard.pro/cloudcardio/go-cloudcard/network"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

var (
	ProposeLearnSyncLoopInterval = 5 * time.Second
	ProposeSaveInterval          = 60 * time.Second
)

// ProposeTask is a sync propose task
type ProposeTask struct {
	quitCh        chan bool
	blockChain    *core.BlockChain
	netService    net.Service
	mutex         sync.Mutex
	latestPropose *corepb.Propose
}

// NewProposeTask return a new propose sync task
func NewProposeTask(blockChain *core.BlockChain, netService net.Service) *ProposeTask {
	propose := &ProposeTask{
		quitCh:     make(chan bool, 1),
		blockChain: blockChain,
		netService: netService,
	}
	oldPropose, err := propose.blockChain.LoadLatestProposeFromStorage()
	if err != nil {
		propose.latestPropose = oldPropose
	} else {
		propose.latestPropose = corepb.NewPropose(0)
	}
	blockChain.SetLatestPropose(propose.latestPropose)
	return propose
}

// Start the sync task
func (spt *ProposeTask) Start() {
	go spt.startSyncLoop()
}

func (spt *ProposeTask) startSyncLoop() {
	syncLoopTicker := time.NewTicker(ProposeLearnSyncLoopInterval)
	saveProposeTicker := time.NewTicker(ProposeSaveInterval)
	for {
		select {
		case <-spt.quitCh:
			logging.VLog().Info("Stopped Propose Learn.")
			return
		case <-syncLoopTicker.C:
			// for the timeout peer, send message again.
			spt.proposeLearnRequest()
		case <-saveProposeTicker.C:
			if spt.latestPropose.Num > 0 {
				spt.blockChain.StoreLatestProposeFromStorage(spt.latestPropose)
			}
		}
	}
}

func (spt *ProposeTask) processProposeLearn(message net.Message) {
	propose := new(corepb.Propose)
	err := proto.Unmarshal(message.Data(), propose)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"pid": message.MessageFrom(),
		}).Debug("Invalid propose message data.")
		spt.netService.ClosePeer(message.MessageFrom(), ErrInvalidProposeMessageData)
		return
	}
	sign := new(ed25519.Signature)
	if ok, err := sign.Verify(propose.CalcHash(), propose.Sign); err != nil && ok {
		address, _ := core.NewAddressFromPublicKey(propose.Sign.Signer)
		if spt.blockChain.Consensus().IsValidStandbyNode(address.String()) {
			if spt.latestPropose.Num <= propose.Num {
				spt.updatePropose(spt.latestPropose)
			}
		}
	} else {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
			"pid": message.MessageFrom(),
		}).Debug("Invalid propose.")
		spt.netService.ClosePeer(message.MessageFrom(), ErrInvalidPropose)
		return
	}

}

func (spt *ProposeTask) updatePropose(newPropose *corepb.Propose) {
	spt.mutex.Lock()
	defer spt.mutex.Unlock()
	spt.latestPropose = newPropose
}

func (spt *ProposeTask) proposeLearnRequest() {
	data, err := proto.Marshal(spt.latestPropose)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Debug("Failed to marshal corepb.Propose.")
		return
	}

	// send message to peers.
	spt.netService.SendMessageToPeers(net.ProposeLearnRequest, data,
		net.MessagePriorityHigh, new(net.ChainSyncPeersFilter))
}

// Stop the propose task
func (spt *ProposeTask) Stop() {
	spt.quitCh <- true
}
