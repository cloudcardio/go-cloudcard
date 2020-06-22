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

package core

import "cloudcard.pro/cloudcardio/go-cloudcard/metrics"

var (
	metricsDuplicatedBlock = metrics.NewCounter("cloudcard.block.duplicated")
	metricsInvalidBlock    = metrics.NewCounter("cloudcard.block.invalid")

	metricsTxVerifiedTime    = metrics.NewGauge("cloudcard.tx.executed")
	metricsTxsInBlock        = metrics.NewGauge("cloudcard.block.txs")
	metricsBlockVerifiedTime = metrics.NewGauge("cloudcard.block.executed")

	metricsBlockOnchainTimer = metrics.NewTimer("cloudcard.block.onchain")
	metricsTxOnchainTimer    = metrics.NewTimer("cloudcard.transaction.onchain")

	// block_pool metrics
	metricsCachedNewBlock      = metrics.NewGauge("cloudcard.block.new.cached")
	metricsCachedDownloadBlock = metrics.NewGauge("cloudcard.block.download.cached")
	metricsLruPoolCacheBlock   = metrics.NewGauge("cloudcard.block.lru.poolcached")
	metricsLruCacheBlock       = metrics.NewGauge("cloudcard.block.lru.blocks")
	metricsLruTailBlock        = metrics.NewGauge("cloudcard.block.lru.tailblock")
)
