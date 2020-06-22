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
	"fmt"
)

// Metrics map for different in/out network msg types
var (
	metricsPacketsIn = metrics.NewMeter("cloudcard.net.packets.in")
	metricsBytesIn   = metrics.NewMeter("cloudcard.net.bytes.in")

	metricsPacketsOut = metrics.NewMeter("cloudcard.net.packets.out")
	metricsBytesOut   = metrics.NewMeter("cloudcard.net.bytes.out")
)

func metricsPacketsInByMessageName(messageName string, size uint64) {
	meter := metrics.NewMeter(fmt.Sprintf("cloudcard.net.packets.in.%s", messageName))
	meter.Mark(1)

	meter = metrics.NewMeter(fmt.Sprintf("cloudcard.net.bytes.in.%s", messageName))
	meter.Mark(int64(size))
}

func metricsPacketsOutByMessageName(messageName string, size uint64) {
	meter := metrics.NewMeter(fmt.Sprintf("cloudcard.net.packets.out.%s", messageName))
	meter.Mark(1)

	meter = metrics.NewMeter(fmt.Sprintf("cloudcard.net.bytes.out.%s", messageName))
	meter.Mark(int64(size))
}
