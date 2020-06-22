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
package main

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/cloudcard"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/sirupsen/logrus"
	"os"
)

func main() {
	strings := os.Args
	configPath := ""
	if len(strings) == 2 {
		configPath = strings[1]
	}
	cloudcardConf, err := config.InitConfig(configPath)
	casc, err := cloudcard.Newcloudcard(cloudcardConf)
	// init log.
	logConf := logging.GetLogConfig(cloudcardConf)
	logging.Init(logConf.LogFile, logConf.LogLevel, logConf.LogRotationTime, logConf.LogAge)

	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to new cloudcard.")
		return
	}
	casc.Setup()
	casc.Run()
}
