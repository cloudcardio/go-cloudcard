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
	"bytes"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"errors"
	"github.com/golang/snappy"
	"github.com/sirupsen/logrus"
	"hash/crc32"
	"time"
)

/*
cloudcardMessage defines protocol in cloudcard, we define our own wire protocol, as the following:

 0               1               2               3              (bytes)
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Number                          |
+-----------------------------------------------+---------------+
|               	Chain ID	                |    Reserved   |
+-----------------------------------------------+---------------+
|           		Reserved   		         	|    Version    |
+-----------------------------------------------+---------------+
|                                                               |
+                                                               +
|                         Message Name                          |
+                                                               +
|                                                               |
+---------------------------------------------------------------+
|                         Data Length                           |
+---------------------------------------------------------------+
|                         Data Checksum                         |
+---------------------------------------------------------------+
|                         Header Checksum                       |
|---------------------------------------------------------------+
|                                                               |
+                         Data                                  +
.                                                               .
|                                                               |
+---------------------------------------------------------------+
*/

const (
	cloudcardMessageMagicNumberEndIdx    = 4
	cloudcardMessageChainIDEndIdx        = 7
	cloudcardMessageReservedEndIdx       = 11
	cloudcardMessageVersionIndex         = 11
	cloudcardMessageVersionEndIdx        = 12
	cloudcardMessageNameEndIdx           = 24
	cloudcardMessageDataLengthEndIdx     = 28
	cloudcardMessageDataCheckSumEndIdx   = 32
	cloudcardMessageHeaderCheckSumEndIdx = 36
	cloudcardMessageHeaderLength         = 36

	// Consider that a block is too large in sync.
	MaxcloudcardMessageDataLength = 512 * 1024 * 1024 // 512m.
	MaxcloudcardMessageNameLength = 24 - 12           // 12.

	DefaultReservedFlag           = 0x0
	ReservedCompressionEnableFlag = 0x80
	ReservedCompressionClientFlag = 0x40
)

var (
	MagicNumber         = []byte{0x43, 0x43, 0x4D, 0x4E}
	RTNTMagicNumber     = []byte{0x43, 0x43, 0x54, 0x4E}
	DefaultReserved     = []byte{DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag}
	CompressionReserved = []byte{DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag, DefaultReservedFlag | ReservedCompressionEnableFlag}

	ErrInsufficientMessageHeaderLength = errors.New("insufficient message header length")
	ErrInsufficientMessageDataLength   = errors.New("insufficient message data length")
	ErrInvalidMagicNumber              = errors.New("invalid magic number")
	ErrInvalidHeaderCheckSum           = errors.New("invalid header checksum")
	ErrInvalidDataCheckSum             = errors.New("invalid data checksum")
	ErrExceedMaxDataLength             = errors.New("exceed max data length")
	ErrExceedMaxMessageNameLength      = errors.New("exceed max message name length")
	ErrUncompressMessageFailed         = errors.New("uncompress message failed")
	ErrInvalidNetworkID                = errors.New("invalid network id")
)

//cloudcardMessage struct
type cloudcardMessage struct {
	content     []byte
	messageName string

	// debug fields.
	sendMessageAt  int64
	writeMessageAt int64
}

// MagicNumber return magicNumber
func (message *cloudcardMessage) MagicNumber() []byte {
	return message.content[0:cloudcardMessageMagicNumberEndIdx]
}

// ChainID return chainID
func (message *cloudcardMessage) ChainID() uint32 {
	chainIdData := make([]byte, 4)
	copy(chainIdData[1:], message.content[cloudcardMessageMagicNumberEndIdx:cloudcardMessageChainIDEndIdx])
	return byteutils.Uint32(chainIdData)
}

// Reserved return reserved
func (message *cloudcardMessage) Reserved() []byte {
	return message.content[cloudcardMessageChainIDEndIdx:cloudcardMessageReservedEndIdx]
}

// Version return version
func (message *cloudcardMessage) Version() byte {
	return message.content[cloudcardMessageVersionIndex]
}

// MessageName return message name
func (message *cloudcardMessage) MessageName() string {
	if message.messageName == "" {
		data := message.content[cloudcardMessageVersionEndIdx:cloudcardMessageNameEndIdx]
		pos := bytes.IndexByte(data, 0)
		if pos != -1 {
			message.messageName = string(data[0:pos])
		} else {
			message.messageName = string(data)
		}
	}
	return message.messageName
}

// DataLength return dataLength
func (message *cloudcardMessage) DataLength() uint32 {
	return byteutils.Uint32(message.content[cloudcardMessageNameEndIdx:cloudcardMessageDataLengthEndIdx])
}

// DataCheckSum return data checkSum
func (message *cloudcardMessage) DataCheckSum() uint32 {
	return byteutils.Uint32(message.content[cloudcardMessageDataLengthEndIdx:cloudcardMessageDataCheckSumEndIdx])
}

// HeaderCheckSum return header checkSum
func (message *cloudcardMessage) HeaderCheckSum() uint32 {
	return byteutils.Uint32(message.content[cloudcardMessageDataCheckSumEndIdx:cloudcardMessageHeaderCheckSumEndIdx])
}

// HeaderWithoutCheckSum return header without checkSum
func (message *cloudcardMessage) HeaderWithoutCheckSum() []byte {
	return message.content[:cloudcardMessageDataCheckSumEndIdx]
}

// Data return data
func (message *cloudcardMessage) Data() ([]byte, error) {
	reserved := message.Reserved()
	data := message.content[cloudcardMessageHeaderLength:]
	if (reserved[2] & ReservedCompressionEnableFlag) > 0 {
		var err error
		data, err = snappy.Decode(nil, data)
		//dstData := make([]byte, MaxcloudcardMessageDataLength)
		//l, err := lz4.UncompressBlock(data, dstData)
		if err != nil {
			return nil, ErrUncompressMessageFailed
		}
		//if l > 0 {
		//	data = make([]byte, l)
		//	data = dstData[:l]
		//}
	}
	return data, nil
}

// OriginalData return original data
func (message *cloudcardMessage) OriginalData() []byte {
	return message.content[cloudcardMessageHeaderLength:]
}

// Content return message content
func (message *cloudcardMessage) Content() []byte {
	return message.content
}

// Length return message Length
func (message *cloudcardMessage) Length() uint64 {
	return uint64(len(message.content))
}

// NewcloudcardMessage new cloudcard message
func NewcloudcardMessage(networkID uint32, chainID uint32, reserved []byte, version byte, messageName string, data []byte) (*cloudcardMessage, error) {

	// Process message compression
	if ((reserved[2] & ReservedCompressionClientFlag) == 0) && ((reserved[2] & ReservedCompressionEnableFlag) > 0) {
		data = snappy.Encode(nil, data)
		//dstData := make([]byte, len(data))
		//ht := make([]int, 64<<10)
		//l, err := lz4.CompressBlock(data, dstData, ht)
		//if err != nil {
		//	panic(err)
		//}
		//if l > 0 {
		//	data = make([]byte, l)
		//	data = dstData[:l]
		//}
	}

	if len(data) > MaxcloudcardMessageDataLength {
		logging.VLog().WithFields(logrus.Fields{
			"messageName": messageName,
			"dataLength":  len(data),
			"limits":      MaxcloudcardMessageDataLength,
		}).Debug("Exceeded max data length.")
		return nil, ErrExceedMaxDataLength
	}

	if len(messageName) > MaxcloudcardMessageNameLength {
		logging.VLog().WithFields(logrus.Fields{
			"messageName":      messageName,
			"len(messageName)": len(messageName),
			"limits":           MaxcloudcardMessageNameLength,
		}).Debug("Exceeded max message name length.")
		return nil, ErrExceedMaxMessageNameLength
	}

	dataCheckSum := crc32.ChecksumIEEE(data)

	message := &cloudcardMessage{
		content: make([]byte, cloudcardMessageHeaderLength+len(data)),
	}

	magicNumber, err := getCurrentNetworkMagicNumber(networkID)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"messageName": messageName,
			"networkID":   networkID,
		}).Debug("invalid network id.")
		return nil, ErrInvalidNetworkID
	}
	// copy fields.
	copy(message.content[0:cloudcardMessageMagicNumberEndIdx], magicNumber)
	chainIdData := byteutils.FromUint32(chainID)
	copy(message.content[cloudcardMessageMagicNumberEndIdx:cloudcardMessageChainIDEndIdx], chainIdData[1:])
	copy(message.content[cloudcardMessageChainIDEndIdx:cloudcardMessageReservedEndIdx], reserved)
	message.content[cloudcardMessageVersionIndex] = version
	copy(message.content[cloudcardMessageVersionEndIdx:cloudcardMessageNameEndIdx], []byte(messageName))
	copy(message.content[cloudcardMessageNameEndIdx:cloudcardMessageDataLengthEndIdx], byteutils.FromUint32(uint32(len(data))))
	copy(message.content[cloudcardMessageDataLengthEndIdx:cloudcardMessageDataCheckSumEndIdx], byteutils.FromUint32(dataCheckSum))

	// header checksum.
	headerCheckSum := crc32.ChecksumIEEE(message.HeaderWithoutCheckSum())
	copy(message.content[cloudcardMessageDataCheckSumEndIdx:cloudcardMessageHeaderCheckSumEndIdx], byteutils.FromUint32(headerCheckSum))

	// copy data.
	copy(message.content[cloudcardMessageHeaderCheckSumEndIdx:], data)

	return message, nil
}

// ParsecloudcardMessage parse cloudcard message
func ParsecloudcardMessage(networkID uint32, data []byte) (*cloudcardMessage, error) {
	if len(data) < cloudcardMessageHeaderLength {
		return nil, ErrInsufficientMessageHeaderLength
	}

	message := &cloudcardMessage{
		content: make([]byte, cloudcardMessageHeaderLength),
	}
	copy(message.content, data)

	if err := message.VerifyHeader(networkID); err != nil {
		return nil, err
	}

	return message, nil
}

// ParseMessageData parse cloudcard message data
func (message *cloudcardMessage) ParseMessageData(data []byte) error {
	if uint32(len(data)) < message.DataLength() {
		return ErrInsufficientMessageDataLength
	}

	message.content = append(message.content, data[:message.DataLength()]...)
	return message.VerifyData()
}

func getCurrentNetworkMagicNumber(networkID uint32) ([]byte, error) {
	if networkID == MajorNetworkID {
		return MagicNumber, nil
	} else if networkID == RTNTNetworkID {
		return RTNTMagicNumber, nil
	} else {
		return nil, ErrInvalidNetworkID
	}
}

// VerifyHeader verify message header
func (message *cloudcardMessage) VerifyHeader(networkID uint32) error {
	magicNumber, err := getCurrentNetworkMagicNumber(networkID)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"networkID":   networkID,
			"magicNumber": message.MagicNumber(),
			"err":         err.Error(),
		}).Debug("Failed to verify header.")
		return err
	}
	if !byteutils.Equal(magicNumber, message.MagicNumber()) {
		logging.VLog().WithFields(logrus.Fields{
			"expect": magicNumber,
			"actual": message.MagicNumber(),
			"err":    "invalid magic number",
		}).Debug("Failed to verify header.")
		return ErrInvalidMagicNumber
	}

	expectedCheckSum := crc32.ChecksumIEEE(message.HeaderWithoutCheckSum())
	if expectedCheckSum != message.HeaderCheckSum() {
		logging.VLog().WithFields(logrus.Fields{
			"expect": expectedCheckSum,
			"actual": message.HeaderCheckSum(),
			"err":    "invalid header checksum",
		}).Debug("Failed to verify header.")
		return ErrInvalidHeaderCheckSum
	}

	if message.DataLength() > MaxcloudcardMessageDataLength {
		logging.VLog().WithFields(logrus.Fields{
			"messageName": message.MessageName(),
			"dataLength":  message.DataLength(),
			"limit":       MaxcloudcardMessageDataLength,
			"err":         "exceeded max data length",
		}).Debug("Failed to verify header.")
		return ErrExceedMaxDataLength
	}

	return nil
}

// VerifyData verify message data
func (message *cloudcardMessage) VerifyData() error {
	expectedCheckSum := crc32.ChecksumIEEE(message.OriginalData())
	if expectedCheckSum != message.DataCheckSum() {
		logging.VLog().WithFields(logrus.Fields{
			"expect": expectedCheckSum,
			"actual": message.DataCheckSum(),
			"err":    "invalid data checksum",
		}).Debug("Failed to verify data")
		return ErrInvalidDataCheckSum
	}
	return nil
}

// FlagWriteMessageAt flag of write message time
func (message *cloudcardMessage) FlagWriteMessageAt() {
	message.writeMessageAt = time.Now().UnixNano()
}

// FlagSendMessageAt flag of send message time
func (message *cloudcardMessage) FlagSendMessageAt() {
	message.sendMessageAt = time.Now().UnixNano()
}

// LatencyFromSendToWrite latency from sendMessage to writeMessage
func (message *cloudcardMessage) LatencyFromSendToWrite() int64 {
	if message.sendMessageAt == 0 {
		return -1
	} else if message.writeMessageAt == 0 {
		message.FlagWriteMessageAt()
	}

	// convert from nano to millisecond.
	return (message.writeMessageAt - message.sendMessageAt) / int64(time.Millisecond)
}
