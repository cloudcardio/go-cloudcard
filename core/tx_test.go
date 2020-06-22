package core

import (
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"math/big"
	"testing"
)

func TestCalcTxSize(t *testing.T) {
	tx := getTransaction()
	fee := tx.CalcFee()
	fmt.Println(fee)

}

func TestNewComplexTransaction(t *testing.T) {
	from := NewAddress([]byte{12, 34, 31, 21, 23, 34, 32, 4, 5, 34, 12, 23, 3, 22, 33, 22, 12,
		32, 12, 12, 3, 33, 2, 33, 23, 23, 33, 45, 78, 67, 65, 45, 43, 32, 23, 12, 12})
	to := NewAddress([]byte{12, 34, 31, 21, 23, 34, 32, 4, 5, 34, 12, 23, 3, 22, 33, 22, 12,
		32, 12, 12, 3, 33, 2, 33, 23, 23, 33, 45, 78, 67, 65, 45, 43, 32, 23, 21, 12})
	amout := big.NewInt(1000000000000000000)
	nounce := 2
	chanId := 10
	priority := 2
	txType := ComplexTx

	hexString := "ac234bdfc245434245"

	commonData := new(corepb.Data)
	commonData.Type = ContractInvokeTx
	commonData.Msg, _ = byteutils.FromHex(hexString)

	data := new(corepb.Data)
	data.Type = txType

	complexData := new(corepb.ComplexData)
	files := make([]*corepb.File, 3)
	for i := 0; i < len(files); i++ {
		file := new(corepb.File)
		file.Content = byteutils.FromInt64(int64(i))
		file.BindKey = "abc"
		file.Name = "brady"
		files[i] = file
	}
	complexData.Data = commonData
	//complexData.Flies = files

	msg, err := proto.Marshal(complexData)
	if err != nil {
		fmt.Println(err.Error())
	}
	tx, err := NewTransaction(from, to, amout, uint64(nounce), uint32(chanId), uint32(priority), txType, msg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(tx.hash)

	if complexData.Flies == nil {
		data := new(corepb.Data)
		err := proto.Unmarshal(tx.data.Msg, data)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(byteutils.Equal(commonData.Msg, data.Msg))
		fmt.Println(byteutils.Hex(data.Msg))
	}

	complexData.Flies = files
	msg, err = proto.Marshal(complexData)
	if err != nil {
		fmt.Println(err.Error())
	}
	tx, err = NewTransaction(from, to, amout, uint64(nounce), uint32(chanId), uint32(priority), txType, msg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(tx.hash)

	complexData = new(corepb.ComplexData)
	err = proto.Unmarshal(tx.data.Msg, complexData)
	if err != nil {
		fmt.Println(err.Error())
	}
	resultFiles := complexData.Flies
	for _, result := range resultFiles {
		fmt.Print(result.BindKey)
		fmt.Print("->")
		fmt.Print(result.State.Result)
		fmt.Print("   fileSize：")
		fmt.Print(result.Size)
		fmt.Println(" byte")
	}
}

func TestNewPledgeTransaction(t *testing.T) {
	from := NewAddress([]byte{12, 34, 31, 21, 23, 34, 32, 4, 5, 34, 12, 23, 3, 22, 33, 22, 12,
		32, 12, 12, 3, 33, 2, 33, 23, 23, 33, 45, 78, 67, 65, 45, 43, 32, 23, 12, 12})
	data := new(corepb.Data)
	data.Type = PledgeTx
	data.Msg = []byte{12, 43}
	tx, err := NewPledgeTransaction(from, big.NewInt(9), 1, 32, 2, data.Type, data.Msg)
	if err != nil {
		fmt.Println(err.Error())
	}
	if tx != nil {
		fmt.Println(tx.hash.Hex())
	}
}

func getTransaction() *Transaction {
	tx := new(Transaction)
	signature := new(corepb.Signature)
	signature.Data = []byte{12, 43, 55, 2, 23}
	signature.Signer = []byte{23, 43, 23, 32}
	tx.sign = signature
	tx.hash = byteutils.Hash{12, 34}
	tx.from = new(Address)
	tx.to = new(Address)
	tx.data = new(corepb.Data)
	tx.data.Msg = byteutils.Hash{23, 43, 11}
	tx.data.Type = "abc"
	return tx
}
