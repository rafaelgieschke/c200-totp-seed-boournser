package main

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ebfe/scard"
)

var DEBUG bool

type Tag interface {
	Transceive(data []byte) (resp []byte, err error)
}

var _ Tag = (*ScardTag)(nil)

type ScardTag struct {
	*scard.Card
}

func (c *ScardTag) Transceive(data []byte) (resp []byte, err error) {
	// Reader seems to be happier if regularly transceiving a fake SELECT APDU
	_, err = c.transceiveRaw([]byte{0x00, 0xa4, 0x04, 0x00})
	if err != nil {
		return
	}
	return c.transceiveRaw(data)
}

func (c *ScardTag) transceiveRaw(data []byte) (resp []byte, err error) {
	if DEBUG {
		fmt.Printf("> %#v\n", data)
	}
	resp, err = c.Transmit(data)
	if DEBUG {
		fmt.Printf("< %#v (%#v)\n", resp, err)
	}
	return
}

type Token struct {
	Tag
}

func xor(data ...uint8) (ret uint8) {
	for _, v := range data {
		ret ^= v
	}
	return
}

func (t *Token) Transceive(data []byte) (resp []byte, err error) {
	buffer := []byte{0x86, uint8(len(data) + 1)}
	buffer = append(buffer, data...)
	buffer = append(buffer, xor(data...))
	resp, err = t.Tag.Transceive(buffer)
	if err != nil {
		return
	}
	if resp[0] != 0xaa {
		return nil, fmt.Errorf("unknown response header byte")
	}
	if resp[2+resp[1]-1] != xor(resp[2:2+resp[1]-1]...) {
		return nil, fmt.Errorf("response checksum incorrect")
	}
	return resp[2 : 2+resp[1]-1], nil
}

func (t *Token) GetInfo() (resp []byte, err error) {
	return t.Transceive([]byte{0x10})
}

func checksum(data []byte) (checksum uint16) {
	reader := bytes.NewReader(data)
	for u := uint16(0); binary.Read(reader, binary.BigEndian, &u) == nil; {
		checksum += u
	}
	checksum |= 0x5115
	return
}

func (t *Token) BurnSeed(seed []byte) (resp []byte, err error) {
	buffer := append([]byte(nil), seed...)
	buffer = append(buffer, 6, 30)
	buffer = binary.BigEndian.AppendUint16(buffer, checksum(seed))

	data, err := t.GetInfo()
	if err != nil {
		return
	}
	key := data[5]
	for i := range buffer {
		buffer[i] ^= key
	}

	return t.Transceive(append([]byte{0x18}, buffer...))
}

func decodeHexOrBase32(str string) ([]byte, error) {
	str = strings.ToUpper(strings.TrimSpace(str))
	data, err := hex.DecodeString(str)
	if err == nil {
		return data, nil
	}
	data, err2 := base32.StdEncoding.DecodeString(str)
	if err2 == nil {
		return data, nil
	}
	return nil, errors.Join(err, err2)
}

func run() (err error) {
	flag.BoolVar(&DEBUG, "debug", false, "show debug output")
	flag.Parse()

	context, err := scard.EstablishContext()
	if err != nil {
		return
	}
	readers, err := context.ListReaders()
	if err != nil {
		return
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Seed (hex or base32): ")
	seedString, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	seed, err := decodeHexOrBase32(seedString)
	if err != nil {
		return
	}

	fmt.Println("Place token on reader...")
	var card *scard.Card
	for card == nil {
		for _, reader := range readers {
			if card, err = context.Connect(reader, scard.ShareShared, scard.ProtocolAny); err == nil {
				break
			}
		}
	}
	token := Token{&ScardTag{card}}

	fmt.Println("Burning seed...")
	_, err = token.BurnSeed(seed)
	if err != nil {
		return
	}
	fmt.Println("Success")
	return
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
