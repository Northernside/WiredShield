package globals

import (
	"errors"
	"io"
)

type VarInt uint32

const (
	MaxVarIntLen = 5
)

func (v VarInt) WriteTo(w io.Writer) (int64, error) {
	var vi [MaxVarIntLen]byte
	n := v.WriteToBytes(vi[:])
	n, err := w.Write(vi[:n])

	return int64(n), err
}

func (v VarInt) WriteToBytes(buf []byte) int {
	num := uint32(v)
	i := 0
	for {
		b := num & 0x7F
		num >>= 7
		if num != 0 {
			b |= 0x80
		}

		buf[i] = byte(b)
		i++

		if num == 0 {
			break
		}
	}

	return i
}

// Len returns the number of bytes required to encode the VarInt
func (v VarInt) Len() int {
	switch {
	case v < 0:
		return MaxVarIntLen
	case v < 1<<(7*1):
		return 1
	case v < 1<<(7*2):
		return 2
	case v < 1<<(7*3):
		return 3
	case v < 1<<(7*4):
		return 4
	default:
		return 5
	}
}

func (v *VarInt) ReadFrom(r io.Reader) (int64, error) {
	var vi uint32
	var num, n int64
	for sec := byte(0x80); sec&0x80 != 0; num++ {
		if num > MaxVarIntLen {
			return 0, errors.New("VarInt is too big")
		}

		var err error
		n, sec, err = readByte(r)
		if err != nil {
			return n, err
		}

		vi |= uint32(sec&0x7F) << uint32(7*num)
	}

	*v = VarInt(vi)
	return n, nil
}

func readByte(r io.Reader) (int64, byte, error) {
	if r, ok := r.(io.ByteReader); ok {
		v, err := r.ReadByte()
		return 1, v, err
	}

	var v [1]byte
	n, err := r.Read(v[:])

	return int64(n), v[0], err
}

type packetIDs struct {
	ID_SharedSecret, ID_Login, ID_ChallengeStart, ID_ChallengeResult, ID_ChallengeFinish VarInt
	ID_Config, ID_Ready, ID_Ping, ID_Pong, Error, ID_BinaryData, ID_BinaryDataEnd        VarInt
	ID_EventTransmission, ID_NodeAttached, ID_NodeDetached                               VarInt
}

var Packet = packetIDs{0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15}
