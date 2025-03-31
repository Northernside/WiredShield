package protocol

import (
	"errors"
	"io"
)

type (
	VarInt uint32
	String string
	Byte   int8
	Bool   bool
	Long   int64
)

type Packet struct {
	ID   VarInt
	Data []byte
}

const (
	MaxVarIntLen  = 5
	MaxVarLongLen = 10
)

func (b Byte) WriteTo(w io.Writer) (int64, error) {
	nn, err := w.Write([]byte{byte(b)})
	return int64(nn), err
}

func (b *Byte) ReadFrom(r io.Reader) (int64, error) {
	n, v, err := readByte(r)
	if err != nil {
		return n, err
	}

	*b = Byte(v)
	return n, nil
}
func (l Long) WriteTo(w io.Writer) (int64, error) {
	n := uint64(l)
	nn, err := w.Write([]byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	})

	return int64(nn), err
}

func (l *Long) ReadFrom(r io.Reader) (int64, error) {
	var bs [8]byte
	nn, err := io.ReadFull(r, bs[:])
	if err != nil {
		return int64(nn), err
	}

	n := int64(nn)
	*l = Long(int64(bs[0])<<56 | int64(bs[1])<<48 | int64(bs[2])<<40 | int64(bs[3])<<32 |
		int64(bs[4])<<24 | int64(bs[5])<<16 | int64(bs[6])<<8 | int64(bs[7]))

	return n, nil
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

func (b Bool) WriteTo(w io.Writer) (int64, error) {
	var v byte
	if b {
		v = 0x01
	} else {
		v = 0x00
	}

	n, err := w.Write([]byte{v})
	return int64(n), err
}

func (b *Bool) ReadFrom(r io.Reader) (int64, error) {
	n, v, err := readByte(r)
	if err != nil {
		return n, err
	}

	*b = v != 0
	return n, nil
}

func (s String) WriteTo(w io.Writer) (int64, error) {
	byteStr := []byte(s)
	v := VarInt(len(byteStr))
	n1, err := v.WriteTo(w)
	if err != nil {
		return n1, err
	}

	n2, err := w.Write(byteStr)
	return n1 + int64(n2), err
}

func (s *String) ReadFrom(r io.Reader) (int64, error) {
	var l VarInt // String length

	nn, err := l.ReadFrom(r)
	if err != nil {
		return nn, err
	}

	n := nn
	bs := make([]byte, l)
	if _, err := io.ReadFull(r, bs); err != nil {
		return n, err
	}

	n += int64(l)
	*s = String(bs)

	return n, nil
}

func (v *VarInt) ReadFromBytes(b []byte) error {
	var result uint32
	var shift uint

	for i, byteVal := range b {
		if i >= MaxVarIntLen {
			return errors.New("varint too long, possible overflow")
		}

		// Extract the 7 bits of data
		part := uint32(byteVal & 0x7F)
		result |= part << shift

		// Check for continuation bit (MSB is 0 means end of VarInt)
		if byteVal&0x80 == 0 {
			*v = VarInt(result)
			return nil
		}

		shift += 7
	}

	return io.ErrUnexpectedEOF
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

func (v VarInt) WriteTo(w io.Writer) (int64, error) {
	var vi [MaxVarIntLen]byte
	n := v.WriteToBytes(vi[:])
	n, err := w.Write(vi[:n])

	return int64(n), err
}

func readVarInt(r io.Reader) (VarInt, error) {
	var id VarInt
	_, err := id.ReadFrom(r)

	return id, err
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
