package protocol

import (
	"io"
	"wired/modules/globals"
)

type (
	String string
	Byte   int8
	Bool   bool
	Long   int64
)

type Packet struct {
	ID   globals.VarInt
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
	v := globals.VarInt(len(byteStr))
	n1, err := v.WriteTo(w)
	if err != nil {
		return n1, err
	}

	n2, err := w.Write(byteStr)
	return n1 + int64(n2), err
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
