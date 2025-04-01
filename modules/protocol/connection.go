// Credits: https://github.com/mxha39

package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	StateInitial    VarInt = 0 // initial connection
	StateAESReady   VarInt = 1 // aes ready
	StateFullyReady VarInt = 2 // fully authenticated connection
)

type Conn struct {
	Address net.IP
	Port    uint16
	State   VarInt
	Key     string
	conn    net.Conn
	r       io.Reader
	w       io.Writer
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func NewConn(c net.Conn) *Conn {
	addr, portStr, _ := net.SplitHostPort(c.RemoteAddr().String())
	port, _ := strconv.Atoi(portStr)
	return &Conn{
		Address: net.ParseIP(addr),
		Port:    uint16(port),
		conn:    c,
		State:   StateInitial,
		r:       c,
		w:       c,
	}
}

func (c *Conn) EnableEncryption(sharedSecret []byte) error {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return err
	}

	c.SetCipher(NewCFB8Encrypter(block, sharedSecret), NewCFB8Decrypter(block, sharedSecret))
	c.State = StateAESReady
	return nil
}

func (c *Conn) SetCipher(encStream, decStream cipher.Stream) {
	c.r = cipher.StreamReader{
		S: decStream,
		R: c.conn,
	}
	c.w = cipher.StreamWriter{
		S: encStream,
		W: c.conn,
	}
}

func (c *Conn) SetReader(r io.Reader) {
	c.r = r
}

func (c *Conn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.w.Write(p)
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) Addr() net.IP {
	return c.Address
}

func (c *Conn) GetSocket() net.Conn {
	return c.conn
}

func (c *Conn) SendPacket(id VarInt, packet any) error {
	//marshal packet
	var (
		data []byte
		err  error
	)

	if packet != nil {
		data, err = EncodePacket(packet)
		if err != nil {
			return err
		}
	}

	//assemble and send packet
	_, err = (&Packet{
		ID:   id,
		Data: data,
	}).Write(c)

	return err
}

func (c *Conn) SendRawPacket(id VarInt, packet []byte) error {
	_, err := (&Packet{
		ID:   id,
		Data: packet,
	}).Write(c)

	return err
}

func MarshalRawPacket(id VarInt, packet []byte) ([]byte, error) {
	var err error
	buf := bytes.Buffer{}
	_, err = (&Packet{
		ID:   id,
		Data: packet,
	}).Write(&buf)

	return buf.Bytes(), err
}

func MarshalPacket(id VarInt, packet any) ([]byte, error) {
	var data []byte
	var err error
	if packet != nil {
		data, err = EncodePacket(packet)
		if err != nil {
			return nil, err
		}
	}

	buf := bytes.Buffer{}
	_, err = (&Packet{
		ID:   id,
		Data: data,
	}).Write(&buf)

	return buf.Bytes(), err
}
