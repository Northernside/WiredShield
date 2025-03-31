package protocol

import (
	"bytes"
	"io"

	"github.com/fxamacker/cbor/v2"
)

/*
	Payload:

	Length Entire Packet (VarInt)
	PacketID (VarInt)
	Data (Byte Array)
*/

func (p *Packet) Write(conn io.Writer) (int64, error) {
	buf := bytes.Buffer{}

	//write packet id to buffer
	_, err := p.ID.WriteTo(&buf)
	if err != nil {
		return 0, err
	}

	//write data to buffer
	_, err = buf.Write(p.Data)
	if err != nil {
		return 0, err
	}

	//write buffer length to connection
	length := VarInt(buf.Len())
	n, err := length.WriteTo(conn)
	if err != nil {
		return n, err
	}

	return buf.WriteTo(conn)
}

func (p *Packet) Read(conn io.Reader) error {
	// Read packet length
	var length VarInt
	_, err := length.ReadFrom(conn)
	if err != nil {
		return err
	}

	var id VarInt
	_, err = id.ReadFrom(conn)
	if err != nil {
		return err
	}
	p.ID = id
	if int(length)-id.Len() > 0 {
		buf := make([]byte, int(length)-id.Len())

		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return err
		}
		p.Data = buf
	}
	return nil

}

func EncodePacket(s any) ([]byte, error) {
	b, ok := s.(interface{ Encode() ([]byte, error) })
	if ok {
		return b.Encode()
	}

	return cbor.Marshal(s)
}

func DecodePacket(data []byte, s any) error {
	return cbor.NewDecoder(bytes.NewReader(data)).Decode(s)
}
