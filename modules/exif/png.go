package exif

import (
	"bufio"
	"encoding/binary"
	"io"
)

/*
	PNG Signature -> 137 80 78 71 13 10 26 10 (8 Bytes)
	PNG Chunk -> Length (4 Bytes) + Type (4 Bytes) + Data (Length Bytes) + CRC (4 Bytes)

	PNG Chunk Types:
		- eXIf: EXIF data
		- iTXt: International text
		- tEXt: Textual data
		- zTXt: Compressed textual data

	Big Endian -> left to right
	Little Endian -> right to left
*/

func CleanPNG(r io.Reader, w io.Writer) error {
	bufReader := bufio.NewReader(r)

	// PNG signature
	sig := make([]byte, 8)
	if _, err := io.ReadFull(bufReader, sig); err != nil {
		return err
	}

	if _, err := w.Write(sig); err != nil {
		return err
	}

	for {
		lengthBytes := make([]byte, 4)
		if _, err := io.ReadFull(bufReader, lengthBytes); err != nil {
			return nil // EOF
		}

		// chunk length
		length := binary.BigEndian.Uint32(lengthBytes)
		chunkType := make([]byte, 4)
		if _, err := io.ReadFull(bufReader, chunkType); err != nil {
			return err
		}

		chunkData := make([]byte, length)
		if _, err := io.ReadFull(bufReader, chunkData); err != nil {
			return err
		}

		// 4b checksum
		crc := make([]byte, 4)
		if _, err := io.ReadFull(bufReader, crc); err != nil {
			return err
		}

		switch string(chunkType) {
		case "eXIf", "iTXt", "tEXt", "zTXt":
			continue
		default:
			w.Write(lengthBytes)
			w.Write(chunkType)
			w.Write(chunkData)
			w.Write(crc)
		}

		// PNG end chunk
		if string(chunkType) == "IEND" {
			return nil
		}
	}
}
