package exif

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

/*
	Segment -> Header (2 Byte) + Data
	3rd Byte -> Length of the segment

	JPEG EXIF Header -> 0xFFE1 -> 0xFF, 0xE1
*/

func CleanJPEG(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)

	soi := make([]byte, 2)
	if _, err := io.ReadFull(br, soi); err != nil {
		return err
	}

	if soi[0] != 0xFF || soi[1] != 0xD8 {
		return errors.New("not a valid JPEG")
	}

	if _, err := w.Write(soi); err != nil {
		return err
	}

	for {
		// read marker (2b header)
		marker := make([]byte, 2)
		if _, err := io.ReadFull(br, marker); err != nil {
			_, _ = io.Copy(w, br)
			return err
		}

		if marker[0] != 0xFF {
			return errors.New("invalid JPEG marker")
		}

		// no segment length for SOF, SOS, EOI
		if marker[1] == 0xDA || marker[1] == 0xD9 {
			if _, err := w.Write(marker); err != nil {
				return err
			}

			_, err := io.Copy(w, br)
			return err
		}

		// read segment length
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(br, lenBytes); err != nil {
			return err
		}

		segLen := int(binary.BigEndian.Uint16(lenBytes))
		segData := make([]byte, segLen-2)
		if _, err := io.ReadFull(br, segData); err != nil {
			return err
		}

		if marker[1] == 0xE1 {
			if len(segData) >= 6 && string(segData[:6]) == "Exif\x00\x00" { // confirm EXIF header
				continue
			}
		}

		w.Write(marker)
		w.Write(lenBytes)
		w.Write(segData)
	}
}
