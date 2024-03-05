package ubiq

import (
	"encoding/binary"
)

// flag indicates that the header is
// part of the authenticated data
const headerV0FlagAAD = 1

type headerV0 struct {
	// version uint8
	flags uint8
	algo  uint8
	// ivlen uint8
	// keylen uint16
	iv  []byte
	key []byte
}

type header struct {
	version uint8
	v0      headerV0
}

// -1 header isn't valid and never will be
// 0 header isn't valid, but more bytes could change that
// >0 header is valid and contains returned number of bytes
func headerValid(buf []byte) int {
	buflen := len(buf)

	if buflen == 0 {
		return 0
	}

	switch buf[0] {
	case 0:
		if buflen > 1 &&
			(buf[1]&^headerV0FlagAAD) != 0 {
			return -1
		}
		if buflen > 2 {
			if _, e := getAlgorithmById(int(
				buf[2])); e != nil {
				return -1
			}
		}
		if buflen > 5 {
			totlen := 6 + int(buf[3]) +
				int(binary.BigEndian.Uint16(buf[4:]))

			if buflen >= totlen {
				return totlen
			}
		}
		return 0
	}

	return -1
}

func newHeader(buf []byte) header {
	var h header

	// if the header is valid, parse it into
	// a more readily usable data structure

	hdrlen := headerValid(buf)
	if hdrlen > 0 {
		h.version = buf[0]

		if h.version == 0 {
			h.v0.flags = buf[1]
			h.v0.algo = buf[2]

			ivlen := int(buf[3])
			keylen := int(binary.BigEndian.Uint16(buf[4:]))

			h.v0.iv = buf[6 : 6+ivlen]
			h.v0.key = buf[6+ivlen : 6+ivlen+keylen]
		}
	}

	return h
}

func (h header) serialize() []byte {
	var hdr []byte

	switch h.version {
	case 0:
		// 1 byte for each of version, flags, algo, and ivlength
		// 2 bytes for key length
		hdr = make([]byte, 6)

		hdr[0] = h.version
		hdr[1] = h.v0.flags
		hdr[2] = h.v0.algo
		hdr[3] = uint8(len(h.v0.iv))
		binary.BigEndian.PutUint16(hdr[4:], uint16(len(h.v0.key)))

		hdr = append(hdr, h.v0.iv...)
		hdr = append(hdr, h.v0.key...)
	}

	return hdr
}
