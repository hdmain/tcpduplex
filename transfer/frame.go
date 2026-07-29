package transfer

import (
	"encoding/binary"
	"unicode/utf8"
)

// Wire frame types carried inside MsgText (magic + type + payload).
const (
	typeOffer  uint8 = 1
	typeAccept uint8 = 2
	typeReject uint8 = 3
	typeChunk  uint8 = 4
	typeAck    uint8 = 5
	typeDone   uint8 = 6
	typeAbort  uint8 = 7
)

var frameMagic = [4]byte{'T', 'F', 'X', '1'}

// Header sizes (excluding data / name / reason tails).
const (
	headerLen      = 5 // magic + type
	idLen          = 16
	offerFixedLen  = headerLen + idLen + 8 + 32 + 2 // + name follows
	acceptLen      = headerLen + idLen + 8
	chunkFixedLen  = headerLen + idLen + 8 // + data follows
	ackLen         = headerLen + idLen + 8
	doneLen        = headerLen + idLen + 1 + 32
	rejectFixedLen = headerLen + idLen + 2 // + reason
	abortFixedLen  = headerLen + idLen + 2 // + reason
)

// Meta describes a file/stream being offered.
type Meta struct {
	ID   ID
	Name string
	Size int64
	// Hash is SHA-256 of the complete content. A zero value means the sender
	// did not supply a hash; the receiver skips verification in that case.
	Hash [32]byte
}

func encodeOffer(m Meta) ([]byte, error) {
	if m.Size < 0 {
		return nil, ErrSizeMismatch
	}
	if !utf8.ValidString(m.Name) {
		return nil, ErrBadFrame
	}
	name := []byte(m.Name)
	if len(name) > 0xffff {
		return nil, ErrBadFrame
	}
	buf := make([]byte, offerFixedLen+len(name))
	copy(buf[:4], frameMagic[:])
	buf[4] = typeOffer
	copy(buf[5:21], m.ID[:])
	binary.BigEndian.PutUint64(buf[21:29], uint64(m.Size))
	copy(buf[29:61], m.Hash[:])
	binary.BigEndian.PutUint16(buf[61:63], uint16(len(name)))
	copy(buf[63:], name)
	return buf, nil
}

func encodeAccept(id ID, resumeOffset int64) []byte {
	buf := make([]byte, acceptLen)
	copy(buf[:4], frameMagic[:])
	buf[4] = typeAccept
	copy(buf[5:21], id[:])
	binary.BigEndian.PutUint64(buf[21:29], uint64(resumeOffset))
	return buf
}

func encodeReject(id ID, reason string) []byte {
	r := []byte(reason)
	if len(r) > 0xffff {
		r = r[:0xffff]
	}
	buf := make([]byte, rejectFixedLen+len(r))
	copy(buf[:4], frameMagic[:])
	buf[4] = typeReject
	copy(buf[5:21], id[:])
	binary.BigEndian.PutUint16(buf[21:23], uint16(len(r)))
	copy(buf[23:], r)
	return buf
}

func encodeChunk(id ID, offset int64, data []byte) []byte {
	buf := make([]byte, chunkFixedLen+len(data))
	copy(buf[:4], frameMagic[:])
	buf[4] = typeChunk
	copy(buf[5:21], id[:])
	binary.BigEndian.PutUint64(buf[21:29], uint64(offset))
	copy(buf[29:], data)
	return buf
}

func encodeAck(id ID, cumOffset int64) []byte {
	buf := make([]byte, ackLen)
	copy(buf[:4], frameMagic[:])
	buf[4] = typeAck
	copy(buf[5:21], id[:])
	binary.BigEndian.PutUint64(buf[21:29], uint64(cumOffset))
	return buf
}

func encodeDone(id ID, ok bool, hash [32]byte) []byte {
	buf := make([]byte, doneLen)
	copy(buf[:4], frameMagic[:])
	buf[4] = typeDone
	copy(buf[5:21], id[:])
	if ok {
		buf[21] = 1
	}
	copy(buf[22:54], hash[:])
	return buf
}

func encodeAbort(id ID, reason string) []byte {
	r := []byte(reason)
	if len(r) > 0xffff {
		r = r[:0xffff]
	}
	buf := make([]byte, abortFixedLen+len(r))
	copy(buf[:4], frameMagic[:])
	buf[4] = typeAbort
	copy(buf[5:21], id[:])
	binary.BigEndian.PutUint16(buf[21:23], uint16(len(r)))
	copy(buf[23:], r)
	return buf
}

type decoded struct {
	typ    uint8
	id     ID
	meta   Meta
	offset int64
	data   []byte
	ok     bool
	hash   [32]byte
	reason string
}

func decodeFrame(b []byte) (decoded, error) {
	var d decoded
	if len(b) < headerLen {
		return d, ErrBadFrame
	}
	if b[0] != frameMagic[0] || b[1] != frameMagic[1] || b[2] != frameMagic[2] || b[3] != frameMagic[3] {
		return d, ErrBadFrame
	}
	d.typ = b[4]
	switch d.typ {
	case typeOffer:
		if len(b) < offerFixedLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		d.meta.ID = d.id
		d.meta.Size = int64(binary.BigEndian.Uint64(b[21:29]))
		copy(d.meta.Hash[:], b[29:61])
		nlen := int(binary.BigEndian.Uint16(b[61:63]))
		if len(b) != offerFixedLen+nlen {
			return d, ErrBadFrame
		}
		d.meta.Name = string(b[63:])
		if !utf8.ValidString(d.meta.Name) {
			return d, ErrBadFrame
		}
	case typeAccept:
		if len(b) != acceptLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		d.offset = int64(binary.BigEndian.Uint64(b[21:29]))
	case typeReject:
		if len(b) < rejectFixedLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		nlen := int(binary.BigEndian.Uint16(b[21:23]))
		if len(b) != rejectFixedLen+nlen {
			return d, ErrBadFrame
		}
		d.reason = string(b[23:])
	case typeChunk:
		if len(b) < chunkFixedLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		d.offset = int64(binary.BigEndian.Uint64(b[21:29]))
		d.data = b[29:]
	case typeAck:
		if len(b) != ackLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		d.offset = int64(binary.BigEndian.Uint64(b[21:29]))
	case typeDone:
		if len(b) != doneLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		d.ok = b[21] != 0
		copy(d.hash[:], b[22:54])
	case typeAbort:
		if len(b) < abortFixedLen {
			return d, ErrBadFrame
		}
		copy(d.id[:], b[5:21])
		nlen := int(binary.BigEndian.Uint16(b[21:23]))
		if len(b) != abortFixedLen+nlen {
			return d, ErrBadFrame
		}
		d.reason = string(b[23:])
	default:
		return d, ErrBadFrame
	}
	return d, nil
}
