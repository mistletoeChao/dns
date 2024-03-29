package dns

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"
)

// HMAC hashing codes. These are transmitted as domain names.
const (
	HmacMD5    = "hmac-md5.sig-alg.reg.int."
	HmacSHA1   = "hmac-sha1."
	HmacSHA256 = "hmac-sha256."
	HmacSHA512 = "hmac-sha512."
	HmacSM3    = "hmac-sm3."
)

// TSIG is the RR the holds the transaction signature of a message.
// See RFC 2845 and RFC 4635.
type TSIG struct {
	Hdr        RR_Header
	Algorithm  string `dns:"domain-name"`
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	MACSize    uint16
	MAC        string `dns:"size-hex"`
	OrigId     uint16
	Error      uint16
	OtherLen   uint16
	OtherData  string `dns:"size-hex"`
}

// TSIG has no official presentation format, but this will suffice.

func (rr *TSIG) String() string {
	s := "\n;; TSIG PSEUDOSECTION:\n"
	s += rr.Hdr.String() +
		" " + rr.Algorithm +
		" " + tsigTimeToString(rr.TimeSigned) +
		" " + strconv.Itoa(int(rr.Fudge)) +
		" " + strconv.Itoa(int(rr.MACSize)) +
		" " + strings.ToUpper(rr.MAC) +
		" " + strconv.Itoa(int(rr.OrigId)) +
		" " + RcodeToString[int(rr.Error)] + // BIND prints NOERROR
		" " + strconv.Itoa(int(rr.OtherLen)) +
		" " + rr.OtherData
	return s
}

// The following values must be put in wireformat, so that the MAC can be calculated.
// RFC 2845, section 3.4.2. TSIG Variables.
type tsigWireFmt struct {
	// From RR_Header
	Name  string `dns:"domain-name"`
	Class uint16
	Ttl   uint32
	// Rdata of the TSIG
	Algorithm  string `dns:"domain-name"`
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
	// MACSize, MAC and OrigId excluded
	Error     uint16
	OtherLen  uint16
	OtherData string `dns:"size-hex"`
}

// If we have the MAC use this type to convert it to wiredata.
// Section 3.4.3. Request MAC
type macWireFmt struct {
	MACSize uint16
	MAC     string `dns:"size-hex"`
}

// 3.3. Time values used in TSIG calculations
type timerWireFmt struct {
	TimeSigned uint64 `dns:"uint48"`
	Fudge      uint16
}

// TsigPrepare generate empty tsig context
func TsigPrepare(keyName, secret, alg, requestMAC string) (hash.Hash, error) {
	rawsecret, err := fromBase64([]byte(secret))
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch alg {
	case HmacMD5:
		h = hmac.New(md5.New, []byte(rawsecret))
	case HmacSHA1:
		h = hmac.New(sha1.New, []byte(rawsecret))
	case HmacSHA256:
		h = hmac.New(sha256.New, []byte(rawsecret))
	case HmacSHA512:
		h = hmac.New(sha512.New, []byte(rawsecret))
	case HmacSM3:
		h = hmac.New(Sm3New, []byte(rawsecret))
	default:
		return nil, ErrKeyAlg
	}

	if requestMAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(requestMAC) / 2)
		m.MAC = requestMAC
		buf := make([]byte, len(requestMAC)) // long enough
		n, _ := PackStruct(m, buf, 0)
		buf = buf[:n]
		_, err = h.Write(buf)
		if err != nil {
			return nil, err
		}
	}

	return h, nil
}

// TsigGenerate fills out the TSIG record attached to the message.
// The message should contain
// a "stub" TSIG RR with the algorithm, key name (owner name of the RR),
// time fudge (defaults to 300 seconds) and the current time
// The TSIG MAC is saved in that Tsig RR.
// When TsigGenerate is called for the first time requestMAC is set to the empty string and
// timersOnly is false.
// If something goes wrong an error is returned, otherwise it is nil.
func TsigGenerate(m *Msg, secret, requestMAC string, timersOnly bool) ([]byte, string, error) {
	if m.IsTsig() == nil {
		panic("dns: TSIG not last RR in additional")
	}
	// If we barf here, the caller is to blame
	rawsecret, err := fromBase64([]byte(secret))
	if err != nil {
		return nil, "", err
	}

	rr := m.Extra[len(m.Extra)-1].(*TSIG)
	m.Extra = m.Extra[0 : len(m.Extra)-1] // kill the TSIG from the msg
	mbuf, err := m.Pack()
	if err != nil {
		return nil, "", err
	}
	buf := tsigBuffer(mbuf, rr, requestMAC, timersOnly)

	t := new(TSIG)
	var h hash.Hash
	switch rr.Algorithm {
	case HmacMD5:
		h = hmac.New(md5.New, []byte(rawsecret))
	case HmacSHA1:
		h = hmac.New(sha1.New, []byte(rawsecret))
	case HmacSHA256:
		h = hmac.New(sha256.New, []byte(rawsecret))
	case HmacSHA512:
		h = hmac.New(sha512.New, []byte(rawsecret))
	case HmacSM3:
		h = hmac.New(Sm3New, []byte(rawsecret))
	default:
		return nil, "", ErrKeyAlg
	}
	io.WriteString(h, string(buf))
	t.MAC = hex.EncodeToString(h.Sum(nil))
	t.MACSize = uint16(len(t.MAC) / 2) // Size is half!

	t.Hdr = RR_Header{Name: rr.Hdr.Name, Rrtype: TypeTSIG, Class: ClassANY, Ttl: 0}
	t.Fudge = rr.Fudge
	t.TimeSigned = rr.TimeSigned
	t.Algorithm = rr.Algorithm
	t.OrigId = m.Id

	tbuf := make([]byte, t.len())
	if off, err := PackRR(t, tbuf, 0, nil, false); err == nil {
		tbuf = tbuf[:off] // reset to actual size used
	} else {
		return nil, "", err
	}
	mbuf = append(mbuf, tbuf...)
	rawSetExtraLen(mbuf, uint16(len(m.Extra)+1))
	return mbuf, t.MAC, nil
}

// TsigUpdate write raw message byte
func TsigUpdate(msg []byte, h hash.Hash) error {
	_, err := h.Write(msg)
	return err
}

// TsigVerify verifies the TSIG on a message.
// If the signature does not validate err contains the
// error, otherwise it is nil.
func TsigVerify(msg []byte, secret, requestMAC string, timersOnly bool, h hash.Hash) error {
	rawsecret, err := fromBase64([]byte(secret))
	if err != nil {
		return err
	}
	// Strip the TSIG from the incoming msg
	stripped, tsig, err := stripTsig(msg)
	if err != nil {
		return err
	}
	//if tsig != nil {
	//	fmt.Printf("tsig: %s\n", tsig.String())
	//}

	msgMAC, err := hex.DecodeString(tsig.MAC)
	if err != nil {
		return err
	}

	var buf []byte
	if h == nil {
		buf = tsigBuffer(stripped, tsig, requestMAC, timersOnly)
	} else {
		buf = tsigBuffer(stripped, tsig, "", timersOnly)
	}

	// Fudge factor works both ways. A message can arrive before it was signed because
	// of clock skew.
	now := uint64(time.Now().Unix())
	ti := now - tsig.TimeSigned
	if now < tsig.TimeSigned {
		ti = tsig.TimeSigned - now
	}
	if uint64(tsig.Fudge) < ti {
		return ErrTime
	}

	//var h hash.Hash
	if h == nil {
		switch tsig.Algorithm {
		case HmacMD5:
			h = hmac.New(md5.New, rawsecret)
		case HmacSHA1:
			h = hmac.New(sha1.New, rawsecret)
		case HmacSHA256:
			h = hmac.New(sha256.New, rawsecret)
		case HmacSHA512:
			h = hmac.New(sha512.New, rawsecret)
		case HmacSM3:
			h = hmac.New(Sm3New, rawsecret)
		default:
			return ErrKeyAlg
		}
	}
	h.Write(buf)
	if !hmac.Equal(h.Sum(nil), msgMAC) {
		return ErrSig
	}
	return nil
}

// Create a wiredata buffer for the MAC calculation.
func tsigBuffer(msgbuf []byte, rr *TSIG, requestMAC string, timersOnly bool) []byte {
	var buf []byte
	if rr.TimeSigned == 0 {
		rr.TimeSigned = uint64(time.Now().Unix())
	}
	if rr.Fudge == 0 {
		rr.Fudge = 300 // Standard (RFC) default.
	}

	if requestMAC != "" {
		m := new(macWireFmt)
		m.MACSize = uint16(len(requestMAC) / 2)
		m.MAC = requestMAC
		buf = make([]byte, len(requestMAC)) // long enough
		n, _ := PackStruct(m, buf, 0)
		buf = buf[:n]
	}

	tsigvar := make([]byte, DefaultMsgSize)
	if timersOnly {
		tsig := new(timerWireFmt)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		n, _ := PackStruct(tsig, tsigvar, 0)
		tsigvar = tsigvar[:n]
	} else {
		tsig := new(tsigWireFmt)
		tsig.Name = strings.ToLower(rr.Hdr.Name)
		tsig.Class = ClassANY
		tsig.Ttl = rr.Hdr.Ttl
		tsig.Algorithm = strings.ToLower(rr.Algorithm)
		tsig.TimeSigned = rr.TimeSigned
		tsig.Fudge = rr.Fudge
		tsig.Error = rr.Error
		tsig.OtherLen = rr.OtherLen
		tsig.OtherData = rr.OtherData
		n, _ := PackStruct(tsig, tsigvar, 0)
		tsigvar = tsigvar[:n]
	}

	if requestMAC != "" {
		x := append(buf, msgbuf...)
		buf = append(x, tsigvar...)
	} else {
		buf = append(msgbuf, tsigvar...)
	}
	return buf
}

// Strip the TSIG from the raw message.
func stripTsig(msg []byte) ([]byte, *TSIG, error) {
	// Copied from msg.go's Unpack()
	// Header.
	var dh Header
	var err error
	dns := new(Msg)
	rr := new(TSIG)
	off := 0
	tsigoff := 0
	if off, err = UnpackStruct(&dh, msg, off); err != nil {
		return nil, nil, err
	}
	if dh.Arcount == 0 {
		return nil, nil, ErrNoSig
	}
	// Rcode, see msg.go Unpack()
	if int(dh.Bits&0xF) == RcodeNotAuth {
		return nil, nil, ErrAuth
	}

	// Arrays.
	dns.Question = make([]Question, dh.Qdcount)
	dns.Answer = make([]RR, dh.Ancount)
	dns.Ns = make([]RR, dh.Nscount)
	dns.Extra = make([]RR, dh.Arcount)

	for i := 0; i < len(dns.Question); i++ {
		off, err = UnpackStruct(&dns.Question[i], msg, off)
		if err != nil {
			return nil, nil, err
		}
	}
	for i := 0; i < len(dns.Answer); i++ {
		dns.Answer[i], off, err = UnpackRR(msg, off)
		if err != nil {
			return nil, nil, err
		}
	}
	for i := 0; i < len(dns.Ns); i++ {
		dns.Ns[i], off, err = UnpackRR(msg, off)
		if err != nil {
			return nil, nil, err
		}
	}
	for i := 0; i < len(dns.Extra); i++ {
		tsigoff = off
		dns.Extra[i], off, err = UnpackRR(msg, off)
		if err != nil {
			return nil, nil, err
		}
		if dns.Extra[i].Header().Rrtype == TypeTSIG {
			rr = dns.Extra[i].(*TSIG)
			// Adjust Arcount.
			arcount, _ := unpackUint16(msg, 10)
			msg[10], msg[11] = packUint16(arcount - 1)
			break
		}
	}
	if rr == nil {
		return nil, nil, ErrNoSig
	}
	return msg[:tsigoff], rr, nil
}

// Translate the TSIG time signed into a date. There is no
// need for RFC1982 calculations as this date is 48 bits.
func tsigTimeToString(t uint64) string {
	ti := time.Unix(int64(t), 0).UTC()
	return ti.Format("20060102150405")
}
