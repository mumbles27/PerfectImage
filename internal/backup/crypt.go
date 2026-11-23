package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Encrypted archive format (all integers big-endian):
//
//	magic     [8]  "PIBACKUP"
//	version   u8   1
//	kdf       u8   1 = argon2id
//	time      u32  argon2 iterations
//	memory    u32  argon2 memory (KiB)
//	threads   u8   argon2 parallelism
//	salt      [16]
//	prefix    [7]  random nonce prefix
//	chunkSize u32  plaintext bytes per chunk
//	check     [32] HMAC-SHA256(macKey, all preceding header bytes)
//
// followed by AES-256-GCM chunks. Every chunk except the last carries
// exactly chunkSize plaintext bytes (+16 tag); the last may be shorter or
// empty. Nonce = prefix || u32 chunk index || final flag (0/1); the AAD is the
// whole header. This detects modification, reordering and truncation.
// Keys: argon2id(passphrase, salt) -> 64 bytes = AES key || HMAC key; the
// header check distinguishes a wrong passphrase from a corrupted body.

const (
	magic            = "PIBACKUP"
	formatV1         = 1
	kdfArgon2id      = 1
	saltLen          = 16
	prefixLen        = 7
	checkLen         = 32
	headerLen        = 8 + 1 + 1 + 4 + 4 + 1 + saltLen + prefixLen + 4 + checkLen
	defaultChunkSize = 64 << 10
	maxChunkSize     = 16 << 20
	tagLen           = 16
)

// Errors returned when opening an archive.
var (
	ErrWrongPassphrase = errors.New("backup: wrong passphrase (or corrupted archive header)")
	ErrCorrupt         = errors.New("backup: archive is corrupted or has been tampered with")
	ErrNotArchive      = errors.New("backup: not a PerfectImage backup archive")
)

// KDFParams are the argon2id cost parameters.
type KDFParams struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultKDF follows the RFC 9106 second recommended option (64 MiB, t=3).
var DefaultKDF = KDFParams{Time: 3, Memory: 64 << 10, Threads: 4}

// limits refuse absurd parameters from an untrusted header (DoS).
func (p KDFParams) valid() bool {
	return p.Time >= 1 && p.Time <= 16 && p.Memory >= 8 && p.Memory <= 1<<20 && p.Threads >= 1 && p.Threads <= 64
}

func deriveKeys(pass []byte, salt []byte, p KDFParams) (enc, mac []byte) {
	k := argon2.IDKey(pass, salt, p.Time, p.Memory, p.Threads, 64)
	return k[:32], k[32:]
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type encWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	header []byte
	prefix []byte
	chunk  int
	buf    []byte
	idx    uint32
	closed bool
	err    error
}

// newEncryptWriter writes the header and returns a writer that encrypts
// everything written to it. Close must be called to write the final chunk;
// it does not close w.
func newEncryptWriter(w io.Writer, passphrase []byte, p KDFParams) (io.WriteCloser, error) {
	if !p.valid() {
		return nil, fmt.Errorf("backup: invalid KDF parameters %+v", p)
	}
	if len(passphrase) == 0 {
		return nil, errors.New("backup: empty passphrase")
	}
	salt := make([]byte, saltLen)
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	encKey, macKey := deriveKeys(passphrase, salt, p)
	h := make([]byte, 0, headerLen)
	h = append(h, magic...)
	h = append(h, formatV1, kdfArgon2id)
	h = binary.BigEndian.AppendUint32(h, p.Time)
	h = binary.BigEndian.AppendUint32(h, p.Memory)
	h = append(h, p.Threads)
	h = append(h, salt...)
	h = append(h, prefix...)
	h = binary.BigEndian.AppendUint32(h, defaultChunkSize)
	m := hmac.New(sha256.New, macKey)
	m.Write(h)
	h = m.Sum(h)
	aead, err := newGCM(encKey)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(h); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead, header: h, prefix: prefix, chunk: defaultChunkSize,
		buf: make([]byte, 0, defaultChunkSize)}, nil
}

func nonce(prefix []byte, idx uint32, final bool) []byte {
	n := make([]byte, 0, 12)
	n = append(n, prefix...)
	n = binary.BigEndian.AppendUint32(n, idx)
	if final {
		return append(n, 1)
	}
	return append(n, 0)
}

func (e *encWriter) emit(p []byte, final bool) error {
	ct := e.aead.Seal(nil, nonce(e.prefix, e.idx, final), p, e.header)
	e.idx++
	if e.idx == 0 {
		return errors.New("backup: archive too large")
	}
	_, err := e.w.Write(ct)
	return err
}

func (e *encWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.closed {
		return 0, errors.New("backup: write after close")
	}
	n := len(p)
	for len(p) > 0 {
		room := e.chunk - len(e.buf)
		if room == 0 {
			// A full buffer is only emitted once more data arrives, so the
			// final chunk is always written by Close.
			if e.err = e.emit(e.buf, false); e.err != nil {
				return 0, e.err
			}
			e.buf = e.buf[:0]
			room = e.chunk
		}
		k := min(room, len(p))
		e.buf = append(e.buf, p[:k]...)
		p = p[k:]
	}
	return n, nil
}

func (e *encWriter) Close() error {
	if e.closed {
		return e.err
	}
	e.closed = true
	if e.err != nil {
		return e.err
	}
	e.err = e.emit(e.buf, true)
	return e.err
}

type decReader struct {
	r      io.Reader
	aead   cipher.AEAD
	header []byte
	prefix []byte
	chunk  int
	idx    uint32
	plain  []byte
	ct     []byte
	peek   []byte // one look-ahead byte
	done   bool
	err    error
}

// readHeader parses and authenticates the header.
func readHeader(r io.Reader, passphrase []byte) (*decReader, error) {
	h := make([]byte, headerLen)
	if _, err := io.ReadFull(r, h); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotArchive
		}
		return nil, err
	}
	if string(h[:8]) != magic {
		return nil, ErrNotArchive
	}
	if h[8] != formatV1 || h[9] != kdfArgon2id {
		return nil, fmt.Errorf("backup: unsupported archive format %d/kdf %d", h[8], h[9])
	}
	off := 10
	p := KDFParams{Time: binary.BigEndian.Uint32(h[off:]), Memory: binary.BigEndian.Uint32(h[off+4:]), Threads: h[off+8]}
	off += 9
	salt := h[off : off+saltLen]
	off += saltLen
	prefix := h[off : off+prefixLen]
	off += prefixLen
	chunk := int(binary.BigEndian.Uint32(h[off:]))
	off += 4
	if !p.valid() || chunk < 1 || chunk > maxChunkSize {
		return nil, ErrCorrupt
	}
	encKey, macKey := deriveKeys(passphrase, salt, p)
	m := hmac.New(sha256.New, macKey)
	m.Write(h[:off])
	if !hmac.Equal(m.Sum(nil), h[off:]) {
		return nil, ErrWrongPassphrase
	}
	aead, err := newGCM(encKey)
	if err != nil {
		return nil, err
	}
	return &decReader{r: r, aead: aead, header: h, prefix: append([]byte(nil), prefix...), chunk: chunk,
		ct: make([]byte, chunk+tagLen)}, nil
}

// newDecryptReader authenticates the header and returns a reader of the
// plaintext. Read returns ErrCorrupt on any authentication failure or
// truncation; io.EOF is only returned after the authenticated final chunk.
func newDecryptReader(r io.Reader, passphrase []byte) (io.Reader, error) {
	return readHeader(r, passphrase)
}

func (d *decReader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		d.err = d.next()
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}

func (d *decReader) next() error {
	buf := d.ct[:0]
	buf = append(buf, d.peek...)
	d.peek = nil
	n, err := io.ReadFull(d.r, d.ct[len(buf):])
	buf = d.ct[:len(buf)+n]
	final := false
	switch {
	case err == nil:
		// Full-size chunk: it is final only if nothing follows.
		var one [1]byte
		m, perr := io.ReadFull(d.r, one[:])
		switch {
		case m == 1:
			d.peek = []byte{one[0]}
		case errors.Is(perr, io.EOF):
			final = true
		default:
			return perr
		}
	case errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
		final = true
	default:
		return err
	}
	if len(buf) < tagLen {
		return ErrCorrupt
	}
	pt, oerr := d.aead.Open(buf[:0:0], nonce(d.prefix, d.idx, final), buf, d.header)
	if oerr != nil {
		return ErrCorrupt
	}
	d.idx++
	d.plain = pt
	if final {
		d.done = true
	}
	return nil
}
