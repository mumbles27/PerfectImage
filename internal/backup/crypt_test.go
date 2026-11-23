package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

var testKDF = KDFParams{Time: 1, Memory: 64, Threads: 1}

func encrypt(t *testing.T, pass string, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := newEncryptWriter(&buf, []byte(pass), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	// Write in odd-sized pieces to exercise buffering.
	for p := plain; len(p) > 0; {
		n := min(len(p), 7777)
		if _, err := w.Write(p[:n]); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decrypt(pass string, ct []byte) ([]byte, error) {
	r, err := newDecryptReader(bytes.NewReader(ct), []byte(pass))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestCryptRoundTrip(t *testing.T) {
	sizes := []int{0, 1, defaultChunkSize - 1, defaultChunkSize, defaultChunkSize + 1, 3 * defaultChunkSize, 3*defaultChunkSize + 17}
	for _, n := range sizes {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		ct := encrypt(t, "correct horse battery staple", plain)
		got, err := decrypt("correct horse battery staple", ct)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: plaintext mismatch", n)
		}
	}
}

func TestCryptFailures(t *testing.T) {
	plain := bytes.Repeat([]byte("perfectimage "), 3*defaultChunkSize/13+100) // > 3 chunks
	ct := encrypt(t, "pass-phrase-123", plain)
	chunk := defaultChunkSize + tagLen
	tests := []struct {
		name   string
		pass   string
		mutate func([]byte) []byte
		want   error
	}{
		{"wrong passphrase", "wrong-passphrase", nil, ErrWrongPassphrase},
		{"flipped body byte", "pass-phrase-123", func(b []byte) []byte { b[headerLen+100] ^= 1; return b }, ErrCorrupt},
		{"flipped last byte", "pass-phrase-123", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }, ErrCorrupt},
		{"header param changed", "pass-phrase-123", func(b []byte) []byte { b[headerLen-checkLen-1] ^= 1; return b }, ErrWrongPassphrase},
		{"truncated mid chunk", "pass-phrase-123", func(b []byte) []byte { return b[:len(b)-5] }, ErrCorrupt},
		{"final chunk removed", "pass-phrase-123", func(b []byte) []byte {
			return b[:headerLen+3*chunk]
		}, ErrCorrupt},
		{"trailing garbage", "pass-phrase-123", func(b []byte) []byte { return append(b, 0, 1, 2) }, ErrCorrupt},
		{"chunks swapped", "pass-phrase-123", func(b []byte) []byte {
			c1 := append([]byte(nil), b[headerLen:headerLen+chunk]...)
			copy(b[headerLen:], b[headerLen+chunk:headerLen+2*chunk])
			copy(b[headerLen+chunk:], c1)
			return b
		}, ErrCorrupt},
		{"header only", "pass-phrase-123", func(b []byte) []byte { return b[:headerLen] }, ErrCorrupt},
		{"not an archive", "pass-phrase-123", func([]byte) []byte { return []byte("hello world, definitely not a backup archive at all......") }, ErrNotArchive},
		{"empty", "pass-phrase-123", func([]byte) []byte { return nil }, ErrNotArchive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := append([]byte(nil), ct...)
			if tt.mutate != nil {
				b = tt.mutate(b)
			}
			_, err := decrypt(tt.pass, b)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestKDFParamsValidated(t *testing.T) {
	if _, err := newEncryptWriter(io.Discard, []byte("x"), KDFParams{Time: 1, Memory: 1 << 30, Threads: 1}); err == nil {
		t.Fatal("absurd memory accepted")
	}
	if _, err := newEncryptWriter(io.Discard, nil, testKDF); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}
