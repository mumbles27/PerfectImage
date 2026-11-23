package siem

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ErrSpillFull is returned when appending would exceed the spill cap.
var ErrSpillFull = errors.New("siem: spill buffer full")

// spill is a size-capped, append-only JSON-lines file used as an on-disk
// backlog while an output is unreachable. A sidecar ".off" file records how
// far the backlog has been delivered so it survives restarts. It is used by a
// single output worker; the mutex only protects Stats readers.
type spill struct {
	path    string
	maxSize int64

	mu      sync.Mutex
	size    int64 // file size
	readOff int64 // delivered prefix
	records int   // undelivered records (approximate after restart)
}

func openSpill(dir, name string, maxSize int64) (*spill, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("siem: spill dir: %w", err)
	}
	s := &spill{path: filepath.Join(dir, name+".spill"), maxSize: maxSize}
	fi, err := os.Stat(s.path)
	switch {
	case err == nil:
		s.size = fi.Size()
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if b, err := os.ReadFile(s.path + ".off"); err == nil {
		if off, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && off >= 0 && off <= s.size {
			s.readOff = off
		}
	}
	if s.size > s.readOff {
		n, err := s.countLines()
		if err != nil {
			return nil, err
		}
		s.records = n
	}
	return s, nil
}

func (s *spill) countLines() (int, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.Seek(s.readOff, io.SeekStart); err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	n := 0
	for sc.Scan() {
		n++
	}
	return n, sc.Err()
}

// Pending returns the number of undelivered records and bytes.
func (s *spill) Pending() (records int, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records, s.size - s.readOff
}

// Append writes records to the end of the backlog, compacting the delivered
// prefix first if needed. It returns ErrSpillFull (writing nothing) when the
// cap would be exceeded.
func (s *spill) Append(recs []Record) error {
	var buf []byte
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			continue
		}
		buf = append(append(buf, b...), '\n')
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.size+int64(len(buf)) > s.maxSize && s.readOff > 0 {
		if err := s.compactLocked(); err != nil {
			return err
		}
	}
	if s.size+int64(len(buf)) > s.maxSize {
		return ErrSpillFull
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	n, err := f.Write(buf)
	s.size += int64(n)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	s.records += len(recs)
	return nil
}

// Peek reads up to n undelivered records without consuming them and returns
// the offset to pass to Commit once they are delivered. Corrupt lines are
// skipped.
func (s *spill) Peek(n int) ([]Record, int64, error) {
	s.mu.Lock()
	off, size := s.readOff, s.size
	s.mu.Unlock()
	if off >= size {
		return nil, off, nil
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, off, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, err
	}
	br := bufio.NewReader(io.LimitReader(f, size-off))
	var out []Record
	for len(out) < n {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			off += int64(len(line))
			var r Record
			if json.Unmarshal(line, &r) == nil {
				out = append(out, r)
			}
		}
		if err != nil {
			break // EOF or a partial trailing line (not yet complete)
		}
	}
	return out, off, nil
}

// Commit marks everything before off as delivered (delivered records count
// n). When the backlog is empty the file is truncated.
func (s *spill) Commit(off int64, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readOff = off
	s.records = max(0, s.records-n)
	if s.readOff >= s.size {
		s.readOff, s.size, s.records = 0, 0, 0
		if err := os.Truncate(s.path, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return writeFileAtomic(s.path+".off", []byte(strconv.FormatInt(s.readOff, 10)))
}

func (s *spill) compactLocked() error {
	src, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer src.Close()
	if _, err := src.Seek(s.readOff, io.SeekStart); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = src.Close()
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.size, s.readOff = n, 0
	return writeFileAtomic(s.path+".off", []byte("0"))
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
