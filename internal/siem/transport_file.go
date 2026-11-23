package siem

import (
	"context"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/logging"
)

// fileTransport appends records as JSON lines to a size-rotated local file.
type fileTransport struct {
	mu sync.Mutex
	f  *logging.RotatingFile
}

func newFileTransport(c config.SIEMOutput) (*fileTransport, error) {
	f, err := logging.NewRotatingFile(c.Path, int64(c.MaxSizeMB)<<20, c.MaxFiles)
	if err != nil {
		return nil, err
	}
	return &fileTransport{f: f}, nil
}

// Send implements transport.
func (t *fileTransport) Send(_ context.Context, batch []Record) error {
	var buf []byte
	for _, r := range batch {
		buf = append(append(buf, jsonBody(r)...), '\n')
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.f.Write(buf)
	return err
}

// Close implements transport.
func (t *fileTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.f.Close()
}
