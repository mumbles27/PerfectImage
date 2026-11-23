package auditlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
)

// GenesisHash is the prev_hash of the first event in a fresh chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// canonicalVersion is bumped if the canonical encoding ever changes.
const canonicalVersion = 1

// Entry is a persisted audit event plus its position in the hash chain.
type Entry struct {
	audit.Event
	Seq      int64  `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	// rawDetails is the exact stored JSON of Details (hashed verbatim).
	rawDetails string
}

// canonical is the hashed representation of an event. Field order is fixed
// by the struct; Details is the stored, compact JSON text.
type canonical struct {
	V         int             `json:"v"`
	ID        string          `json:"id"`
	Time      string          `json:"time"`
	ActorID   string          `json:"actor_id"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Outcome   string          `json:"outcome"`
	Reason    string          `json:"reason"`
	SourceIP  string          `json:"source_ip"`
	UserAgent string          `json:"user_agent"`
	RequestID string          `json:"request_id"`
	Details   json.RawMessage `json:"details"`
}

// CanonicalJSON returns the canonical encoding of e whose Details are stored
// as rawDetails. Time is UTC with millisecond precision.
func canonicalJSON(e audit.Event, rawDetails string) ([]byte, error) {
	if rawDetails == "" {
		rawDetails = "{}"
	}
	return json.Marshal(canonical{
		V:         canonicalVersion,
		ID:        e.ID,
		Time:      e.Time.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano),
		ActorID:   e.ActorID,
		Actor:     e.Actor,
		Action:    e.Action,
		Target:    e.Target,
		Outcome:   string(e.Outcome),
		Reason:    e.Reason,
		SourceIP:  e.SourceIP,
		UserAgent: e.UserAgent,
		RequestID: e.RequestID,
		Details:   json.RawMessage(rawDetails),
	})
}

// ChainHash returns hex(SHA-256(prevHash || "\n" || canonicalJSON)).
func ChainHash(prevHash string, canonicalJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{'\n'})
	h.Write(canonicalJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// encodeDetails redacts and marshals details to compact JSON ("{}" if empty).
func encodeDetails(d map[string]any) (string, error) {
	if len(d) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(audit.Redact(d))
	if err != nil {
		return "", fmt.Errorf("audit: marshal details: %w", err)
	}
	return string(b), nil
}

// VerifyResult is the outcome of a chain verification.
type VerifyResult struct {
	OK         bool      `json:"ok"`
	Checked    int64     `json:"checked"`
	AnchorSeq  int64     `json:"anchor_seq"`
	HeadSeq    int64     `json:"head_seq"`
	HeadHash   string    `json:"head_hash"`
	BrokenSeq  int64     `json:"broken_seq,omitempty"`
	Problem    string    `json:"problem,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
}

// Verify walks the whole chain from the retention anchor and checks every
// link (prev_hash) and every hash. It reads inside one transaction, so it
// sees a consistent snapshot while writes continue.
func (s *Store) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{VerifiedAt: s.now()}
	// A single statement reads one consistent WAL snapshot, so the anchor
	// and the rows always agree even if retention prunes concurrently.
	rows, err := s.db.QueryContext(ctx, `SELECT c.anchor_seq, c.anchor_hash, `+prefixed("e.")+`
		FROM audit_chain c LEFT JOIN audit_events e ON 1 = 1 WHERE c.id = 1 ORDER BY e.seq`)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	var anchorHash string
	first := true
	var prev string
	for rows.Next() {
		var aseq int64
		var ahash string
		en, null, err := scanEntryWithAnchor(rows, &aseq, &ahash)
		if err != nil {
			return res, err
		}
		if first {
			first = false
			res.AnchorSeq, anchorHash = aseq, ahash
			prev = anchorHash
			res.HeadSeq, res.HeadHash = aseq, ahash
		}
		if null {
			continue // empty table
		}
		res.Checked++
		if en.Seq <= res.AnchorSeq {
			res.BrokenSeq, res.Problem = en.Seq, "event at or before the retention anchor"
			return res, nil
		}
		if en.PrevHash != prev {
			res.BrokenSeq, res.Problem = en.Seq, "prev_hash does not match the previous event (event removed or reordered)"
			return res, nil
		}
		c, err := canonicalJSON(en.Event, en.rawDetails)
		if err != nil {
			res.BrokenSeq, res.Problem = en.Seq, "details are not valid JSON"
			return res, nil
		}
		if ChainHash(prev, c) != en.Hash {
			res.BrokenSeq, res.Problem = en.Seq, "hash mismatch (event modified)"
			return res, nil
		}
		prev = en.Hash
		res.HeadSeq, res.HeadHash = en.Seq, en.Hash
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	res.OK = true
	return res, nil
}
