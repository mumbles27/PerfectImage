package auditlog

import (
	"context"
	"strings"
	"time"
)

// Filter selects audit events. Zero fields are ignored.
type Filter struct {
	From    time.Time // inclusive
	To      time.Time // exclusive
	Actor   string    // case-insensitive substring of actor or actor_id
	Action  string    // case-insensitive prefix ("auth." matches "auth.login")
	Outcome string    // exact
	Target  string    // case-insensitive substring
	Limit   int       // Query: page size (default 50, max 1000); Each: 0 = all
	Offset  int
}

// Params returns the filter as a map (for audit details of exports).
func (f Filter) Params() map[string]any {
	m := map[string]any{}
	if !f.From.IsZero() {
		m["from"] = f.From.UTC().Format(time.RFC3339)
	}
	if !f.To.IsZero() {
		m["to"] = f.To.UTC().Format(time.RFC3339)
	}
	for k, v := range map[string]string{"actor": f.Actor, "action": f.Action, "outcome": f.Outcome, "target": f.Target} {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (f Filter) where() (string, []any) {
	var conds []string
	var args []any
	if !f.From.IsZero() {
		conds, args = append(conds, "ts >= ?"), append(args, f.From.UTC().UnixMilli())
	}
	if !f.To.IsZero() {
		conds, args = append(conds, "ts < ?"), append(args, f.To.UTC().UnixMilli())
	}
	if f.Actor != "" {
		p := "%" + escapeLike(f.Actor) + "%"
		conds, args = append(conds, `(actor LIKE ? ESCAPE '\' OR actor_id LIKE ? ESCAPE '\')`), append(args, p, p)
	}
	if f.Action != "" {
		conds, args = append(conds, `action LIKE ? ESCAPE '\'`), append(args, escapeLike(f.Action)+"%")
	}
	if f.Outcome != "" {
		conds, args = append(conds, "outcome = ?"), append(args, f.Outcome)
	}
	if f.Target != "" {
		conds, args = append(conds, `target LIKE ? ESCAPE '\'`), append(args, "%"+escapeLike(f.Target)+"%")
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Query returns one page of matching events (newest first) and the total
// number of matches.
func (s *Store) Query(ctx context.Context, f Filter) ([]Entry, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where, args := f.where()
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	var out []Entry
	err := s.each(ctx, `SELECT `+entryColumns+` FROM audit_events`+where+` ORDER BY seq DESC LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset), func(e Entry) error {
			out = append(out, e)
			return nil
		})
	return out, total, err
}

// Each streams matching events in chain order (oldest first) to fn.
func (s *Store) Each(ctx context.Context, f Filter, fn func(Entry) error) error {
	where, args := f.where()
	q := `SELECT ` + entryColumns + ` FROM audit_events` + where + ` ORDER BY seq`
	if f.Limit > 0 {
		q += ` LIMIT ? OFFSET ?`
		args = append(args, f.Limit, max(f.Offset, 0))
	}
	return s.each(ctx, q, args, fn)
}

func (s *Store) each(ctx context.Context, q string, args []any, fn func(Entry) error) error {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}
