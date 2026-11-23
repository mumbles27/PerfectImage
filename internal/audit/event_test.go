package audit

import (
	"context"
	"testing"
)

func TestSwappable(t *testing.T) {
	s := NewSwappable()
	if err := s.Record(context.Background(), Event{Action: "x"}); err != nil {
		t.Fatal(err)
	}
	var got []Event
	s.Set(RecorderFunc(func(_ context.Context, e Event) error { got = append(got, e); return nil }))
	_ = s.Record(context.Background(), Event{Action: "a", Outcome: OutcomeSuccess})
	if len(got) != 1 || got[0].Action != "a" || got[0].Time.IsZero() {
		t.Fatalf("got %+v", got)
	}
	s.Set(nil)
	_ = s.Record(context.Background(), Event{Action: "b"})
	if len(got) != 1 {
		t.Fatal("recorder not reset")
	}
	var zero Swappable
	if err := zero.Record(context.Background(), Event{}); err != nil {
		t.Fatal(err)
	}
}
