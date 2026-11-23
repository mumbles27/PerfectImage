package packer

import (
	"strconv"
	"strings"
	"time"
)

// Event is one line of `packer -machine-readable` output:
// timestamp,target,type,data...
type Event struct {
	Time   time.Time
	Target string
	Type   string
	Data   []string
}

// ParseMachineLine parses a machine-readable line. ok is false for lines
// that are not in the format (they are logged verbatim).
func ParseMachineLine(line string) (ev Event, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return Event{}, false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return Event{}, false
	}
	ev = Event{Time: time.Unix(ts, 0).UTC(), Target: unescape(parts[1]), Type: parts[2]}
	for _, p := range parts[3:] {
		ev.Data = append(ev.Data, unescape(p))
	}
	return ev, true
}

var unescaper = strings.NewReplacer(`%!(PACKER_COMMA)`, ",", `\n`, "\n", `\r`, "\r")

func unescape(s string) string { return unescaper.Replace(s) }

// Readable renders an event as human-readable log lines. It returns nil for
// events that carry no useful text (version info, artifact bookkeeping...).
func (e Event) Readable() []string {
	data := func(i int) string {
		if i < len(e.Data) {
			return e.Data[i]
		}
		return ""
	}
	var text string
	switch e.Type {
	case "ui":
		switch data(0) {
		case "error":
			text = prefixLines("ERROR: ", data(1))
		default: // say, message
			text = data(1)
		}
	case "artifact":
		switch data(1) {
		case "id":
			text = "==> artifact " + data(0) + " id: " + data(2)
		case "string":
			text = "==> artifact " + data(0) + ": " + data(2)
		}
	case "error":
		text = prefixLines("ERROR: ", data(0))
	case "error-count":
		text = "==> errors: " + data(0)
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(text, "\n"), "\n")
}

func prefixLines(prefix, s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// ArtifactID returns the artifact id carried by an "artifact,<n>,id,<id>"
// event.
func (e Event) ArtifactID() (string, bool) {
	if e.Type == "artifact" && len(e.Data) >= 3 && e.Data[1] == "id" {
		return e.Data[2], true
	}
	return "", false
}
