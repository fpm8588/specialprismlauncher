package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Event kinds.
const (
	KindOK     = "ok"     // request was forwarded; Status is the upstream status
	KindDeny   = "deny"   // host not on the allowlist
	KindError  = "error"  // upstream could not be reached
	KindAuth   = "auth"   // wrong or missing token
	KindLocked = "locked" // client address locked out after repeated bad tokens
	KindBad    = "bad"    // malformed route
)

// Event is one thing the relay did, shown in the admin interface and written to the log file.
type Event struct {
	Seq    int64     `json:"seq"`
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Method string    `json:"method,omitempty"`
	Host   string    `json:"host,omitempty"`
	Path   string    `json:"path,omitempty"`
	Status int       `json:"status,omitempty"`
	Bytes  int64     `json:"bytes,omitempty"`
	Millis int64     `json:"ms,omitempty"`
	Client string    `json:"client,omitempty"`
	Note   string    `json:"note,omitempty"`
}

// Line renders the event for the log file. Query strings are never part of an event.
func (e Event) Line() string {
	s := fmt.Sprintf("%s %-6s", e.Time.UTC().Format("2006-01-02T15:04:05Z"), e.Kind)
	if e.Method != "" {
		s += " " + e.Method
	}
	if e.Host != "" {
		s += " " + e.Host + e.Path
	}
	if e.Status != 0 {
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	if e.Bytes != 0 {
		s += fmt.Sprintf(" %dB", e.Bytes)
	}
	if e.Millis != 0 {
		s += fmt.Sprintf(" %dms", e.Millis)
	}
	if e.Client != "" {
		s += " from " + e.Client
	}
	if e.Note != "" {
		s += " (" + e.Note + ")"
	}
	return s
}

// EventLog keeps the most recent events in memory and optionally appends them to a file.
type EventLog struct {
	mu   sync.Mutex
	buf  []Event
	max  int
	next int64
	out  io.Writer
}

// NewEventLog returns a log holding up to max events. out may be nil.
func NewEventLog(max int, out io.Writer) *EventLog {
	return &EventLog{max: max, next: 1, out: out}
}

// Add stamps e with a sequence number (and the time, if unset), stores it and returns it.
func (l *EventLog) Add(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.next
	l.next++
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.buf = append(l.buf, e)
	if len(l.buf) > l.max {
		l.buf = append(l.buf[:0], l.buf[len(l.buf)-l.max:]...)
	}
	if l.out != nil {
		fmt.Fprintln(l.out, e.Line())
	}
	return e
}

// Since returns events with Seq greater than seq (oldest first, at most limit of the newest),
// and the highest sequence number issued so far.
func (l *EventLog) Since(seq int64, limit int) ([]Event, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	i := sort.Search(len(l.buf), func(i int) bool { return l.buf[i].Seq > seq })
	out := l.buf[i:]
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return append([]Event{}, out...), l.next - 1
}

// RotatingFile is an append-only log file that rolls over to <path>.1 when it grows past max bytes.
type RotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

// NewRotatingFile opens (creating directories as needed) the log file at path.
func NewRotatingFile(path string, max int64) (*RotatingFile, error) {
	r := &RotatingFile{path: path, max: max}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

// Write implements io.Writer.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size+int64(len(p)) > r.max {
		r.f.Close()
		_ = os.Remove(r.path + ".1")
		_ = os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
