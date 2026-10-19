package main

import (
	"sort"
	"sync"
	"time"
)

// HostStat is the per-upstream-host tally.
type HostStat struct {
	Host     string    `json:"host"`
	Requests int64     `json:"requests"`
	Errors   int64     `json:"errors"` // upstream unreachable, or HTTP status >= 500
	Bytes    int64     `json:"bytes"`
	Last     time.Time `json:"last"`
}

// DeniedHost is a host the launcher asked for that is not on the allowlist.
type DeniedHost struct {
	Host  string    `json:"host"`
	Count int64     `json:"count"`
	Last  time.Time `json:"last"`
}

// StatsSnapshot is what the admin interface shows.
type StatsSnapshot struct {
	Since     time.Time    `json:"since"`
	Requests  int64        `json:"requests"`
	Denied    int64        `json:"denied"`
	Errors    int64        `json:"errors"`
	AuthFails int64        `json:"authFails"`
	BytesDown int64        `json:"bytesDown"`
	Hosts     []HostStat   `json:"hosts"`
	DeniedFor []DeniedHost `json:"deniedHosts"`
}

// Stats accumulates counters from events.
type Stats struct {
	mu        sync.Mutex
	since     time.Time
	requests  int64
	denied    int64
	errors    int64
	authFails int64
	bytes     int64
	hosts     map[string]*HostStat
	deniedFor map[string]*DeniedHost
}

// NewStats returns empty stats.
func NewStats() *Stats {
	s := &Stats{}
	s.Reset()
	return s
}

// Reset zeroes everything.
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.since = time.Now()
	s.requests, s.denied, s.errors, s.authFails, s.bytes = 0, 0, 0, 0, 0
	s.hosts = map[string]*HostStat{}
	s.deniedFor = map[string]*DeniedHost{}
}

// Add folds one event into the counters.
func (s *Stats) Add(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e.Kind {
	case KindOK, KindError:
		s.requests++
		s.bytes += e.Bytes
		h := s.hosts[e.Host]
		if h == nil {
			h = &HostStat{Host: e.Host}
			s.hosts[e.Host] = h
		}
		h.Requests++
		h.Bytes += e.Bytes
		h.Last = e.Time
		if e.Kind == KindError || e.Status >= 500 {
			s.errors++
			h.Errors++
		}
	case KindDeny:
		s.denied++
		d := s.deniedFor[e.Host]
		if d == nil {
			d = &DeniedHost{Host: e.Host}
			s.deniedFor[e.Host] = d
		}
		d.Count++
		d.Last = e.Time
	case KindAuth, KindLocked:
		s.authFails++
	}
}

// Forget drops a host from the denied list (after it has been allowed).
func (s *Stats) Forget(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.deniedFor, normalizeHost(host))
}

// Snapshot returns a copy: hosts by request count, denied hosts most recent first.
func (s *Stats) Snapshot() StatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := StatsSnapshot{
		Since: s.since, Requests: s.requests, Denied: s.denied, Errors: s.errors,
		AuthFails: s.authFails, BytesDown: s.bytes,
		Hosts: []HostStat{}, DeniedFor: []DeniedHost{},
	}
	for _, h := range s.hosts {
		out.Hosts = append(out.Hosts, *h)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].Requests > out.Hosts[j].Requests })
	if len(out.Hosts) > 50 {
		out.Hosts = out.Hosts[:50]
	}
	for _, d := range s.deniedFor {
		out.DeniedFor = append(out.DeniedFor, *d)
	}
	sort.Slice(out.DeniedFor, func(i, j int) bool { return out.DeniedFor[i].Last.After(out.DeniedFor[j].Last) })
	return out
}
