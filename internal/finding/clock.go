package finding

import (
	"slices"
	"time"
)

// A time-dependent rule is judged at the collection time of the reads it
// rests on, never the session's start or the time a report is rendered; a
// read with no recorded time makes it abstain (docs/spec/engagement.md,
// "Severity in context").
const (
	// ReasonNoCollectionTime is the abstention of a time-dependent rule
	// whose read carries no collection time.
	ReasonNoCollectionTime = "unavailable:collection_time"
	// ReasonLeftDuringCollection is the abstention of a leaver rule whose
	// leaving date passed between the earliest and the latest read it rests
	// on: an absence seen before the person left says nothing about
	// offboarding, and a presence may predate the leaving.
	ReasonLeftDuringCollection = "left_date_within_collection"
)

// Leaving is whether a declared leaving date had passed when scheck read
// what a judgment rests on.
type Leaving int

// The outcomes of LeftAt.
const (
	// LeftUnknown: a read carries no collection time, or the date does
	// not parse.
	LeftUnknown Leaving = iota
	// LeftUnread: no read returned a response, so nothing was seen at any
	// time; the rule keeps its own reason for missing evidence.
	LeftUnread
	// LeftNotPassed: the date had not passed at the latest read.
	LeftNotPassed
	// LeftWithin: it passed at the latest read but not the earliest.
	LeftWithin
	// LeftPassed: it had passed at the earliest read.
	LeftPassed
)

// LeftAt says whether left, a date in zone, had passed at the collection
// times of the reads a judgment rests on: a date passes at 24:00 of that
// day in zone. A presence and an absence both need it passed at the
// earliest read (docs/spec/engagement.md, "Severity in context").
func LeftAt(left string, zone *time.Location, times []time.Time) Leaving {
	if zone == nil {
		zone = time.UTC
	}
	d, err := time.Parse(time.DateOnly, left)
	if err == nil && len(times) == 0 {
		return LeftUnread
	}
	first, last, ok := Span(times)
	if err != nil || !ok {
		return LeftUnknown
	}
	day := d.Format(time.DateOnly)
	switch {
	case first.In(zone).Format(time.DateOnly) > day:
		return LeftPassed
	case last.In(zone).Format(time.DateOnly) > day:
		return LeftWithin
	}
	return LeftNotPassed
}

// Span is the earliest and latest of times; ok is false when there are
// none or one is unrecorded (zero).
func Span(times []time.Time) (first, last time.Time, ok bool) {
	if len(times) == 0 || slices.ContainsFunc(times, time.Time.IsZero) {
		return time.Time{}, time.Time{}, false
	}
	first, last = times[0], times[0]
	for _, t := range times[1:] {
		if t.Before(first) {
			first = t
		}
		if t.After(last) {
			last = t
		}
	}
	return first, last, true
}

// ReadDate is a read's collection date as an excerpt names it, in zone.
func ReadDate(t time.Time, zone *time.Location) string {
	if zone == nil {
		zone = time.UTC
	}
	return t.In(zone).Format(time.DateOnly)
}

// The Not checked lines of a left person's abstained Workspace access
// judgment, which the report's person line reads (docs/spec/report.md,
// "People who left").
const (
	NotCheckedLeaverIdentity     = "Declared account identity is missing or ambiguous."
	NotCheckedLeaverUnrecognized = "The account was read, but its status or access evidence was not recognized."
	NotCheckedUsersUnread        = "The users were not read."
	NotCheckedUsersIncomplete    = "The users list was incomplete, so an address missing from it is not proven gone."
)
