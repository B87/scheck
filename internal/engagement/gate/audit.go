package gate

import (
	"time"
)

// Entry is one gate line in the run's audit log (docs/spec/scope.md,
// "Audit"). A request has a send line written before it is dialled and a
// result line after, keyed by request_id; a refusal has one line; every DNS
// query has its own. Every value is redacted or typed before it is set.
type Entry struct {
	Time      time.Time         `json:"time"`
	Event     string            `json:"event"` // send | result | refused | reused | dns | dns_answer
	RequestID string            `json:"request_id"`
	Stage     string            `json:"stage,omitempty"`
	Asset     string            `json:"asset,omitempty"`
	Op        string            `json:"op"`
	Params    map[string]string `json:"params,omitempty"`
	Method    string            `json:"method,omitempty"`
	URL       string            `json:"url,omitempty"`
	DestIP    string            `json:"dest_ip,omitempty"`
	Port      int               `json:"port,omitempty"`
	TLS       string            `json:"tls,omitempty"`
	Level     string            `json:"level,omitempty"`
	Principal string            `json:"principal,omitempty"`
	// Window is the index of the authorization window a probe was
	// admitted in.
	Window     *int     `json:"window,omitempty"`
	Source     string   `json:"source,omitempty"`
	Decision   string   `json:"decision"`
	Detail     string   `json:"detail,omitempty"`
	Status     int      `json:"status,omitempty"`
	Attempt    int      `json:"attempt,omitempty"`
	RetryOf    string   `json:"retry_of,omitempty"`
	RedirectOf string   `json:"redirect_of,omitempty"`
	NextOf     string   `json:"next_of,omitempty"`
	Page       int      `json:"page,omitempty"`
	BytesIn    int64    `json:"bytes_in,omitempty"`
	Stored     int      `json:"bytes_stored,omitempty"`
	OutputHash string   `json:"output_sha256,omitempty"`
	Redactions int      `json:"redactions,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Dropped    []Drop   `json:"dropped,omitempty"`
	Headers    int      `json:"headers_dropped,omitempty"`
	Answers    []string `json:"answers,omitempty"`
	DurationMS int64    `json:"duration_ms,omitempty"`
}

// record writes an entry; a send line that cannot be written stops the
// send (send.go), and any other failure is the run's to report. Every
// string a target or the engagement could have put in it is redacted here,
// once, as the runner redacts params and argv before its audit line: a
// discovered name can match redact_extra.
func (g *Gate) record(e Entry) error {
	if e.Time.IsZero() {
		e.Time = g.now().UTC()
	}
	red := func(v string) string { out, _ := g.redactor.RedactString(v); return out }
	if e.Params != nil {
		params := make(map[string]string, len(e.Params))
		for k, v := range e.Params {
			params[k] = red(v)
		}
		e.Params = params
	}
	// DestIP too: the resolver's address, or one dialled, which the gate
	// refuses when redact_extra matches it.
	e.URL, e.Detail, e.DestIP = red(e.URL), red(e.Detail), red(e.DestIP)
	for i, a := range e.Answers {
		if i == 0 {
			e.Answers = append([]string(nil), e.Answers...)
		}
		e.Answers[i] = red(a)
	}
	return g.audit.Record(e)
}
