package gate

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// probeWorld serves shop.example.com with a git HEAD file and returns the
// world, the server and the probe request. The window is open.
func probeWorld(t *testing.T, handler http.HandlerFunc) (*world, *server, Request) {
	t.Helper()
	w := newWorld(t)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, handler)
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/", "/.git/HEAD"}, FirstParty: true}}
	w.windows = []Window{{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}}
	return w, srv, Request{Op: "web.probe", Asset: "domain:example.com", Params: map[string]string{"host": "shop.example.com"}}
}

func gitHead(status int, contentType, body string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		if contentType == "" {
			rw.Header()["Content-Type"] = nil
		} else {
			rw.Header().Set("Content-Type", contentType)
		}
		rw.WriteHeader(status)
		_, _ = rw.Write([]byte(body))
	}
}

// A probe keeps whether its response matched and nothing of the body, and is
// one request however the site answers.
func TestProbeKeepsNoBodyAndIsSentOnce(t *testing.T) {
	for name, tc := range map[string]struct {
		status      int
		contentType string
		body        string
		matched     bool
	}{
		"a git HEAD":                    {200, "text/plain", "ref: refs/heads/main\n", true},
		"no content type":               {200, "", "ref: refs/heads/main\n", true},
		"binary/octet-stream":           {200, "binary/octet-stream", "ref: refs/heads/main\n", true},
		"application/x-trash":           {200, "application/x-trash", "ref: refs/heads/main\n", true},
		"an xhtml catch-all":            {200, "application/xhtml+xml", "ref: refs/heads/main\n", false},
		"a catch-all page":              {200, "text/html", "ref: refs/heads/main\n", false},
		"another body":                  {200, "text/plain", "<html>welcome</html>", false},
		"not found":                     {404, "text/plain", "ref: refs/heads/main\n", false},
		"a server error, not run again": {503, "text/plain", "ref: refs/heads/main\n", false},
		"rate limited, not asked again": {429, "text/plain", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			w, srv, probe := probeWorld(t, gitHead(tc.status, tc.contentType, tc.body))
			res := w.gate().Send(context.Background(), probe)
			if res.Response == nil || res.Response.Status != tc.status || res.Response.Matched != tc.matched {
				t.Fatalf("%+v", res)
			}
			if len(res.Response.Body) != 0 {
				t.Errorf("a probe kept %q", res.Response.Body)
			}
			if srv.hits.Load() != 1 {
				t.Errorf("%d requests for one probe", srv.hits.Load())
			}
			for _, e := range w.audit.entries(t) {
				if e.Event == "result" && (e.Stored != 0 || e.Window == nil) {
					t.Errorf("result line %+v", e)
				}
			}
		})
	}
}

// Step 6: the site's mode decides, and a confirm site runs only what the
// operator approved; a refusal sends nothing.
func TestProbeNeedsTheSitesMode(t *testing.T) {
	for name, tc := range map[string]struct {
		mode     string
		approved bool
		sent     bool
	}{
		"off": {"off", false, false}, "confirm unapproved": {"confirm", false, false},
		"confirm approved": {"confirm", true, true}, "all": {"all", false, true},
	} {
		t.Run(name, func(t *testing.T) {
			w, srv, probe := probeWorld(t, gitHead(200, "text/plain", "ref: refs/heads/main\n"))
			w.scope.probeMode = tc.mode
			if tc.approved {
				w.scope.approved = map[string]bool{"https://shop.example.com/.git/HEAD": true}
			}
			res := w.gate().Send(context.Background(), probe)
			switch {
			case tc.sent && (!res.OK() || srv.hits.Load() != 1):
				t.Errorf("%+v", res)
			case !tc.sent && (res.Decision != "refused:level" || srv.hits.Load() != 0 || w.dials.Load() != 0):
				t.Errorf("%+v, %d hits", res, srv.hits.Load())
			}
		})
	}
}

// Step 8: a probe needs first-party evidence for the origin, which the
// front page of a name under a domain root is not.
func TestProbeNeedsFirstPartyEvidence(t *testing.T) {
	w, srv, probe := probeWorld(t, gitHead(200, "text/plain", "ref: refs/heads/main\n"))
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/"}}}
	res := w.gate().Send(context.Background(), probe)
	if res.Decision != "refused:first_party" || srv.hits.Load() != 0 || w.dials.Load() != 0 {
		t.Errorf("%+v", res)
	}
}

// No second op can read another path: a probe op's path is its own.
func TestProbeOpsAreLiteralGETs(t *testing.T) {
	for name, op := range map[string]Op{
		"a path parameter": {ID: "web.p1", Provider: "web", Method: GET, URL: "https://{host}{path}", Level: Probe, Accept: []string{"*/*"}, MaxBytes: 64,
			Params: []Param{{Name: "host", Type: Host}, {Name: "path", Type: URLPath}}, Signature: &Signature{Pattern: "x"}},
		"no signature": {ID: "web.p2", Provider: "web", Method: GET, URL: "https://{host}/.env", Level: Probe, Accept: []string{"*/*"}, MaxBytes: 64,
			Params: []Param{{Name: "host", Type: Host}}},
		"a post": {ID: "web.p3", Provider: "web", Method: POST, URL: "https://{host}/.env", Level: Probe, Accept: []string{"*/*"}, MaxBytes: 64,
			Params: []Param{{Name: "host", Type: Host}}, Signature: &Signature{Pattern: "x"}},
		"too long a read": {ID: "web.p4", Provider: "web", Method: GET, URL: "https://{host}/.env", Level: Probe, Accept: []string{"*/*"}, MaxBytes: ProbeMaxBytes + 1,
			Params: []Param{{Name: "host", Type: Host}}, Signature: &Signature{Pattern: "x"}},
		"a signature on a read": {ID: "web.p5", Provider: "web", Method: GET, URL: "https://{host}/.env", Level: Observe, Accept: []string{"*/*"}, MaxBytes: 64,
			Params: []Param{{Name: "host", Type: Host}}, Signature: &Signature{Pattern: "x"}},
		"a scan": {ID: "web.p6", Provider: "web", Method: GET, URL: "https://{host}/.env", Level: Scan, Accept: []string{"*/*"}, MaxBytes: 64,
			Params: []Param{{Name: "host", Type: Host}}, Signature: &Signature{Pattern: "x"}},
	} {
		if _, err := NewRegistry(op); err == nil {
			t.Errorf("%s was registered", name)
		}
	}
}
