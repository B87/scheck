package bounded

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/runner"
)

// Enumerate lists the candidates of every kind from the fact sheet and
// applies the deterministic filters. It never executes anything and never
// consults a model: an item that leaves here as anything but StatusJudged
// has been settled by code and is never sent (docs/SPEC.md §5.9).
//
// docs/ROADMAP-RESEARCH.md tabulates the sources per platform, every filter
// and the reason for it, and the two sources deliberately left out
// (persist.timers duplicates persist.units; macOS launchctl is dominated by
// Apple's own loaded jobs, so the plists on disk are the inventory).
func Enumerate(sheet *baseline.FactSheet, ctx *operator.Merged) []Item {
	var out []Item
	for _, k := range Kinds {
		switch k {
		case KindListener:
			out = append(out, listeners(sheet, ctx)...)
		case KindPersistence:
			out = append(out, persistence(sheet)...)
		case KindSUID:
			out = append(out, suid(sheet)...)
		case KindAdmin:
			out = append(out, admins(sheet)...)
		}
	}
	for i := range out {
		out[i].Platform = string(sheet.Platform)
	}
	return out
}

// source reads one check's result and says whether its evidence may be
// judged at all. Truncated, redacted or unparsed output is insufficient:
// bytes were removed, and what was removed cannot be judged (§4.2, §7.5).
func source(sheet *baseline.FactSheet, id string) (runner.Result, string, bool) {
	res, ok := sheet.Get(id)
	if !ok || res.Status != runner.StatusOK {
		return res, "", false
	}
	if res.Truncated || res.Redactions > 0 || check.HasMarker(res.Raw) {
		return res, "truncated or redacted capture", true
	}
	return res, "", true
}

// item builds one candidate, marking it insufficient when either the whole
// capture or this line lost bytes.
func item(kind Kind, key string, res runner.Result, insufficient, excerpt string, fields map[string]string) Item {
	it := Item{Kind: kind, Key: key, Check: res.CheckID, Observation: res.Observation,
		Excerpt: excerpt, Fields: fields, Status: StatusJudged}
	switch {
	case insufficient != "":
		it.Status, it.Reason = StatusInsufficient, insufficient
	case excerpt == "" || check.HasMarker(excerpt):
		it.Status, it.Reason = StatusInsufficient, "the record's own line lost bytes"
	}
	return it
}

// filtered marks an item code has already settled.
func filtered(it Item, reason string) Item {
	it.Status, it.Reason = StatusFiltered, reason
	return it
}

// excerptLine returns the first line of raw holding every token, verbatim,
// so finding.Store can validate it against the observation.
func excerptLine(raw string, tokens ...string) string {
	for l := range strings.SplitSeq(raw, "\n") {
		if strings.TrimSpace(l) == "" || check.IsMarkerLine(l) {
			continue
		}
		hit := true
		for _, t := range tokens {
			if t != "" && !strings.Contains(l, t) {
				hit = false
				break
			}
		}
		if hit {
			return strings.TrimRight(l, "\r")
		}
	}
	return ""
}

func records(res runner.Result) []check.Record {
	recs, ok := res.Parsed.(check.Records)
	if !ok {
		return nil
	}
	return recs.Items
}

func lines(res runner.Result) []string {
	ls, ok := res.Parsed.([]string)
	if !ok {
		return nil
	}
	return ls
}

// --- listeners ---------------------------------------------------------

// loopback reports whether an address is bound to this host only. A
// wildcard bind ("*", "0.0.0.0", "::") is not loopback.
func loopback(addr string) bool {
	a := strings.TrimSpace(addr)
	return a == "::1" || a == "localhost" || strings.HasPrefix(a, "127.")
}

func listeners(sheet *baseline.FactSheet, ctx *operator.Merged) []Item {
	res, insufficient, ok := source(sheet, "net.listeners")
	if !ok {
		return nil
	}
	declared := map[string]operator.Service{}
	if ctx != nil {
		for _, s := range ctx.Structured.ExpectedServices {
			declared[strings.ToLower(s.Key())] = s
		}
	}
	seen := map[string]bool{}
	var out []Item
	for _, rec := range records(res) {
		proto, addr, port := rec[check.FieldProtocol], rec[check.FieldAddress], rec[check.FieldPort]
		key := fmt.Sprintf("%s/%s", port, strings.ToLower(proto))
		if seen[key] {
			continue // one candidate per port and protocol, not per address family
		}
		seen[key] = true
		fields := map[string]string{
			"protocol": proto, "port": port, "address": addr,
			"process": rec[check.FieldProcess], "reachable": "beyond this host",
		}
		if loopback(addr) {
			fields["reachable"] = "this host only"
		}
		it := item(KindListener, "listener:"+key, res, insufficient, excerptLine(res.Raw, ":"+port), fields)
		switch {
		case it.Status != StatusJudged:
		case loopback(addr):
			it = filtered(it, "bound to loopback")
		default:
			if s, declaredHere := declared[strings.ToLower(key)]; declaredHere {
				// expected_services matching is §6.3's, in code. Reporting a
				// declared listener anyway was a phase 2 false positive.
				it = filtered(it, "declared in expected_services as "+s.Purpose)
			}
		}
		out = append(out, it)
	}
	return out
}

func servicePort(it Item) (int, string, bool) {
	port, err := strconv.Atoi(it.Fields["port"])
	if err != nil || port < 1 || port > 65535 {
		return 0, "", false
	}
	proto := strings.ToLower(it.Fields["protocol"])
	if proto != "tcp" && proto != "udp" {
		return 0, "", false
	}
	return port, proto, true
}

// --- persistence -------------------------------------------------------

// cronEntry splits a `grep -rH . /etc/crontab /etc/cron.d` line into its
// file and the entry, and says whether the entry is an executable one: a
// comment or a variable assignment schedules nothing.
var cronAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

func cronEntry(line string) (file, entry string, ok bool) {
	before, after, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	file, entry = before, strings.TrimSpace(after)
	if entry == "" || strings.HasPrefix(entry, "#") || cronAssign.MatchString(entry) {
		return file, entry, false
	}
	return file, entry, true
}

// cronCommand returns the command of a cron entry: five schedule fields, a
// user, then the command. `@reboot` and friends take one field.
func cronCommand(entry string) string {
	f := strings.Fields(entry)
	skip := 6
	if strings.HasPrefix(entry, "@") {
		skip = 2
	}
	if len(f) <= skip {
		return ""
	}
	return strings.Join(f[skip:], " ")
}

func persistence(sheet *baseline.FactSheet) []Item {
	var out []Item
	// systemd: the enabled unit files are the inventory. persist.timers is a
	// schedule report of units already listed here, so it adds no candidate.
	if res, insufficient, ok := source(sheet, "persist.units"); ok {
		for _, rec := range records(res) {
			name := rec[check.FieldName]
			if name == "" {
				continue
			}
			fields := map[string]string{"entry_kind": "systemd unit", "unit": name, "state": rec[check.FieldState]}
			out = append(out, item(KindPersistence, "unit:"+name, res, insufficient, excerptLine(res.Raw, name), fields))
		}
	}
	if res, insufficient, ok := source(sheet, "persist.cron"); ok {
		for _, l := range lines(res) {
			file, entry, executable := cronEntry(l)
			if !executable {
				continue
			}
			command := cronCommand(entry)
			key := command
			if key == "" {
				key = entry
			}
			fields := map[string]string{"entry_kind": "cron entry", "file": file, "entry": entry, "command": command}
			out = append(out, item(KindPersistence, "cron:"+file+":"+key, res, insufficient, excerptLine(res.Raw, entry), fields))
		}
	}
	// macOS: the third-party LaunchDaemons and LaunchAgents. launchctl list
	// is the loaded set, dominated by Apple's own jobs, so the plists on
	// disk are the inventory a judgement is about.
	if res, insufficient, ok := source(sheet, "persist.launch_dirs"); ok {
		for _, l := range lines(res) {
			path := strings.TrimSpace(l)
			if path == "" {
				continue
			}
			fields := map[string]string{"entry_kind": "launchd job", "path": path, "label": strings.TrimSuffix(pathBase(path), ".plist")}
			out = append(out, item(KindPersistence, "launchd:"+path, res, insufficient, excerptLine(res.Raw, path), fields))
		}
	}
	return out
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pathDir(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "/"
}

// --- SUID --------------------------------------------------------------

func suid(sheet *baseline.FactSheet) []Item {
	res, insufficient, ok := source(sheet, "fs.suid")
	if !ok {
		return nil
	}
	// The world-writable correlation is code's: the model is told the fact,
	// never asked to compute it (jev-1.13 does not compare paths reliably).
	writable := map[string]bool{}
	if ww, _, ok := source(sheet, "fs.world_writable"); ok {
		for _, l := range lines(ww) {
			writable[strings.TrimSpace(l)] = true
		}
	}
	var out []Item
	for _, l := range lines(res) {
		path := strings.TrimSpace(l)
		if path == "" {
			continue
		}
		fields := map[string]string{"path": path, "name": pathBase(path), "directory": pathDir(path),
			"directory_is_world_writable": strconv.FormatBool(writable[pathDir(path)])}
		out = append(out, item(KindSUID, "suid:"+path, res, insufficient, excerptLine(res.Raw, path), fields))
	}
	return out
}

// --- administrative accounts -------------------------------------------

// sudoersGrant matches a sudoers rule: "principal host=(runas) commands".
var sudoersGrant = regexp.MustCompile(`^(%?[A-Za-z_][A-Za-z0-9._-]*)\s+\S+\s*=\s*(.*)$`)

// standardAdmins are the distributions' own administrative principals. They
// are the documented way to hold sudo rights, so they are not candidates;
// the account behind them is, through its own record.
var standardAdmins = map[string]bool{"root": true, "%sudo": true, "%wheel": true, "%admin": true}

// unrestricted reports whether a sudoers rule grants every command, which is
// what accounts.unexpected_admin means by administrative rights. A rule
// listing specific commands (scheck's own fragment, for one) is not one.
func unrestricted(rest string) bool {
	body := rest
	if i := strings.Index(body, ")"); i >= 0 && strings.HasPrefix(strings.TrimSpace(body), "(") {
		body = body[i+1:]
	}
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	for part := range strings.SplitSeq(body, ",") {
		p := strings.TrimSpace(part)
		p = strings.TrimPrefix(p, "NOPASSWD:")
		p = strings.TrimPrefix(p, "PASSWD:")
		if strings.TrimSpace(p) == "ALL" {
			return true
		}
	}
	return false
}

func admins(sheet *baseline.FactSheet) []Item {
	var out []Item
	// Linux: an account with uid 0 is root-equivalent by definition.
	for _, id := range []string{"accounts.passwd", "accounts.users"} {
		res, insufficient, ok := source(sheet, id)
		if !ok {
			continue
		}
		for _, rec := range records(res) {
			name, uid := rec[check.FieldName], strings.TrimSpace(rec[check.FieldUID])
			if name == "" || uid != "0" {
				continue
			}
			it := item(KindAdmin, "admin:"+name, res, insufficient, excerptLine(res.Raw, name),
				map[string]string{"account": name, "rights": "uid 0", "shell": rec[check.FieldShell], "home": rec[check.FieldHome]})
			if name == "root" {
				it = filtered(it, "root is the account uid 0 names")
			}
			out = append(out, it)
		}
	}
	// Linux: a sudoers principal with an unrestricted grant.
	for _, id := range []string{"privesc.sudoers", "privesc.sudoers_d"} {
		res, insufficient, ok := source(sheet, id)
		if !ok {
			continue
		}
		for _, l := range lines(res) {
			body := l
			if strings.HasPrefix(body, "/") { // grep -rH prefixes the file
				if i := strings.Index(body, ":"); i >= 0 {
					body = body[i+1:]
				}
			}
			body = strings.TrimSpace(body)
			if body == "" || strings.HasPrefix(body, "#") || strings.HasPrefix(body, "Defaults") || strings.HasPrefix(body, "@") {
				continue
			}
			m := sudoersGrant.FindStringSubmatch(body)
			if m == nil {
				continue
			}
			principal := m[1]
			it := item(KindAdmin, "admin:"+principal, res, insufficient, excerptLine(res.Raw, body),
				map[string]string{"account": principal, "rights": "sudo: " + strings.TrimSpace(m[2])})
			switch {
			case standardAdmins[strings.ToLower(principal)]:
				it = filtered(it, "a distribution's own administrative principal")
			case !unrestricted(m[2]):
				it = filtered(it, "the sudo grant lists specific commands, not ALL")
			}
			out = append(out, dedupeKey(out, it)...)
		}
	}
	// macOS: the admin group's membership.
	if res, insufficient, ok := source(sheet, "accounts.admins"); ok {
		raw, _ := res.Parsed.(string)
		for l := range strings.SplitSeq(raw, "\n") {
			_, after, found := strings.Cut(l, "GroupMembership:")
			if !found {
				continue
			}
			for name := range strings.FieldsSeq(after) {
				it := item(KindAdmin, "admin:"+name, res, insufficient, excerptLine(res.Raw, name),
					map[string]string{"account": name, "rights": "member of the admin group"})
				if name == "root" {
					it = filtered(it, "root is the account uid 0 names")
				}
				out = append(out, dedupeKey(out, it)...)
			}
		}
	}
	return out
}

// dedupeKey drops an item whose key is already enumerated: an account can be
// both uid 0 and a sudoers principal, and it is one candidate either way.
func dedupeKey(have []Item, it Item) []Item {
	for _, h := range have {
		if h.Key == it.Key {
			return nil
		}
	}
	return []Item{it}
}
