package github

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

type permission struct{ Known, Mutation bool }

var permissionKeys = map[string]string{"actions": "rw", "artifact-metadata": "rw", "attestations": "rw", "checks": "rw", "code-quality": "rw", "contents": "rw", "deployments": "rw", "discussions": "rw", "id-token": "w", "issues": "rw", "models": "r", "packages": "rw", "pages": "rw", "pull-requests": "rw", "security-events": "rw", "statuses": "rw", "vulnerability-alerts": "r"}

func permissions(v any) permission {
	switch p := v.(type) {
	case string:
		if p == "read-all" {
			return permission{Known: true}
		}
		if p == "write-all" {
			return permission{Known: true, Mutation: true}
		}
	case map[string]any:
		out := permission{Known: true}
		for k, v := range p {
			allowed, ok := permissionKeys[k]
			value, isString := v.(string)
			if !ok || !isString || (value != "none" && value != "read" && value != "write") || value == "read" && !strings.Contains(allowed, "r") || value == "write" && !strings.Contains(allowed, "w") {
				return permission{}
			}
			if value == "write" && k != "id-token" {
				out.Mutation = true
			}
		}
		return out
	}
	return permission{}
}
func effectivePermissions(doc, job map[string]any, d DefaultEvidence) permission {
	if v, ok := job["permissions"]; ok {
		return permissions(v)
	}
	if v, ok := doc["permissions"]; ok {
		return permissions(v)
	}
	if usableRead(d.Read) && d.Setting != nil && d.Setting.Permissions != nil {
		switch *d.Setting.Permissions {
		case "read":
			return permission{Known: true}
		case "write":
			return permission{Known: true, Mutation: true}
		}
	}
	return permission{}
}
func mapping(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func text(v any) (string, bool)            { s, ok := v.(string); return s, ok && !marked(s) }
func marked(s string) bool {
	return strings.Contains(s, "[REDACTED:") || strings.Contains(s, "[TRUNCATED:")
}

// conditions never evaluate GitHub expressions. False excludes, unknown abstains.
func condition(m map[string]any) (enabled, known bool) {
	v, ok := m["if"]
	if !ok {
		return true, true
	}
	if b, ok := v.(bool); ok {
		return b, true
	}
	if s, ok := text(v); ok {
		if s == "true" {
			return true, true
		}
		if s == "false" {
			return false, true
		}
	}
	return false, false
}

type triggers struct{ Eligible, PRTarget, Known bool }

func workflowTriggers(v any) triggers {
	t := triggers{Known: true}
	names := []string{}
	switch ev := v.(type) {
	case string:
		if marked(ev) {
			return triggers{}
		}
		names = append(names, ev)
	case []any:
		for _, n := range ev {
			s, ok := text(n)
			if !ok {
				t.Known = false
			} else {
				names = append(names, s)
			}
		}
	case map[string]any:
		for n, config := range ev {
			if marked(n) {
				t.Known = false
				continue
			}
			if !eventConfig(n, config) {
				t.Known = false
				continue
			}
			names = append(names, n)
		}
	default:
		return triggers{}
	}
	if len(names) == 0 {
		t.Known = false
	}
	for _, n := range names {
		switch n {
		case "pull_request_target":
			t.PRTarget = true
			t.Eligible = true
		case "push", "workflow_dispatch", "schedule":
			t.Eligible = true
		case "pull_request":
		default:
			t.Known = false
		}
	}
	return t
}

type reference struct {
	Known, External, Mutable, Local bool
	Value                           string
}

var remoteReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[A-Za-z0-9_./+-]+$`)
var dockerReference = regexp.MustCompile(`^docker://(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-fA-F0-9]{64})?$`)
var imageDigest = regexp.MustCompile(`@sha256:[a-fA-F0-9]{64}$`)

func localPath(s string) bool {
	if !strings.HasPrefix(s, "./") || len(s) < 3 || marked(s) {
		return false
	}
	for p := range strings.SplitSeq(s[2:], "/") {
		if p == "" || p == "." || p == ".." || !commandToken.MatchString(p) {
			return false
		}
	}
	return true
}
func actionReference(v any) reference {
	s, ok := text(v)
	if !ok || strings.Contains(s, "${{") {
		return reference{}
	}
	if strings.HasPrefix(s, "./") {
		return reference{Known: localPath(s), Local: localPath(s), Value: s}
	}
	if dockerReference.MatchString(s) {
		return reference{Known: true, External: true, Mutable: !imageDigest.MatchString(s), Value: s}
	}
	if remoteReference.MatchString(s) {
		name, _, _ := strings.Cut(s, "@")
		for part := range strings.SplitSeq(name, "/") {
			if part == "." || part == ".." {
				return reference{}
			}
		}
		_, ref, _ := strings.Cut(s, "@")
		return reference{Known: true, External: true, Mutable: !fullSHA.MatchString(ref), Value: s}
	}
	return reference{}
}

type workflowResult struct {
	Mutable, Joined, PRUnsafe    bool
	UnsafeCheckoutOptOut         bool
	PinKnown, JoinKnown, PRKnown bool
	Evidence                     []string
	RunnerNotes                  []string
	Gaps                         []string
	Limit                        bool
}

func inspectWorkflow(w WorkflowEvidence, d DefaultEvidence) workflowResult {
	out := workflowResult{PinKnown: true, JoinKnown: true, PRKnown: true}
	doc := w.Document
	if doc == nil || w.Gap != "" || !ciReadOK(w.Read) {
		return workflowResult{Gaps: []string{"workflow_evidence_unknown"}}
	}
	ev := workflowTriggers(doc["on"])
	if !ev.Known {
		out.PRKnown = false
	}
	jobs, ok := mapping(doc["jobs"])
	if !ok || len(jobs) == 0 {
		return workflowResult{Gaps: []string{"workflow_jobs_unknown"}}
	}
	keys := []string{}
	for k := range jobs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, id := range keys {
		job, ok := mapping(jobs[id])
		if !ok || marked(id) {
			out.PinKnown = false
			out.JoinKnown = false
			out.PRKnown = false
			continue
		}
		if !jobShape(job) {
			out.PinKnown, out.JoinKnown, out.PRKnown = false, false, false
			out.Gaps = append(out.Gaps, "unsupported_job_or_step_structure")
			continue
		}
		runnerNote(job, &out)
		if v, exists := job["uses"]; exists {
			r := actionReference(v)
			out.Mutable = out.Mutable || r.Known && r.External && r.Mutable
			if !r.Known {
				out.PinKnown = false
			}
			out.JoinKnown = false
			if ev.PRTarget {
				out.PRKnown = false
			}
			if r.Mutable {
				out.Evidence = append(out.Evidence, id+": "+r.Value)
			}
			continue
		}
		steps, ok := job["steps"].([]any)
		if !ok {
			out.PinKnown = false
			out.JoinKnown = false
			out.PRKnown = false
			continue
		}
		perm := effectivePermissions(doc, job, d)
		if perm.Known && perm.Mutation {
			out.Evidence = append(out.Evidence, id+": requested mutation permission; "+permissionEvidence(doc, job, d))
		}
		enabled, condKnown := condition(job)
		if !condKnown {
			out.JoinKnown = false
			if ev.PRTarget {
				out.PRKnown = false
			}
		}
		if _, matrix := job["strategy"]; matrix {
			out.JoinKnown = false
			if ev.PRTarget {
				out.PRKnown = false
			}
			condKnown = false
		}
		workingKnown := workingDirectory(doc) && workingDirectory(job) && supportedShell(doc) && supportedShell(job)
		checkout := false
		flowKnown := workingKnown && condKnown
		jobMutable := false
		jobPinKnown := true
		for _, entry := range steps {
			step, ok := mapping(entry)
			if !ok {
				jobPinKnown = false
				flowKnown = false
				continue
			}
			stepEnabled, stepKnown := condition(step)
			if !stepKnown {
				flowKnown = false
				out.JoinKnown = false
			}
			if v, exists := step["uses"]; exists {
				ref := actionReference(v)
				if !ref.Known {
					jobPinKnown = false
					flowKnown = false
					continue
				}
				if ref.External && ref.Mutable {
					jobMutable = true
					out.Evidence = append(out.Evidence, id+": "+ref.Value)
					if enabled && condKnown && stepKnown && stepEnabled && perm.Known && perm.Mutation && ev.Eligible {
						out.Joined = true
					}
				}
				if checkoutAction(ref.Value) {
					if !stepKnown || !stepEnabled {
						if !stepKnown {
							flowKnown = false
							out.JoinKnown = false
						}
						continue
					}
					if checkout {
						flowKnown = false
					}
					if with, ok := mapping(step["with"]); ok {
						if opt, ok := with["allow-unsafe-pr-checkout"].(bool); ok && opt {
							out.UnsafeCheckoutOptOut = true
						}
					}
					var known bool
					checkout, known = prCheckout(step)
					if checkout {
						out.Evidence = append(out.Evidence, id+": requests PR-controlled checkout ref")
					}
					if !known {
						flowKnown = false
					}
				} else if ref.Local {
					if checkout && flowKnown && enabled && stepEnabled && stepKnown && perm.Known && perm.Mutation && ev.PRTarget && workingDirectory(step) {
						out.PRUnsafe = true
						out.Evidence = append(out.Evidence, id+": requests local-code execution")
					}
					// Local/composite internals are opaque even when their request is recognized.
					if !checkout {
						flowKnown = false
					}
				} else {
					flowKnown = false
				}
			} else if v, exists := step["run"]; exists {
				run, ok := text(v)
				known, exec, limit := execution(run)
				if !ok || !workingDirectory(step) || !supportedShell(step) {
					known = false
				}
				out.Limit = out.Limit || limit
				if checkout && flowKnown && known && exec && enabled && stepEnabled && stepKnown && perm.Known && perm.Mutation && ev.PRTarget {
					out.PRUnsafe = true
					out.Evidence = append(out.Evidence, id+": requests local-code execution")
				}
				if !known {
					flowKnown = false
				}
			} else {
				flowKnown = false
			}
		}
		out.Mutable = out.Mutable || jobMutable
		out.PinKnown = out.PinKnown && jobPinKnown
		if !jobPinKnown || jobMutable && (!perm.Known || perm.Mutation && (!ev.Eligible || !condKnown)) {
			out.JoinKnown = false
		}
		if ev.PRTarget && (!flowKnown || !perm.Known) {
			out.PRKnown = false
		}
	}
	if !out.PinKnown {
		out.Gaps = append(out.Gaps, "unsupported_dependency_reference")
	}
	if !out.JoinKnown {
		out.Gaps = append(out.Gaps, "effective_permission_or_job_unknown")
	}
	if !out.PRKnown {
		out.Gaps = append(out.Gaps, "PR_control_flow_unknown")
	}
	return out
}
func ciReadOK(r Read) bool {
	return (r.Decision == "sent" || r.Decision == "reused") && r.Status == 200 && r.Reason == "" && r.Gap == "" && !r.Truncated
}
func checkoutAction(s string) bool {
	name, _, _ := strings.Cut(s, "@")
	return strings.EqualFold(name, "actions/checkout")
}
func normalizedExpression(s string) string {
	return regexp.MustCompile(`\$\{\{([^{}]+)\}\}`).ReplaceAllStringFunc(s, func(expr string) string { return "${{" + strings.TrimSpace(expr[3:len(expr)-2]) + "}}" })
}
func prCheckout(step map[string]any) (bool, bool) {
	with, exists := step["with"]
	if !exists {
		return false, true
	}
	m, ok := mapping(with)
	if !ok {
		return false, false
	}
	if p, exists := m["path"]; exists {
		if s, ok := text(p); !ok || s != "." {
			return false, false
		}
	}
	if p, exists := m["repository"]; exists {
		if s, ok := text(p); !ok || normalizedExpression(s) != "${{github.event.pull_request.head.repo.full_name}}" {
			return false, false
		}
	}
	v, exists := m["ref"]
	if !exists {
		return false, true
	}
	s, ok := text(v)
	if !ok {
		return false, false
	}
	n := normalizedExpression(s)
	if slices.Contains([]string{"${{github.event.pull_request.head.sha}}", "${{github.event.pull_request.head.ref}}", "refs/pull/${{github.event.pull_request.number}}/merge"}, n) {
		return true, true
	}
	if !strings.Contains(s, "${{") && !marked(s) {
		return false, true
	}
	return false, false
}
func workingDirectory(m map[string]any) bool {
	if v, ok := m["working-directory"]; ok {
		s, ok := text(v)
		if !ok || s != "." {
			return false
		}
	}
	if defaults, exists := m["defaults"]; exists {
		d, ok := mapping(defaults)
		if !ok {
			return false
		}
		if v, ok := d["run"]; ok {
			run, ok := mapping(v)
			if !ok {
				return false
			}
			return workingDirectory(run)
		}
	}
	return true
}

var commandToken = regexp.MustCompile(`^[A-Za-z0-9_./:@=+-]+$`)

func execution(run string) (known, exec, limit bool) {
	if len(run) > 16<<10 {
		return false, false, true
	}
	lines := strings.Split(run, "\n")
	if len(lines) > 100 {
		return false, false, true
	}
	for _, line := range lines {
		if len(line) > 4<<10 {
			return false, false, true
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tokens := strings.Fields(line)
		for _, t := range tokens {
			if !commandToken.MatchString(t) {
				return false, false, false
			}
		}
		recognized := false
		switch tokens[0] {
		case "make":
			recognized = len(tokens) == 1 || len(tokens) == 2 && !strings.HasPrefix(tokens[1], "-") && !strings.Contains(tokens[1], "=")
		case "npm":
			recognized = len(tokens) == 2 && slices.Contains([]string{"ci", "install", "test"}, tokens[1]) || len(tokens) == 3 && tokens[1] == "run" && !strings.HasPrefix(tokens[2], "-")
		case "pnpm", "yarn":
			recognized = len(tokens) == 2 && slices.Contains([]string{"install", "test", "build"}, tokens[1]) || len(tokens) == 3 && tokens[1] == "run" && !strings.HasPrefix(tokens[2], "-")
		case "sh", "bash", "python", "python3":
			recognized = len(tokens) == 2 && localPath(tokens[1])
		default:
			recognized = len(tokens) == 1 && localPath(tokens[0])
		}
		if !recognized {
			return false, false, false
		}
		exec = true
	}
	return true, exec, false
}
func runnerNote(job map[string]any, out *workflowResult) {
	v, exists := job["runs-on"]
	if !exists {
		return
	}
	labels := []string{}
	switch x := v.(type) {
	case string:
		if s, ok := text(x); ok && !strings.Contains(s, "${{") {
			labels = append(labels, s)
		} else {
			out.Gaps = append(out.Gaps, "runner_selection_unknown")
		}
	case []any:
		for _, v := range x {
			if s, ok := text(v); ok && !strings.Contains(s, "${{") {
				labels = append(labels, s)
			} else {
				out.Gaps = append(out.Gaps, "runner_selection_unknown")
			}
		}
	case map[string]any:
		if group, ok := text(x["group"]); ok && !strings.Contains(group, "${{") {
			out.RunnerNotes = append(out.RunnerNotes, "Requests runner group "+group+"; availability and isolation were not assessed")
		}
		if s, ok := text(x["labels"]); ok {
			labels = append(labels, s)
		}
	default:
		out.Gaps = append(out.Gaps, "runner_selection_unknown")
	}
	if slices.Contains(labels, "self-hosted") {
		out.RunnerNotes = append(out.RunnerNotes, "Requests self-hosted runner labels; repository access, availability and isolation were not assessed")
	}
}

func scheduleConfig(v any) bool {
	entries, ok := v.([]any)
	if !ok || len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		m, ok := mapping(entry)
		if !ok {
			return false
		}
		cron, ok := text(m["cron"])
		if !ok || cron == "" || strings.Contains(cron, "${{") {
			return false
		}
	}
	return true
}

// Shell source is interpreted only under a supported command shell.
func supportedShell(m map[string]any) bool {
	if v, exists := m["shell"]; exists {
		s, ok := text(v)
		if !ok || (s != "bash" && s != "sh") {
			return false
		}
	}
	if v, exists := m["defaults"]; exists {
		d, ok := mapping(v)
		if !ok {
			return false
		}
		if v, exists := d["run"]; exists {
			r, ok := mapping(v)
			return ok && supportedShell(r)
		}
	}
	return true
}

func permissionEvidence(doc, job map[string]any, d DefaultEvidence) string {
	v, exists := job["permissions"]
	if !exists {
		v, exists = doc["permissions"]
	}
	if !exists && d.Setting != nil && d.Setting.Permissions != nil {
		return "repository default: " + *d.Setting.Permissions
	}
	b, _ := json.Marshal(v)
	return "permissions: " + string(b)
}

// The frozen grammar recognizes configuration requests only in supported forms.
// Invalid relevant structure cannot provide affirmative execution evidence.
func literal(s any) bool {
	v, ok := text(s)
	return ok && strings.TrimSpace(v) != "" && !strings.Contains(v, "${{")
}
func literalList(v any) bool {
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return false
	}
	for _, x := range a {
		if !literal(x) {
			return false
		}
	}
	return true
}
func eventConfig(event string, v any) bool {
	if event == "schedule" {
		return scheduleConfig(v)
	}
	if v == nil {
		return true
	}
	m, ok := mapping(v)
	if !ok {
		return false
	}
	for k, x := range m {
		switch k {
		case "types":
			if event != "pull_request" && event != "pull_request_target" || !literalList(x) {
				return false
			}
			for _, activity := range x.([]any) {
				if !slices.Contains(strings.Fields("assigned unassigned labeled unlabeled opened edited closed reopened synchronize converted_to_draft locked unlocked enqueued dequeued milestoned demilestoned ready_for_review review_requested review_request_removed auto_merge_enabled auto_merge_disabled"), activity.(string)) {
					return false
				}
			}
		case "branches", "branches-ignore", "paths", "paths-ignore":
			if event != "push" && event != "pull_request" && event != "pull_request_target" || !literalList(x) {
				return false
			}
		case "tags", "tags-ignore":
			if event != "push" || !literalList(x) {
				return false
			}
		default:
			return false
		}
	}
	for _, key := range []string{"branches", "paths", "tags"} {
		_, a := m[key]
		_, b := m[key+"-ignore"]
		if a && b {
			return false
		}
	}
	return true
}
func runnerShape(v any) bool {
	if literal(v) || literalList(v) {
		return true
	}
	m, ok := mapping(v)
	if !ok || len(m) == 0 {
		return false
	}
	for k, x := range m {
		switch k {
		case "group":
			if !literal(x) {
				return false
			}
		case "labels":
			if !literal(x) && !literalList(x) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func jobShape(job map[string]any) bool {
	if v, reusable := job["uses"]; reusable {
		s, ok := text(v)
		if !ok {
			return false
		}
		name, _, _ := strings.Cut(s, "@")
		parts := strings.Split(name, "/")
		remote := len(parts) == 5 && parts[2] == ".github" && parts[3] == "workflows" && (strings.HasSuffix(parts[4], ".yml") || strings.HasSuffix(parts[4], ".yaml")) && actionReference(v).Known
		local := strings.HasPrefix(s, "./.github/workflows/") && strings.Count(s, "/") == 3 && localPath(s) && (strings.HasSuffix(s, ".yml") || strings.HasSuffix(s, ".yaml"))
		if !remote && !local {
			return false
		}
		for k := range job {
			if !slices.Contains([]string{"name", "uses", "with", "secrets", "strategy", "needs", "if", "permissions", "concurrency"}, k) {
				return false
			}
		}
		return true
	}
	for _, key := range []string{"with", "secrets"} {
		if _, exists := job[key]; exists {
			return false
		}
	}
	if !runnerShape(job["runs-on"]) {
		return false
	}
	steps, ok := job["steps"].([]any)
	if !ok || len(steps) == 0 {
		return false
	}
	for _, entry := range steps {
		step, ok := mapping(entry)
		if !ok {
			return false
		}
		_, uses := step["uses"]
		_, run := step["run"]
		if uses == run {
			return false
		}
		if uses {
			for _, key := range []string{"shell", "working-directory"} {
				if _, exists := step[key]; exists {
					return false
				}
			}
			if _, ok := text(step["uses"]); !ok {
				return false
			}
		} else {
			if _, ok := text(step["run"]); !ok {
				return false
			}
			if _, exists := step["with"]; exists {
				return false
			}
		}
		if v, exists := step["with"]; exists {
			if _, ok := mapping(v); !ok {
				return false
			}
		}
	}
	return true
}
