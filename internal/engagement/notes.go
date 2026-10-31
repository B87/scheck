package engagement

import (
	"fmt"
	"slices"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/workspace"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/engagement/rules"
	"github.com/b87/scheck/internal/finding"
)

// ContextTableVersion identifies C3's table: the CNAME targets, actions and
// secret names that contradict a not_used area. A change to it changes
// this constant (docs/spec/engagement.md, "Context notes").
const ContextTableVersion = "2026-10-31"

// cnameClouds are the CNAME target suffixes of a cloud provider's hosting.
// ghs.googlehosted.com is left out: Google Sites uses it too.
var cnameClouds = []struct{ suffix, provider string }{
	{".run.app", "Google Cloud"}, {".appspot.com", "Google Cloud"}, {".cloudfunctions.net", "Google Cloud"},
	{".amazonaws.com", "AWS"}, {".cloudfront.net", "AWS"},
}

// contextActions are the actions that contradict an area, with what they
// do as the note says it.
var contextActions = map[string]map[string]string{
	"cloud": {
		"google-github-actions/auth":            "which signs in to Google Cloud",
		"google-github-actions/setup-gcloud":    "which sets up the Google Cloud CLI",
		"google-github-actions/deploy-cloudrun": "which deploys to Google Cloud Run",
		"aws-actions/configure-aws-credentials": "which signs in to AWS",
		"aws-actions/amazon-ecr-login":          "which signs in to AWS's container registry",
		"azure/login":                           "which signs in to Azure",
	},
	"hosts": {
		"appleboy/ssh-action":      "which connects to a server over SSH",
		"appleboy/scp-action":      "which copies files to a server over SSH",
		"easingthemes/ssh-deploy":  "which deploys to a server over SSH",
		"webfactory/ssh-agent":     "which loads an SSH key to connect to a server",
		"shimataro/ssh-key-action": "which installs an SSH key to connect to a server",
	},
}

// cloudSecret says an Actions secret's name suggests a cloud account.
func cloudSecret(name string) bool {
	n := strings.ToUpper(name)
	return n == "GOOGLE_APPLICATION_CREDENTIALS" || n == "GOOGLE_CREDENTIALS" ||
		slices.ContainsFunc([]string{"AWS_", "GCP_", "GOOGLE_CLOUD_", "AZURE_"}, func(p string) bool { return strings.HasPrefix(n, p) })
}

// hostSecrets are the Actions secret names that suggest a server.
var hostSecrets = []string{"SSH_PRIVATE_KEY", "SSH_KEY", "SSH_HOST", "DEPLOY_HOST", "DEPLOY_SSH_KEY", "SERVER_SSH_KEY"}

// areaPhrase is how C3 names what the operator said they do not run.
var areaPhrase = map[string]string{"cloud": "cloud accounts", "hosts": "servers", "data": "data stores",
	"email": "email", "external": "internet-facing services"}

// contextNotes are C1 to C3 over what this session's Recon holds and the
// engagement's declarations. A note rests on something seen, never on
// what was not read; it has no id and no severity (docs/spec/engagement.md,
// "Context notes"). judged are the network collectors' verdicts, by asset.
func (r *run) contextNotes(judged map[string][]finding.Judgment) []ereport.ContextNote {
	var out []ereport.ContextNote
	out = append(out, r.workspaceDomainNotes()...)
	out = append(out, r.deploysToNotes(judged)...)
	return append(out, r.notUsedNotes()...)
}

// shortID is an asset id as a note names it: repo:github:o/r is github:o/r.
func shortID(id string) string {
	if s, ok := strings.CutPrefix(id, "repo:"); ok {
		return s
	}
	return strings.TrimPrefix(id, "saas:")
}

// ownerName is an asset id as a note names its owner: o/r, or o.
func ownerName(id string) string {
	if s, ok := strings.CutPrefix(id, "repo:github:"); ok {
		return s
	}
	return strings.TrimPrefix(id, "saas:github:")
}

// domainRoots are the declared domain roots' names.
func (r *run) domainRoots() []string {
	var out []string
	for _, root := range r.res.Roots {
		if name, ok := strings.CutPrefix(root.ID, "domain:"); ok {
			out = append(out, name)
		}
	}
	return out
}

// workspaceDomainNotes is C1: a verified domain of a Workspace tenant that
// is not itself a domain root, so its mail records were not read.
func (r *run) workspaceDomainNotes() []ereport.ContextNote {
	var out []ereport.ContextNote
	roots := r.domainRoots()
	// The names whose mail records the web collector read: never "not
	// read" (a sender or no_mail name under a root is read too).
	read := map[string]bool{}
	for _, ra := range r.recon.Assets {
		if ra.Web != nil {
			for _, m := range ra.Web.Mail {
				read[strings.TrimSuffix(strings.ToLower(m.Domain), ".")] = true
			}
		}
	}
	for _, ra := range r.recon.Assets {
		if ra.Workspace == nil {
			continue
		}
		domains, _ := workspace.TenantDomains(*ra.Workspace)
		names := make([]string, 0, len(domains))
		for d := range domains {
			names = append(names, d)
		}
		slices.Sort(names)
		for _, d := range names {
			if d == "" || slices.Contains(roots, d) || read[d] {
				continue
			}
			detail := fmt.Sprintf("`%s` is a verified domain of your Workspace tenant and is under none of your domain roots, "+
				"so its SPF, DKIM and DMARC were not read. Add it under `roots` to have them read.", d)
			// The most specific root holding it.
			under := ""
			for _, root := range roots {
				if strings.HasSuffix(d, "."+root) && len(root) > len(under) {
					under = root
				}
			}
			if under != "" {
				detail = fmt.Sprintf("`%s` is a verified domain of your Workspace tenant under the root `%s`; scheck reads "+
					"mail records only at each root and the mail domains you declare, so its SPF and DMARC were not read. Add it under `roots` to have them read.", d, under)
			}
			out = append(out, ereport.ContextNote{Kind: ereport.NoteContextWorkspaceDomain, Source: ra.ID, Detail: detail})
		}
	}
	return out
}

// readPhrase words a read's reason in a note.
func readPhrase(reason string) string {
	switch {
	case reason == "":
		return ""
	case strings.HasPrefix(reason, "insufficient_permission"):
		return "the credential was not allowed to read it"
	}
	return strings.ReplaceAll(strings.TrimPrefix(reason, "unavailable:"), "_", " ")
}

// deploysToNotes is C2: a repository declared to deploy somewhere that
// GitHub did not show, shows archived, or that was not read, and on which
// nothing was judged.
func (r *run) deploysToNotes(judged map[string][]finding.Judgment) []ereport.ContextNote {
	var out []ereport.ContextNote
	for _, a := range r.res.Assets {
		if a.DeploysTo == "" || !strings.HasPrefix(a.ID, "repo:github:") {
			continue
		}
		judgedHere := false
		for _, js := range judged {
			judgedHere = judgedHere || slices.ContainsFunc(js, func(j finding.Judgment) bool { return j.Asset == a.ID })
		}
		state, reason := githubc.RepositoryUnread, ""
		for _, ra := range r.recon.Assets {
			if ra.GitHub != nil && slices.ContainsFunc(ra.GitHub.RepositoriesAccess, func(x githubc.RepositoryAccess) bool { return x.Asset == a.ID }) {
				state, reason = githubc.RepositoryState(*ra.GitHub, a.ID)
			}
		}
		org, name, _ := strings.Cut(ownerName(a.ID), "/")
		head := fmt.Sprintf("`%s` (`%s`) is declared to deploy %s, but ", a.Name, shortID(a.ID), a.DeploysTo)
		var detail string
		switch {
		case state == githubc.RepositoryFound:
			continue
		case state == githubc.RepositoryArchived:
			// Archived is said even beside judgments: they are on a
			// repository nothing deploys from.
			detail = head + "GitHub shows it archived. If " + a.DeploysTo + " now deploys from another repository, declare that one."
		case judgedHere:
			continue
		case state == githubc.RepositoryMissing:
			raise := ""
			if a.DeploysTo == "production" {
				// Only production raises a finding's rating.
				raise = " and no production raise applied"
			}
			detail = head + fmt.Sprintf("the GitHub credential sees no repository `%s` in `%s`, so nothing on it was judged%s. "+
				"Check the name, whether it was renamed or moved, and whether the credential can see it.", name, org, raise)
		default:
			why := ""
			if p := readPhrase(reason); p != "" {
				why = " (" + p + ")"
			}
			detail = head + "it was not read in this run" + why + ", so nothing on it was judged."
		}
		out = append(out, ereport.ContextNote{Kind: ereport.NoteContextDeploysTo, Source: "assets." + a.Name + ".deploys_to", Detail: detail})
	}
	return out
}

// notUsedNotes is C3: an area declared not used that the evidence
// contradicts, one note per area.
func (r *run) notUsedNotes() []ereport.ContextNote {
	var out []ereport.ContextNote
	for i, area := range r.res.NotUsed {
		clauses := r.contradictions(area)
		if len(clauses) == 0 {
			continue
		}
		var but string
		switch n := len(clauses); {
		case n == 1:
			but = clauses[0]
		case n <= 3:
			but = strings.Join(clauses[:n-1], "; ") + "; and " + clauses[n-1]
		default:
			but = strings.Join(clauses[:3], "; ") + fmt.Sprintf("; and %d more", n-3)
		}
		detail := fmt.Sprintf("You said you run no %s (`not_used`), but %s. If these are yours, remove `%s` from `not_used`.",
			areaPhrase[area], but, area)
		out = append(out, ereport.ContextNote{Area: area, Kind: ereport.NoteContextNotUsed, Source: fmt.Sprintf("not_used[%d]", i), Detail: detail})
	}
	return out
}

// contradictions are the clauses of what was seen that contradicts area,
// in canonical order: DNS, then workflows, then secret names, then hosts,
// then Workspace. A name suggests; a clause never says it leaks.
func (r *run) contradictions(area string) []string {
	var out []string
	if area == "cloud" && r.scoped != nil {
		for _, d := range r.scoped.Domains {
			for _, n := range d.Names {
				if n.ExcludedBy != "" {
					continue
				}
				for _, target := range n.Chain {
					t := strings.TrimSuffix(strings.ToLower(target), ".")
					if i := slices.IndexFunc(cnameClouds, func(c struct{ suffix, provider string }) bool { return strings.HasSuffix(t, c.suffix) }); i >= 0 {
						out = append(out, fmt.Sprintf("`%s` is a CNAME to `%s` (%s)", n.Name, t, cnameClouds[i].provider))
						break
					}
				}
			}
		}
	}
	// Every workflow clause before any secret clause, whatever the
	// organization.
	for _, ra := range r.recon.Assets {
		if does := contextActions[area]; ra.GitHub != nil && does != nil {
			for _, u := range githubc.ActionUses(*ra.GitHub) {
				if what, ok := does[u.Action]; ok {
					out = append(out, fmt.Sprintf("a workflow in `%s` (`%s`) uses `%s`, %s", ownerName(u.Asset), u.Workflow, u.Action, what))
				}
			}
		}
	}
	for _, ra := range r.recon.Assets {
		if ra.GitHub == nil {
			continue
		}
		for _, s := range githubc.SecretNames(*ra.GitHub, ra.ID) {
			if area == "cloud" && cloudSecret(s.Name) || area == "hosts" && slices.Contains(hostSecrets, strings.ToUpper(s.Name)) {
				kind := "an Actions secret"
				if strings.HasPrefix(s.Asset, "saas:") {
					kind = "an organization Actions secret"
				}
				out = append(out, fmt.Sprintf("`%s` has %s named `%s`", ownerName(s.Asset), kind, s.Name))
			}
		}
	}
	if area == "data" {
		for _, ra := range r.recon.Assets {
			c, ok := r.hosts[ra.Name]
			if !ok {
				continue
			}
			for _, db := range rules.Databases(c.Facts()) {
				addr := db.Address
				if strings.Contains(addr, ":") {
					addr = "[" + addr + "]"
				}
				clause := fmt.Sprintf("`%s` listens on %s:%d on `%s`", db.Process, addr, db.Port, ra.Name)
				if db.ByPort {
					clause += ", read as a data store from its port"
				}
				out = append(out, clause)
			}
		}
	}
	if area == "email" {
		for _, ra := range r.recon.Assets {
			if ra.Workspace == nil {
				continue
			}
			if n, whole := workspace.Mailboxes(*ra.Workspace); n > 0 {
				count := fmt.Sprint(n)
				if !whole {
					// A partial users read is a lower bound.
					count = "at least " + count
				}
				out = append(out, fmt.Sprintf("%s %s in `%s` %s a Gmail mailbox", count, plural(n, "account", "accounts"), shortID(ra.ID), plural(n, "has", "have")))
			}
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
