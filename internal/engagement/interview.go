package engagement

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

// FileHeader is the comment scheck init writes above every engagement file.
// The file names people, departures and accepted weaknesses.
const FileHeader = "# This file names people, people who have left, and accepted weaknesses.\n" +
	"# Keep it out of public repositories.\n" +
	"# Written by `scheck init`. Editing by hand is equally valid.\n"

// Consumer is one reader of an interview answer. Slice is the roadmap slice
// that owns it. A question with no consumer is not in this list.
type Consumer struct {
	ID    string
	Slice string
}

// Question is one interview question. The prompt is what the operator
// reads; a question that offers what the file declares adds that list
// (Text).
type Question struct {
	ID        string
	Prompt    string
	Consumers []Consumer
	answered  func(*File) bool
	apply     func(*File, string) error
	// offer, when set, is the list printed under the prompt from what the
	// file declares so far.
	offer func(*File) string
	// notes, when set, are lines printed after an accepted answer.
	notes func(string) []string
	// left, when set, are lines printed after a blank or accepted answer
	// about what the file still leaves unanswered.
	left func(*File) []string
}

// Text is the prompt as scheck init prints it for f.
func (q Question) Text(f *File) string {
	if q.offer == nil {
		return q.Prompt
	}
	return q.Prompt + "\n" + q.offer(f)
}

// Answered reports whether the file already answers q.
func (q Question) Answered(f *File) bool {
	if f == nil || q.answered == nil {
		return false
	}
	return q.answered(f)
}

// MergedSlices are the slices whose consumers must already exist. E9
// joins at its step 9 (docs/ROADMAP.md, E9).
var MergedSlices = []string{"E1a", "E1b", "E1c", "E2", "E4", "E5", "E6", "E7", "E9", "G5", "G3"}

// Questions is the interview, in the order scheck init asks.
// It asks the Intake questions that have a consumer in a merged slice
// and nothing else (docs/spec/engagement.md, "Intake").
func Questions() []Question {
	return []Question{
		{ID: "trigger", Prompt: "What brought you to run this? One of: a customer questionnaire, an audit, a funding round, an incident, or a routine check.",
			Consumers: []Consumer{{ID: "report.header.trigger", Slice: "E2"}},
			answered:  func(f *File) bool { return f.Engagement.Trigger != "" },
			apply:     applyTrigger},
		{ID: "name", Prompt: "A short name for this assessment, using only lowercase letters, digits and hyphens. For example: brightcart-2026-q4.",
			Consumers: []Consumer{{ID: "run.directory", Slice: "E1b"}},
			answered:  func(f *File) bool { return f.Engagement.Name != "" },
			apply:     applyName},
		{ID: "operator", Prompt: "Your name or team, as it should be printed on the report.",
			Consumers: []Consumer{{ID: "report.header.operator", Slice: "E2"}},
			answered:  func(f *File) bool { return f.Engagement.Operator != "" },
			apply:     applyOperator},
		{ID: "timezone", Prompt: "The time zone the company works in, as a place name such as Europe/London. Dates in this file are read in that zone.",
			Consumers: []Consumer{{ID: "engagement.timezone", Slice: "E1a"}},
			answered:  func(f *File) bool { return f.Engagement.Timezone != "" },
			apply:     applyTimezone},
		{ID: "roots", Prompt: "What is in scope? One per line.\n" +
			"  domain: a domain you own, including parked ones and ones that send no mail\n" +
			"  saas: google-workspace:the-sign-in-domain\n" +
			"  saas: github:the-organization\n" +
			"  cloud: gcp:the-project   (only a cloud account you administer; a server at a hosting company is a host)\n" +
			"  host: user@address       (or host: local for this computer)\n" +
			"Leave out anything you do not know. Do not paste a password or a key.",
			Consumers: []Consumer{{ID: "scope.roots", Slice: "E4"}},
			answered:  func(f *File) bool { return len(f.Roots) > 0 },
			apply:     applyRoots},
		{ID: "exclude", Prompt: "Is anything explicitly off limits? One per line, as domain:, url:, repo:, or host:. If nothing, leave this blank.",
			Consumers: []Consumer{{ID: "scope.exclude", Slice: "E4"}},
			answered:  func(f *File) bool { return len(f.Exclude) > 0 },
			apply:     applyExclude},
		{ID: "mail", Prompt: "Mail, for the domains you listed. One fact per line, and a blank line between senders.\n" +
			"  domain: example.com\n" +
			"  service: Google Workspace\n" +
			"  selector: the DKIM name, if you know it\n" +
			"A selector is the short DNS name that points at that sender's key. If you do not know it, leave it out. That leaves the check undone. Do not guess a name.\n" +
			"A domain that sends no mail at all:\n" +
			"  nomail: example.net",
			Consumers: []Consumer{{ID: "email.dkim_missing", Slice: "E7"}, {ID: "email.spf_undeclared_sender", Slice: "E7"}, {ID: "email.no_mail_spoofable", Slice: "E7"}},
			answered:  func(f *File) bool { return !hasDomain(f) || len(f.Mail.Senders) > 0 || len(f.Mail.NoMail) > 0 },
			apply:     applyMail},
		{ID: "people", Prompt: "Who should be named? One person or shared login per block, and a blank line before the next. You do not need to list every employee.\n" +
			"  handle: dani\n" +
			"  kind: employee\n" +
			"  workspace: dani@example.com\n" +
			"  github: their-login\n" +
			"kind is employee, contractor, shared, service, or break_glass.\n" +
			"break_glass is an emergency login almost nobody uses. Leave it out if you do not have one.\n" +
			"A contractor may have org: the company they work for. A shared login needs used_by: the handles of the people who use it, separated by commas.\n" +
			"Leave workspace or github out when you do not know it. Do not guess a spelling, and do not invent a login.",
			Consumers: []Consumer{{ID: "identity.unattributed_admin", Slice: "E5"}, {ID: "identity.external_admin", Slice: "E5"}, {ID: "identity.shared_admin", Slice: "E5"}},
			answered:  func(f *File) bool { return len(f.People) > 0 },
			apply:     applyPeople},
		{ID: "left", Prompt: "Who has left recently? One block each.\n" +
			"  handle: the handle from the previous answer\n" +
			"  left: YYYY-MM-DD\n" +
			"If you do not know the day, leave that person out. Do not guess the day.",
			Consumers: []Consumer{{ID: "identity.former_person_has_access", Slice: "E5"}},
			answered: func(f *File) bool {
				if len(f.People) == 0 {
					return true
				}
				for _, p := range f.People {
					if p.Left != "" {
						return true
					}
				}
				return false
			},
			apply: applyLeft},
		{ID: "admins", Prompt: "Who do you expect to be a super admin or an owner? One tenant per block. Use handles from the people you named. If you cannot name them for a service, leave that service out.\n" +
			"  where: google-workspace:example.com\n" +
			"  handles: alice, sam",
			Consumers: []Consumer{{ID: "identity.unexpected_admin", Slice: "E5"}},
			answered:  func(f *File) bool { return !hasSaaS(f) || len(f.Access.Admins) > 0 },
			apply:     applyAdmins},
		{ID: "deploys", Prompt: "Which repositories deploy the live production environment, as opposed to a demo or a staging copy? One per block. If you do not know the repository, leave this blank. Do not guess a name.\n" +
			"  name: shop\n" +
			"  repo: github:org/shop\n" +
			"  deploys_to: production\n" +
			"deploys_to is production, staging, or development. production raises findings on that repository. It does not ask which CI.",
			Consumers: []Consumer{{ID: "github.deploys_to", Slice: "E5"}},
			answered:  func(f *File) bool { return !hasGitHub(f) || anyDeploys(f) },
			apply:     applyDeploys},
		{ID: "mfa", Prompt: "Who must use 2-step verification? One tenant per block.\n" +
			"  where: google-workspace:example.com\n" +
			"  enforced: everyone\n" +
			"enforced is everyone (including shared and break-glass accounts), admins, some, none, or unknown. Yes and no are not answers. unknown is a real answer.\n" +
			"For Google Workspace, a second factor that another sign-in service such as Okta or Microsoft Entra asks for counts; the next question asks about it.",
			Consumers: []Consumer{{ID: "workspace.two_step_not_enforced", Slice: "E6"}, {ID: "github.mfa_not_required", Slice: "E5"}},
			answered:  func(f *File) bool { return !hasSaaS(f) || len(f.Access.MFA) > 0 },
			apply:     applyMFA},
		{ID: "mfa_sign_in", Prompt: "When people sign in to Google Workspace, does Google send them to another sign-in service, such as Okta or Microsoft Entra, instead of asking for their Google password? One tenant per block.\n" +
			"  where: google-workspace:example.com\n" +
			"  sign_in: another_provider\n" +
			"sign_in is google (people type their Google password on Google's sign-in page), another_provider (some or all people are sent to another service to sign in), or unknown. Yes and no are not answers.\n" +
			"To tell: open mail.google.com in a private window and type your work address. If Google then asks for your password, that is google; if it jumps to your company's own login page, that is another_provider.\n" +
			"This is not about using Google to sign in to other apps, such as Slack: that is google. If your other service sends people to Google to sign in, that is google too.\n" +
			"With another_provider, scheck still reports every account Google does not require 2-step verification for, but no longer ranks it higher for contradicting your 2-step verification answer, except super administrators, who can still sign in with a Google password. scheck does not read the other service: check yourself that it asks everyone for a second factor.\n" +
			"unknown and google keep those findings ranked higher.",
			Consumers: []Consumer{{ID: "workspace.two_step_sign_in", Slice: "E6"}},
			answered:  func(f *File) bool { return len(signInOffers(f)) == 0 },
			apply:     applySignIn,
			offer:     offerSignIn,
			left:      signInLeft},
		{ID: "exposed", Prompt: "Which exact web addresses are meant to be on the internet, and why? One per block. Naming one only changes a single low finding about a page that announces its software. It does not make other findings on that site less serious. If you have no such page, leave this blank.\n" +
			"  url: https://shop.example.com/\n" +
			"  audience: internet\n" +
			"  reason: the shop",
			Consumers: []Consumer{{ID: "web.version_disclosed", Slice: "E7"}},
			answered:  func(f *File) bool { return len(f.Intent.ExposedOnPurpose) > 0 },
			apply:     applyExposed},
		{ID: "restricted", Prompt: "Which exact web addresses must not answer except from a named place? One per block. The place is internet, vpn, lan (the office network), localhost (this machine only), or airgapped. If you do not know the address, leave this blank. This check runs only if you later give a vantage. This interview does not pick one.\n" +
			"  url: https://shop.example.com/admin\n" +
			"  audience: vpn",
			Consumers: []Consumer{{ID: "web.restricted_reachable", Slice: "E7"}},
			answered:  func(f *File) bool { return len(f.Intent.NotExposed) > 0 },
			apply:     applyRestricted},
		{ID: "framework", Prompt: "What are your websites built with? One or more of: laravel, django, rails, spring, wordpress, node, php. Or none (a static site or a hosted platform), or unknown, on their own. Separate several with commas.\n" +
			"This does nothing until you turn probes on in the file (defaults: probe: confirm) and give an authorization window. Then it picks which framework-specific probes are sent: a Laravel debug page is asked for only on a site you called Laravel. " +
			"If you are not sure, say unknown or leave it blank: scheck sends only the probes that apply to any site and does not guess a framework from what a site answers.",
			Consumers: []Consumer{{ID: "web.probe_selection", Slice: "G3"}},
			answered:  func(f *File) bool { return !hasWeb(f) || len(f.Defaults.Framework) > 0 },
			apply:     applyFramework},
		{ID: "reach", Prompt: "For each server you want checked, one block. A pasted private key is refused. If you do not know user@address, leave this blank.\n" +
			"  name: shop\n" +
			"  host: user@203.0.113.5\n" +
			"  identity: ~/.ssh/shop\n" +
			"  known_hosts: ~/known_hosts\n" +
			"  jump: ops@198.51.100.7\n" +
			"identity is a path to a key file, never the key. jump is one machine you connect through, if you use one.",
			Consumers: []Consumer{{ID: "host.reach", Slice: "E1b"}, {ID: "host.jump", Slice: "E1c"}},
			answered:  func(f *File) bool { return reachAnswered(f) },
			apply:     applyReach},
		{ID: "context", Prompt: "For each server, one block. A session means someone can log in, such as SSH, not that customers can open the website.\n" +
			"  name: shop\n" +
			"  exposure: internet\n" +
			"  environment: prod\n" +
			"  service: 443 tcp internet the public HTTPS listener\n" +
			"  service: 5432 tcp localhost the shop's Postgres, used only by the app on this server\n" +
			"exposure is internet (the internet can open a session), vpn, lan, or airgapped. internet raises remote-access and network findings one step. airgapped lowers remote-access findings two steps. vpn and lan do not move a finding.\n" +
			"environment is prod, staging, or dev. dev lowers findings one step. prod does not raise them.\n" +
			"A service is a port that should be open, with tcp or udp, then who should reach it: localhost (only this server), lan (the office network), vpn, or internet, then a few words on what it is. " +
			"A database only this server uses is localhost: it should be open, to this server. scheck reports a service that listens more widely than you said. " +
			"If you do not know who should reach it, leave that word out. If you do not know the port, leave service out. Do not name a port you hope is closed.",
			Consumers: []Consumer{{ID: "host.context.exposure", Slice: "E1b"}, {ID: "host.context.environment", Slice: "E1b"}, {ID: "svc.expected_missing", Slice: "E1b"},
				{ID: finding.IDDBListensUnfiltered, Slice: "E9"}, {ID: finding.IDSvcListensBeyond, Slice: "E9"}, {ID: finding.IDSensitiveListens, Slice: "G5"}},
			answered: func(f *File) bool { return !hostNeedsContext(f) },
			apply:    applyContext,
			notes:    contextNotes},
		{ID: "app_paths", Prompt: "Is an application installed on a server you named, as files on its disk? If it runs only in containers or Kubernetes, or you do not know, leave this blank: .env files are then not looked for, and the report says so (not checked, not clean).\n" +
			"Otherwise, one block per server: name is the server's name from your earlier answer, then one folder per line. Example:\n" +
			"  name: shop\n" +
			"  path: /srv/shop\n" +
			"  path: /var/www/api\n" +
			"scheck lists files named .env up to 4 folders deep under each folder and reports who can read them. It never opens them. " +
			"Folders must be under /srv, /var/www, /opt, /app, /data, /home, /root or /Users (others are refused), at most 5 per server. " +
			"Under /home, /root and /Users a .env is listed and not judged.",
			Consumers: []Consumer{{ID: finding.IDEnvFileExposed, Slice: "G5"}},
			answered:  func(f *File) bool { return !hasHost(f) || anyAppPaths(f) },
			apply:     applyAppPaths},
		{ID: "matters_most", Prompt: "Which of these hold the data that would hurt the company most if it leaked or was lost, such as customer records, payment details, source code or contracts? " +
			"Give the number of each, and a few words on what the data is, one per line (for example `2: customer orders and invoices`). If you are not sure, leave this blank.\n" +
			"Problems found on what you pick rank higher. Account and access problems, exposed secrets and open databases there move up one step. " +
			"This answer alone never makes anything critical. Other findings, such as web headers or email settings, do not move. Leaving it blank changes no finding.",
			Consumers: []Consumer{{ID: "severity.data_matters_most", Slice: "E9"}, {ID: "plan.github_tier4", Slice: "E9"},
				{ID: "report.rank_tiebreak", Slice: "E2"}, {ID: "report.matters_most_readout", Slice: "E9"}},
			answered: func(f *File) bool { return len(f.Data.MattersMost) > 0 || len(offers(f)) == 0 },
			apply:    applyMattersMost,
			offer:    offerText},
		{ID: "not_used", Prompt: "Which of these do you not operate at all? One per line: hosts, cloud, data, cicd, email, web, external.\n" +
			"hosts only when you have no servers. cloud only when you administer no cloud project. data (databases and backups you operate) only when you also have no cloud project. cicd only when you have no GitHub organization and no repository. email only when you have no domain. web only when you have no domain and no url. external only when you have no domain, url, or network.\n" +
			"You cannot say identity, secrets, or logging do not apply. You cannot set aside an area you already named something in.",
			Consumers: []Consumer{{ID: "coverage.not_applicable", Slice: "E2"}},
			answered:  func(f *File) bool { return len(f.NotUsed) > 0 },
			apply:     applyNotUsed},
	}
}

// Apply merges answer into f for the question id. A blank answer changes
// nothing. An answer shaped like a credential is refused by the same
// detector as validation, and the value is not in the error. A refused
// answer may leave f partly changed; the caller restores its own copy, as
// init does.
func Apply(f *File, id, answer string) error {
	_, err := Answer(f, id, answer)
	return err
}

// Answer is Apply, and the lines scheck init prints after an accepted
// answer (a service declared with no audience).
func Answer(f *File, id, answer string) ([]string, error) {
	q, ok := questionByID(id)
	if !ok {
		return nil, fmt.Errorf("unknown question %q", id)
	}
	answer = strings.TrimSpace(answer)
	var lines []string
	if answer != "" && !isSkip(answer) {
		if d, ok := policy.DetectCredential(answer); ok {
			return nil, credentialRefusal(d)
		}
		if err := q.apply(f, answer); err != nil {
			return nil, err
		}
		if q.notes != nil {
			lines = q.notes(answer)
		}
	}
	if q.left != nil {
		lines = append(lines, q.left(f)...)
	}
	return lines, nil
}

// Explanations is what scheck init prints when the file names a Google
// Workspace tenant. They are not questions and they do not write
// authorization.mailboxes.
func Explanations(f *File) []string {
	if !hasWorkspace(f) {
		return nil
	}
	return []string{explainOAuth, explainMail}
}

const explainOAuth = "Optional check of apps people have allowed into their Google account. " +
	"This is not a question about which apps you use. To turn it on later, set SCHECK_WORKSPACE_PROFILE=directory_oauth in the environment, not in this file. " +
	"The Google credential stays in the environment. Pasting a refresh token, a client secret, or a service-account file into this file is refused. " +
	"The permission this check needs is admin.directory.user.security. Google does not offer a read-only form of it. " +
	"The same permission can also revoke app access, sign people out, and turn off 2-step verification. " +
	"The checks that do not look at apps do not need it. A separate credential keeps that permission off the everyday admin login. " +
	"This check does not sign in as staff and does not want an approval entry for mailboxes."

const explainMail = "Optional check of whether mail is forwarded. This is not a question about whether forwarding is on purpose. " +
	"It needs a service account, created by whoever manages Google, whose domain-wide delegation is gmail.readonly and nothing else. " +
	"That permission can read every message. scheck reads forwarding settings and filters only. Most small companies do not already have that account. " +
	"The key stays in the environment. This file gets no key, no path to a key, and no list of staff mailboxes. " +
	"Whoever approves access to staff mailboxes has to approve it. You write that approval by hand, only after they approve, as asset, who approved it, the date, and an expiry at most 90 days later. " +
	"There is no way to skip some mailboxes. This interview does not write, renew, or extend that approval."

// Encode writes f as an engagement file, with the header comment.
func Encode(f *File) ([]byte, error) {
	fillDefaults(f)
	var buf bytes.Buffer
	buf.WriteString(FileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fillDefaults(f *File) {
	if f.Schema == 0 {
		f.Schema = Schema
	}
	if f.Defaults.Probe == "" {
		f.Defaults.Probe = "off"
	}
	if f.Defaults.Scan == "" {
		f.Defaults.Scan = "off"
	}
	if f.Defaults.Throttle == nil {
		f.Defaults.Throttle = &Throttle{Rate: DefaultRate, Concurrency: DefaultConcurrency}
	}
	if f.Defaults.Profile == "" {
		f.Defaults.Profile = DefaultProfile
	}
	if f.Limits.Timeout == "" {
		f.Limits.Timeout = "1h"
	}
}

func questionByID(id string) (Question, bool) {
	for _, q := range Questions() {
		if q.ID == id {
			return q, true
		}
	}
	return Question{}, false
}

func credentialRefusal(detector string) error {
	return fmt.Errorf("holds a value shaped like a credential (detector %s): credentials come from the environment or the provider's own login, never from this file", detector)
}

func isSkip(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "skip", "nothing", "n/a":
		return true
	default:
		return false
	}
}

func applyTrigger(f *File, answer string) error {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "questionnaire", "a customer questionnaire", "customer questionnaire":
		f.Engagement.Trigger = "questionnaire"
	case "audit", "an audit":
		f.Engagement.Trigger = "audit"
	case "funding", "a funding round", "funding round":
		f.Engagement.Trigger = "funding"
	case "incident", "an incident":
		f.Engagement.Trigger = "incident"
	case "routine", "a routine check", "routine check":
		f.Engagement.Trigger = "routine"
	default:
		return fmt.Errorf("trigger must be questionnaire, audit, funding, incident, or routine")
	}
	return nil
}

func applyName(f *File, answer string) error {
	name := strings.TrimSpace(answer)
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name %q must be lowercase letters, digits and hyphens, and start with a letter or digit", name)
	}
	f.Engagement.Name = name
	return nil
}

func applyOperator(f *File, answer string) error {
	op := strings.TrimSpace(answer)
	if op == "" {
		return fmt.Errorf("the report needs a name or a team")
	}
	f.Engagement.Operator = op
	return nil
}

func applyTimezone(f *File, answer string) error {
	zone := strings.TrimSpace(answer)
	if zone == "" || zone == "Local" {
		return fmt.Errorf("%q is not a time zone such as Europe/London", zone)
	}
	if _, err := time.LoadLocation(zone); err != nil {
		return fmt.Errorf("%q is not a time zone such as Europe/London", zone)
	}
	f.Engagement.Timezone = zone
	return nil
}

func applyRoots(f *File, answer string) error {
	return applyLocators(&f.Roots, answer)
}

func applyExclude(f *File, answer string) error {
	return applyLocators(&f.Exclude, answer)
}

func applyLocators(dst *[]Locator, answer string) error {
	for _, line := range linesOf(answer) {
		k, v, ok := splitField(line)
		if !ok {
			return fmt.Errorf("%q needs a kind and a value, such as domain: example.com", line)
		}
		loc, err := locatorOf(k, v)
		if err != nil {
			return err
		}
		*dst = append(*dst, loc)
	}
	return nil
}

func locatorOf(kind, value string) (Locator, error) {
	var loc Locator
	switch kind {
	case "domain":
		loc.Domain = value
	case "url":
		loc.URL = value
	case "host":
		loc.Host = value
	case "network":
		loc.Network = value
	case "cloud":
		loc.Cloud = value
	case "saas":
		loc.SaaS = value
	case "repo":
		loc.Repo = value
	default:
		return Locator{}, fmt.Errorf("%q is not a locator kind", kind)
	}
	k := Kind(kind)
	if _, err := parseLocator(k, value); err != nil {
		return Locator{}, err
	}
	return loc, nil
}

func applyMail(f *File, answer string) error {
	var cur Sender
	flush := func() error {
		if cur.Domain == "" && cur.Service == "" && len(cur.DKIMSelectors) == 0 {
			return nil
		}
		if cur.Domain == "" || cur.Service == "" {
			return fmt.Errorf("a sender needs a domain and a service")
		}
		f.Mail.Senders = append(f.Mail.Senders, cur)
		cur = Sender{}
		return nil
	}
	for _, line := range linesOf(answer) {
		k, v, ok := splitField(line)
		if !ok {
			return fmt.Errorf("%q is not a mail line", line)
		}
		switch k {
		case "nomail":
			if err := flush(); err != nil {
				return err
			}
			f.Mail.NoMail = append(f.Mail.NoMail, v)
		case "domain":
			if cur.Domain != "" || cur.Service != "" {
				if err := flush(); err != nil {
					return err
				}
			}
			cur.Domain = v
		case "service":
			cur.Service = v
		case "selector":
			if !unknownAnswer(v) {
				cur.DKIMSelectors = append(cur.DKIMSelectors, v)
			}
		default:
			return fmt.Errorf("%q is not a mail field", k)
		}
	}
	return flush()
}

func applyPeople(f *File, answer string) error {
	if f.People == nil {
		f.People = map[string]Person{}
	}
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		h := block["handle"]
		if !nameRe.MatchString(h) {
			return fmt.Errorf("handle %q must be lowercase letters, digits and hyphens", h)
		}
		kind, err := normKind(block["kind"])
		if err != nil {
			return err
		}
		p := Person{Kind: kind, Org: block["org"]}
		if w := block["workspace"]; w != "" {
			if !isAddress(w) {
				return fmt.Errorf("%q is not an email address; leave workspace out if you do not know it", w)
			}
			p.Workspace = []string{w}
		}
		if g := block["github"]; g != "" {
			if !isPeopleGitHubLogin(g) {
				return fmt.Errorf("%q is not a GitHub login; leave github out if you do not know it", g)
			}
			p.GitHub = []string{g}
		}
		if u := block["used_by"]; u != "" {
			for _, name := range splitList(u) {
				if !nameRe.MatchString(name) {
					return fmt.Errorf("used_by %q must be a handle of a person you have named", name)
				}
				p.UsedBy = append(p.UsedBy, name)
			}
		}
		if _, ok := f.People[h]; ok {
			return fmt.Errorf("handle %s is listed twice", h)
		}
		if p.Kind == "shared" && len(p.UsedBy) == 0 {
			return fmt.Errorf("%s is a shared login and needs used_by: the handles of the people who use it", h)
		}
		if p.Kind != "shared" && len(p.UsedBy) > 0 {
			return fmt.Errorf("only a shared login has used_by")
		}
		f.People[h] = p
	}
	for _, p := range f.People {
		if p.Kind != "shared" {
			continue
		}
		for _, u := range p.UsedBy {
			other, ok := f.People[u]
			if !ok {
				return fmt.Errorf("used_by %q is not a handle you have named", u)
			}
			if other.Kind == "shared" || other.Kind == "service" {
				return fmt.Errorf("used_by %s must be a person, not a %s login", u, other.Kind)
			}
		}
	}
	return nil
}

func applyLeft(f *File, answer string) error {
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		h := block["handle"]
		p, ok := f.People[h]
		if !ok {
			return fmt.Errorf("%q is not a handle you have named", h)
		}
		day := block["left"]
		if _, err := time.Parse("2006-01-02", day); err != nil {
			return fmt.Errorf("left for %s must be YYYY-MM-DD; leave this person out if you do not know the day", h)
		}
		p.Left = day
		f.People[h] = p
	}
	return nil
}

func applyAdmins(f *File, answer string) error {
	if f.Access.Admins == nil {
		f.Access.Admins = map[string][]string{}
	}
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		where := block["where"]
		if _, err := parseLocator(KindSaaS, where); err != nil {
			return fmt.Errorf("where: %w", err)
		}
		var handles []string
		for _, h := range splitList(block["handles"]) {
			if _, ok := f.People[h]; !ok {
				return fmt.Errorf("%q is not a handle you have named", h)
			}
			handles = append(handles, h)
		}
		if len(handles) == 0 {
			return fmt.Errorf("name the handles you expect, or leave this tenant out")
		}
		f.Access.Admins[where] = handles
	}
	return nil
}

func applyDeploys(f *File, answer string) error {
	if f.Assets == nil {
		f.Assets = map[string]Asset{}
	}
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		name := block["name"]
		if !nameRe.MatchString(name) {
			return fmt.Errorf("name %q must be lowercase letters, digits and hyphens", name)
		}
		repo := block["repo"]
		if _, err := parseLocator(KindRepo, repo); err != nil {
			return err
		}
		to := block["deploys_to"]
		if !contains(DeployTargets, to) {
			return fmt.Errorf("deploys_to must be production, staging, or development")
		}
		a := f.Assets[name]
		a.Repo = repo
		a.DeploysTo = to
		f.Assets[name] = a
	}
	return nil
}

func applyMFA(f *File, answer string) error {
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		where := block["where"]
		if _, err := parseLocator(KindSaaS, where); err != nil {
			return fmt.Errorf("where: %w", err)
		}
		enforced, err := normMFA(block["enforced"])
		if err != nil {
			return err
		}
		f.Access.MFA = append(f.Access.MFA, MFA{Where: where, Enforced: enforced})
	}
	return nil
}

// signInOffers are the access.mfa entries the sign_in question asks
// about: a Google Workspace tenant whose answer, everyone or some, a
// sign_in answer changes, and that has none yet.
func signInOffers(f *File) []int {
	var out []int
	for i, m := range f.Access.MFA {
		if strings.HasPrefix(m.Where, "google-workspace:") && (m.Enforced == "everyone" || m.Enforced == "some") && m.SignIn == "" {
			out = append(out, i)
		}
	}
	return out
}

func offerSignIn(f *File) string {
	lines := []string{}
	for _, i := range signInOffers(f) {
		m := f.Access.MFA[i]
		lines = append(lines, fmt.Sprintf("Answer for: %s (access.mfa[%d], enforced: %s)", m.Where, i, m.Enforced))
	}
	return strings.Join(lines, "\n")
}

func applySignIn(f *File, answer string) error {
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	offered := signInOffers(f)
	for _, block := range blocks {
		where := block["where"]
		i := slices.IndexFunc(offered, func(i int) bool { return strings.EqualFold(f.Access.MFA[i].Where, where) })
		if i < 0 {
			names := []string{}
			for _, j := range offered {
				names = append(names, f.Access.MFA[j].Where)
			}
			return fmt.Errorf("answer only for the tenants listed: %s", strings.Join(names, ", "))
		}
		signIn, err := normSignIn(block["sign_in"])
		if err != nil {
			return err
		}
		f.Access.MFA[offered[i]].SignIn = signIn
	}
	return nil
}

// signInLeft is the line for each offered tenant still without a sign_in.
func signInLeft(f *File) []string {
	var out []string
	for _, i := range signInOffers(f) {
		m := f.Access.MFA[i]
		what := "a unit where Google does not require 2-step verification will rank higher"
		if m.Enforced == "some" {
			what = "if the list of users is complete and Google reports every active account as not required to use 2-step verification, every unit with an active account will rank higher"
		}
		out = append(out, "No sign_in given for "+m.Where+": "+what+" for contradicting your answer, even if another sign-in service asks those accounts for a second factor.")
	}
	return out
}

func applyExposed(f *File, answer string) error {
	return applyExposure(&f.Intent.ExposedOnPurpose, answer, true)
}

func applyRestricted(f *File, answer string) error {
	return applyExposure(&f.Intent.NotExposed, answer, false)
}

func applyExposure(dst *[]Exposure, answer string, wantReason bool) error {
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		e := Exposure{URL: block["url"], Audience: normAudience(block["audience"]), Reason: block["reason"]}
		if e.URL == "" || e.Audience == "" || (wantReason && e.Reason == "") {
			return fmt.Errorf("a web address needs a url, an audience, and a reason")
		}
		if !wantReason && e.Reason == "" {
			e.Reason = ""
		}
		if _, err := parseLocator(KindURL, e.URL); err != nil {
			return err
		}
		if !contains(Audiences, e.Audience) {
			return fmt.Errorf("audience must be internet, vpn, lan, localhost, or airgapped")
		}
		*dst = append(*dst, e)
	}
	return nil
}

func applyReach(f *File, answer string) error {
	if f.Assets == nil {
		f.Assets = map[string]Asset{}
	}
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		name := block["name"]
		if !nameRe.MatchString(name) {
			return fmt.Errorf("name %q must be lowercase letters, digits and hyphens", name)
		}
		host := block["host"]
		if _, err := parseLocator(KindHost, host); err != nil {
			return err
		}
		a := f.Assets[name]
		a.Host = host
		a.Identity = block["identity"]
		a.KnownHosts = block["known_hosts"]
		a.Jump = block["jump"]
		f.Assets[name] = a
		if !hasRootValue(f.Roots, host) {
			f.Roots = append(f.Roots, Locator{Host: host})
		}
	}
	return nil
}

func applyContext(f *File, answer string) error {
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	services := servicesOf(answer)
	// A refused answer changes nothing: each block works on a copy of its
	// host's context, written back only once the whole answer is accepted,
	// so the operator can type it again.
	done := map[string]Asset{}
	for i, block := range blocks {
		name := block["name"]
		a, ok := done[name]
		if !ok {
			a, ok = f.Assets[name]
		}
		if !ok || a.Host == "" {
			return fmt.Errorf("%q is not a server you named", name)
		}
		c := HostContext{}
		if a.Context != nil {
			c = *a.Context
			c.ExpectedServices = slices.Clone(c.ExpectedServices)
		}
		a.Context = &c
		if exp := block["exposure"]; exp != "" {
			exp = normExposure(exp)
			if !contains(Exposures, exp) {
				return fmt.Errorf("exposure must be internet, vpn, lan, or airgapped")
			}
			if exp == "internet" && contains(f.NotUsed, "external") {
				return fmt.Errorf("you said you run nothing internet-facing (not_used: external); a server the internet can reach is internet-facing")
			}
			a.Context.Exposure = exp
		}
		if env := block["environment"]; env != "" {
			env = normEnvironment(env)
			if !contains(Environments, env) {
				return fmt.Errorf("environment must be prod, staging, or dev")
			}
			a.Context.Environment = env
		}
		for _, svc := range services[i] {
			s, err := parseService(svc)
			if err != nil {
				return err
			}
			// Intake refuses a port declared twice (validate.go); say so
			// here, before the answers are lost.
			if slices.ContainsFunc(a.Context.ExpectedServices, func(e Service) bool { return e.Port == s.Port && e.Proto == s.Proto }) {
				return refusef("%d/%s is declared twice on %s; give one service line per port and put both audiences' words on it.", s.Port, s.Proto, name)
			}
			a.Context.ExpectedServices = append(a.Context.ExpectedServices, s)
		}
		done[name] = a
	}
	maps.Copy(f.Assets, done)
	return nil
}

func applyAppPaths(f *File, answer string) error {
	blocks, err := blocksOf(answer)
	if err != nil {
		return err
	}
	paths := repeatedOf(answer, "path")
	done := map[string]Asset{}
	for i, block := range blocks {
		name := block["name"]
		a, ok := done[name]
		if !ok {
			a, ok = f.Assets[name]
		}
		if !ok || a.Host == "" {
			return fmt.Errorf("%q is not a server you named", name)
		}
		a.AppPaths = slices.Clone(a.AppPaths)
		for _, p := range paths[i] {
			if !slices.Contains(a.AppPaths, p) {
				a.AppPaths = append(a.AppPaths, p)
			}
		}
		if len(a.AppPaths) == 0 {
			return fmt.Errorf("%s: give at least one path: line, or leave the answer blank", name)
		}
		// Refuse here what intake would, before the answers are lost.
		if pr := appPathProblems(a.AppPaths); len(pr) > 0 {
			return fmt.Errorf("%s: %s", name, pr[0].Msg)
		}
		done[name] = a
	}
	maps.Copy(f.Assets, done)
	return nil
}

func anyAppPaths(f *File) bool {
	for _, a := range f.Assets {
		if a.Host != "" && len(a.AppPaths) > 0 {
			return true
		}
	}
	return false
}

func applyNotUsed(f *File, answer string) error {
	roots, err := rootRefs(f)
	if err != nil {
		return err
	}
	for _, line := range linesOf(answer) {
		area := strings.ToLower(strings.TrimSpace(line))
		if !contains(Areas, area) {
			return fmt.Errorf("%q is not an area", area)
		}
		if why := notUsedRefusal(area, roots, repoAssets(f), hostAssets(f), internetHosts(f)); why != "" {
			return fmt.Errorf("%s", why)
		}
		f.NotUsed = append(f.NotUsed, area)
	}
	return nil
}

// applyFramework records what the sites are built with, for every site:
// defaults.framework. none and unknown stand alone.
func applyFramework(f *File, answer string) error {
	var list []string
	for _, line := range linesOf(answer) {
		for _, w := range splitList(strings.ToLower(line)) {
			if !contains(Frameworks, w) {
				return fmt.Errorf("%q is not one of %s", w, strings.Join(Frameworks, ", "))
			}
			if !contains(list, w) {
				list = append(list, w)
			}
		}
	}
	if len(list) > 1 && (contains(list, "none") || contains(list, "unknown")) {
		return fmt.Errorf("none and unknown stand alone: they say the sites have no framework, or that you do not know it")
	}
	f.Defaults.Framework = list
	return nil
}

// hasWeb reports a root that is a website: a domain or a url.
func hasWeb(f *File) bool {
	return hasDomain(f) || slices.ContainsFunc(f.Roots, func(r Locator) bool { return r.URL != "" })
}

func rootRefs(f *File) ([]Ref, error) {
	var out []Ref
	for _, loc := range f.Roots {
		k, v, ok := loc.one()
		if !ok {
			continue
		}
		r, err := parseLocator(k, v)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (l Locator) one() (Kind, string, bool) {
	switch {
	case l.Domain != "":
		return KindDomain, l.Domain, true
	case l.URL != "":
		return KindURL, l.URL, true
	case l.Host != "":
		return KindHost, l.Host, true
	case l.Network != "":
		return KindNetwork, l.Network, true
	case l.Cloud != "":
		return KindCloud, l.Cloud, true
	case l.SaaS != "":
		return KindSaaS, l.SaaS, true
	case l.Repo != "":
		return KindRepo, l.Repo, true
	default:
		return "", "", false
	}
}

// parseService reads `<port> <tcp|udp> [localhost|lan|vpn|internet]
// <purpose>`: a third word that is an audience is the audience, otherwise
// the rest is the purpose (docs/spec/engagement.md, "Intake").
func parseService(s string) (Service, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return Service{}, fmt.Errorf("a service needs a port and tcp or udp; leave it out if you do not know")
	}
	var port int
	if _, err := fmt.Sscan(fields[0], &port); err != nil || port < 1 || port > 65535 {
		return Service{}, fmt.Errorf("%q is not a port", fields[0])
	}
	proto := strings.ToLower(fields[1])
	if !contains(Protos, proto) {
		return Service{}, fmt.Errorf("protocol must be tcp or udp; leave the service out if you do not know")
	}
	svc := Service{Port: port, Proto: proto}
	rest := fields[2:]
	if len(rest) > 0 {
		switch w := strings.ToLower(rest[0]); w {
		case "localhost", "lan", "vpn", "internet":
			svc.Audience, rest = w, rest[1:]
		case "airgapped":
			return Service{}, fmt.Errorf("a service's audience is localhost, lan, vpn or internet; airgapped describes a host")
		}
	}
	svc.Purpose = strings.Join(rest, " ")
	return svc, nil
}

// contextNotes says, for each service declared with no audience, what
// scheck will and will not judge of it.
func contextNotes(answer string) []string {
	var out []string
	for _, block := range servicesOf(answer) {
		for _, line := range block {
			if svc, err := parseService(line); err == nil && svc.Audience == "" {
				out = append(out, fmt.Sprintf("No audience given for %d/%s: scheck will check that it is listening, but not whether it listens more widely than it should.", svc.Port, svc.Proto))
			}
		}
	}
	return out
}

// servicesOf is every service: line of each block, in the order blocksOf
// returns the blocks: a host may declare several.
func servicesOf(s string) [][]string { return repeatedOf(s, "service") }

// repeatedOf is every line of the key in each block, in the order blocksOf
// returns the blocks.
func repeatedOf(s, key string) [][]string {
	var out [][]string
	var cur []string
	open := false
	for line := range strings.SplitSeq(s, "\n") {
		if strings.TrimSpace(line) == "" {
			if open {
				out = append(out, cur)
			}
			cur, open = nil, false
			continue
		}
		k, v, ok := splitField(line)
		if !ok {
			continue
		}
		open = true
		if k == key {
			cur = append(cur, v)
		}
	}
	if open {
		out = append(out, cur)
	}
	return out
}

func normKind(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "employee":
		return "employee", nil
	case "contractor":
		return "contractor", nil
	case "shared", "shared login":
		return "shared", nil
	case "service", "service login":
		return "service", nil
	case "break_glass", "break-glass", "break glass":
		return "break_glass", nil
	default:
		return "", fmt.Errorf("kind must be employee, contractor, shared, service, or break_glass")
	}
}

func normSignIn(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "google", "google password", "directly":
		return "google", nil
	case "another_provider", "another provider", "another identity provider", "okta", "entra", "microsoft entra", "azure ad", "jumpcloud", "onelogin":
		return "another_provider", nil
	case "unknown", "i do not know", "i don't know", "not sure":
		return "unknown", nil
	case "sso":
		return "", fmt.Errorf("sso can mean either. Write another_provider if Google sends people to another service to sign in, or google if people sign in with Google, including when they use Google to sign in to other apps")
	case "yes", "true", "no", "false":
		return "", fmt.Errorf("%s is ambiguous. Write another_provider if some or all people sign in to Google through another service such as Okta or Microsoft Entra, google if everyone signs in with a Google password, or unknown", s)
	default:
		return "", fmt.Errorf("sign_in must be google, another_provider, or unknown")
	}
}

func normMFA(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "everyone", "every account":
		return "everyone", nil
	case "admins", "only admins":
		return "admins", nil
	case "some", "some accounts":
		return "some", nil
	case "none", "nobody":
		return "none", nil
	case "unknown", "i do not know", "i don't know":
		return "unknown", nil
	case "yes", "true", "no", "false":
		return "", fmt.Errorf("%s is not an answer; write everyone, admins, some, none, or unknown", s)
	default:
		return "", fmt.Errorf("enforced must be everyone, admins, some, none, or unknown")
	}
}

func normAudience(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "office", "office network", "the office network":
		return "lan"
	case "this machine", "this machine only":
		return "localhost"
	case "cut off", "no network":
		return "airgapped"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func normExposure(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "office", "office network":
		return "lan"
	case "cut off", "no network":
		return "airgapped"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func normEnvironment(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "live", "production":
		return "prod"
	case "development":
		return "dev"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func unknownAnswer(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "unknown", "i do not know", "i don't know", "i do not know the selector":
		return true
	default:
		return false
	}
}

func linesOf(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func blocksOf(s string) ([]map[string]string, error) {
	var out []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
		}
	}
	for line := range strings.SplitSeq(s, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		k, v, ok := splitField(line)
		if !ok {
			continue
		}
		cur[k] = v
	}
	flush()
	if len(out) == 0 {
		return nil, fmt.Errorf("that answer did not include a field; write key: value lines, or leave the answer blank")
	}
	return out, nil
}

func splitField(line string) (string, string, bool) {
	k, v, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	k = strings.ToLower(strings.TrimSpace(k))
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	if k == "" || v == "" {
		return "", "", false
	}
	return k, v, true
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	return slices.Contains(list, s)
}

func hasDomain(f *File) bool {
	for _, r := range f.Roots {
		if r.Domain != "" {
			return true
		}
	}
	return false
}

func hasSaaS(f *File) bool {
	for _, r := range f.Roots {
		if r.SaaS != "" {
			return true
		}
	}
	return false
}

func hasWorkspace(f *File) bool {
	for _, r := range f.Roots {
		if strings.HasPrefix(r.SaaS, "google-workspace:") {
			return true
		}
	}
	return false
}

func hasGitHub(f *File) bool {
	for _, r := range f.Roots {
		if strings.HasPrefix(r.SaaS, "github:") || r.Repo != "" {
			return true
		}
	}
	for _, a := range f.Assets {
		if a.Repo != "" {
			return true
		}
	}
	return false
}

func reachAnswered(f *File) bool {
	if !hasHost(f) {
		return false
	}
	for _, r := range f.Roots {
		if r.Host != "" && !assetHasHost(f, r.Host) {
			return false
		}
	}
	return true
}

func assetHasHost(f *File, host string) bool {
	for _, a := range f.Assets {
		if a.Host == host {
			return true
		}
	}
	return false
}

func hasHost(f *File) bool {
	for _, r := range f.Roots {
		if r.Host != "" {
			return true
		}
	}
	for _, a := range f.Assets {
		if a.Host != "" {
			return true
		}
	}
	return false
}

func hasRootValue(roots []Locator, host string) bool {
	for _, r := range roots {
		if r.Host == host {
			return true
		}
	}
	return false
}

func anyDeploys(f *File) bool {
	for _, a := range f.Assets {
		if a.DeploysTo != "" {
			return true
		}
	}
	return false
}

func hostNeedsContext(f *File) bool {
	for _, a := range f.Assets {
		if a.Host == "" {
			continue
		}
		if a.Context == nil || (a.Context.Exposure == "" && a.Context.Environment == "" && len(a.Context.ExpectedServices) == 0) {
			return true
		}
	}
	return false
}
