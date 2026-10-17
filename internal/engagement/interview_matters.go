package engagement

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// refusal is a sentence the interview prints as written: the spec's
// wording, a full sentence (docs/spec/engagement.md, "The
// `data.matters_most` question").
type refusal string

func (r refusal) Error() string { return string(r) }

func refusef(format string, a ...any) error { return refusal(fmt.Sprintf(format, a...)) }

// maxWhat is the longest description an answer may give one asset.
const maxWhat = 120

// offered is one asset the data.matters_most question offers: its label
// and the reference written to asset (docs/spec/engagement.md, "The
// `data.matters_most` question").
type offered struct {
	label string
	ref   string
	id    string
	org   bool
}

// offerGroups is the order the question offers kinds in. Domain roots and
// networks are never offered: the data is on a site or a server.
var offerGroups = []func(Locator) bool{
	func(l Locator) bool { return l.Host != "" },
	func(l Locator) bool { return strings.HasPrefix(l.SaaS, "google-workspace:") },
	func(l Locator) bool { return strings.HasPrefix(l.SaaS, "github:") },
	func(l Locator) bool { return l.Repo != "" },
	func(l Locator) bool { return l.URL != "" },
	func(l Locator) bool { return l.Cloud != "" },
}

// offers is what the question offers from f: every declared, non-excluded
// asset of the offered kinds, grouped in offerGroups' order, roots in file
// order and then the assets entries no root is, in name order. An assets
// entry for a root is labelled with its name.
func offers(f *File) []offered {
	excludes := excludeRefs(f)
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range f.Assets {
			if !yield(n) {
				return
			}
		}
	})
	var out []offered
	seen := map[string]bool{}
	add := func(l Locator, name string) {
		k, v, ok := l.one()
		if !ok {
			return
		}
		r, err := parseLocator(k, v)
		if err != nil || seen[r.ID] || slices.ContainsFunc(excludes, func(x Ref) bool { return Excludes(x, r) }) {
			return
		}
		seen[r.ID] = true
		o := offered{label: string(k) + ": " + v, ref: v, id: r.ID, org: k == KindSaaS && strings.HasPrefix(v, "github:")}
		if name != "" {
			o.label, o.ref = name+" ("+o.label+")", name
		}
		if o.org {
			o.label += " (GitHub organization: its members and admins)"
		}
		out = append(out, o)
	}
	for _, in := range offerGroups {
		for _, root := range f.Roots {
			if !in(root) {
				continue
			}
			add(root, assetNamed(f, names, root))
		}
		for _, n := range names {
			if l := f.Assets[n].Locator; in(l) {
				add(l, n)
			}
		}
	}
	return out
}

// excludeRefs are the file's excludes that parse.
func excludeRefs(f *File) []Ref {
	var out []Ref
	for _, x := range f.Exclude {
		if k, v, ok := x.one(); ok {
			if r, err := parseLocator(k, v); err == nil {
				out = append(out, r)
			}
		}
	}
	return out
}

// assetNamed is the assets entry for the root, "" when none.
func assetNamed(f *File, names []string, root Locator) string {
	for _, n := range names {
		if f.Assets[n].Locator == root {
			return n
		}
	}
	return ""
}

// offerText is the numbered list printed under the prompt.
func offerText(f *File) string {
	var b strings.Builder
	org := false
	for i, o := range offers(f) {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, o.label)
		org = org || o.org
	}
	if org {
		b.WriteString("Picking an organization covers its members and admins. To cover a repository's code, pick the repository.\n")
		b.WriteString("A repository that is not listed, under an organization above: repo: github:org/name: a few words\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// applyMattersMost reads `N: a few words` lines, and `repo:
// github:org/name: a few words` for a repository under a declared GitHub
// organization root, which becomes an assets entry. Any bad line refuses
// the whole answer.
func applyMattersMost(f *File, answer string) error {
	list := offers(f)
	var items []DataItem
	picked := map[int]bool{}
	newRepos := map[string]Asset{}
	for _, line := range linesOf(answer) {
		k, rest, ok := strings.Cut(line, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		switch {
		case !ok:
			return errMattersLine
		case k == "repo":
			name, a, what, err := mattersRepo(f, newRepos, rest)
			if err != nil {
				return err
			}
			newRepos[name] = a
			items = append(items, DataItem{What: what, Asset: name})
			continue
		case k == "domain" || (strings.Contains(k, ".") && !strings.ContainsAny(k, " \t")):
			return refusal("A domain is not offered: pick the site (url) or server that holds the data.")
		}
		n, err := strconv.Atoi(k)
		if err != nil {
			return errMattersLine
		}
		what, err := mattersWhat(rest, k)
		if err != nil {
			return err
		}
		if n < 1 || n > len(list) {
			return refusef("There is no number %d here; pick from 1 to %d.", n, len(list))
		}
		if picked[n] {
			return refusef("%d is listed twice; give one line per number and put both descriptions on it.", n)
		}
		picked[n] = true
		items = append(items, DataItem{What: what, Asset: list[n-1].ref})
	}
	if f.Assets == nil && len(newRepos) > 0 {
		f.Assets = map[string]Asset{}
	}
	maps.Copy(f.Assets, newRepos)
	f.Data.MattersMost = append(f.Data.MattersMost, items...)
	return nil
}

var errMattersLine error = refusal("Write each line as a number, a colon and a few words, for example `2: customer orders and invoices`.")

// mattersWhat is a line's description: required and short.
func mattersWhat(rest, n string) (string, error) {
	what := strings.TrimSpace(rest)
	if what == "" {
		return "", refusef("Say in a few words what data number %s holds, for example `%s: customer orders and invoices`.", n, n)
	}
	if utf8.RuneCountInString(what) > maxWhat {
		return "", refusef("Keep the description of number %s to %d characters or fewer.", n, maxWhat)
	}
	return what, nil
}

// mattersRepo reads `github:org/name: a few words` for a repository under
// a declared GitHub organization root: the assets entry it becomes, named
// from the repository's last path segment, as the deploys question names
// one.
func mattersRepo(f *File, pending map[string]Asset, rest string) (string, Asset, string, error) {
	rest = strings.TrimSpace(rest)
	prefix, tail, ok := strings.Cut(rest, ":")
	locator, what, ok2 := strings.Cut(tail, ":")
	if !ok || !ok2 || strings.TrimSpace(prefix) != "github" {
		return "", Asset{}, "", refusal("Write a repository as repo: github:org/name: a few words.")
	}
	repo := "github:" + strings.TrimSpace(locator)
	r, err := parseLocator(KindRepo, repo)
	if err != nil {
		return "", Asset{}, "", err
	}
	for i, o := range offers(f) {
		if o.id == r.ID {
			return "", Asset{}, "", refusef("%s is already listed as number %d; pick that number.", repo, i+1)
		}
	}
	org, seg, _ := strings.Cut(strings.TrimPrefix(repo, "github:"), "/")
	if !slices.ContainsFunc(f.Roots, func(l Locator) bool { return strings.EqualFold(l.SaaS, "github:"+org) }) {
		return "", Asset{}, "", refusef("%s is not under a GitHub organization you listed under roots.", repo)
	}
	// Exclude wins: an excluded repository is never offered, nor taken here.
	for _, x := range excludeRefs(f) {
		if Excludes(x, r) {
			return "", Asset{}, "", refusef("%s is excluded (%s), so scheck reads nothing in it; it cannot be picked.", repo, x.ID)
		}
	}
	for _, a := range pending {
		if p, err := parseLocator(KindRepo, a.Repo); err == nil && p.ID == r.ID {
			return "", Asset{}, "", refusef("%s is listed twice; give one line per repository and put both descriptions on it.", repo)
		}
	}
	if _, taken := f.Assets[seg]; taken || !nameRe.MatchString(seg) || pending[seg].Repo != "" || rootWritten(f, seg) {
		return "", Asset{}, "", refusef("name this repository in the deploys question or in the file's assets; `%s` cannot be used as a name here.", seg)
	}
	desc := strings.TrimSpace(what)
	switch {
	case desc == "":
		return "", Asset{}, "", refusef("Say in a few words what data %s holds, for example `repo: %s: customer orders and invoices`.", repo, repo)
	case utf8.RuneCountInString(desc) > maxWhat:
		return "", Asset{}, "", refusef("Keep the description of %s to %d characters or fewer.", repo, maxWhat)
	}
	return seg, Asset{Repo: repo}, desc, nil
}

// rootWritten says a root is written as s, which an assets name may not
// shadow.
func rootWritten(f *File, s string) bool {
	return slices.ContainsFunc(f.Roots, func(l Locator) bool {
		_, v, ok := l.one()
		return ok && v == s
	})
}
