package compare

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/report"
)

func TestFixedNeedsEveryCondition(t *testing.T) {
	const web = "host:203.0.113.6:22"
	tests := []struct {
		name string
		mut  func(e, l *lab)
		want Category
		why  string
	}{
		{"decided complete and absent", func(e, l *lab) { l.notMatched("fw.a", web) }, Fixed, ""},
		{"rule incomplete", func(e, l *lab) { l.rule("fw.a", web, "not_matched", false) }, NotConfirmed, CauseIncomplete},
		{"later asset failed", func(e, l *lab) {
			l.Assets[0].Status, l.Assets[0].Reason = "failed", "failed"
			l.notMatched("fw.a", web)
		}, NotRechecked, CauseAssetNotRead},
		{"later asset refused", func(e, l *lab) { l.Assets[0].Status = "refused" }, NotRechecked, CauseAssetNotRead},
		{"later asset incomplete", func(e, l *lab) { l.Assets[0].Status = "incomplete" }, NotRechecked, CauseAssetNotRead},
		{"asset left the run", func(e, l *lab) { l.Assets = nil }, NotRechecked, CauseAssetNotInRun},
		{"rule did not run", func(e, l *lab) {}, NotRechecked, CauseRuleNotAssessed},
		{"rule not assessed", func(e, l *lab) { l.rule("fw.a", web, "not_assessed", true) }, NotRechecked, CauseRuleUndecided},
		{"scheck version differs", func(e, l *lab) { l.ScheckVersion = "0.0.4"; l.notMatched("fw.a", web) }, NotConfirmed, CauseRulesChanged},
		{"dev build is never the same", func(e, l *lab) {
			e.ScheckVersion, l.ScheckVersion = "dev", "dev"
			l.notMatched("fw.a", web)
		}, NotConfirmed, CauseRulesChanged},
		{"dirty build is never the same", func(e, l *lab) {
			e.ScheckVersion, l.ScheckVersion = "0.0.3-dirty", "0.0.3-dirty"
			l.notMatched("fw.a", web)
		}, NotConfirmed, CauseRulesChanged},
		{"principal changed", func(e, l *lab) {
			e.principal(web, "alice")
			l.principal(web, "bob")
			l.notMatched("fw.a", web)
		}, NotConfirmed, CausePrincipalChanged},
		{"machine replaced at the address", func(e, l *lab) {
			*l.Assets[0].BoundID = "B-other"
			l.notMatched("fw.a", web)
		}, NotConfirmed, CauseAssetReplaced},
		{"abstained subject", func(e, l *lab) {
			l.rule("fw.a", web, "not_matched", true, report.AssessmentOutcome{Outcome: "abstained", Detail: map[string]any{}})
		}, NotRechecked, CauseRuleUndecided},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, l := pairLab()
			e.find("fw.a", web, "", "medium")
			tc.mut(e, l)
			i := category(compareOK(t, e, l), "fw.a")
			if i.Category != tc.want || i.Cause != tc.why {
				t.Errorf("got %s/%q, want %s/%q", i.Category, i.Cause, tc.want, tc.why)
			}
		})
	}
}

func TestDeclarationChangeBlocksOnlyRulesThatReadDeclarations(t *testing.T) {
	const web = "host:203.0.113.6:22"
	for _, tc := range []struct {
		reads []string
		want  Category
	}{
		{nil, Fixed},
		{[]string{"check:fw.status"}, Fixed},
		{[]string{"check:fw.status", "declared:people.carol.left"}, NotConfirmed},
	} {
		e, l := pairLab()
		e.find("fw.no_firewall_active", web, "", "medium", tc.reads...)
		l.notMatched("fw.no_firewall_active", web)
		l.Engagement.Source.SHA256 = "bbbb"
		if got := category(compareOK(t, e, l), "fw.no_firewall_active").Category; got != tc.want {
			t.Errorf("reads %v: got %s, want %s", tc.reads, got, tc.want)
		}
	}
}

func TestVantageChangeBlocksWebFindingsOnly(t *testing.T) {
	for _, tc := range []struct {
		asset string
		want  Category
	}{
		{"domain:example.com", NotConfirmed},
		{"host:203.0.113.6:22", Fixed},
	} {
		e, l := pairLab()
		e.asset("domain:example.com", "example", "domain", "collected", "")
		l.asset("domain:example.com", "example", "domain", "collected", "")
		l.Run.Vantage = "vpn"
		e.find("web.a", tc.asset, "", "medium")
		l.notMatched("web.a", tc.asset)
		if got := category(compareOK(t, e, l), "web.a").Category; got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.asset, got, tc.want)
		}
	}
}

func TestNewNeedsTheEarlierRunToHaveLooked(t *testing.T) {
	const web = "host:203.0.113.6:22"
	for _, tc := range []struct {
		name string
		mut  func(e, l *lab)
		want Category
		why  string
	}{
		{"earlier decided absent", func(e, l *lab) { e.notMatched("fw.a", web) }, New, ""},
		{"earlier did not run the rule", func(e, l *lab) {}, FirstReported, CauseRuleNotAssessed},
		{"earlier read it in part", func(e, l *lab) { e.rule("fw.a", web, "not_matched", false) }, FirstReported, CauseIncomplete},
		{"earlier run lacked the asset", func(e, l *lab) { e.Assets = nil }, FirstReported, CauseAssetNotInRun},
		{"rules changed", func(e, l *lab) { e.ScheckVersion = "0.0.2"; e.notMatched("fw.a", web) }, FirstReported, CauseRulesChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, l := pairLab()
			l.find("fw.a", web, "", "high")
			tc.mut(e, l)
			i := category(compareOK(t, e, l), "fw.a")
			if i.Category != tc.want || i.Cause != tc.why {
				t.Errorf("got %s/%q, want %s/%q", i.Category, i.Cause, tc.want, tc.why)
			}
		})
	}
}

func TestMovedHostIsOneFindingNotFixedPlusNew(t *testing.T) {
	e := newLab("0.0.3", t0)
	l := newLab("0.0.3", t0.Add(24*time.Hour*7))
	e.asset("host:203.0.113.5:22", "deploy", "host", "collected", "M1")
	l.asset("host:203.0.113.9:22", "deploy", "host", "collected", "M1")
	e.find("sshd.password", "host:203.0.113.5:22", "", "high")
	l.find("sshd.password", "host:203.0.113.9:22", "", "high")
	c := compareOK(t, e, l)
	if len(c.Instances) != 1 {
		t.Fatalf("instances: %+v", c.Instances)
	}
	i := c.Instances[0]
	if i.Category != StillOpen || i.Identity != "moved" || i.Earlier.Asset != "host:203.0.113.5:22" || i.Later.Asset != "host:203.0.113.9:22" {
		t.Errorf("got %+v", i)
	}
	if c.Summary.Moved != 1 || c.Summary.Fixed != 0 || c.Summary.New != 0 {
		t.Errorf("summary: %+v", c.Summary)
	}
}

func TestSharedMachineIDIsNoIdentity(t *testing.T) {
	// Two hosts built from one image report one machine id: a finding that
	// leaves one of them must not be read as moving to the other.
	e := newLab("0.0.3", t0)
	l := newLab("0.0.3", t0.Add(24*time.Hour*7))
	e.asset("host:203.0.113.20:22", "a", "host", "collected", "CLONE")
	e.asset("host:203.0.113.21:22", "b", "host", "collected", "CLONE")
	l.asset("host:203.0.113.22:22", "a", "host", "collected", "CLONE")
	l.asset("host:203.0.113.21:22", "b", "host", "collected", "CLONE")
	e.find("sshd.password", "host:203.0.113.20:22", "", "high")
	l.find("sshd.password", "host:203.0.113.22:22", "", "high")
	c := compareOK(t, e, l)
	var gone, appeared bool
	for _, i := range c.Instances {
		switch i.Category {
		case NotRechecked:
			gone = true
		case FirstReported:
			appeared = true
		case StillOpen:
			t.Errorf("a shared machine id joined two hosts: %+v", i)
		}
	}
	if !gone || !appeared {
		t.Errorf("want the old one not re-checked and the new one first reported: %+v", c.Instances)
	}
	for _, a := range c.Assets {
		if a.Change == "moved" {
			t.Errorf("moved on a shared id: %+v", a)
		}
	}
}

func TestSameWeaknessOnTwoAssetsStaysTwoFindings(t *testing.T) {
	e := newLab("0.0.3", t0)
	l := newLab("0.0.3", t0.Add(24*time.Hour*7))
	for _, r := range []*lab{e, l} {
		r.asset("host:203.0.113.1:22", "a", "host", "collected", "A")
		r.asset("host:203.0.113.2:22", "b", "host", "collected", "B")
	}
	e.find("sshd.password", "host:203.0.113.1:22", "", "high")
	l.notMatched("sshd.password", "host:203.0.113.1:22")
	l.find("sshd.password", "host:203.0.113.2:22", "", "high")
	e.notMatched("sshd.password", "host:203.0.113.2:22")
	c := compareOK(t, e, l)
	if c.Summary.Fixed != 1 || c.Summary.New != 1 || c.Summary.Moved != 0 {
		t.Errorf("want one fixed and one new, got %+v", c.Summary)
	}
}

func TestRenamedSubjectFollowsProviderID(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	ef := e.find("identity.no_2sv", ws, "alice@example.com", "high")
	ef.Subject.ProviderID = "u-41"
	lf := l.find("identity.no_2sv", ws, "alice.smith@example.com", "high")
	lf.Subject.ProviderID = "u-41"
	c := compareOK(t, e, l)
	i := category(c, "identity.no_2sv")
	if i.Category != StillOpen || i.Identity != "renamed" || len(c.Instances) != 1 {
		t.Errorf("got %+v", c.Instances)
	}
}

func TestSubjectWithoutProviderIDIsNotJoinedByGuess(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	e.find("identity.no_2sv", ws, "alice@example.com", "high")
	l.find("identity.no_2sv", ws, "alice.smith@example.com", "high")
	c := compareOK(t, e, l)
	if len(c.Instances) != 2 {
		t.Fatalf("want two instances, got %+v", c.Instances)
	}
	for _, i := range c.Instances {
		if i.Category == StillOpen {
			t.Errorf("joined without a provider id: %+v", i)
		}
	}
}

func TestRedactedSubjectsNeverJoin(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("svc.a", web, "[REDACTED:extra:5 bytes]", "high")
	l.find("svc.a", web, "[REDACTED:extra:5 bytes]", "high")
	c := compareOK(t, e, l)
	for _, i := range c.Instances {
		if i.Category == StillOpen || i.Category == Fixed {
			t.Errorf("joined on a redaction marker: %+v", i)
		}
	}
}

func TestSeverityChangeCarriesTheChain(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("fw.a", web, "", "high")
	lf := l.find("fw.a", web, "", "info")
	lf.Adjustments = append(lf.Adjustments, adj("exposed_on_purpose", "to_info", "engagement.yaml", "assets.web.context.exposure"))
	lf.SeverityBase = "high"
	c := compareOK(t, e, l)
	i := c.Instances[0]
	if i.Category != StillOpen || i.Severity == nil || !i.Severity.LoweredByDeclaration || len(i.Severity.Added) != 1 {
		t.Fatalf("got %+v", i)
	}
}

func TestAcceptanceChanges(t *testing.T) {
	const web = "host:203.0.113.6:22"
	exp := "2026-10-05"
	t.Run("open then accepted", func(t *testing.T) {
		e, l := pairLab()
		e.find("fw.a", web, "", "high")
		lf := l.find("fw.a", web, "", "high")
		lf.Status = "accepted"
		lf.Acceptance = acceptance("carol", &exp)
		i := compareOK(t, e, l).Instances[0]
		if i.Category != AcceptedSince || i.Acceptance == nil || i.Acceptance.AcceptedBy != "carol" {
			t.Errorf("got %+v", i)
		}
	})
	t.Run("accepted then expired", func(t *testing.T) {
		e, l := pairLab()
		ef := e.find("fw.a", web, "", "high")
		ef.Status = "accepted"
		ef.Acceptance = acceptance("carol", &exp)
		l.find("fw.a", web, "", "high")
		i := compareOK(t, e, l).Instances[0]
		if i.Category != Reopened || i.Cause != CauseAcceptanceExpired {
			t.Errorf("got %+v", i)
		}
	})
	t.Run("accepted then still accepted", func(t *testing.T) {
		e, l := pairLab()
		for _, r := range []*lab{e, l} {
			f := r.find("fw.a", web, "", "high")
			f.Status = "accepted"
			far := "2027-01-01"
			f.Acceptance = acceptance("carol", &far)
		}
		i := compareOK(t, e, l).Instances[0]
		if i.Category != StillAccepted {
			t.Errorf("got %+v", i)
		}
	})
}

func TestExitCodes(t *testing.T) {
	const web = "host:203.0.113.6:22"
	t.Run("nothing worse is 0 and says it fixed nothing", func(t *testing.T) {
		e, l := pairLab()
		e.find("fw.a", web, "", "high")
		l.find("fw.a", web, "", "high")
		c := compareOK(t, e, l)
		if c.Exit.Code != 0 || c.Exit.OpenAtOrAboveThreshold != 1 {
			t.Errorf("%+v", c.Exit)
		}
	})
	t.Run("a new finding is 1", func(t *testing.T) {
		e, l := pairLab()
		e.notMatched("fw.a", web)
		l.find("fw.a", web, "", "high")
		if c := compareOK(t, e, l); c.Exit.Code != 1 {
			t.Errorf("%+v", c.Exit)
		}
	})
	t.Run("a new finding below the threshold is 0", func(t *testing.T) {
		e, l := pairLab()
		e.notMatched("fw.a", web)
		l.find("fw.a", web, "", "low")
		if c := compareOK(t, e, l); c.Exit.Code != 0 {
			t.Errorf("%+v", c.Exit)
		}
	})
	t.Run("a moved finding is not worse", func(t *testing.T) {
		e := newLab("0.0.3", t0)
		l := newLab("0.0.3", t0.Add(24*time.Hour))
		e.asset("host:203.0.113.5:22", "d", "host", "collected", "M1")
		l.asset("host:203.0.113.9:22", "d", "host", "collected", "M1")
		e.find("x", "host:203.0.113.5:22", "", "high")
		l.find("x", "host:203.0.113.9:22", "", "high")
		if c := compareOK(t, e, l); c.Exit.Code != 0 {
			t.Errorf("%+v", c.Exit)
		}
	})
	t.Run("an incomplete later run is 2 and never fixes", func(t *testing.T) {
		e, l := pairLab()
		e.find("fw.a", web, "", "high")
		l.Assets[0].Status = "incomplete"
		l.Exit.Code = 2
		c := compareOK(t, e, l)
		if c.Exit.Code != 2 || c.Summary.Fixed != 0 {
			t.Errorf("%+v %+v", c.Exit, c.Summary)
		}
	})
	t.Run("an incomplete earlier run does not set 2", func(t *testing.T) {
		e, l := pairLab()
		e.Exit.Code = 2
		e.find("fw.a", web, "", "high")
		l.notMatched("fw.a", web)
		if c := compareOK(t, e, l); c.Exit.Code != 0 {
			t.Errorf("%+v", c.Exit)
		}
	})
}

func TestRefusals(t *testing.T) {
	in := func(l *lab, sha string) Input { return Input{Report: l.Report, SHA256: sha} }
	e, l := pairLab()
	t.Run("different engagements", func(t *testing.T) {
		o := newLab("0.0.3", t0.Add(time.Hour))
		o.Engagement.Name = "globex"
		expectRefusal(t, in(e, "a"), in(o, "b"), "different engagements")
	})
	t.Run("the same run", func(t *testing.T) {
		expectRefusal(t, in(e, "a"), in(e, "a"), "same run")
	})
	t.Run("swapped", func(t *testing.T) {
		expectRefusal(t, in(l, "b"), in(e, "a"), "earlier run first")
	})
	t.Run("equal start", func(t *testing.T) {
		o := newLab("0.0.3", t0)
		expectRefusal(t, in(e, "a"), in(o, "b"), "same run")
	})
}

func expectRefusal(t *testing.T, a, b Input, want string) {
	t.Helper()
	_, err := Compare(a, b)
	var r *Refusal
	if !errors.As(err, &r) || !strings.Contains(r.Why, want) {
		t.Fatalf("got %v, want a refusal naming %q", err, want)
	}
}

func TestEarlierOnlySubjectsAreWithheldWhenRedactionRulesDiffer(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.Redaction.Operator.Rules = 0
	l.Redaction.Operator.Rules = 1
	e.find("svc.a", web, "secret-name", "high")
	l.notMatched("svc.a", web)
	c := compareOK(t, e, l)
	i := c.Instances[0]
	if i.Earlier.Subject != nil || !i.Earlier.SubjectWithheld {
		t.Errorf("subject printed: %+v", i.Earlier)
	}
}

func TestSecretsFixedKeepsTheRevocationCaveat(t *testing.T) {
	const repo = "repo:github:example-org/shop"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(repo, "shop", "repo", "collected", "")
	}
	f := e.find("secrets.in_history", repo, "aws:k@abc", "high")
	f.Area = "secrets"
	l.notMatched("secrets.in_history", repo)
	i := category(compareOK(t, e, l), "secrets.in_history")
	if i.Category != Fixed || len(i.Notes) != 1 || i.Notes[0] != NoteRevocationUnchecked {
		t.Errorf("got %+v", i)
	}
}

func TestComparisonIsDeterministic(t *testing.T) {
	const web = "host:203.0.113.6:22"
	build := func() *Comparison {
		e, l := pairLab()
		for i := range 8 {
			id := "r." + string(rune('a'+i))
			e.find(id, web, "", "high")
			if i%2 == 0 {
				l.notMatched(id, web)
			} else {
				l.find(id, web, "", "medium")
			}
		}
		return compareOK(t, e, l)
	}
	a, b := build(), build()
	var x, y strings.Builder
	if err := WriteJSON(&x, a); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&y, b); err != nil {
		t.Fatal(err)
	}
	if x.String() != y.String() {
		t.Error("two comparisons of the same pair differ")
	}
}
