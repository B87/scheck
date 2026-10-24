package web

import (
	"reflect"
	"testing"
)

func TestInputFromKeepsDeclarationsSeparateFromEvidence(t *testing.T) {
	evidence := Evidence{Mail: []MailEvidence{{Domain: "example.com"}, {Domain: "unused.example.com"}}, Sites: []Site{{Name: "www.example.com"}}}
	other := Evidence{Mail: []MailEvidence{{Domain: "parent.test"}}, Sites: []Site{
		{Name: "www.example.com", Declared: true, Pages: []Page{{URL: "https://www.example.com/login", RequestID: "declared-login"}}},
		{Name: "outside.test", Pages: []Page{{RequestID: "outside"}}},
	}}
	in := InputFrom("domain:example.com", "example.com", evidence, ScopeView{
		Senders: []SenderDeclaration{{Domain: "EXAMPLE.COM.", Service: "workspace", Selectors: []string{"GOOGLE"}}, {Domain: "unread.test", Service: "other"}},
		NoMail:  []string{"UNUSED.EXAMPLE.COM.", "unread.test"}, OtherEvidence: []Evidence{other},
		Gaps: []Gap{{Reason: "unavailable:ct_source"}}, Doubt: "unavailable:resolver_unchecked",
	})
	want := []MailContext{{Domain: "example.com", Senders: []MailSender{{Service: "workspace", Selectors: []string{"google"}}}}, {Domain: "unused.example.com", NoMail: true}}
	if !reflect.DeepEqual(in.MailContext, want) {
		t.Fatalf("mail declarations: %#v", in.MailContext)
	}
	if len(in.MailPolicies) != 1 || in.MailPolicies[0].Domain != "parent.test" || !reflect.DeepEqual(in.Evidence.Mail, evidence.Mail) {
		t.Fatal("other-root policy replaced local mail evidence")
	}
	if len(in.Evidence.Sites) != 1 || in.Evidence.Sites[0].Name != "www.example.com" || !in.Evidence.Sites[0].Declared {
		t.Fatalf("introduced an unselected site: %#v", in.Evidence.Sites)
	}
	if len(in.Evidence.Sites[0].Pages) == 0 || in.Evidence.Sites[0].Pages[0].RequestID != "declared-login" {
		t.Fatal("lost declared URL evidence")
	}
	if evidence.Sites[0].Declared || len(evidence.Sites[0].Pages) != 0 {
		t.Fatal("mutated original persisted evidence")
	}
	if len(in.Gaps) != 1 || in.Doubt != "unavailable:resolver_unchecked" {
		t.Fatal("lost uncertainty")
	}
}
