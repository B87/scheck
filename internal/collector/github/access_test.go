package github

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
)

const accessRepository = `{"id":4,"name":"example","full_name":"acme/example","owner":{"id":2,"login":"acme","type":"Organization"},"private":true,"visibility":"private"}`

func accessFake() *fakeSender {
	return &fakeSender{results: map[string][]gate.Result{
		OpRepository:        {result("repo", accessRepository, false)},
		OpCollaborators:     {result("collab", `[{"id":1,"login":"alice","type":"User","role_name":"admin","permissions":{"admin":true,"pull":true,"push":true,"maintain":false,"triage":false}}]`, true)},
		OpDeployKeys:        {result("keys", `[{"id":9,"read_only":false}]`, true)},
		OpMembersWithoutMFA: {result("mfa", `[{"id":1,"login":"alice","type":"User"}]`, true)},
		OpOwnersWithoutMFA:  {result("ownermfa", `[]`, true)},
	}}
}
func accessTarget() RepositoryTarget {
	return RepositoryTarget{Asset: "repo:github:acme/example", Owner: "acme", Name: "example"}
}
func TestAccessOpsAreFixedGetReads(t *testing.T) {
	r, err := gate.NewRegistry(Ops...)
	if err != nil {
		t.Fatal(err)
	}
	_ = r
	for _, op := range Ops {
		if op.Method != gate.GET || op.Auth != gate.GitHubToken || op.APIVersion != "2026-03-10" || op.MaxBytes != 1<<20 {
			t.Fatalf("op widened: %+v", op)
		}
		if op.List != nil && op.List.Next != nil && op.List.MaxPages != 100 {
			t.Fatal("uncapped list")
		}
		if op.ID == OpDeployKeys && strings.Join(op.Keep, ",") != "id,read_only" {
			t.Fatal("key material projection")
		}
	}
}
func TestAccessReadsPreserveEffectivePermissionsAndExplicitFalse(t *testing.T) {
	f := accessFake()
	e := CollectAccess(context.Background(), f, Organization{Asset: "saas:github:acme", Name: "acme", Stage: "recon"}, Evidence{OwnerAuthority: true}, []RepositoryTarget{accessTarget(), accessTarget()})
	if !e.MembersWithoutMFA.Complete || !e.MembersWithoutMFA.VisibilityComplete || len(e.MembersWithoutMFA.Items) != 1 || len(e.RepositoriesAccess) != 1 {
		t.Fatalf("bad evidence: %+v", e)
	}
	a := e.RepositoriesAccess[0]
	if a.Repository == nil || !a.Collaborators.Complete || !a.DeployKeys.Complete || len(a.Reads()) != 3 {
		t.Fatalf("access: %+v", a)
	}
	if a.Collaborators.VisibilityComplete || !slices.Contains(a.Collaborators.Gaps, "repository_collaborator_visibility_unknown") {
		t.Fatal("credential-limited collaborator list claimed full repository visibility")
	}
	c := a.Collaborators.Items[0]
	if c.Permissions == nil || c.Permissions.Admin == nil || !*c.Permissions.Admin || c.Permissions.Maintain == nil || *c.Permissions.Maintain {
		t.Fatal("explicit permissions lost")
	}
	if a.DeployKeys.Items[0].ReadOnly == nil || *a.DeployKeys.Items[0].ReadOnly {
		t.Fatal("false read_only lost")
	}
	if len(f.requests) != 5 {
		t.Fatalf("request count %d", len(f.requests))
	}
}
func TestAccessNeverRequestsMFAWithoutOwnerAuthority(t *testing.T) {
	f := accessFake()
	e := CollectAccess(context.Background(), f, Organization{Asset: "saas:github:acme", Name: "acme", Stage: "recon"}, Evidence{}, nil)
	if len(f.requests) != 0 || e.MembersWithoutMFA.Complete || e.OwnersWithoutMFA.Complete || len(e.MembersWithoutMFA.Reads) != 1 || e.MembersWithoutMFA.Reads[0].Gap != "owner_authority_unknown" {
		t.Fatal("MFA reads without authority")
	}
}
func TestRepositoryMismatchOrMissingObjectDoesNotReadChildren(t *testing.T) {
	for _, body := range []string{"null", `{}`, strings.Replace(accessRepository, "acme/example", "moved/example", 1), strings.Replace(accessRepository, `"name":"example"`, `"name":"other"`, 1)} {
		f := accessFake()
		f.results[OpRepository][0].Response.Body = []byte(body)
		a := CollectRepository(context.Background(), f, accessTarget(), "recon")
		if a.Repository != nil || a.RepositoryRead.Gap != "unrecognized_repository" || len(f.requests) != 1 {
			t.Fatalf("followed unmatched repository %q", body)
		}
	}
	for _, kind := range []string{"denied", "truncated"} {
		f := accessFake()
		if kind == "denied" {
			f.results[OpRepository][0].Response.Status = 403
		} else {
			f.results[OpRepository][0].Response.Truncated = true
		}
		a := CollectRepository(context.Background(), f, accessTarget(), "recon")
		if a.Repository != nil || len(f.requests) != 1 {
			t.Fatal("used unavailable object")
		}
	}
}
func TestAccessMissingOrNullFieldsRemainUnknown(t *testing.T) {
	for _, body := range []string{`[{"id":1,"login":"alice","type":"User"}]`, `[{"id":1,"login":"alice","type":"User","permissions":null,"role_name":null}]`, `[{"id":1,"login":"alice","type":"User","permissions":{"pull":true}}]`} {
		f := accessFake()
		f.results[OpCollaborators][0].Response.Body = []byte(body)
		f.results[OpDeployKeys][0].Response.Body = []byte(`[{"id":9,"read_only":null}]`)
		a := CollectRepository(context.Background(), f, accessTarget(), "recon")
		c := a.Collaborators.Items[0]
		if c.Permissions != nil && c.Permissions.Admin != nil {
			t.Fatal("missing admin became known")
		}
		if a.DeployKeys.Items[0].ReadOnly != nil {
			t.Fatal("null read_only became false")
		}
	}
}
func TestEveryAccessPopulationPreservesUnknownEvidence(t *testing.T) {
	for _, op := range []string{OpMembersWithoutMFA, OpOwnersWithoutMFA, OpCollaborators, OpDeployKeys} {
		for _, kind := range []string{"denied", "truncated", "null", "malformed", "unknown_item", "marked"} {
			t.Run(op+"/"+kind, func(t *testing.T) {
				f := accessFake()
				r := &f.results[op][0]
				switch kind {
				case "denied":
					r.Response.Status = 403
				case "truncated":
					r.Response.Truncated = true
				case "null":
					r.Response.Body = []byte("null")
				case "malformed":
					r.Response.Body = []byte("broken")
				case "unknown_item":
					r.Response.Body = []byte(`[{}]`)
				case "marked":
					if op == OpDeployKeys {
						r.Response.Body = []byte(`[{"id":9,"read_only":"[REDACTED:test:4 bytes]"}]`)
					} else {
						r.Response.Body = []byte(`[{"id":1,"login":"[REDACTED:test:4 bytes]","type":"User"}]`)
					}
				}
				e := CollectAccess(context.Background(), f, Organization{Asset: "saas:github:acme", Name: "acme", Stage: "recon"}, Evidence{OwnerAuthority: true}, []RepositoryTarget{accessTarget()})
				var complete bool
				switch op {
				case OpMembersWithoutMFA:
					complete = e.MembersWithoutMFA.Complete
				case OpOwnersWithoutMFA:
					complete = e.OwnersWithoutMFA.Complete
				case OpCollaborators:
					complete = e.RepositoriesAccess[0].Collaborators.Complete
				case OpDeployKeys:
					complete = e.RepositoriesAccess[0].DeployKeys.Complete
				}
				if complete {
					t.Fatal("unknown population marked complete")
				}
			})
		}
	}
}
func TestAccessPaginationUsesGateOwnedNextOf(t *testing.T) {
	f := accessFake()
	first := f.results[OpDeployKeys][0]
	first.Response.Population.More = true
	f.results[OpDeployKeys] = []gate.Result{first, result("keys2", `[{"id":10,"read_only":true}]`, true)}
	a := CollectRepository(context.Background(), f, accessTarget(), "recon")
	if !a.DeployKeys.Complete || len(a.DeployKeys.Items) != 2 || len(a.DeployKeys.Reads) != 2 {
		t.Fatal("pagination lost")
	}
	last := f.requests[len(f.requests)-1]
	if last.NextOf != "keys" || last.Params["page"] != "" {
		t.Fatal("caller chose page")
	}
}

func TestStandaloneRepositoryReadsOmitEmptyOrganizationMetadata(t *testing.T) {
	f := accessFake()
	access := CollectRepository(context.Background(), f, accessTarget(), "recon")
	e := Evidence{RepositoriesAccess: []RepositoryAccess{access}}
	reads := e.Reads()
	if len(reads) != 3 {
		t.Fatalf("empty org reads included: %+v", reads)
	}
	for _, read := range reads {
		if read.Op == "" {
			t.Fatal("empty read")
		}
	}
}
