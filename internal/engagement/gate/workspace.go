package gate

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

const workspacePrefix = "saas:google-workspace:"

var customerIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// workspaceSession never supplies a principal until current user admission and
// delegated identity can be established in step 2. Step 1 never reuses evidence.
// docs/spec/workspace-collector.md, "Principal and resume".
type workspaceSession struct {
	credential             *Credential
	expires                time.Time
	scopesKnown            bool
	customer               string
	domains                map[string]bool
	aliases                map[string]bool // verified domain aliases
	domainRoot             bool
	bound                  bool
	units                  map[string]bool
	unitIDs                map[string]string
	assignmentObservations int
	inventory              map[string]workspaceUser
	fingerprints           map[string]string
	owners                 map[string]string
	usersComplete          bool
	inventoryBad           bool
	cursors                map[string]bool
	principal              string
	// optional holds each optional surface's own tokens, or the failure of
	// its exchange, for as long as the baseline authentication lasts.
	optional map[WorkspaceSurface]*workspaceOptional
	// exchanges counts each per-mailbox surface's exchanges for the whole
	// session: a rebinding does not reset it.
	exchanges map[WorkspaceSurface]int
	// actedAs are the admitted ids a mailbox token was issued for in this
	// session: the mailboxes scheck signed in as, whatever their reads did.
	actedAs map[string]bool
}

// workspaceToken is one optional token, or the failure of the exchange that
// asked for it.
type workspaceToken struct {
	credential *Credential
	expires    time.Time
	failure    *halt
}

// workspaceOptional is one surface's state under the current binding: its
// one tenant-wide token, or a per-mailbox surface's tokens by admitted user
// id, and a failure every later read of the surface repeats.
type workspaceOptional struct {
	token   *workspaceToken
	tokens  map[string]*workspaceToken
	failure *halt
	// attempts, succeeded and failedInARow drive the per-mailbox breaker.
	attempts, failedInARow int
	succeeded              bool
}

// unbind forgets the tenant binding and every optional token or remembered
// optional failure minted under it: none outlives the binding.
func (s *workspaceSession) unbind() { s.bound, s.optional = false, nil }

// dropAuth forgets authentication and binding together.
func (s *workspaceSession) dropAuth() {
	s.unbind()
	s.credential = nil
}

// surfaceRead is one pinned read of an optional surface: its exact URL
// template, the fields it may keep and its exact list shape (nil for one
// object).
type surfaceRead struct {
	url  string
	keep []string
	list *List
	// emptyNoContent says HTTP 204 with no body is the empty list. Only the
	// Gmail filters read sets it (docs/spec/workspace-collector.md, "Reads
	// and projections").
	emptyNoContent bool
}

// workspaceSurface is an optional surface: its one scope, its own audited
// exchange, the profiles that select it and its pinned reads. A mailbox
// surface asks for one token per admitted mailbox, acting as that account
// (docs/spec/workspace-collector.md, "Credential files and profiles").
type workspaceSurface struct {
	scope, exchange string
	profiles        []string
	mailbox         bool
	// badRequest is the decision for a read Google answers 400, ""
	// when 400 means nothing particular for the surface.
	badRequest string
	// projectFirst discards everything outside Keep before redaction, so
	// filter criteria never reach redaction, audit or persistence.
	projectFirst bool
	reads        []surfaceRead
}

// Mailbox surface limits (docs/spec/workspace-collector.md, "Credential files and profiles").
const (
	mailboxExchangeCap = 1000 // per session
	breakerFirst       = 5    // every one of a binding's first exchanges failing
	breakerInARow      = 20   // consecutive per-mailbox failures
)

var workspaceSurfaces = map[WorkspaceSurface]workspaceSurface{
	WorkspaceOAuthGrants: {scope: googleScopePrefix + "admin.directory.user.security", exchange: "workspace.credential_exchange_oauth_grants", profiles: []string{"directory_oauth", "directory_oauth_mail"},
		reads: []surfaceRead{{url: "https://admin.googleapis.com/admin/directory/v1/users/{user}/tokens", keep: []string{"clientId", "scopes", "userKey", "displayText", "anonymous", "nativeApp"},
			list: &List{Items: "items", Kind: KindOther, Envelope: "admin#directory#tokenList", MaxItems: 1000, SelfRef: "userKey"}}}},
	WorkspaceGmailForwarding: {scope: googleScopePrefix + "gmail.readonly", exchange: "workspace.credential_exchange_gmail_forwarding", profiles: []string{"directory_mail", "directory_oauth_mail"}, mailbox: true, projectFirst: true,
		// Google answers 400 for a mailbox it does not serve (no Gmail service).
		badRequest: "unavailable:mailbox_unavailable",
		reads: []surfaceRead{
			{url: "https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding", keep: []string{"enabled", "emailAddress", "disposition"}},
			{url: "https://gmail.googleapis.com/gmail/v1/users/me/settings/filters", keep: []string{"id", "action.forward", "action.addLabelIds", "action.removeLabelIds"},
				list: &List{Items: "filter", Kind: KindOther, MaxItems: 1000}, emptyNoContent: true},
		}},
}

func workspaceSurfaceScope(s WorkspaceSurface) string { return workspaceSurfaces[s].scope }

// workspaceExchangeID is the audited op of a surface's token exchange, ""
// for a surface that is not compiled.
func workspaceExchangeID(s WorkspaceSurface) string {
	if s == WorkspaceBaseline {
		return workspaceTokenID
	}
	return workspaceSurfaces[s].exchange
}

func workspaceTokenOps() []Op {
	surfaces := append([]WorkspaceSurface{WorkspaceBaseline}, slices.Sorted(maps.Keys(workspaceSurfaces))...)
	out := []Op{}
	for _, s := range surfaces {
		out = append(out, Op{ID: workspaceExchangeID(s), Provider: "google", Method: POST, Class: CredentialExchange, URL: workspaceTokenURL, Level: Observe, Accept: []string{"application/json"}, MaxBytes: googleTokenLimit})
	}
	return out
}

// workspaceSelected lists the optional surfaces a profile selects, for the
// binding summary: profile names stay in the gate.
func workspaceSelected(profile string) []WorkspaceSurface {
	out := []WorkspaceSurface{}
	for _, s := range slices.Sorted(maps.Keys(workspaceSurfaces)) {
		if slices.Contains(workspaceSurfaces[s].profiles, profile) {
			out = append(out, s)
		}
	}
	return out
}

// workspaceOffers names, for each surface a profile does not select, the
// profile that selects it as well: a collector's advice never guesses which
// profile combines which surfaces.
func workspaceOffers(profile string) map[WorkspaceSurface]string {
	profiles := []string{"directory"}
	for _, s := range slices.Sorted(maps.Keys(workspaceSurfaces)) {
		for _, p := range workspaceSurfaces[s].profiles {
			if !slices.Contains(profiles, p) {
				profiles = append(profiles, p)
			}
		}
	}
	current := workspaceSelected(profile)
	out := map[WorkspaceSurface]string{}
	for _, s := range slices.Sorted(maps.Keys(workspaceSurfaces)) {
		if slices.Contains(current, s) {
			continue
		}
		want := append(slices.Clone(current), s)
		slices.Sort(want)
		for _, p := range profiles {
			if slices.Equal(workspaceSelected(p), want) {
				out[s] = p
			}
		}
	}
	return out
}

// pinnedRead is the surface whose table pins a read to host+path, and that
// read; ok is false for a path no surface pins.
func pinnedRead(hostPath string) (WorkspaceSurface, surfaceRead, bool) {
	for _, s := range slices.Sorted(maps.Keys(workspaceSurfaces)) {
		for _, r := range workspaceSurfaces[s].reads {
			if u, err := url.Parse(r.url); err == nil && u.Host+u.Path == hostPath {
				return s, r, true
			}
		}
	}
	return "", surfaceRead{}, false
}

// checkSurfaceRead holds an optional surface's read to its table row: one
// admitted user's exact read, keeping only the row's fields, in the row's
// exact list shape (docs/spec/workspace-collector.md, "Reads and projections").
func (c *compiled) checkSurfaceRead() error {
	def, ok := workspaceSurfaces[c.Surface]
	if !ok {
		return errors.New("an optional credential surface needs a compiled Workspace read")
	}
	i := slices.IndexFunc(def.reads, func(r surfaceRead) bool { return r.url == c.URL })
	if i < 0 {
		return errors.New("an optional surface reads only its pinned paths")
	}
	r := def.reads[i]
	if len(c.Params) != 2 || c.types["domain"].Type != DNSName || c.types["domain"].Optional || c.types["user"].Type != UserKey || c.types["user"].Optional ||
		c.Subject != workspacePrefix+"{domain}/users/{user}" || c.UserIdentity != nil || c.PreserveMalformed {
		return errors.New("an optional surface read names one admitted user and nothing else")
	}
	for _, field := range c.Keep {
		if !slices.Contains(r.keep, field) {
			return errors.New("an optional surface read keeps only its pinned fields")
		}
	}
	if (c.List == nil) != (r.list == nil) || c.List != nil && !reflect.DeepEqual(*c.List, *r.list) {
		return errors.New("an optional surface read has its pinned list shape")
	}
	c.projectFirst = def.projectFirst
	c.emptyNoContent = r.emptyNoContent
	return nil
}

func (c *compiled) workspaceResource(name string) bool {
	return c.Auth == WorkspaceADC && name == "customer" && c.types[name].Type == CustomerID
}

// Bootstrap paths are a deliberately narrow exception, enforced at registration
// as well as admission. A collector cannot turn customer binding into a new read.
func (c *compiled) checkWorkspaceOp() error {
	exchange := slices.ContainsFunc(workspaceTokenOps(), func(o Op) bool { return o.ID == c.ID })
	if strings.HasPrefix(c.ID, "workspace.") && !exchange && c.Auth != WorkspaceADC {
		return errors.New("Workspace reads require the private Workspace credential pipeline")
	}
	if c.Surface != WorkspaceBaseline && (c.Auth != WorkspaceADC || workspaceSurfaceScope(c.Surface) == "") {
		return errors.New("an optional credential surface needs a compiled Workspace read")
	}
	// Nothing reaches the Gmail host but a pinned Workspace read, and a
	// pinned read belongs to its surface alone.
	pinnedSurface, _, pinned := WorkspaceBaseline, surfaceRead{}, false
	if u, err := url.Parse(c.URL); err == nil {
		pinnedSurface, _, pinned = pinnedRead(u.Host + u.Path)
		if u.Host == "gmail.googleapis.com" && (!pinned || c.Auth != WorkspaceADC) {
			return errors.New("only a pinned Workspace read reaches the Gmail host")
		}
	}
	for _, p := range c.Params {
		if p.Type == CustomerID && !c.workspaceResource(p.Name) {
			return errors.New("customer parameters require a compiled Workspace read")
		}
	}
	if c.Auth != WorkspaceADC {
		if c.UserIdentity != nil || c.List != nil && (c.List.Tree != nil || c.List.Assignment != nil) {
			return errors.New("structural tenant identity constraints require Workspace admission")
		}
		return nil
	}
	if pinned && pinnedSurface != c.Surface {
		return errors.New("Workspace optional reads use their own compiled surface and path")
	}
	if c.Provider != "google" || c.Method != GET || c.Class != Read || (c.Subject != workspacePrefix+"{domain}" && c.Subject != workspacePrefix+"{domain}/users/{user}") || c.types["domain"].Type != DNSName || c.WorkflowYAML || c.GitHubMetadata || len(c.Accept) != 1 || c.Accept[0] != "application/json" || c.MaxBytes != 1<<20 {
		return errors.New("invalid compiled Workspace foundation read")
	}
	if c.Surface != WorkspaceBaseline {
		return c.checkSurfaceRead()
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host != "admin.googleapis.com" || u.User != nil || u.Fragment != "" || strings.Contains(c.URL, "%") || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") {
		return errors.New("Workspace reads require a compiled Directory endpoint")
	}
	for _, values := range u.Query() {
		if len(values) != 1 {
			return errors.New("duplicate Workspace query selector")
		}
	}
	bootstrapPath := workspaceBootstrapPath(c.ID)
	if strings.HasPrefix(c.ID, "workspace.bootstrap_") && bootstrapPath == "" {
		return errors.New("unknown Workspace bootstrap operation")
	}
	if bootstrapPath != "" && c.URL != "https://admin.googleapis.com"+bootstrapPath {
		return errors.New("Workspace bootstrap requires its exact compiled path")
	}
	if bootstrapPath != "" {
		count := 2
		if c.ID == "workspace.bootstrap_customer" {
			count = 1
		}
		if len(c.Params) != count || c.List != nil || u.RawQuery != "" || c.Subject != workspacePrefix+"{domain}" {
			return errors.New("invalid Workspace bootstrap shape")
		}
	}
	perUser := c.types["user"].Type == UserKey
	assignment := c.List != nil && c.List.Assignment != nil
	if perUser && c.types["user"].Optional {
		return errors.New("Workspace user selector is required")
	}
	if c.List != nil && c.List.SelfRef != "" {
		return errors.New("only an optional surface read lists items naming its user")
	}
	if perUser && !assignment {
		if c.Subject != workspacePrefix+"{domain}/users/{user}" || c.UserIdentity == nil || c.List != nil || u.Path != "/admin/directory/v1/users/{user}" {
			return errors.New("Workspace user read requires admitted stable identity")
		}
		if u.Query().Get("projection") != "full" || u.Query().Get("viewType") != "admin_view" || len(u.Query()) != 2 {
			return errors.New("Workspace user detail uses full admin projection")
		}
	} else if c.ID != "workspace.bootstrap_customer" {
		if c.types["customer"].Type != CustomerID || c.types["customer"].Optional {
			return errors.New("Workspace customer selector must be a required gate-filled id")
		}
		inPath := strings.HasPrefix(u.Path, "/admin/directory/v1/customer/{customer}/") || u.Path == "/admin/directory/v1/customers/{customer}" || strings.HasPrefix(u.Path, "/admin/directory/v1/customers/{customer}/")
		usersQuery := u.Path == "/admin/directory/v1/users" && u.Query().Get("customer") == "{customer}" && c.List != nil && c.List.Kind == KindUser && c.UserIdentity != nil
		if !inPath && !usersQuery {
			return errors.New("Workspace read must select the bound customer")
		}
		if inPath && u.Query().Has("customer") {
			return errors.New("duplicate Workspace tenant selector")
		}
		if usersQuery && (u.Query().Get("projection") != "full" || u.Query().Get("viewType") != "admin_view" || u.Query().Get("maxResults") != "100") {
			return errors.New("Workspace users require full customer inventory")
		}
		if assignment {
			if u.Path != "/admin/directory/v1/customer/{customer}/roleassignments" || u.Query().Get("maxResults") != "100" || c.UserIdentity != nil {
				return errors.New("invalid Workspace assignment selector")
			}
			if !perUser || u.Query().Get("userKey") != "{user}" || u.Query().Get("includeIndirectRoleAssignments") != "true" || c.Subject != workspacePrefix+"{domain}/users/{user}" || c.List.MaxPages != 10 {
				return errors.New("invalid Workspace assignment beneficiary")
			}
			f := c.List.Assignment
			for _, field := range []string{f.Assignee, f.Type, f.Scope, f.Unit} {
				if !fieldPath.MatchString(field) || !slices.Contains(c.Keep, field) {
					return errors.New("invalid assignment reference projection")
				}
			}
		}
		for key := range u.Query() {
			if key != "customer" && key != "projection" && key != "viewType" && key != "maxResults" && key != "pageToken" && (!assignment || (key != "userKey" && key != "includeIndirectRoleAssignments")) && (c.List == nil || c.List.Tree == nil || (key != "type" && key != "orgUnitPath")) {
				return errors.New("unsupported Workspace selector")
			}
		}
	}
	if c.List != nil {
		if c.List.Envelope == "" || c.List.MaxItems != 1000 {
			return errors.New("Workspace inventory requires recognized bounded envelope")
		}
		if c.List.Kind == KindOrgUnit && (c.List.Tree == nil || u.Query().Get("type") != "all_including_parent" || u.Query().Get("orgUnitPath") != "/" || c.List.Next != nil) {
			return errors.New("Workspace units require complete root tree")
		}
		if c.List.Kind == KindUser && (c.UserIdentity == nil || c.List.Next == nil || c.List.MaxPages != 10 || len(c.List.UserKeys) == 0) {
			return errors.New("Workspace users require bounded exclusion-aware inventory")
		}
	}
	if c.UserIdentity != nil {
		f := c.UserIdentity
		for _, key := range append([]string{f.ID, f.Primary, f.Customer, f.Unit}, f.Aliases...) {
			if !fieldPath.MatchString(key) || !slices.Contains(c.Keep, key) {
				return errors.New("invalid or unretained user identity field")
			}
		}
	}
	if c.List != nil && c.UserIdentity != nil {
		f := c.UserIdentity
		if c.List.ExcludeKey != f.Unit {
			return errors.New("user exclusion field must equal the admitted unit field")
		}
		for _, field := range append([]string{f.ID, f.Primary}, f.Aliases...) {
			if !slices.Contains(c.List.UserIDs, field) || !slices.Contains(c.List.UserKeys, field) {
				return errors.New("user admission keys must include every structural identity")
			}
		}
	}
	if c.List != nil && c.List.Tree != nil {
		f := c.List.Tree
		for _, key := range []string{f.ID, f.ParentID, f.ParentPath, f.Name} {
			if !fieldPath.MatchString(key) || !slices.Contains(c.Keep, key) {
				return errors.New("invalid or unretained unit tree field")
			}
		}
	}

	if c.types["domain"].Optional {
		return errors.New("Workspace domain is required")
	}

	return nil
}

// Only these three operations may read private, unbound Directory evidence.
func workspaceBootstrapPath(id string) string {
	switch id {
	case "workspace.bootstrap_customer":
		return "/admin/directory/v1/customers/my_customer"
	case "workspace.bootstrap_domains":
		return "/admin/directory/v1/customer/{customer}/domains"
	case "workspace.bootstrap_aliases":
		return "/admin/directory/v1/customer/{customer}/domainaliases"
	default:
		return ""
	}
}

func (g *Gate) attachWorkspace(ctx context.Context, p *pending) *halt {
	domain := p.b.params["domain"]
	if p.r.Asset != workspacePrefix+domain {
		return sticky(refused("out_of_scope", "the Workspace domain must equal the declared asset"))
	}
	if !g.workspaceLoaded {
		g.workspaceSource, g.workspaceSourceError = g.loadGoogleSource()
		g.workspaceLoaded = true
	}
	if g.workspaceSource == nil {
		return sticky(refused("no_credentials", g.workspaceSourceError))
	}
	source := g.workspaceSource
	profile := g.getenv("SCHECK_WORKSPACE_PROFILE")
	if profile == "" {
		profile = "directory"
	}
	currentSubject, _ := userKey(g.getenv("SCHECK_WORKSPACE_SUBJECT"))
	if profile != source.profile || currentSubject != source.subject && source.kind == "service_account" || source.kind == "authorized_user" && g.getenv("SCHECK_WORKSPACE_SUBJECT") != "" {
		if session := g.workspace[p.r.Asset]; session != nil {
			session.optional = nil
		}
		return &halt{decision: "unavailable:credential_changed", detail: "Workspace credential settings changed during this session. Restart or resume the run with the intended profile and account", sticky: true}
	}
	if g.workspace == nil {
		g.workspace = map[string]*workspaceSession{}
	}
	session := g.workspace[p.r.Asset]
	if session == nil {
		session = &workspaceSession{}
		g.workspace[p.r.Asset] = session
	}
	if p.op.ID == "workspace.bootstrap_customer" {
		g.clearWorkspacePages(p.r.Asset)
		session.assignmentObservations = 0
		session.unitIDs = nil
		session.customer, session.domains, session.aliases, session.bound, session.domainRoot = "", nil, nil, false, false
		session.units, session.inventory, session.fingerprints, session.owners = nil, nil, nil, nil
		session.usersComplete, session.inventoryBad, session.principal = false, false, ""
		session.unbind()
	}
	// Reject foreign selectors before even exchanging a credential.
	if p.op.ID != "workspace.bootstrap_customer" && (p.op.types["user"].Type != UserKey || p.op.types["customer"].Type == CustomerID) && (session.customer == "" || p.b.params["customer"] != session.customer) {
		return sticky(refused("tenant_binding", "the selector is not this session's bootstrap customer"))
	}
	switch p.op.ID {
	case "workspace.bootstrap_customer":
	case "workspace.bootstrap_domains":
		g.clearWorkspacePages(p.r.Asset)
		session.usersComplete, session.principal = false, ""
		session.unbind()
		session.domains, session.aliases = nil, nil
		session.domainRoot = false
	case "workspace.bootstrap_aliases":
		g.clearWorkspacePages(p.r.Asset)
		session.usersComplete, session.principal = false, ""
		session.unbind()
		if session.domains == nil {
			return refused("tenant_binding", "complete recognized domains are required before aliases")
		}
	default:
		if !session.bound {
			return sticky(refused("tenant_binding", "the declared domain has not been bound to this customer"))
		}
	}
	if session.credential == nil || !g.now().Before(session.expires) {
		session.dropAuth()
		// Expiry never preserves a tenant authorization established with an earlier token.
		if p.op.ID != "workspace.bootstrap_customer" {
			return &halt{decision: "unavailable:bootstrap_required", detail: "the Workspace access token expired. Restart or resume the run to authenticate and verify the Workspace customer again", sticky: true}
		}
		exchange, err := source.exchange(g.now(), WorkspaceBaseline)
		if err != nil {
			return &halt{decision: "unavailable:credential_exchange", detail: err.Error()}
		}
		result := g.Send(ctx, Request{Op: workspaceTokenID, Asset: p.r.Asset, Stage: p.r.Stage, exchange: exchange})
		if !result.OK() {
			return &halt{decision: result.Decision, detail: result.Detail, until: result.Until, reason: result.Reason}
		}
		if exchange.token == "" || !g.now().Before(exchange.expires) {
			return &halt{decision: "unavailable:credential_exchange", detail: "the credential response did not establish a usable token"}
		}
		session.credential = &Credential{Env: source.env, header: "Authorization", value: "Bearer " + exchange.token, secret: exchange.token, secrets: exchange.credential.secrets, Scopes: exchange.scopes}
		session.expires, session.scopesKnown = exchange.expires, exchange.scopesKnown
	}
	if p.op.List != nil && p.op.List.Tree != nil {
		g.clearWorkspacePages(p.r.Asset)
		session.units, session.unitIDs = nil, nil
		session.usersComplete = false
		session.principal = ""
	}
	if p.op.List != nil && p.op.List.Kind == KindUser && p.r.NextOf == "" {
		g.clearWorkspacePages(p.r.Asset)
		g.workspaceUsersStart(p.r.Asset)
	}
	if p.op.ID == "workspace.delegated_user" {
		session.principal = ""
	}
	if p.op.List != nil && p.op.List.Kind == KindUser && session.units == nil {
		return &halt{decision: "unavailable:exclusion_unknown", detail: "A complete organizational-unit inventory is required before users can be read"}
	}
	if p.op.types["user"].Type == UserKey {
		if !session.usersComplete {
			return &halt{decision: "unavailable:exclusion_unknown", detail: "A complete current user inventory is required before account details can be read", sticky: true}
		}
		if user, ok := session.inventory[p.b.params["user"]]; !ok || user.id != p.b.params["user"] {
			return refused("tenant_binding", "the account was not admitted from current Workspace inventory")
		}
	}
	if p.op.List != nil && p.op.List.Assignment != nil {
		if !session.usersComplete || session.unitIDs == nil {
			return &halt{decision: "unavailable:exclusion_unknown", detail: "Current admitted users and units are required before assignment reads", sticky: true}
		}
		if session.assignmentObservations >= 10000 {
			return &halt{decision: "unavailable:limit_reached", detail: "The tenant assignment observation budget was reached", sticky: true}
		}
	}
	if p.op.Surface != WorkspaceBaseline {
		cred, h := g.workspaceOptionalCredential(ctx, p, session, source)
		if h != nil {
			return h
		}
		p.cred = cred
		return nil
	}
	p.cred = session.credential
	return nil
}

// workspaceOptionalCredential is an optional surface's own token, asked for
// with exactly its one scope after baseline admission, never the baseline
// token. A mailbox surface has one token per admitted mailbox, acting as the
// gate's own record of that account. A failed exchange is remembered, for
// the surface or for that mailbox, so later reads send nothing and carry its
// classification: a refused scope is an optional permission gap
// (docs/spec/workspace-collector.md, "Credential files and profiles").
func (g *Gate) workspaceOptionalCredential(ctx context.Context, p *pending, session *workspaceSession, source *googleSource) (*Credential, *halt) {
	surface := workspaceSurfaces[p.op.Surface]
	if !slices.Contains(surface.profiles, source.profile) {
		return nil, &halt{decision: "unavailable:profile_not_selected", detail: "The selected Workspace profile does not include this optional read", sticky: true}
	}
	if session.optional == nil {
		session.optional = map[WorkspaceSurface]*workspaceOptional{}
	}
	opt := session.optional[p.op.Surface]
	if opt == nil {
		opt = &workspaceOptional{tokens: map[string]*workspaceToken{}}
		session.optional[p.op.Surface] = opt
	}
	// Profile, then the approval, then the existing mailbox admission.
	// Checked on every read, including one that would reuse a cached token
	// (docs/spec/workspace-collector.md, "Mailbox authorization").
	if surface.mailbox {
		ap, h := g.mailboxDecision(p.r.Asset)
		if h != nil {
			opt.failure = h
			return nil, h
		}
		if opt.failure != nil && opt.failure.decision == "refused:mailbox_authorization" {
			opt.failure = nil
		}
		p.approved = ap
	}
	if surface.mailbox && source.kind != "service_account" {
		return nil, &halt{decision: "unavailable:needs_service_account", detail: "Mail settings are read only through a service account with domain-wide delegation", sticky: true}
	}
	if source.kind == "service_account" && session.principal == "" {
		return nil, &halt{decision: "unavailable:principal_unknown", detail: "The delegated account must be verified before an optional permission is requested", sticky: true}
	}
	if opt.failure != nil {
		h := *opt.failure
		return nil, &h
	}
	actAs, user := "", ""
	slot := &opt.token
	if surface.mailbox {
		user = p.b.params["user"]
		var h *halt
		if actAs, h = session.mailboxSubject(user); h != nil {
			return nil, h
		}
		t := opt.tokens[user]
		slot = &t
		defer func() { opt.tokens[user] = *slot }()
	}
	if t := *slot; t != nil && t.failure != nil {
		h := *t.failure
		return nil, &h
	}
	if t := *slot; t != nil && t.credential != nil && g.now().Before(t.expires) {
		return t.credential, nil
	}
	if surface.mailbox {
		if session.exchanges == nil {
			session.exchanges = map[WorkspaceSurface]int{}
		}
		if session.exchanges[p.op.Surface] >= mailboxExchangeCap {
			opt.failure = &halt{decision: "unavailable:limit_reached", reason: "limit_reached", detail: "The session's mailbox sign-in budget was reached", sticky: true}
			h := *opt.failure
			return nil, &h
		}
		session.exchanges[p.op.Surface]++
	}
	var exchange *googleExchange
	var err error
	if surface.mailbox {
		exchange, err = source.mailboxExchange(g.now(), p.op.Surface, actAs, user)
	} else {
		exchange, err = source.exchange(g.now(), p.op.Surface)
	}
	if err != nil {
		return nil, &halt{decision: "unavailable:credential_exchange", detail: err.Error(), sticky: true}
	}
	t := &workspaceToken{}
	*slot = t
	result := g.Send(ctx, Request{Op: surface.exchange, Asset: p.r.Asset, Stage: p.r.Stage, exchange: exchange})
	switch {
	case !result.OK():
		t.failure = &halt{decision: result.Decision, detail: result.Detail, until: result.Until, reason: result.Reason, sticky: true}
	case exchange.token == "" || !g.now().Before(exchange.expires):
		t.failure = &halt{decision: "unavailable:credential_exchange", detail: "the credential response did not establish a usable token", sticky: true}
	}
	dialled := !strings.HasPrefix(result.Decision, "refused:")
	switch {
	case surface.mailbox && t.failure != nil && !dialled:
		// Refused before it left this machine (a deadline, a stopped
		// provider): the surface's, uncounted, with its reason.
		session.exchanges[p.op.Surface]--
		*slot = nil
		opt.failure = t.failure
	case surface.mailbox:
		// Google was asked to act as this mailbox, answered or not.
		if session.actedAs == nil {
			session.actedAs = map[string]bool{}
		}
		session.actedAs[user] = true
		scope := exchange.failure
		if t.failure != nil && !exchange.answered {
			scope = failTransient
		}
		opt.attempts++
		mailboxOutcome(opt, t, scope)
	case t.failure != nil:
		opt.failure = t.failure
	}
	if opt.failure != nil {
		h := *opt.failure
		return nil, &h
	}
	if t.failure != nil {
		h := *t.failure
		return nil, &h
	}
	// The optional token never outlives the authentication it extends.
	t.expires = exchange.expires
	if session.expires.Before(t.expires) {
		t.expires = session.expires
	}
	t.credential = &Credential{Env: source.env, header: "Authorization", value: "Bearer " + exchange.token, secret: exchange.token, secrets: exchange.credential.secrets, Scopes: exchange.scopes}
	return t.credential, nil
}

// mailboxOutcome decides whether a per-mailbox exchange failure belongs to
// that mailbox or to the surface. A refused scope or a rate limit is the
// surface's; so is a breaker trip, when a binding's first exchanges all
// fail or many fail in a row, since a revoked key or a broken clock looks
// like one mailbox failing after another
// (docs/spec/workspace-collector.md, "Credential files and profiles").
func mailboxOutcome(opt *workspaceOptional, t *workspaceToken, scope failureScope) {
	if t.failure == nil {
		opt.succeeded, opt.failedInARow = true, 0
		return
	}
	if scope == failSurface {
		opt.failure = t.failure
		return
	}
	// A failure of this mailbox's own sign-in repeats for it alone.
	t.failure.sticky = false
	if scope != failTransient && !strings.HasPrefix(t.failure.reason, "insufficient_permission") {
		t.failure.decision, t.failure.reason = "unavailable:mailbox_credential", ""
		t.failure.detail = "Google did not issue a token for this mailbox"
	}
	opt.failedInARow++
	if !opt.succeeded && opt.attempts >= breakerFirst || opt.failedInARow >= breakerInARow {
		opt.failure = &halt{decision: "unavailable:credential_exchange", detail: "Google did not sign scheck in as one mailbox after another, so scheck stopped asking", sticky: true}
	}
}

// mailboxSubject is the address a per-mailbox token acts as: the gate's own
// record of an admitted current account, whose primary address is in a
// verified domain of the bound tenant, never an address a collector or a
// response supplied.
func (s *workspaceSession) mailboxSubject(id string) (string, *halt) {
	user, ok := s.inventory[id]
	if !s.usersComplete || !ok || user.id != id {
		return "", refused("tenant_binding", "the account was not admitted from current Workspace inventory")
	}
	_, domain, _ := strings.Cut(user.primary, "@")
	if !s.domains[domain] && !s.aliases[domain] {
		return "", refused("tenant_binding", "the account's address is not in a verified domain of this Workspace")
	}
	if !user.mailbox {
		return "", &halt{decision: "unavailable:mailbox_inactive", detail: "The account list did not report this account active with a mailbox"}
	}
	return user.primary, nil
}

// workspaceResponse is a private response pipeline, sharing Send, TLS, address
// checks, budgets and audit with every other op. No raw body, header or hash is
// retained for credential exchanges or an unbound tenant.
// docs/spec/workspace-collector.md, "Boundary", "Tenant binding and scope".
func (s *sending) workspaceResponse(resp *http.Response) (Result, *retry) {
	op := s.a.b.op
	limit := int(op.MaxBytes)
	raw, wire, code, err := readBody(resp, limit)
	s.e.BytesIn, s.e.Status = wire, resp.StatusCode
	if err != nil {
		s.res.end("unavailable:response_read_failed", "the private Google response could not be read")
		return s.finish(nil, nil)
	}
	if len(raw) > limit {
		code = codeTooLarge
	}
	if code == "" && !accepts(op.Accept, resp.Header.Get("Content-Type")) {
		code = codeContentType
	}
	if s.r.exchange != nil {
		s.r.exchange.answered = true
		if resp.StatusCode != http.StatusOK || code != "" || !readGoogleToken(raw, s.r.exchange, s.start) {
			s.res.end("unavailable:credential_exchange", "Google authentication did not return a usable access token. Check the selected credential setup, then retry")
			if resp.StatusCode != http.StatusOK && code == "" {
				s.res.Detail = googleExchangeFailure(raw)
				// The baseline credential was accepted: a refused optional
				// scope is a coverage gap, never a refusal of the asset.
				if scope := workspaceSurfaceScope(s.r.exchange.surface); scope != "" && googleScopeDenied(raw) {
					s.res.Reason = "insufficient_permission:" + strings.TrimPrefix(scope, googleScopePrefix)
					s.res.Detail = "Google did not authorize this credential for the optional read permission"
					s.r.exchange.failure = failSurface
				}
				// An administrator's policy can refuse one mailbox; it is that
				// mailbox's gap, not the surface's.
				if scope := workspaceSurfaceScope(s.r.exchange.surface); workspaceSurfaces[s.r.exchange.surface].mailbox && googleErrorCode(raw) == "admin_policy_enforced" {
					s.res.Reason = "insufficient_permission:" + strings.TrimPrefix(scope, googleScopePrefix)
					s.res.Detail = "Google's administrator policy did not let this credential act for this mailbox"
				}
			}
			if resp.StatusCode >= 500 && workspaceSurfaces[s.r.exchange.surface].mailbox {
				// Google failing is not Google refusing one mailbox.
				s.res.end("unavailable:server_error", "Google's token endpoint answered with a server error")
				s.r.exchange.failure = failTransient
			}
			if resp.StatusCode == 429 {
				s.res.end("unavailable:credential_rate_limit", "Google credential exchange was rate limited")
				s.res.Reason = "limit_reached"
				s.r.exchange.failure = failSurface
			}
		}
		return s.finish(nil, nil)
	}
	session := s.g.workspace[s.r.Asset]
	bootstrap := workspaceBootstrapPath(op.ID) != ""
	out := &Response{Status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		s.res.end("unavailable:workspace_read", "Google Workspace read did not succeed")
		switch resp.StatusCode {
		case 401:
			session.dropAuth()
			s.res.Reason, s.res.Kind, s.res.Detail = "refused", "access", "Google did not accept the Workspace credential"
		case 403, 404:
			s.res.Reason = "insufficient_permission"
		case 429:
			s.res.Reason = "limit_reached"
		}
		if bootstrap {
			session.unbind()
		}
		retryAfter, hasRetryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), s.g.now())
		if resp.StatusCode == 429 || resp.StatusCode == 403 && (hasRetryAfter || code == "" && googleRateLimited(raw)) {
			s.res.Reason = "limit_reached"
			return s.finish(out, &retry{provider: "google", after: retryAfter, rateLimit: true})
		}
		if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			s.res.end("unavailable:server_error", "Google Workspace read encountered a temporary server error")
			return s.finish(out, &retry{provider: "google", after: retryAfter, code: "server_error", detail: "Google Workspace read encountered a temporary server error"})
		}
		return s.finish(out, nil)
	}
	if code != "" {
		session.unbind()
		s.res.end("unavailable:"+code, "the Workspace response was not usable within its declared limits")
		if code == codeTooLarge || code == codeBomb {
			s.res.Reason = "limit_reached"
		}
		return s.finish(out, nil)
	}
	// Discard everything outside the binding projection before generic redaction.
	projected, err := workspaceProjection(raw, op.ID)
	if err != nil {
		session.unbind()
		s.res.end("unavailable:tenant_binding", "Google did not return recognized binding evidence")
		if errors.Is(err, errWorkspacePopulationLimit) {
			s.res.Reason = "limit_reached"
		}
		return s.finish(out, nil)
	}
	clean, hits, err := s.red.RedactJSON(projected)
	if err != nil || len(hits) > 0 {
		session.unbind()
		s.res.end("unavailable:tenant_binding", "Workspace binding evidence was redacted or malformed")
		return s.finish(out, nil)
	}
	if !session.consume(op.ID, clean, s.a.b.params["domain"]) {
		session.unbind()
		s.res.end("unavailable:tenant_binding", "scheck could not verify that the declared Workspace domain belongs to the customer selected by these credentials. Check the domain and credential setup")
		return s.finish(out, nil)
	}
	if session.bound {
		summary := map[string]any{"id": session.customer, "domain": s.a.b.params["domain"], "profile": s.g.workspaceSource.profile, "surfaces": workspaceSelected(s.g.workspaceSource.profile), "offers": workspaceOffers(s.g.workspaceSource.profile), "scopes": session.credential.Scopes, "scopes_known": session.scopesKnown}
		// A successful client-authenticated refresh proves the client id,
		// never whose sign-in the refresh token holds
		// (docs/spec/workspace-collector.md, "OAuth scope interpretation").
		if s.g.workspaceSource.kind == "authorized_user" {
			summary["assessment_client"] = s.g.workspaceSource.clientID
		}
		out.Body = marshal(summary)
		out.Body, out.Redactions, _ = s.red.RedactJSON(out.Body)
	}
	return s.finish(out, nil)
}

var errWorkspacePopulationLimit = errors.New("Workspace binding population limit")

func workspaceProjection(raw []byte, id string) ([]byte, error) {
	obj, err := strictGoogleObject(raw)
	if err != nil {
		return nil, err
	}
	if id == "workspace.bootstrap_customer" {
		return marshal(map[string]json.RawMessage{"id": obj["id"]}), nil
	}
	key, fields := "domains", []string{"domainName", "verified"}
	if id == "workspace.bootstrap_aliases" {
		key, fields = "domainAliases", []string{"domainAliasName", "parentDomainName", "verified"}
	}
	rows := []json.RawMessage{}
	if value, present := obj[key]; present {
		if string(value) == "null" || json.Unmarshal(value, &rows) != nil {
			return nil, errors.New("invalid binding array")
		}
	}
	if len(rows) > 1000 {
		return nil, errWorkspacePopulationLimit
	}
	projected := make([]map[string]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		item, err := strictGoogleObject(row)
		if err != nil {
			return nil, err
		}
		kept := map[string]json.RawMessage{}
		for _, field := range fields {
			if v, present := item[field]; present {
				kept[field] = v
			}
		}
		projected = append(projected, kept)
	}
	return marshal(map[string]any{key: projected}), nil
}

func (s *workspaceSession) consume(id string, raw []byte, root string) bool {
	obj, err := strictGoogleObject(raw)
	if err != nil {
		return false
	}
	switch id {
	case "workspace.bootstrap_customer":
		var customer string
		if json.Unmarshal(obj["id"], &customer) != nil || !customerIDRE.MatchString(customer) || customer == "my_customer" {
			return false
		}
		s.customer = customer
	case "workspace.bootstrap_domains":
		var rows []struct {
			Name     string `json:"domainName"`
			Verified *bool  `json:"verified"`
		}
		if value, present := obj["domains"]; present && (json.Unmarshal(value, &rows) != nil || string(value) == "null") {
			return false
		}
		if len(rows) > 1000 {
			return false
		}
		domains := map[string]bool{}
		for _, row := range rows {
			name, err := dnsName(row.Name)
			if err != nil || row.Verified == nil {
				return false
			}
			if prior, present := domains[name]; present && prior != *row.Verified {
				return false
			}
			domains[name] = *row.Verified
		}
		s.domains, s.domainRoot = domains, domains[root]
	case "workspace.bootstrap_aliases":
		var rows []struct {
			Name     string `json:"domainAliasName"`
			Parent   string `json:"parentDomainName"`
			Verified *bool  `json:"verified"`
		}
		if value, present := obj["domainAliases"]; present && (json.Unmarshal(value, &rows) != nil || string(value) == "null") {
			return false
		}
		if len(rows) > 1000 {
			return false
		}
		seen := map[string]struct {
			parent   string
			verified bool
		}{}
		matched := s.domainRoot
		for _, row := range rows {
			name, err := dnsName(row.Name)
			if err != nil || row.Verified == nil {
				return false
			}
			parent, err := dnsName(row.Parent)
			if err != nil {
				return false
			}
			if verified, present := s.domains[parent]; !present || !verified {
				return false
			}
			entry := struct {
				parent   string
				verified bool
			}{parent, *row.Verified}
			if prior, present := seen[name]; present && prior != entry {
				return false
			}
			seen[name] = entry
			if domainVerified, present := s.domains[name]; present && domainVerified != *row.Verified {
				return false
			}
			if name == root && *row.Verified {
				matched = true
			}
		}
		s.aliases = map[string]bool{}
		for name, entry := range seen {
			s.aliases[name] = entry.verified
		}
		s.bound = matched
		return matched
	}
	return true
}

// Refreshes revoke pending continuations before contact, including failed reads.
func (g *Gate) clearWorkspacePages(asset string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, page := range g.pages {
		if page.asset == asset {
			delete(g.pages, id)
		}
	}
}
