package report

import "github.com/b87/scheck/internal/finding"

// FixedItem is one sub-item of an area's fixed list that no rule in this
// version judges: a stable id and the words the report prints.
type FixedItem struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// fixedNotJudged is, per area, the practitioner's sub-items this version
// does not judge, in the order the report prints them. The lists come from
// what a consultant checks, never from the rules that exist, so a reader can
// tell checked from checked thinly; an item leaves the list in the commit
// that builds its rule (docs/spec/report.md, "Coverage", "The lists are
// fixed, whatever rules are built").
var fixedNotJudged = map[finding.Area][]FixedItem{
	finding.AreaIdentity: {
		{"identity.sso", "sign-in through another identity provider (SSO), and that provider's 2-step verification"},
		{"identity.twostep_kind", "which kind of 2-step verification people use (security key, app or text message)"},
		{"identity.app_passwords", "app passwords and other sign-ins that skip 2-step verification"},
		{"identity.delegation", "service accounts allowed to act as any Workspace user (domain-wide delegation)"},
		{"identity.app_access_policy", "which third-party apps staff may connect to Workspace (app access control)"},
		{"identity.recovery", "administrators' recovery email and phone"},
		{"identity.github_apps", "GitHub Apps installed on the organization and what they can reach"},
		{"identity.github_tokens", "GitHub's rules for personal access tokens"},
		{"identity.ssh_keys", "GitHub members' SSH keys"},
		{"identity.leaver_unlisted_write", "write to production repositories by a departed person not listed among its collaborators (read per login from a later step)"},
		{"identity.leaver_additions", "deploy keys, GitHub App authorizations and self-hosted runners a departed person added"},
		{"identity.leaver_activity", "what a departed person did after leaving (audit log not read)"},
	},
	finding.AreaSecrets: {
		{"secrets.push_protection", "whether GitHub blocks secrets before they are pushed (push protection)"},
		{"secrets.ci_logs", "secrets printed in CI logs"},
		{"secrets.images", "secrets inside container images"},
		{"secrets.chat_docs", "secrets pasted in chat and shared documents"},
	},
	finding.AreaCloud: {
		{"cloud.public_storage", "storage buckets and disk snapshots anyone can read"},
		{"cloud.admin_people", "administrator roles (such as Owner or Editor) held by people"},
		{"cloud.admin_service_accounts", "administrator roles held by service accounts, including the default ones"},
		{"cloud.keys", "long-lived keys for service accounts and users, and their age"},
		{"cloud.databases", "databases with a public address or authorized networks open to anyone"},
		{"cloud.firewall", "network firewall rules open to the whole internet"},
		{"cloud.org_policies", "organization-wide guardrails (organization policies)"},
	},
	finding.AreaData: {
		{"data.db_signin", "who can sign in to each database (pg_hba.conf, database users and their passwords)"},
		{"data.db_firewall_rules", "databases on hosts that filter with firewalld or their own nftables rules (scheck does not read those rules yet)"},
		{"data.db_containers", "databases published by Docker or Podman, whose port rules bypass the host firewall"},
		{"data.other_stores", "data stores not in scheck's database list (Elasticsearch, MinIO, RabbitMQ and others)"},
		{"data.drive_sharing", "Google Drive sharing defaults, and files shared with anyone who has the link"},
		{"data.backups", "whether backups exist, where they are kept, and who can delete them"},
	},
	finding.AreaCICD: {
		{"cicd.push_production", "who can push to repositories that deploy to production, contractors included"},
		{"cicd.environments", "review rules on the production deployment environment"},
		{"cicd.fork_approval", "approval before workflows run on pull requests from forks"},
		{"cicd.self_hosted", "self-hosted runners that public repositories can use"},
		{"cicd.allowed_actions", "which third-party actions the organization allows"},
		{"cicd.oidc", "trust from workflows to cloud accounts (OIDC)"},
		{"cicd.webhooks", "webhooks and where they send data"},
	},
	finding.AreaExternal: {
		{"external.open_ports", "which ports and services answer from the internet (scheck reads; it does not scan)"},
		{"external.registrar", "the registrar account: who can sign in, its 2-step verification, auto-renew and when the domain expires"},
		{"external.dns_account", "the DNS hosting account and who can change records"},
	},
	finding.AreaWeb: {
		{"web.exposed_files", "exposed files, debug pages and admin panels (such as /.git, /.env or /admin)"},
		{"web.third_party_scripts", "third-party scripts the site loads"},
		{"web.cors", "which other sites may read the site's responses (CORS)"},
	},
	finding.AreaHosts: {
		{"hosts.firewall_linux", "the firewall on Linux hosts, apart from database ports and the services you declared"},
		{"hosts.listeners", "listening services you did not declare"},
		{"hosts.admins_sudo", "who can become root or administrator, and sudo rules that need no password"},
		{"hosts.ssh_keys", "SSH keys allowed to log in (authorized_keys)"},
		{"hosts.ssh_match", "SSH settings inside Match blocks, and whether PAM accepts an empty password"},
		{"hosts.disk_linux", "disk encryption on Linux hosts"},
		{"hosts.suid", "programs that run with root rights (SUID files)"},
		{"hosts.persistence", "programs started at boot or on a schedule"},
		{"hosts.credential_files", "credential files (.env files, ~/.aws, ~/.ssh, cloud CLI logins)"},
	},
	finding.AreaEmail: {
		{"email.forwarding_policy", "whether Workspace lets staff forward mail outside the company (the tenant setting)"},
		{"email.spoofing_protection", "Workspace protection against spoofed and lookalike senders"},
		{"email.mta_sts", "encryption of mail in transit (MTA-STS and TLS reporting)"},
	},
	finding.AreaLogging: {
		{"logging.workspace_alerts", "alerts on administrator changes and suspicious sign-ins in Workspace"},
		{"logging.github_audit", "GitHub audit log retention and streaming"},
		{"logging.cloud_audit", "cloud audit logs"},
		{"logging.host_logs_offhost", "whether host logs are kept anywhere off the host"},
	},
}

// withFixedList gives an area row its fixed list: an unbuilt item leaves
// the row at most partial and lifts nothing that was not checked
// (docs/spec/report.md, "Coverage").
func withFixedList(row Row, area finding.Area) Row {
	row.NotJudged = fixedNotJudged[area]
	if row.Mark == "assessed" && len(row.NotJudged) > 0 {
		row.Mark = "partial"
	}
	return row
}
