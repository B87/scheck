# 0.0.2 lab, domain part: sealed labels

Sealed 2026-10-09, before the first code commit of E7 (`docs/ROADMAP.md`, E3, "sealed in
parts"), on branch `e7-domain-web` at `d747429`.

| | |
|---|---|
| Labels | `~/scheck-lab-labels.age` on the seeder's machine, outside every repository |
| sha256 | `7954d10433c7a9c7ecff0fb94da4e7cde0c20f75e12de5be3c1938219ebbd070` |
| Encryption | `age`, to the seeder's SSH key; read with `age -d -i ~/.ssh/id_rsa ~/scheck-lab-labels.age` |
| Seeder | the user (Bernat), applying DNS records and site files written by the implementing session (Claude Opus 5.5, `claude-opus-5-5`); no private extras |
| Lab roots | `schecklab.bbarroso.page` (seeded), `scheckclean.bbarroso.page` (clean variant), subdomains of a domain the team owns, separate from the Workspace tenant's |
| Sites | private repository `B87/scheck-lab`, served from the team's own server |

**Not blind.** The implementing session wrote every seeded item of this part, so its
recall is a check that E7 finds what it was built to find, not a blind measurement. The
acceptance record says so beside the recall result. The rest of the lab (GitHub
organization, Workspace tenant, SSH host) is still to be seeded blind.

**False-positive target** for this part, fixed at sealing: no finding at low or above on
the clean variant, and none at low or above on the seeded root beyond the sealed items.
Info findings are counted, not gated.

**Not seeded:** missing HSTS. The team holds no domain under a TLD that is not
HSTS-preloaded, so `web.hsts_missing` and `web.plaintext_http` fire only on fixtures; on
the lab's `.page` names they are disproved by the preloaded TLD.

**Lab safety** (`docs/ROADMAP.md`, E3): no seeded item is exploitable by anyone outside
the team while the lab exists.

**Observed while seeding**, general behaviour of the lab's DNS host and not a label:
Cloudflare with DNSSEC answers a name that does not exist with NOERROR and no data
through public resolvers (compact denial), and answers an address query for an in-zone
CNAME whose target does not exist with no CNAME in the answer; only a CNAME query shows
the chain. E7's DNS reads and fixtures cover both.
