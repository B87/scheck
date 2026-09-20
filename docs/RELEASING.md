# Releasing scheck

Releases are built by **GoReleaser OSS 2.18.2**, verified on four native runners,
and left as drafts in [b87/scheck](https://github.com/b87/scheck/releases).
A maintainer publishes manually. Creating a draft does not satisfy the acceptance
gate or establish a claim about model quality.

M4.7 automation is implemented; its hosted rehearsal is still pending. M4.5,
M4.6 and M2.7 remain independent prerequisites for publishing 0.0.1. No passing
live evaluation or acceptance sign-off is supplied by this automation.

## Repository setup and tool pins

1. Make `b87/scheck` a public GitHub repository, push the source and workflows, and
   use `main` as the default branch. If this clone has no remote, add
   `git remote add origin git@github.com:b87/scheck.git`.
2. Enable Actions. Use read-only default workflow permissions; the draft job alone
   requests `contents: write`. The workflow uses `GITHUB_TOKEN`, not a PAT or a
   model credential. Never use `pull_request_target` to execute contributed code.
3. Protect `main` with the CI check and integration jobs. Restrict creation of `v*`
   tags to maintainers and prohibit their deletion/update through a tag ruleset.
   Published tags and assets must never be moved or replaced. Enable GitHub release
   immutability if available for this repository.
4. Allow the four hosted runner labels in `release.yml`: `ubuntu-24.04`,
   `ubuntu-24.04-arm`, `macos-15-intel`, and `macos-15` (Apple Silicon).
   Failure or unavailability of any runner blocks sign-off; cross-compilation alone
   is not execution evidence.

Go comes from `go.mod`; golangci-lint is pinned to 2.13.2 and actionlint to 1.7.12.
Actions are pinned to
commit SHAs with their release versions in comments. When upgrading, review the
upstream changes, verify the tag-to-SHA mapping, update both workflows consistently,
and repeat the rehearsal. Do not use `latest` for build tools. GoReleaser's archive
configuration is the sole packaging implementation. Python 3 and the GitHub CLI
on hosted runners perform guards and smoke checks, not packaging.

## Local validation

From the repository root, with the pinned tools installed:

```sh
make check
git diff --exit-code
python3 -m unittest discover -s scripts -p 'test_release.py' -v
goreleaser check
goreleaser release --snapshot --clean
```

The snapshot command cross-compiles all four archives into ignored `dist/` without
uploading or publishing. A snapshot is not a release candidate: its generated
version/name may differ from a real tag and it intentionally permits dirty source.
Use the tag workflow for exact version and clean-tree verification.

For an existing clean local tag, `goreleaser release --clean --skip=publish` builds
release-shaped artifacts without uploading. GoReleaser expects an origin remote
and full Git history. Do not bypass its validation for a production release.

`make integ` requires a working Docker or Podman runtime. CI explicitly runs
`docker info` first so unavailable containers cannot silently turn into a pass.
No routine check, build or artifact smoke test needs a model key or runs a real-host
assessment. Live evaluations are separate opt-in work that costs money.

## Candidate, tag, and draft

1. Finish M4.5 and the live M2.7 gate. Select a reviewed, clean commit and record
   its full SHA. Run M4.6's twelve criteria and configuration walkthrough against
   this exact candidate. Store the dated sign-off outside the source tree so adding
   evidence does not change the candidate SHA. Identify any reused evidence and why
   it applies to this commit; prompt/model changes require matching live evidence.
2. Confirm `git status --porcelain` is empty and CI is green. Confirm the release
   notes header in `.goreleaser.yaml` names the implemented report schema (currently
   1.5) and limitations accurately. Product and schema versions are independent.
3. Create an annotated version tag on the candidate and push it explicitly:

   ```sh
   git tag -a v0.0.1 FULL_CANDIDATE_SHA -m 'Release v0.0.1'
   git push origin refs/tags/v0.0.1
   ```

4. Watch the **Release** workflow. It checks out and validates the tag, runs
   `make check` (including `go fix`), rejects tracked changes, runs integration
   tests, and only then invokes GoReleaser. A manual dispatch's `tag` input selects
   the commit for checks as well as packaging; it does not build the dispatch branch.
5. GoReleaser builds all four targets with CGO disabled, embeds the full tag in
   `internal/version.Version`, creates a draft, and uploads four archives and
   `checksums.txt`. `darwin` means macOS. Every archive contains only `scheck` and
   `LICENSE`. Prerelease tags are marked as prereleases.
6. Each native smoke job downloads the draft assets, checks their exact inventory,
   SHA-256 hashes and archive contents, then executes its matching binary's
   `--version`, `catalog --format json`, and `explain sshd.config --format json`.
   These commands only inspect the compiled catalog. Review all four job summaries
   and the final review job. A failed workflow leaves an unready draft.

## Publication checklist and evidence

Copy this checklist into a dated `validation-vVERSION.md` record. Include the full
candidate SHA, tag, date and maintainer. Attach it to the draft **after** automated
smoke checks (which expect exactly the five build assets), and link it from the notes.
Archive relevant workflow logs before GitHub's retention period expires.

- [ ] Tag resolves to the approved full commit SHA; working source was clean.
- [ ] M4.5 golden regression evidence is linked, covering each platform and both
  mock and recorded native-tool-calling responses.
- [ ] M4.6 results enumerate SPEC §12 criteria 1–12 individually with PASS and
  evidence links. Include macOS local/SSH, Ubuntu/Fedora, throwaway-host filesystem
  and configuration comparisons, and the live audit log.
- [ ] Configuration walkthrough provenance and validation examples pass against
  the release candidate.
- [ ] M2.7 frozen quality/adversarial criteria pass at the required repeat count;
  records identify model, prompt version, code version and outcomes. Criterion 7's
  clean-host cost measurement is recorded. Mock runs are not quality evidence.
- [ ] Release workflow link, commit and all four native runner results are recorded;
  every archive downloads, verifies and executes successfully. No failed/skipped job.
- [ ] Generated notes are reviewed: report schema version, supported platforms,
  installation/checksum commands, MIT license, limitations and evidence links.
  Replace the placeholder validation paragraph. Do not erase earlier failed live
  observations from the evaluation record.
- [ ] macOS artifacts are accurately described as unsigned and unnotarized.
- [ ] The full workflow is complete and no release run is active; all evidence is
  attached and reviewed. Choose **Publish release** in GitHub explicitly.

Publication is a human gate, not an automatic parser of acceptance records. GitHub
maintainers can publish drafts despite failed Actions; they must enforce this checklist.
The first published release establishes SPEC §7.4's compatibility baseline. Schema
additions then bump MINOR; removals, renames and type changes bump MAJOR.

## Rehearsal and recovery

Before marking M4.7 complete, create a new annotated prerelease tag such as
`v0.0.1-rehearsal.1` on the reviewed automation commit and push that tag. This uses
the normal workflow and stays unpublished; live acceptance gates need not be passed
to rehearse draft mechanics. Record the tag, SHA, workflow URL, four downloaded
artifact smoke results, and recovery test outcome here or in an attached record.
Do not publish the rehearsal draft or treat it as acceptance sign-off.

Manually dispatch the same tag again after draft creation to confirm it refuses to
overwrite the draft. The same guard rejects published releases. A GitHub API or
authentication error also fails closed; it is not interpreted as release absence.

For an upload/build failure:

1. Inspect the failed job and verify the release is still a draft. Never delete a
   published release or move its tag.
2. If only smoke execution failed transiently, use **Re-run failed jobs**; it downloads
   the same assets again. Do this before adding validation attachments.
3. To rebuild/re-upload, save any notes/evidence and manually delete only the
   unpublished draft in GitHub. Keep the tag. Dispatch the existing tag again;
   preflight must see no existing release. No workflow deletes or replaces releases.
4. If code or workflow changes are needed, commit them and create a new tag. Never
   move the previous tag to make a retry build different source.

Tag-level concurrency serializes workflows but cannot prevent a maintainer from
editing a release concurrently. Do not manually create, edit or publish it during
an active release run. After publication, corrections require a new version.

**Rehearsal status:** pending. During implementation, the local checkout had no
remote and the authenticated GitHub API returned 404 for `b87/scheck`; no remote tag,
draft or publication was created. Local tests do not substitute for hosted evidence.

**Local validation (2026-09-20):** `make check`, Docker `make integ`, the five release
guard tests, GoReleaser configuration validation and actionlint 1.7.12 passed.
GoReleaser 2.18.2 built all four archives both as a snapshot and from an isolated
temporary repository tagged `v0.0.1-rehearsal.1` with publishing disabled. All four
archive inventories and checksums passed; the downloaded-copy macOS arm64 binary
passed version, catalog and explain checks. This temporary tag was never pushed.
