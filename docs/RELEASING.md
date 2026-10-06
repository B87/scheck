# Releasing scheck

Releases are built by **GoReleaser OSS 2.18.2**, verified on four native runners,
and left as drafts in [b87/scheck](https://github.com/b87/scheck/releases).
A maintainer publishes manually. Creating a draft does not satisfy a release's gates
or establish a claim about quality; the gates are in [ROADMAP.md](ROADMAP.md) and
their record is `docs/eval/acceptance-<version>.md`.

## Repository setup and tool pins

1. `b87/scheck` is a public GitHub repository with `main` as the default branch. If a
   clone has no remote, add `git remote add origin git@github.com:b87/scheck.git`.
2. Actions use read-only default workflow permissions. Two jobs request
   `contents: write`: `draft`, which creates the draft, and `smoke`, which cannot
   otherwise see it — a draft release is invisible to a token without push access, so
   a read-only token reports "release not found" rather than a permission error. The
   smoke jobs download and verify only; they never create, edit or publish a release.
   The workflow uses `GITHUB_TOKEN`, not a PAT or a model credential. Never use
   `pull_request_target` to execute contributed code.
3. `main` is protected by the CI check and integration jobs. Creation of `v*` tags is
   restricted to maintainers and their deletion or update is prohibited by a tag
   ruleset. Published tags and assets are never moved or replaced. Enable GitHub
   release immutability if available.
4. The four hosted runner labels in `release.yml` are `ubuntu-24.04`,
   `ubuntu-24.04-arm`, `macos-15-intel` and `macos-15` (Apple Silicon). Failure or
   unavailability of any runner blocks sign-off; cross-compilation alone is not
   execution evidence.

Go comes from `go.mod`; golangci-lint is pinned to 2.13.2 and actionlint to 1.7.12.
Actions are pinned to commit SHAs with their release versions in comments. When
upgrading, review the upstream changes, verify the tag-to-SHA mapping, update both
workflows consistently, and repeat the rehearsal. Do not use `latest` for build tools.
GoReleaser's archive configuration is the sole packaging implementation; Python 3 and
the GitHub CLI on hosted runners perform guards and smoke checks, not packaging.

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
version may differ from a real tag and it permits dirty source. Use the tag workflow
for exact version and clean-tree verification.

For an existing clean local tag, `goreleaser release --clean --skip=publish` builds
release-shaped artifacts without uploading. GoReleaser expects an origin remote and
full Git history. Do not bypass its validation for a production release.

`make integ` requires a working Docker or Podman runtime. CI runs `docker info` first
so unavailable containers cannot silently turn into a pass. No routine check, build or
artifact smoke test needs a model key or contacts a real target. Live evaluations are
separate opt-in work that costs money (`make live`).

## Candidate, tag and draft

1. Select a reviewed, clean commit and record its full SHA. Run the release's gates
   from [ROADMAP.md](ROADMAP.md) against this exact candidate and record them in
   `docs/eval/acceptance-<version>.md`. Store the dated sign-off outside the source
   tree if adding it would change the candidate SHA. Identify any reused evidence and
   why it applies to this commit; a change to a model prompt, model or decision
   threshold requires matching live evidence.
2. Confirm `git status --porcelain` is empty and CI is green. Confirm the release
   notes header in `.goreleaser.yaml` names the implemented report schema versions and
   limitations accurately. Product and schema versions are independent.
3. Create an annotated version tag on the candidate and push it explicitly:

   ```sh
   git tag -a vX.Y.Z FULL_CANDIDATE_SHA -m 'Release vX.Y.Z'
   git push origin refs/tags/vX.Y.Z
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
   SHA-256 hashes and archive contents, then runs its matching binary's `--version`,
   `catalog --format json` and `explain sshd.config --format json`. These commands only
   inspect the compiled catalog. Review all four job summaries and the final review job.
   A failed workflow leaves an unready draft.

## Publication checklist

Copy this checklist into the acceptance record. Include the full candidate SHA, tag,
date and maintainer. Attach evidence to the draft **after** automated smoke checks
(which expect exactly the five build assets), and link it from the notes. Archive
relevant workflow logs before GitHub's retention period expires.

- [ ] Tag resolves to the approved full commit SHA; working source was clean.
- [ ] Every release gate in [ROADMAP.md](ROADMAP.md) for this version is recorded
  individually with PASS and evidence links.
- [ ] The host collector has not regressed: its golden command traces and reports are
  unchanged, or every change is explained (`spec/host-collector.md §9`), and its
  acceptance criteria (`spec/host-collector.md §10`) still hold.
- [ ] Any model feature that is on by default has a passing record against criteria
  frozen before the run (`docs/eval/`). Mock runs are not quality evidence.
- [ ] Release workflow link, commit and all four native runner results are recorded;
  every archive downloads, verifies and executes. No failed or skipped job.
- [ ] Generated notes are reviewed: report schema versions, supported platforms,
  installation and checksum commands, MIT license, limitations and evidence links.
  Earlier failed observations stay in their evaluation records.
- [ ] macOS artifacts are described as unsigned and unnotarized.
- [ ] The workflow is complete and no release run is active; all evidence is attached
  and reviewed. Choose **Publish release** in GitHub explicitly.

Publication is a human gate, not an automatic parser of acceptance records. GitHub
maintainers can publish drafts despite failed Actions; they must enforce this
checklist. Published report schemas follow `spec/host-collector.md §6.4`: additions bump
MINOR; removals, renames and type changes bump MAJOR.

## Rehearsal and recovery

When the release workflow, its pins or its jobs change, rehearse before the next real
release: create an annotated prerelease tag such as `vX.Y.Z-rehearsal.1` on the
reviewed commit and push it. It uses the normal workflow and stays unpublished. Record
the tag, SHA, workflow URL, four smoke results and the recovery test outcome in the
acceptance record. Never publish a rehearsal draft or treat it as sign-off.

Dispatch the same tag again after draft creation to confirm it refuses to overwrite
the draft. The refusal lands in the **draft** job's recheck, not in `validate`: listing
drafts requires push access, so `validate`'s read-only preflight sees published
releases only. Overwriting a *published* release is the unrecoverable case and is
refused first and cheapest; a draft is refused by the only job that could create one,
before GoReleaser runs. A GitHub API or authentication error fails closed; it is not
read as release absence.

For an upload or build failure:

1. Inspect the failed job and verify the release is still a draft. Never delete a
   published release or move its tag.
2. If only smoke execution failed transiently, use **Re-run failed jobs**; it downloads
   the same assets again. Do this before adding validation attachments.
3. To rebuild, save any notes and evidence and manually delete only the unpublished
   draft. Keep the tag. Dispatch the existing tag again; preflight must see no existing
   release. No workflow deletes or replaces releases.
4. If code or workflow changes are needed, commit them and create a new tag. Never move
   a previous tag to make a retry build different source.

Tag-level concurrency serializes workflows but cannot prevent a maintainer from
editing a release concurrently. Do not create, edit or publish it manually during an
active release run. After publication, corrections require a new version.

**Why the rehearsal exists.** The 0.0.1 rehearsal's first attempt
(`v0.0.1-rehearsal.1`) produced a correct draft and then failed every smoke job with
`release not found`: `smoke` had inherited `contents: read`, and a read-only token
cannot see a draft at all. No local validation, snapshot or `--skip=publish` build
exercises a second job downloading a draft with a scoped token, so only a hosted
rehearsal could find it. The second attempt passed on all four runners, and the
overwrite guard refused a repeat dispatch as described above.
