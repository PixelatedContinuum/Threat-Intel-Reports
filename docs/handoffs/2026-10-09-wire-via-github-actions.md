# Hand-off: move the Wire off `main` and deploy the site with GitHub Actions

**Date:** 2026-10-09
**Branch carrying the repo-side work:** `claude/gracious-curie-truz72`
**Status:** repo side done and pushed; three steps remain, in three different places.

---

## What this changes and why

The Wire refreshes hourly. Until now each refresh was a commit to `main`, so 37 of the
last 50 commits on the site were `wire: refresh` and the real history was buried under them.

After this change:

```
 LXC-102 (OpenCTI host)                 GitHub                                   Readers
 ─────────────────────                  ──────                                   ───────
 wire_export.py ──► wire.yml ──► force-push ONE orphan commit ──► branch wire-data
                                                                       │
                                                      push event ──────┤
 you push a report ────────────────────────────────► branch main       │
                                                      push event ──────┤
                                                                       ▼
                                           .github/workflows/pages.yml
                                           checkout main
                                           copy origin/wire-data:wire.yml → _data/wire.yml
                                           gate it (check-wire.js)
                                           jekyll build (github-pages gem, same as today)
                                           deploy to Pages ─────────────────────────► the-hunters-ledger.com
```

`main` becomes a history of the site. `wire-data` is a one-commit mailbox that is overwritten
every hour and never grows. The Wire still updates hourly with nobody touching anything, and
every push to `main` now gets a full build, the unit tests and the source-side gates run in CI.

---

## Already done (this repository, this branch)

| File | What it is |
|---|---|
| `.github/workflows/pages.yml` | Build on push to `main` or `wire-data`; deploy only when the repository variable `PAGES_VIA_ACTIONS` is `true`; a `gates` job runs `npm test` and the eight source-side gates plus `check-report.js` on every report. |
| `tools/wire/push-wire-data.sh` | Generator-side publisher. Writes `wire.yml` as a single orphan commit and force-pushes it to `wire-data` using git plumbing, so it never touches the clone's working tree or branch. Refuses a file with no `generated_at` or with a `description` field. Tested against a scratch bare remote: two runs leave the branch at exactly one commit. |
| `tools/report-tooling/check-wire.js` | The staleness check now reads `origin/wire-data:wire.yml` first and falls back to `origin/main:_data/wire.yml`, so it is correct before, during and after the cutover. |
| `tools/report-tooling/README.md`, `lib/check-wire.js` | Wording updated for the new path. |

The workflow is **inert for readers until Step 2**. From the moment the branch merges, the
`build` and `gates` jobs run on every push and show red in the Actions tab if anything regresses,
but `deploy` is skipped, so the existing deploy-from-branch keeps serving the site unchanged.

---

## Remaining steps, in order

Do them in this order. It has no window where the live Wire goes stale: the Actions build falls
back to the copy of `_data/wire.yml` committed on `main` until the generator switches over, and
during that overlap the generator's hourly commits to `main` trigger the Actions build anyway.

### Step 1: merge the branch

**Where:** GitHub, this repository. A cloud session can open the PR; you merge it.

1. Open a pull request from `claude/gracious-curie-truz72` into `main` and merge it.
2. Go to **Actions** and confirm the run "Build and deploy site" shows `Build (main + newest Wire)`
   and `Tests and source gates` green and `Deploy to GitHub Pages` skipped.
3. If `build` is red, read the log before continuing. The most likely cause is the
   `actions/jekyll-build-pages` step, and the fix belongs in this repo.

### Step 2: switch Pages to GitHub Actions

**Where:** GitHub repository settings, in the browser. This is yours; no session can do it.

1. **Settings → Pages → Build and deployment → Source:** change *Deploy from a branch* to
   **GitHub Actions**. The custom domain and HTTPS settings stay as they are. The `CNAME` file in
   the repo is harmless and can stay.
2. **Settings → Environments → `github-pages` → Deployment branches and tags.** GitHub creates
   this environment with "Selected branches" limited to `main`. Add **`wire-data`** as an allowed
   branch. Without it, every hourly run will fail at deploy with
   *"Branch 'wire-data' is not allowed to deploy to github-pages due to environment protection
   rules"* and the Wire will never update through this path.
3. **Settings → Secrets and variables → Actions → Variables → New repository variable:**
   name `PAGES_VIA_ACTIONS`, value `true`.
4. **Actions → Build and deploy site → Run workflow** (on `main`). Confirm `Deploy to GitHub
   Pages` now runs and succeeds, then load the-hunters-ledger.com, a report page, and `/wire/`.
   The Wire page's "Updated … UTC" line should match the `generated_at` of the file that was
   built in (the build log prints it).

**Rollback** at any point: set the variable to `false` and switch Pages Source back to
*Deploy from a branch* (`main`, `/ (root)`). The old path is unchanged and resumes immediately.

### Step 3: point the generator at `wire-data`

**Where:** your host, LXC-102 (the machine that runs `wire_export.py` on the hourly timer and
holds a clone of this repository with push rights). Not a cloud session.

1. In the site clone on LXC-102, pull `main` so `tools/wire/push-wire-data.sh` is present:
   `git pull origin main`.
2. Find the timer's publish step. Today it does something equivalent to
   `cp wire.yml _data/wire.yml && git add _data/wire.yml && git commit -m "wire: refresh …" && git push origin main`.
   Replace that whole step with one line, run from inside the clone:

   ```sh
   /path/to/Threat-Intel-Reports/tools/wire/push-wire-data.sh /path/to/generated/wire.yml
   ```

   It uses the clone's existing `origin` and credentials (the same ones that pushed to `main`),
   needs no checkout, no stash and no branch switch, and prints one line on success. Exit 1 means
   it refused the input (no `generated_at`, or a `description` field present); exit 2 is a git or
   push failure. Keep whatever alerting the old step had and attach it to a non-zero exit here.
3. Run the timer's job once by hand and check:
   - `git ls-remote origin wire-data` prints a hash.
   - The Actions tab shows a new "Build and deploy site" run triggered by `wire-data`, with
     `deploy` green.
   - `/wire/` on the live site shows the new timestamp.
   - After the second hourly run, `git rev-list --count origin/wire-data` is still `1`.
4. Only now remove the old commit-to-main step for good, if you kept it running in parallel.

If `wire-data` needs a credential of its own (for example the clone pushes with a deploy key that
is scoped per branch, which is unusual), the key needs write access to `refs/heads/wire-data` and
nothing else. Branch protection on `main` is irrelevant to this branch; do **not** protect
`wire-data`, because the script force-pushes it by design.

### Step 4: clean up `main` (after Step 3 is verified)

**Where:** this repository. A cloud session can do all of it.

1. `git rm _data/wire.yml` and add `_data/wire.yml` to `.gitignore`. The workflow writes the
   file into the checkout at build time; ignoring it stops a local Jekyll run from ever
   committing it back.
2. Local preview builds then need the data too. Either run
   `git fetch origin wire-data && git show origin/wire-data:wire.yml > _data/wire.yml`
   before `jekyll serve`, or add that as a `wire:pull` script in `tools/report-tooling/package.json`.
3. `tools/report-tooling/lib/staged-gate.js` still routes `_data/wire.yml` to the wire gate.
   Leave it: it is harmless and still right for the rare hand edit during an incident.
4. Optional: in `.github/workflows/pages.yml`, the "no wire-data branch" fallback can be turned
   into a hard failure once the branch has existed for a while, so a deleted branch is noticed.

---

## Things worth knowing

- **Cost.** The repository is public, so Actions minutes are free. A build is roughly one to two
  minutes; hourly pushes are about 48 minutes a day. `concurrency: cancel-in-progress` means a
  burst of pushes still yields one deploy.
- **Artifact size.** The built site is about 80 MB, well under the 1 GB Pages artifact limit.
- **Gate behaviour in CI.** Malformed Wire data is dropped so `/wire/` renders its "not currently
  available" state and a report push is never blocked by a generator problem. Stale but
  well-formed data is published with a warning annotation (the page prints its own timestamp). A
  failure on `wire/index.md` itself fails the build, because that is a code bug on `main`.
- **The `gates` job does not block deploy.** A tooling regression shows red on the commit, which
  is the point, but it should not hold back a report. Flip that by adding `needs: gates` to the
  `deploy` job if you decide you want it strict.
- **`check-wire.js` outside CI** still fetches on its own. On a machine without network access to
  GitHub it reports NOT CHECKED rather than guessing, same as before.
- **Scheduled-workflow expiry does not apply.** GitHub disables cron-triggered workflows after 60
  days of repository inactivity; this workflow is push-triggered, and the hourly push is itself
  activity.

## What this unlocks next

Once the site is built by Actions, build-time steps that GitHub's branch deploy could never run
become cheap: a Pagefind full-text index over the rendered HTML, generated actor and technique
cross-reference pages, consolidated YARA and Sigma feed files, and a MISP feed built from the
STIX bundles. Each is a job step in the same workflow.
