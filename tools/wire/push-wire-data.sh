#!/bin/sh
# Publish a freshly generated wire.yml to the `wire-data` branch as ONE orphan
# commit (wire.yml plus a copy of main's pages.yml, see below), replacing whatever
# was there. Run by the Wire generator host after
# wire_export.py writes the file; this replaces the old "commit to main" step.
#
# Why an orphan commit and a force-push. The branch is a mailbox, not a history:
# only its newest content is ever read (by .github/workflows/pages.yml, which
# copies wire.yml into _data/ before building). Rewriting it each hour keeps the
# branch at exactly one commit forever, so the repository never grows by a
# 200 KB YAML file every hour and main's history is no longer 70% "wire: refresh".
#
# Why plumbing commands rather than checkout/add/commit. Nothing here touches the
# working tree, the index or the current branch of the clone it runs in, so it
# cannot collide with a publish in progress and needs no stash or worktree. The
# blob is written straight to the object store, wrapped in a tree, wrapped in a
# commit with no parent, and that commit is pushed by hash to the remote ref.
#
# Usage:
#   tools/wire/push-wire-data.sh /path/to/wire.yml
#
# Environment (all optional):
#   WIRE_REMOTE   remote to push to                 (default: origin)
#   WIRE_BRANCH   branch to overwrite               (default: wire-data)
#   WIRE_AUTHOR   author/committer for the commit   (default: Wire generator <wire@the-hunters-ledger.com>)
#
# Run it from inside a clone of the site repository (any branch, any state).
# Exit codes: 0 pushed, 1 refused (bad input), 2 git/push failure.

set -eu

SRC=${1:?usage: push-wire-data.sh /path/to/wire.yml}
REMOTE=${WIRE_REMOTE:-origin}
BRANCH=${WIRE_BRANCH:-wire-data}
AUTHOR=${WIRE_AUTHOR:-"Wire generator <wire@the-hunters-ledger.com>"}

[ -s "$SRC" ] || { echo "refusing: $SRC is missing or empty" >&2; exit 1; }
STAMP=$(sed -n 's/^generated_at:[ \t]*//p' "$SRC" | head -n 1)
[ -n "$STAMP" ] || { echo "refusing: $SRC carries no generated_at line, so it is not a wire export" >&2; exit 1; }
if grep -q '^[ \t]*description:' "$SRC"; then
  echo "refusing: $SRC carries a description field; the Wire aggregates headlines and attribution only (check-wire.js would fail the build)" >&2
  exit 1
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "run this from inside the site repository clone" >&2; exit 2; }
cd "$ROOT"

NAME=${AUTHOR%% <*}
EMAIL=${AUTHOR#*<}; EMAIL=${EMAIL%>}
export GIT_AUTHOR_NAME="$NAME" GIT_AUTHOR_EMAIL="$EMAIL"
export GIT_COMMITTER_NAME="$NAME" GIT_COMMITTER_EMAIL="$EMAIL"

BLOB=$(git hash-object -w "$SRC") || exit 2

# The commit also carries main's .github/workflows/pages.yml. GitHub runs a push
# event from the workflow files in the PUSHED commit's tree, so a commit holding
# wire.yml alone triggers nothing and the site is never rebuilt (found at cutover,
# 2026-10-09). The workflow checks out main whatever woke it, so this copy only
# has to exist; taking it from $REMOTE/main each run keeps it current (run.sh
# fast-forwards main first). Only pages.yml: any other workflow copied here would
# fire on every hourly push too.
WF=.github/workflows/pages.yml
WF_BLOB=$(git rev-parse --verify --quiet "refs/remotes/$REMOTE/main:$WF") || {
  echo "refusing: $REMOTE/main has no $WF, so a push to $BRANCH would trigger no build" >&2
  exit 2
}
TMP_INDEX=$(mktemp) || exit 2
trap 'rm -f "$TMP_INDEX"' EXIT
rm -f "$TMP_INDEX"
TREE=$(GIT_INDEX_FILE=$TMP_INDEX sh -c '
  git update-index --add --cacheinfo "100644,$1,wire.yml" &&
  git update-index --add --cacheinfo "100644,$2,$3" &&
  git write-tree' sh "$BLOB" "$WF_BLOB" "$WF") || exit 2
COMMIT=$(git commit-tree "$TREE" -m "wire: refresh $STAMP") || exit 2

if git push --force --quiet "$REMOTE" "$COMMIT:refs/heads/$BRANCH"; then
  echo "pushed wire.yml ($STAMP) to $REMOTE/$BRANCH as $COMMIT"
else
  echo "push to $REMOTE/$BRANCH failed" >&2
  exit 2
fi
