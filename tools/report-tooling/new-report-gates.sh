#!/usr/bin/env bash
# new-report-gates.sh: the one command a doer runs on a NEW report before the preview push.
#
#   bash tools/report-tooling/new-report-gates.sh <report folder holding index.md> [--out DIR] [--baseline-md FILE] [--views FILE]
#
# The folder may be OUTSIDE this checkout (threat-intel-vault/reports/<slug>/); nothing is
# written to the checkout. It prints one line per gate, PASS, FAIL or NOT CHECKED, then a count.
# Exit 0 only when every gate is PASS; 1 when any gate FAILs; 2 when none FAIL but one is NOT CHECKED.
#
# --baseline-md FILE  render the completeness baseline from FILE (tab lines stripped) instead of from the
#                     folder's own markdown. Use it when the report was copied or edited after the baseline text
#                     existed: pass the vault copy while checking the site copy, and a paragraph lost in between
#                     shows as missing. Without it the baseline is the folder's own markdown, which can only
#                     catch what the tab layout itself drops.
#
# --views FILE        the report's report_views curation file (what would be _data/report_views/<report folder>.yml),
#                     for a file that sits OUTSIDE this checkout, for example beside the vault report. It is passed to
#                     the render, so the page the gates measure carries the curated views the live page will carry, not
#                     the generic ones. Without it the render sees only the curation files already in this checkout.
#
# Gates, in order:
#   render              render-report.rb renders the folder twice with the site's own layouts:
#                       tagged (as written) and untagged (every tab line removed)
#   check-tabs          check-tabs.js --require: a report that declares no tab tags FAILs
#   completeness        check-report-text.js at 1280 and 390, the untagged render as baseline
#   control-body        the same with --control (deletes one body paragraph): must exit 1
#   control-teardown    the same with --control-teardown: must exit 1
#   browser             check-browser-report.js on the tagged render, in a real browser
#
# WHAT IT NEEDS, and what it does without it (never a PASS):
#   node + npm ci in tools/report-tooling   check-tabs, completeness and browser; without node, or
#                                           without jsdom/js-yaml/ws, those gates are NOT CHECKED
#   ruby with the gems jekyll (3.x), jekyll-seo-tag, kramdown-parser-gfm and sass (Ruby Sass 3.7:
#                                           gem install jekyll jekyll-seo-tag kramdown-parser-gfm sass)
#                                           without them render is NOT CHECKED and so are the
#                                           completeness, control and browser gates, which need the render
#   openssl                                 a throwaway certificate for the local https server the
#                                           browser gate fetches from; missing, those gates are NOT CHECKED
#   network to the-hunters-ledger.com       the theme's main.css and main.min.js exist only on the live
#                                           site; unreachable, the page would run unstyled, so the
#                                           completeness, control and browser gates are NOT CHECKED
#   a Chrome or Chromium (HL_CHROME, or /usr/bin/chromium, /usr/bin/google-chrome, /usr/bin/brave)
#                                           none found: the gates that drive it are NOT CHECKED
#   A closed <details> teardown in the report is needed for control-teardown; with none it is NOT CHECKED.
#   Images not yet copied into this checkout's assets/ are fetched from the live site and 404 there.
#
# It starts one local server and, in the gates, one headless browser at a time. Both are stopped on exit,
# on error and on Ctrl-C or kill. Each browser is started by the gate that uses it, on a port the browser picks
# (lib/cdp.js), and is never one this run did not start. Every browser step is bounded: HL_GATE_STEP_TIMEOUT
# seconds (default 1200), after which the step is stopped and reported NOT CHECKED. Within it the CDP driver
# bounds each command (HL_CDP_SEND_TIMEOUT_MS) and the whole browser run (HL_CDP_RUN_TIMEOUT_MS).

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

usage() { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
OUT=""
BASELINE_MD=""
VIEWS=""
FOLDER=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --baseline-md) BASELINE_MD="${2:-}"; shift 2 ;;
    --views) VIEWS="${2:-}"; shift 2 ;;
    -*) echo "unknown option $1" >&2; usage >&2; exit 2 ;;
    *) FOLDER="$1"; shift ;;
  esac
done
if [ -z "$FOLDER" ]; then echo "usage: bash new-report-gates.sh <report folder holding index.md> [--out DIR] [--baseline-md FILE] [--views FILE]" >&2; exit 2; fi
if [ -f "$FOLDER" ]; then FOLDER="$(dirname "$FOLDER")"; fi
if [ ! -f "$FOLDER/index.md" ]; then echo "no index.md in $FOLDER" >&2; exit 2; fi
FOLDER="$(cd "$FOLDER" && pwd)"
MD="$FOLDER/index.md"
BASELINE_ARGS=()
if [ -n "$BASELINE_MD" ]; then
  if [ -d "$BASELINE_MD" ]; then BASELINE_MD="$BASELINE_MD/index.md"; fi
  if [ ! -f "$BASELINE_MD" ]; then echo "no baseline markdown at $BASELINE_MD" >&2; exit 2; fi
  BASELINE_ARGS=("$(cd "$(dirname "$BASELINE_MD")" && pwd)/$(basename "$BASELINE_MD")")
fi

VIEWS_ARGS=()
if [ -n "$VIEWS" ]; then
  if [ ! -f "$VIEWS" ]; then echo "no report_views file at $VIEWS" >&2; exit 2; fi
  VIEWS_ARGS=(--views "$(cd "$(dirname "$VIEWS")" && pwd)/$(basename "$VIEWS")")
fi

if [ -z "$OUT" ]; then OUT="$(mktemp -d /tmp/hl-new-report-gates.XXXXXX)"; KEEP=0; else mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"; KEEP=1; fi

PASS=0; FAIL=0; NC=0
line() { # status gate detail
  printf '%-12s %-17s %s\n' "$1" "$2" "$3"
  case "$1" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; *) NC=$((NC+1));; esac
}
last() { grep -v '^\s*$' "$1" 2>/dev/null | tail -n 1 | cut -c1-200; }

# Browsers started by THIS run carry this tag in their profile directory name (lib/cdp.js reads
# HL_CDP_RUN_TAG), so the backstop below can stop exactly them and never a browser another run started.
export HL_CDP_RUN_TAG="g$$"
MY_BROWSERS='user-data-dir=[^ ]*hl-cdp-profile-g'"$$"'-'
SERVER_PID=""
CHILD_PID=""
cleanup() {
  if [ -n "$CHILD_PID" ]; then kill -TERM "$CHILD_PID" 2>/dev/null; wait "$CHILD_PID" 2>/dev/null; CHILD_PID=""; fi
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; fi
  # The node steps clean up their own browsers on every exit path; this is the backstop for the ones
  # that could not (a step killed with SIGKILL), limited to this run's own tag.
  if pgrep -f "$MY_BROWSERS" >/dev/null 2>&1; then
    pkill -KILL -f "$MY_BROWSERS" 2>/dev/null
    sleep 0.5
  fi
  rm -rf "${TMPDIR:-/tmp}"/hl-cdp-profile-g$$-* 2>/dev/null
  [ "$KEEP" = 0 ] && rm -rf "$OUT"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# Run one node step in the background and wait on it, so Ctrl-C or a kill of this script acts at once
# (bash defers a trap until a foreground command ends) and the step is bounded. Sets rc: the step's exit
# code, or 2 (NOT CHECKED) when it ran past HL_GATE_STEP_TIMEOUT.
STEP_TIMEOUT="${HL_GATE_STEP_TIMEOUT:-1200}"
run_step() { # outfile command...
  local out="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --kill-after=15 "$STEP_TIMEOUT" "$@" > "$out" 2>&1 &
  else
    "$@" > "$out" 2>&1 &
  fi
  CHILD_PID=$!
  wait "$CHILD_PID"; rc=$?
  CHILD_PID=""
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    echo "NOT CHECKED  the step ran past ${STEP_TIMEOUT}s (HL_GATE_STEP_TIMEOUT) and was stopped" >> "$out"
    rc=2
  fi
}

echo "new-report-gates: $MD"
[ -n "$VIEWS" ] && echo "report_views:     ${VIEWS_ARGS[1]}"
echo "evidence folder:  $OUT$( [ "$KEEP" = 0 ] && echo ' (removed on exit; pass --out DIR to keep it)')"

HAVE_NODE=1; command -v node >/dev/null 2>&1 || HAVE_NODE=0
if [ "$HAVE_NODE" = 0 ]; then
  for g in check-tabs render completeness control-body control-teardown browser; do line "NOT CHECKED" "$g" "node is not on PATH"; done
  echo "gates: $PASS PASS, $FAIL FAIL, $NC NOT CHECKED"; exit 2
fi
cd "$HERE" || exit 2

# --- check-tabs --require (needs only node)
node check-tabs.js --require "$MD" > "$OUT/check-tabs.txt" 2>&1; rc=$?
case $rc in
  0) line PASS check-tabs "$(head -n 1 "$OUT/check-tabs.txt" | cut -c1-200)" ;;
  1) line FAIL check-tabs "$(head -n 1 "$OUT/check-tabs.txt" | cut -c1-200)" ;;
  *) line "NOT CHECKED" check-tabs "$(last "$OUT/check-tabs.txt")" ;;
esac

# --- render
RENDER_OK=0
if ! command -v ruby >/dev/null 2>&1; then
  line "NOT CHECKED" render "ruby is not on PATH"
else
  ruby render-report.rb "$FOLDER" "$OUT/render" ${BASELINE_ARGS[@]+"${BASELINE_ARGS[@]}"} ${VIEWS_ARGS[@]+"${VIEWS_ARGS[@]}"} > "$OUT/render.txt" 2>&1; rc=$?
  case $rc in
    0) RENDER_OK=1; line PASS render "$(last "$OUT/render.txt")" ;;
    1) line FAIL render "$(last "$OUT/render.txt")" ;;
    *) line "NOT CHECKED" render "$(last "$OUT/render.txt")" ;;
  esac
fi

SLUG=""
[ "$RENDER_OK" = 1 ] && SLUG="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).slug)' "$OUT/render/render.json")"

# --- local server (needs the render, openssl and the live theme assets)
SERVER_OK=0; SERVER_WHY="the render did not complete"
if [ "$RENDER_OK" = 1 ]; then
  if ! command -v openssl >/dev/null 2>&1; then SERVER_WHY="openssl is not on PATH, so no certificate for the local https server"
  else
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 1 -subj "/CN=127.0.0.1" > /dev/null 2>&1
    # A reused --out holds the PREVIOUS run's ready.json: its ports would pass the wait below and
    # point the gates at a server that no longer exists (or at another run's). Delete it first.
    rm -f "$OUT/ready.json" "$OUT/server.log"
    node lib/gate-server.js --tagged "$OUT/render/tagged.html" --untagged "$OUT/render/untagged.html" --css "$OUT/render/custom.css" \
      --slug "$SLUG" --cert "$OUT/cert.pem" --key "$OUT/key.pem" --ready "$OUT/ready.json" > "$OUT/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 100); do [ -s "$OUT/ready.json" ] && break; kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.2; done
    if [ -s "$OUT/ready.json" ] && grep -q '"http"' "$OUT/ready.json" && kill -0 "$SERVER_PID" 2>/dev/null; then
      SERVER_OK=1
      HTTP_PORT="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).http)' "$OUT/ready.json")"
      HTTPS_PORT="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).https)' "$OUT/ready.json")"
    else
      SERVER_WHY="$(node -e 'try{console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).error)}catch(e){console.log("the local server did not start")}' "$OUT/ready.json" 2>/dev/null)"
      SERVER_PID=""
    fi
  fi
fi

BASE_URL="http://127.0.0.1:${HTTP_PORT:-0}"
text_gate() { # gate-name expected-exit extra-flag
  local name="$1" want="$2" flag="${3:-}"
  if [ "$SERVER_OK" = 0 ]; then line "NOT CHECKED" "$name" "$SERVER_WHY"; return; fi
  run_step "$OUT/$name.txt" node check-report-text.js --baseline "$BASE_URL/__baseline/untagged/" --page "$BASE_URL/reports/$SLUG/" --width 1280,390 $flag
  if [ "$want" = 0 ]; then
    case $rc in 0) line PASS "$name" "$(last "$OUT/$name.txt")" ;; 1) line FAIL "$name" "$(last "$OUT/$name.txt")" ;; *) line "NOT CHECKED" "$name" "$(last "$OUT/$name.txt")" ;; esac
  else
    case $rc in
      1) line PASS "$name" "control fired (exit 1): $(last "$OUT/$name.txt")" ;;
      0) line FAIL "$name" "the control did NOT fire (exit 0): the completeness check cannot see a deleted paragraph" ;;
      *) line "NOT CHECKED" "$name" "$(last "$OUT/$name.txt")" ;;
    esac
  fi
}
text_gate completeness 0
text_gate control-body 1 --control
text_gate control-teardown 1 --control-teardown

# --- browser gate, on the tagged render, one browser at a time
if [ "$SERVER_OK" = 0 ]; then
  line "NOT CHECKED" browser "$SERVER_WHY"
else
  run_step "$OUT/browser.txt" env HL_SITE_BASE="https://127.0.0.1:$HTTPS_PORT" NODE_TLS_REJECT_UNAUTHORIZED=0 node check-browser-report.js "$SLUG" --md "$MD"
  summary="$(grep -E '^(PASS|FAIL|NOT CHECKED)' "$OUT/browser.txt" | tail -n 1 | cut -c1-200)"
  [ -z "$summary" ] && summary="$(last "$OUT/browser.txt")"
  case $rc in 0) line PASS browser "$summary" ;; 1) line FAIL browser "$summary (rows: $OUT/browser.txt)" ;; *) line "NOT CHECKED" browser "$summary" ;; esac
fi

echo "gates: $PASS PASS, $FAIL FAIL, $NC NOT CHECKED"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
if [ "$NC" -gt 0 ]; then exit 2; fi
exit 0
