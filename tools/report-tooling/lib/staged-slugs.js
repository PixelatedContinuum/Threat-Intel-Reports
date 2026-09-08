'use strict';

/* Which staged path belongs to which campaign, for the victim-naming gate's routing.

   Four of the five routes name a campaign directly: `reports/<slug>/index.md`,
   `hunting-detections/<slug>-detections.md`, `ioc-feeds/<slug>-iocs.json` and
   `stix/<slug>.json` are each a campaign's own file, so the slug in the path IS the
   campaign. Nothing more to check.

   `assets/images/<name>/` is different: it is a GUESS about what `<name>` means, because
   the images directory is shared with content that is not a campaign at all
   (`behind-the-reports/`, `cards/`, and whatever comes next). Treating every directory
   under there as a campaign slug means an SVG text edit under
   `assets/images/behind-the-reports/` looks for a campaign called `behind-the-reports`,
   finds no vault feed, and blocks the commit as NOT CHECKED for a change that could not
   possibly publish a victim name. Diagnosed 2026-09-08.

   The fix is not to whitelist `behind-the-reports` — that fixes one directory and leaves
   the next non-campaign folder to be discovered the same way. It is to ask whether `<name>`
   actually resolves to a campaign before trusting the guess: does anything a real campaign
   produces exist under that name. `resolvesToCampaign` checks four independent artifacts,
   any one of which is enough, because a campaign that has published through any one route
   already has a slug the victim gate can check against.

   `exists` and `catalogText` are injected rather than called directly against the real
   filesystem, so this stays a pure function under test (same shape as `staged-gate.js`'s
   `opts.existing`) and the caller wires it to `fs` once. */

function norm(p) { return String(p).replace(/\\/g, '/').replace(/^\.\//, ''); }

function directSlug(p) {
  var m = /^reports\/([^/]+)\/index\.md$/.exec(p)
       || /^hunting-detections\/(.+)-detections\.md$/.exec(p)
       || /^ioc-feeds\/(.+)-iocs\.json$/.exec(p)
       || /^stix\/(.+)\.json$/.exec(p);
  return m ? m[1] : null;
}

/* The four signals. The first three are the campaign's own generated artifacts sitting in
   the working tree right now, staged in this commit or not: `git add` requires a file to
   exist in the working tree before it can be staged, so a campaign whose report is being
   added in the SAME commit as its first screenshots still resolves here, because by the
   time this runs the co-staged report is already sitting on disk under its own path. The
   fourth is the catalog entry `hunters-ledger-publish` Step 4 writes, checked as plain text
   rather than parsed YAML to avoid a new dependency for three substring checks.

   THE HOLE THIS DOES NOT CLOSE: if screenshots are staged before the report file exists on
   disk at all, none of the four signals fire yet and the image is treated as non-campaign
   content for this commit. This repo's own pipeline does not author in that order --
   report-screenshot-placement runs only after report-writer has already produced the report
   -- so the exposure is a hypothetical out-of-order flow, not the one this repo uses. Anyone
   changing that order should re-open this comment. */
function resolvesToCampaign(slug, exists, catalogText) {
  if (exists('reports/' + slug + '/index.md')) return true;
  if (exists('hunting-detections/' + slug + '-detections.md')) return true;
  if (exists('ioc-feeds/' + slug + '-iocs.json')) return true;
  // The surviving-viewer-stub shape staged-gate.js already routes on: a feed retired to
  // an `ioc-feeds/<slug>/index.md` stub still names a real campaign.
  if (exists('ioc-feeds/' + slug + '/index.md')) return true;
  if (catalogText) {
    if (catalogText.indexOf('/reports/' + slug + '/') !== -1) return true;
    if (catalogText.indexOf('/hunting-detections/' + slug + '-detections') !== -1) return true;
    if (catalogText.indexOf('/ioc-feeds/' + slug + '-iocs.json') !== -1) return true;
  }
  return false;
}

/* paths: staged repo-relative paths (backslashes and a leading `./` tolerated, matching
   stagedPaths()'s output). opts.exists(relPath): true if relPath is present in the working
   tree; defaults to a function that always returns false, so a caller that forgets to wire
   it gets the SAFE failure (an images path resolves to nothing) rather than the unsafe one.
   opts.catalogText: the raw text of `_data/catalog.yml`, or falsy if it could not be read.

   Returns { slug: [paths that belong to it], ... }, mirroring the module-scope SLUG_PATHS
   map precommit.js built inline before this was extracted. */
function campaignSlugs(paths, opts) {
  opts = opts || {};
  var exists = opts.exists || function () { return false; };
  var catalogText = opts.catalogText || null;
  var slugPaths = {};
  (paths || []).map(norm).filter(Boolean).forEach(function (p) {
    var slug = directSlug(p);
    if (!slug) {
      var im = /^assets\/images\/([^/]+)\//.exec(p);
      if (im && resolvesToCampaign(im[1], exists, catalogText)) slug = im[1];
    }
    if (slug && slug !== 'hunters-ledger-stix-bundles') {
      (slugPaths[slug] = slugPaths[slug] || []).push(p);
    }
  });
  return slugPaths;
}

module.exports = { campaignSlugs: campaignSlugs, resolvesToCampaign: resolvesToCampaign };
