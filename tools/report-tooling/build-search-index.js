#!/usr/bin/env node
'use strict';

/* Build the site-search index (T-0548). Replaces `npx pagefind@1.3.0 --site _site` in .github/workflows/pages.yml with the same Pagefind (pinned to 1.3.0 in package.json,
   exact version) driven through its Node API, so the Wire rows can be added as custom records beside the pages:

     node build-search-index.js --site ../../_site [--records-out FILE] [--wire-bundle NAME]

   1. createIndex() with no options, addDirectory({ path: site }): the same page indexing the CLI did (every HTML file; a page is indexed only when it carries
      data-pagefind-body, which _layouts/default.html withholds from unlisted pages, so an embargoed report still never reaches the index).
   2. one addCustomRecord per Wire row (lib/wire-search-records.js): nKEV, CVE and non-digest headline rows, text defanged.
   3. writeFiles({ outputPath: <site>/pagefind }).
      --wire-bundle NAME (off by default): the Wire records go into a SECOND index written to <site>/NAME instead of the first, so the search page can load it with
      Pagefind's mergeIndex and an indexWeight below 1. Pagefind 1.3 has no per-record weight for custom records (CustomRecord holds url, content, language, meta, filters, sort
      and nothing else); a whole index can be weighted at query time, which is the only lever that ranks Wire results below pages. Measured in T-0548 (index-ret.md).
   4. the records it indexed are written to --records-out as JSON ({ records, counts, source }) for `check-defang.js --site <dir> --records <file>`, which gates them.

   Output keeps the CLI line the workflow greps ("Indexed N pages") and adds "Wire records: ...". Indicator values are never printed, only counts.
   Exit 0 indexed; 1 a record count is zero while the source has rows, a builder problem (duplicate id, count mismatch), or Pagefind reported an error; 2 NOT CHECKED
   (no site directory, no wire page: the Wire renders its unavailable state, so only pages are indexed and that is said). */

var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var R = require('./lib/wire-search-records.js');

async function main() {
  var argv = process.argv.slice(2), site = path.join(__dirname, '..', '..', '_site'), out = path.join(os.tmpdir(), 'wire-search-records.json'), wireBundle = null;
  for (var a = 0; a < argv.length; a++) {
    if (argv[a] === '--site') site = argv[++a];
    else if (argv[a] === '--records-out') out = argv[++a];
    else if (argv[a] === '--wire-bundle') wireBundle = argv[++a];
    else if (argv[a] === '-h' || argv[a] === '--help') { console.log('usage: node build-search-index.js --site <_site dir> [--records-out FILE]'); return 0; }
  }
  if (!fs.existsSync(site) || !fs.statSync(site).isDirectory()) { console.log('NOT CHECKED  not a directory: ' + site); return 2; }
  site = path.resolve(site);

  var built = R.buildFromSite(site);
  var pagefind = await import('pagefind');
  var created = await pagefind.createIndex();
  if (!created.index) { console.log('FAIL  Pagefind createIndex: ' + created.errors.join('; ')); return 1; }
  var index = created.index;
  var rc = 0, added = 0, wireIndex = index;
  if (wireBundle) {
    var created2 = await pagefind.createIndex();
    if (!created2.index) { console.log('FAIL  Pagefind createIndex (Wire bundle): ' + created2.errors.join('; ')); return 1; }
    wireIndex = created2.index;
  }

  var dir = await index.addDirectory({ path: site });
  if (dir.errors && dir.errors.length) { console.log('FAIL  Pagefind addDirectory: ' + dir.errors.join('; ')); rc = 1; }

  if (!built) {
    console.log('NOTE  no wire/index.html in the site: no Wire records (the Wire page is absent)');
  } else {
    if (built.problems.length) { built.problems.forEach(function (p) { console.log('FAIL  records: ' + p); }); rc = 1; }
    var rowsInSource = built.source.nkev + built.source.cves + built.source.headlines;
    for (var i = 0; i < built.records.length; i++) {
      var res = await wireIndex.addCustomRecord(built.records[i]);
      if (res.errors && res.errors.length) { console.log('FAIL  Pagefind addCustomRecord (' + built.records[i].meta.section + '): ' + res.errors.join('; ')); rc = 1; }
      else added++;
    }
    console.log('Wire records: ' + R.SECTIONS.nkev + ' ' + built.counts.nkev + ' of ' + built.source.nkev + ' rows, ' + R.SECTIONS.cves + ' ' + built.counts.cves + ' of ' + built.source.cves +
      ' rows, ' + R.SECTIONS.headlines + ' ' + built.counts.headlines + ' of ' + built.source.headlines + ' rows (' + built.source.vulnDigest + ' vuln digest headline items left out), ' +
      added + ' added to the index; defang residual pass cleared ' + (built.defang ? built.defang.residual : 0) + ' token(s), ' + (built.defang ? built.defang.unresolved : 0) + ' unresolved; rows with no Details entry: nKEV ' + built.noDetails.nkev + ', CVEs ' + built.noDetails.cves);
    if (rowsInSource === 0) console.log('NOTE  the Wire page has no rows (unavailable state): no Wire records');
    [['nkev', 'nKEV'], ['cves', 'CVEs'], ['headlines', 'Headlines']].forEach(function (k) {
      if (built.source[k[0]] > 0 && built.counts[k[0]] === 0) { console.log('FAIL  zero ' + k[1] + ' records while the page has ' + built.source[k[0]] + ' rows'); rc = 1; }
    });
    // a Wire with rows in one tab and none in another is normal (a tab can be unavailable); a Wire page with rows but no record at all is not
    if (rowsInSource > 0 && built.records.length === 0) { console.log('FAIL  the Wire page has rows but no record was built'); rc = 1; }
    fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    fs.writeFileSync(out, JSON.stringify({ counts: built.counts, source: built.source, records: built.records }));
    console.log('records file: ' + out + ' (' + built.records.length + ' records, for check-defang.js --records)');
  }

  var w = await index.writeFiles({ outputPath: path.join(site, 'pagefind') });
  if (w.errors && w.errors.length) { console.log('FAIL  Pagefind writeFiles: ' + w.errors.join('; ')); rc = 1; }
  if (wireBundle) {
    var w2 = await wireIndex.writeFiles({ outputPath: path.join(site, wireBundle) });
    if (w2.errors && w2.errors.length) { console.log('FAIL  Pagefind writeFiles (Wire bundle): ' + w2.errors.join('; ')); rc = 1; }
    console.log('Wire records written to a second bundle: ' + path.join(site, wireBundle) + ' (load it with mergeIndex and an indexWeight below 1)');
  }
  // addDirectory's page_count counts every HTML file it parsed, including the ones left out for want of data-pagefind-body; the CLI printed the pages that reached the index.
  // The bundle's own entry file holds that number (pages + custom records), so the line the workflow greps keeps its old meaning.
  var shown = dir.page_count + ' (files parsed; the index entry could not be read)';
  try {
    var entry = JSON.parse(fs.readFileSync(path.join(site, 'pagefind', 'pagefind-entry.json'), 'utf8'));
    var total = Object.keys(entry.languages).reduce(function (n, l) { return n + entry.languages[l].page_count; }, 0);
    var inFirst = wireBundle ? 0 : added;
    shown = String(total - inFirst);
    console.log('Index entries: ' + total + ' = ' + (total - inFirst) + ' pages + ' + inFirst + ' Wire records in this bundle (' + dir.page_count + ' HTML files parsed, ' + (dir.page_count - (total - inFirst)) + ' without data-pagefind-body left out)');
  } catch (e) { rc = rc || 1; console.log('FAIL  cannot read pagefind-entry.json: ' + e.message); }
  console.log('Indexed ' + shown + ' pages');
  await pagefind.close();
  return rc;
}

main().then(function (rc) { process.exit(rc); }, function (e) { console.log('FAIL  ' + (e && e.stack || e)); process.exit(1); });
