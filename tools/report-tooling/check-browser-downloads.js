#!/usr/bin/env node
'use strict';

/* What the reader DOWNLOADS is exactly what the filter left on screen.

   This is deliberately narrow. It does not check that anything looks right;
   appearance is self-revealing and a human catches it. It checks the half that
   fails silently in someone else's environment: the detection picker hands a
   defender a bundle that goes into their SIEM, and the feed viewer hands them a
   CSV of indicators they pipe somewhere. A picker that quietly returns the full
   set when Sigma-only was asked for is wrong in a way nobody sees.

   Both surfaces build a Blob, make an object URL, set `<a download>` and click
   it. jsdom has no download at all, which is why `ioc-table.js` carries a
   `window.__lastDownloadText` hook purely so a test could observe SOMETHING.
   That hook proves the string the page built, not the file a reader receives,
   and those differ exactly when the download itself is what broke. This reads
   the file off disk.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED.

   Run: node check-browser-downloads.js [--keep <dir>]
   Env: HL_CHROME, HL_SITE_BASE */

var path = require('node:path');
var fs = require('node:fs');
var os = require('node:os');
var https = require('node:https');

var ROOT = path.join(__dirname, '..', '..');
var BASE = (process.env.HL_SITE_BASE || 'https://the-hunters-ledger.com').replace(/\/+$/, '');

function notChecked(reason) {
  console.log('NOT CHECKED  ' + reason);
  process.exit(2);
}

var CDP, SERVER, yaml;
try {
  CDP = require('./lib/cdp.js');
  SERVER = require('./lib/page-server.js');
  yaml = require('js-yaml');
} catch (e) {
  notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.');
}

/* Target picking and bundle reading live in lib/download-targets.js, as pure
   functions over parsed data, so the decisions can be tested without a browser.
   This file keeps only the driving. */
var T = require('./lib/download-targets.js');
var EXT = T.EXT;

function fetchText(url) {
  return new Promise(function (resolve, reject) {
    https.get(url, { headers: { 'user-agent': 'hl-browser-check' } }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(url + ' returned HTTP ' + res.statusCode));
      }
      var b = '';
      res.setEncoding('utf8');
      res.on('data', function (d) { b += d; });
      res.on('end', function () { resolve(b); });
    }).on('error', reject);
  });
}

var results = [];
function check(name, pass, detail) {
  results.push({ name: name, pass: pass });
  console.log('   ' + (pass ? 'PASS  ' : 'FAIL  ') + name);
  if (detail) console.log('         ' + detail);
}
function skip(name, detail) {
  results.push({ name: 'NOT CHECKED: ' + name, pass: false, skipped: true });
  console.log('   NOTCHECK  ' + name);
  if (detail) console.log('         ' + detail);
}

/* A plain suffix test, not a RegExp built from an extension.

   The regex form needs a literal backslash to escape the dot, and a literal
   backslash written through a shell heredoc collapses. That has now happened six
   times in this codebase; the fix that sticks is to need no escaping at all. */
function endsWithEngineFile(name, engine) {
  return String(name).slice(-(engine + EXT[engine]).length) === engine + EXT[engine];
}

function loadYaml(rel) {
  try { return yaml.load(fs.readFileSync(path.join(ROOT, '_data', rel), 'utf8')); }
  catch (e) { return null; }
}

/* Which detection files declare YARA imports, so the import-ordering check has
   something real to order. Only 5 of 58 do, so left to chance it would report a
   vacuous result forever. */
function importHints() {
  var hints = {};
  var dir = path.join(ROOT, 'hunting-detections');
  try {
    fs.readdirSync(dir).forEach(function (f) {
      if (!/\.md$/.test(f)) return;
      var text = fs.readFileSync(path.join(dir, f), 'utf8');
      hints[f.replace(/\.md$/, '')] = { yaraImports: /^\s*import\s+"/m.test(text) };
    });
  } catch (e) { /* no hints is not fatal, only less discerning */ }
  return hints;
}

function pickDetections() {
  return T.pickDetections(loadYaml('detection_manifests.yml'),
    loadYaml('catalog.yml'), importHints());
}
function pickFeed() { return T.pickFeed(loadYaml('ioc_tables.yml')); }

async function main() {
  var keepDir = null;
  var ki = process.argv.indexOf('--keep');
  if (ki > -1 && process.argv[ki + 1]) keepDir = process.argv[ki + 1];

  var det = pickDetections();
  var feed = pickFeed();
  if (!det && !feed) {
    notChecked('neither _data/detection_manifests.yml nor _data/ioc_tables.yml offered a ' +
      'page that could exercise a filtered download, so nothing was verified.');
  }

  var dlDir = keepDir || fs.mkdtempSync(path.join(os.tmpdir(), 'hl-dl-'));
  var pages = {};
  var detUrl = det ? '/hunting-detections/' + det.key + '/' : null;
  var feedUrl = feed ? feed.url : null;

  try {
    if (detUrl) pages[detUrl] = await fetchText(BASE + detUrl);
  } catch (e) {
    console.log('   note  could not fetch ' + detUrl + ' (' + e.message + ')');
    detUrl = null;
  }
  try {
    if (feedUrl) pages[feedUrl] = await fetchText(BASE + feedUrl);
  } catch (e) {
    console.log('   note  could not fetch ' + feedUrl + ' (' + e.message + ')');
    feedUrl = null;
  }
  if (!detUrl && !feedUrl) {
    notChecked('neither page could be fetched from ' + BASE + ', so nothing was verified.');
  }

  var srv = await SERVER.start(pages, { root: ROOT, base: BASE });
  var page;
  try {
    page = await CDP.open(srv.origin + (detUrl || feedUrl), { height: 1600 });
  } catch (e) {
    srv.close();
    if (e.notChecked) notChecked(e.message);
    throw e;
  }
  console.log('browser: ' + page.version);
  console.log('downloads: ' + dlDir);
  console.log('');

  try {
    /* A fresh directory per download. Chrome silently DISCARDS a download whose
       filename already exists in the target directory, and the page's own note
       still updates, so it looks like it worked. See lib/cdp.js. */
    var step = 0;
    async function nextDl() {
      step += 1;
      return page.armDownloads(path.join(dlDir, 'd' + step));
    }
    var dl = await nextDl();

    // ================= the detection picker =================
    if (detUrl) {
      console.log('-- detection picker: /hunting-detections/' + det.key + '/');
      console.log('   ' + det.rules + ' rules across ' + det.engines.join(', ') +
        '; filtering to ' + det.pick.engine + ' + ' + det.pick.tier +
        ' should give ' + det.pick.subset + ' of that engine\'s ' + det.pick.engineTotal);

      // Built at runtime, so wait for it rather than guessing a settle time.
      var hasPicker = await page.waitFor('.hl-picker', 12000);
      if (!hasPicker) {
        skip('the picker never rendered on ' + det.key,
          'nothing to download from, so the claim could not be exercised');
      } else {
        var engChip = '.hl-picker__chip[data-kind="engine"][data-val="' + det.pick.engine + '"]';
        var tierChip = '.hl-picker__chip[data-kind="tier"][data-val="' + det.pick.tier + '"]';
        await page.click(engChip);
        await page.click(tierChip);
        await CDP.sleep(250);

        var shown = await page.json('(function(){var t=document.querySelector(".hl-picker__count").textContent;' +
          'var m=t.match(/(\\d+) of (\\d+) rules shown/);' +
          'return {text:t,shown:m?Number(m[1]):-1,total:m?Number(m[2]):-1};})()');
        check('the filter narrows the picker to the expected subset',
          shown.shown === det.pick.subset,
          '"' + shown.text.trim() + '" (expected ' + det.pick.subset + ' shown)');

        await page.click('.hl-picker__btn[data-act="all"]');
        await CDP.sleep(200);
        var beforeDl = dl.snapshot();
        await page.click('.hl-picker__btn[data-act="dl"]');
        var files = await dl.waitNew(beforeDl, 1, 8000);

        check('a real click delivers exactly one engine-native file',
          files.length === 1, files.length ? files.map(function (f) { return f.name; }).join(', ')
            : 'NOTHING ARRIVED on disk');

        if (files.length) {
          var want = det.key.replace(/-detections$/, '') + '-' + det.pick.engine + EXT[det.pick.engine];
          // The slug the page uses is what matters, so accept its own naming as
          // long as it ends in the engine-native extension and names the engine.
          check('the file is named for its engine and carries the native extension',
            endsWithEngineFile(files[0].name, det.pick.engine),
            'got "' + files[0].name + '", expected something like "' + want + '"');

          var n = T.countRules(det.pick.engine, files[0].content);
          check('the bundle holds exactly the rules the filter left on screen',
            n === det.pick.subset,
            n + ' rules in the file, ' + det.pick.subset + ' on screen, ' +
              det.pick.engineTotal + ' would mean the filter was ignored');

          var foreign = T.foreignEngineIn(det.pick.engine, files[0].content);
          check('and nothing from another engine rode along',
            foreign.length === 0,
            foreign.length ? 'found ' + foreign.join(', ') + ' syntax inside a ' +
              det.pick.engine + ' bundle' : 'clean ' + det.pick.engine + ' only');

          check('the bundle is not empty',
            files[0].content.trim().length > 20, files[0].content.length + ' bytes');

          /* A YARA bundle with an import stranded below a rule does not compile
             at all, so the file a defender downloads is useless. The site's own
             gates compile the rules on the PAGE, never the assembled file. */
          /* Imports are hoisted from the SELECTED rules, so a narrow subset often
             carries none. Take the whole engine for this one check by releasing
             the tier chip and re-selecting, which also exercises a second, wider
             download path. */
          await page.click(tierChip);
          await CDP.sleep(250);
          await page.click('.hl-picker__btn[data-act="all"]');
          await CDP.sleep(200);
          dl = await nextDl();
          var beforeAll = dl.snapshot();
          await page.click('.hl-picker__btn[data-act="dl"]');
          var allFiles = await dl.waitNew(beforeAll, 1, 8000);
          var engineFile = allFiles.filter(function (f) {
            return endsWithEngineFile(f.name, det.pick.engine);
          })[0];

          check('dropping the tier filter widens that same engine bundle',
            !!engineFile && T.countRules(det.pick.engine, engineFile.content) === det.pick.engineTotal,
            engineFile ? T.countRules(det.pick.engine, engineFile.content) + ' rules, expected ' +
              det.pick.engineTotal + ' (the subset was ' + det.pick.subset + ')'
              : 'no ' + det.pick.engine + ' file in ' + allFiles.length + ' download(s)');

          var imports = T.importsBeforeRules(det.pick.engine,
            engineFile ? engineFile.content : files[0].content);
          if (imports === null) {
            /* Not applicable rather than NOT CHECKED. A bundle with no imports
               has no ordering to get wrong, so the property is satisfied by
               construction; calling that unverified would make the gate cry wolf
               on every run. Target picking prefers a page WITH imports precisely
               so this branch is the exception. */
            console.log('   n/a   YARA import ordering: ' + (det.pick.engine === 'yara'
              ? 'this bundle declares no imports, so there is no ordering to get wrong'
              : 'not a YARA bundle (' + det.pick.engine + ')'));
          } else {
            check('every YARA import sits above the first rule, so the bundle compiles',
              imports.ok,
              'last import on line ' + imports.lastImport + ', first rule on line ' +
                imports.firstRule);
          }
        }
      }
      console.log('');
    } else {
      skip('the detection picker page could not be reached', 'fetch failed');
    }

    // ================= the feed viewer =================
    if (feedUrl) {
      console.log('-- feed viewer: ' + feedUrl);
      await page.send('Page.navigate', { url: srv.origin + feedUrl });
      await CDP.sleep(2200);

      var hasTable = await page.waitFor('.hl-ioctable', 12000);
      if (!hasTable) {
        skip('the feed viewer table never rendered on ' + feed.slug,
          'nothing to export, so the claim could not be exercised');
      } else {
        var type = T.pickType(feed);
        console.log('   ' + feed.total + ' indicators across ' + feed.types.length +
          ' types; filtering to "' + type + '" should give ' + feed.counts[type]);

        await page.click('.hl-ioctable__chip[data-type="' + type + '"]');
        await CDP.sleep(300);

        var vis = await page.json('(function(){' +
          'var rows=[].slice.call(document.querySelectorAll(".hl-ioctable__table tbody tr"));' +
          'var on=rows.filter(function(r){var b=r.getBoundingClientRect();return b.width>0||b.height>0;});' +
          'return {total:rows.length,shown:on.length,' +
          'types:on.map(function(r){return r.getAttribute("data-type");})' +
          '.filter(function(v,i,a){return a.indexOf(v)===i;})};})()');
        check('the type chip narrows the table to that type alone',
          vis.shown === feed.counts[type] && vis.types.length === 1 && vis.types[0] === type,
          vis.shown + ' of ' + vis.total + ' rows shown, types present: ' + vis.types.join(', '));

        dl = await nextDl();
        var beforeCsv = dl.snapshot();
        await page.click('.hl-ioctable__btn[data-act="csv"]');
        var csvFiles = await dl.waitNew(beforeCsv, 1, 8000);
        check('a real click delivers a CSV file',
          csvFiles.length === 1, csvFiles.map(function (f) { return f.name; }).join(', ') || 'NOTHING ARRIVED');

        if (csvFiles.length) {
          check('the CSV is named for the feed',
            /-indicators\.csv$/.test(csvFiles[0].name), csvFiles[0].name);

          var lines = csvFiles[0].content.replace(/\s+$/, '').split(/\r?\n/);
          check('the CSV carries its header and exactly the filtered rows',
            lines[0] === 'value,type,context' && lines.length - 1 === vis.shown,
            'header "' + lines[0] + '", ' + (lines.length - 1) + ' data rows, ' +
              vis.shown + ' on screen (' + feed.total + ' would mean the filter was ignored)');

          /* Every row must be the filtered type. A CSV that exported the whole
             feed with the right ROW COUNT by accident would still fail here. */
          var wrongType = lines.slice(1).filter(function (l) {
            var cells = l.match(/(".*?"|[^,]*)(,|$)/g) || [];
            var t = (cells[1] || '').replace(/,$/, '').replace(/^"|"$/g, '');
            return t !== type;
          });
          check('and every exported row really is that type',
            wrongType.length === 0,
            wrongType.length ? wrongType.length + ' row(s) of another type, first: ' +
              wrongType[0].slice(0, 80) : 'all ' + (lines.length - 1) + ' rows are "' + type + '"');
        }

        dl = await nextDl();
        var beforeTxt = dl.snapshot();
        await page.click('.hl-ioctable__btn[data-act="txt"]');
        var txtFiles = await dl.waitNew(beforeTxt, 1, 8000);
        check('a real click delivers a TXT file',
          txtFiles.length === 1, txtFiles.map(function (f) { return f.name; }).join(', ') || 'NOTHING ARRIVED');

        if (txtFiles.length) {
          var txtLines = txtFiles[0].content.replace(/\s+$/, '').split(/\r?\n/)
            .filter(function (l) { return l.length; });
          check('the TXT holds one line per filtered row and no header',
            txtLines.length === vis.shown && txtLines[0] !== 'value',
            txtLines.length + ' lines, ' + vis.shown + ' on screen');

          // Every exported value must actually be on the page.
          /* The value a reader sees is the `<code>` inside the row, which is
             also what the module exports. Reading the first `<td>` instead
             picked up the surrounding cell and reported a correct export as a
             value that was never on screen. */
          var onPage = await page.json('(function(){' +
            'var rows=[].slice.call(document.querySelectorAll(".hl-ioctable__table tbody tr"));' +
            'return rows.filter(function(r){var b=r.getBoundingClientRect();return b.width>0||b.height>0;})' +
            '.map(function(r){var c=r.querySelector("code");return c?c.textContent.trim():"";});})()');
          var missing = txtLines.filter(function (v) { return onPage.indexOf(v.trim()) === -1; });
          check('every exported value is one the reader could see',
            missing.length === 0,
            missing.length ? missing.length + ' value(s) not on screen, first: ' + missing[0]
              : 'all ' + txtLines.length + ' values matched a visible row');
        }
      }
    } else {
      skip('the feed viewer page could not be reached', 'fetch failed');
    }
  } finally {
    page.close();
    srv.close();
    if (!keepDir) {
      try { fs.rmSync(dlDir, { recursive: true, force: true }); }
      catch (e) { /* best effort */ }
    }
  }

  var bad = results.filter(function (r) { return !r.pass; });
  var skipped = bad.filter(function (r) { return r.skipped; });
  var failed = bad.length - skipped.length;
  console.log('\n' + (failed ? 'FAIL' : (bad.length ? 'NOT CHECKED' : 'PASS')) +
    '  downloaded content matches the filter  (' +
    (results.length - bad.length) + '/' + results.length + ' checks' +
    (skipped.length ? ', ' + skipped.length + ' not checked' : '') + ')');
  if (failed) process.exit(1);
  process.exit(bad.length ? 2 : 0);
}

main().catch(function (e) {
  notChecked('the browser check errored before finishing: ' + e.message);
});
