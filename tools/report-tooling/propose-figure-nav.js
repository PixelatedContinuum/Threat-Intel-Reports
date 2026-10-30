'use strict';

/* Authoring aid for figure_nav. Prints each report's figures beside its heading
   anchors so parts can be matched to sections by eye, and emits a starter block
   ready to paste into front matter.

   It proposes nothing about WHICH sections a graphic's parts belong to, because
   that needs the picture, and the part names live in hand-written English inside
   a long alt attribute. Guessing them is the prose parsing the design rejected,
   and the same fragility that produced nine ATT&CK table shapes.

   What it does do is remove the one step a person cannot do reliably: writing the
   anchor. Anchors are generated ids, invisible in the markdown, and wrong ones
   fail silently. */

var fs = require('node:fs');
var path = require('node:path');
var KS = require('./lib/kramdown-slug.js');
var CFN = require('./lib/check-figure-nav.js');
var RT = require('./lib/report-target.js');

var ROOT = path.join(__dirname, '..', '..');
var REPORTS = path.join(ROOT, 'reports');

function altFor(md, image) {
  var found = null;
  md.replace(/<figure[\s\S]*?<\/figure>/g, function (block) {
    if (found) return block;
    var m = block.match(/\/assets\/images\/[^"'\s)]*?\/([^/"'\s)]+\.svg)/);
    if (!m || m[1] !== image) return block;
    var a = block.match(/alt="([^"]*)"/);
    if (a) found = a[1];
    return block;
  });
  return found;
}

var args = process.argv.slice(2);
var showAlt = args.indexOf('--alt') !== -1;
var only = args.filter(function (a) { return a.indexOf('--') !== 0; })[0];

/* This tool only prints. A --write (or --apply) would otherwise be ignored while
   looking like it ran, so it is refused outright, with or without a target
   (T-0500.1.9, audit I03). */
if (args.indexOf('--write') !== -1 || args.indexOf('--apply') !== -1) {
  console.error('refusing --write: propose-figure-nav.js only prints a starter block to paste ' +
    'into front matter; it never writes a report.');
  process.exit(2);
}

var targets;
if (only) {
  var t = RT.resolveTarget(only, REPORTS);
  if (t.error) { console.error(t.error); process.exit(2); }
  if (!fs.existsSync(t.file)) { console.error('no index.md at ' + t.file); process.exit(2); }
  targets = [t];
} else {
  targets = fs.readdirSync(REPORTS, { withFileTypes: true })
    .filter(function (e) { return e.isDirectory(); })
    .map(function (e) { return e.name; })
    .sort()
    .map(function (n) { return { mode: 'name', slug: n, file: path.join(REPORTS, n, 'index.md') }; });
}

var totalFigures = 0;
var totalReports = 0;

targets.forEach(function (target) {
  var slug = target.mode === 'path' ? target.file : target.slug;
  var file = target.file;
  if (!fs.existsSync(file)) return;
  var md = fs.readFileSync(file, 'utf8');
  var images = CFN.figureImages(md);
  if (!images.length) return;

  totalReports++;
  totalFigures += images.length;

  var declared = CFN.parseFigureNav(CFN.frontMatter(md)) || [];
  var have = {};
  declared.forEach(function (e) { have[e.image] = e.parts.length; });

  console.log('');
  console.log('===== ' + slug + '  (' + images.length + ' figures, ' +
    declared.length + ' declared) =====');

  console.log('-- anchors --');
  KS.headings(md).forEach(function (h) {
    if (h.level > 3) return;
    var pad = h.level === 3 ? '    ' : '  ';
    console.log(pad + h.text + (h.inDetails ? '   [in teardown]' : ''));
    console.log(pad + '  #' + h.slug);
  });

  console.log('-- figures --');
  images.forEach(function (n) {
    console.log('  ' + n + (have[n] ? '   [declared, ' + have[n] + ' parts]' : '   [none]'));
    if (showAlt) {
      var alt = altFor(md, n);
      if (alt) console.log('      alt: ' + alt.replace(/\s+/g, ' ').slice(0, 2000));
    }
  });

  var todo = images.filter(function (n) { return !have[n]; });
  if (!todo.length) { console.log('-- nothing left to declare --'); return; }

  console.log('-- starter block --');
  console.log('figure_nav:');
  todo.forEach(function (n) {
    console.log('  - image: ' + n);
    console.log('    parts:');
    console.log('      - label: ""');
    console.log('        anchor: "#"');
  });
});

console.log('');
console.log(totalReports + ' reports carry figures, ' + totalFigures + ' figures in total');
