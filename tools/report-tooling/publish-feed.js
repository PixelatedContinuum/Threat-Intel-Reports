#!/usr/bin/env node
'use strict';

/* Copies a vault IOC feed into this repo's ioc-feeds/, without its private metadata.

     node tools/report-tooling/publish-feed.js <vault feed path> [--out-dir <dir>]

   This is the go-live copy step (hunters-ledger-publish, references/preview-and-go-live.md).
   Use it instead of `cp`: the vault feed carries `metadata.victim_names`, the list of victim
   identifiers the naming gate searches for, and a plain copy publishes that list
   (lib/feed-private.js has the history). The output file keeps the vault feed's name and
   every other field in its original order, written with two spaces and a trailing newline,
   the corpus style.

   It prints the keys it removed, or that there were none. Exit codes: 0 written, 1 refused
   (the input is not a JSON object), 2 could not run (unreadable input, unwritable output). */

var fs = require('node:fs');
var path = require('node:path');
var P = require('./lib/feed-private.js');

var DEFAULT_OUT = path.join(__dirname, '..', '..', 'ioc-feeds');

function publish(src, outDir) {
  var raw = fs.readFileSync(src, 'utf8').replace(/^﻿/, '');
  var feed = JSON.parse(raw);
  if (!feed || typeof feed !== 'object' || Array.isArray(feed)) {
    return { status: 1, message: 'REFUSED  ' + src + ' is not a JSON object, so it is not a feed this tool can publish' };
  }
  var r = P.strip(feed);
  var dest = path.join(outDir, path.basename(src));
  fs.writeFileSync(dest, JSON.stringify(r.feed, null, 2) + '\n', 'utf8');
  return {
    status: 0, dest: dest, removed: r.removed,
    message: 'WROTE  ' + dest + '\n  removed private metadata: ' +
      (r.removed.length ? r.removed.join(', ') : 'none present (checked: ' + P.PRIVATE_METADATA_KEYS.join(', ') + ')')
  };
}

if (require.main === module) {
  var args = process.argv.slice(2);
  var outDir = DEFAULT_OUT, src = null;
  for (var i = 0; i < args.length; i++) {
    if (args[i] === '--out-dir') outDir = args[++i];
    else if (!src) src = args[i];
  }
  if (!src || !outDir) {
    console.log('usage: publish-feed.js <vault feed path> [--out-dir <dir>]');
    process.exit(2);
  }
  var res;
  try { res = publish(src, outDir); }
  catch (e) { console.log('NOT DONE  ' + e.message); process.exit(2); }
  console.log(res.message);
  process.exit(res.status);
}

module.exports = { publish: publish, DEFAULT_OUT: DEFAULT_OUT };
