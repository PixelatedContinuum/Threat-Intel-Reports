'use strict';
/* HL-FIXTURE: opens one page through lib/cdp.js (or the module named by HL_CDP_MODULE),
   prints {pid, port, profileDir, title} as one JSON line, then does what argv[2] says:
   hang | exit | throw | close. Used by test/cdp-isolation.test.js and cdp-fixtures/ to end a run in each way a run can end. */
var CDP = require(process.env.HL_CDP_MODULE || '../lib/cdp.js');
(async function () {
  var p = await CDP.open('about:blank', { settle: 50, port: process.env.HL_RUNNER_PORT ? Number(process.env.HL_RUNNER_PORT) : undefined });
  console.log(JSON.stringify({ pid: p.pid, watchdog: p.watchdog, port: p.port, profileDir: p.profileDir, title: await p.evaluate('document.title') }));
  var how = process.argv[2];
  if (how === 'hang') await new Promise(function () {});
  if (how === 'exit') process.exit(0);
  if (how === 'throw') { setTimeout(function () { throw new Error('boom after open'); }, 10); await new Promise(function () {}); }
  p.close();
})().catch(function (e) { console.log('ERR ' + (e.notChecked ? 'NC ' : '') + e.message); process.exit(e.notChecked ? 2 : 1); });
