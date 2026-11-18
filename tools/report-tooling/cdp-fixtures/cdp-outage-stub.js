'use strict';
/* HL-FIXTURE: a stand-in for lib/cdp.js and lib/page-server.js, loaded with `node --require` ahead of
   tools/report-tooling/check-browser-defang.js so the gate's own source runs unchanged and a lost
   browser connection or a listening server can be injected with no browser on the machine
   (T-0500.1.7.6 finding 4; the reviewer's probe did the same through vm.runInNewContext).

   HL_STUB_CDP_FAIL_ON: a substring of a CDP method name; send() rejects with a notChecked error for a
   method that contains it (empty: every command fails). The error has the shape lib/cdp.js raises when
   the debugging connection drops (lib/cdp.js failPending).

   HL_STUB_SERVER_ERROR: when set, startDir() rejects with that message, the way a denied loopback
   listen now does (T-0500.1.7.6 finding 6).

   HL_STUB_CDP_HARD=1: the rejected error is a plain Error with no notChecked mark (the control: the
   gate must still call a real crash FAIL, so the NOT CHECKED cases are not a gate that always exits 2). */
var Module = require('node:module');
var realLoad = Module._load;
var failOn = process.env.HL_STUB_CDP_FAIL_ON || '';

function lost(method) {
  var e = new Error('stub: the browser debugging connection was lost before ' + method);
  if (process.env.HL_STUB_CDP_HARD !== '1') e.notChecked = true;
  return e;
}

var page = {
  send: function (method) {
    if (!failOn || String(method).indexOf(failOn) > -1) return Promise.reject(lost(method));
    return Promise.resolve({});
  },
  evaluate: function () { return Promise.resolve(null); },
  close: function () {},
  networkFailures: function () { return []; }
};

var cdp = {
  open: function () { return Promise.resolve(page); },
  sleep: function () { return Promise.resolve(); }
};

var server = {
  startDir: function () {
    if (process.env.HL_STUB_SERVER_ERROR) return Promise.reject(new Error(process.env.HL_STUB_SERVER_ERROR));
    return Promise.resolve({ origin: 'http://127.0.0.1:9', misses: [], close: function () {} });
  }
};

Module._load = function (request) {
  if (/[\/\\]cdp\.js$/.test(request)) return cdp;
  if (/[\/\\]page-server\.js$/.test(request)) return server;
  return realLoad.apply(this, arguments);
};
