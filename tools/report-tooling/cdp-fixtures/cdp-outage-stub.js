'use strict';
/* HL-FIXTURE: a stand-in for lib/cdp.js and lib/page-server.js, loaded with `node --require` ahead of
   a browser gate (check-browser-defang.js, check-browser-downloads.js, check-browser-report.js,
   check-browser-wire.js) so the gate's own source runs unchanged and a lost browser connection or a
   listening server can be injected with no browser on the machine (T-0500.1.7.6 finding 4; the
   reviewer's probe did the same through vm.runInNewContext).

   HL_STUB_CDP_FAIL_ON: a substring of a CDP method name; send() rejects with a notChecked error for a
   method that contains it (empty: every command fails). The error has the shape lib/cdp.js raises when
   the debugging connection drops (lib/cdp.js failPending).

   HL_STUB_SERVER_ERROR: when set, startDir() and start() reject with that message, the way a
   denied loopback listen does. The error carries notChecked, as lib/page-server.js:96-99 and
   :150-153 mark it (T-0500.1.7.6 finding 6).

   HL_STUB_CDP_HARD=1: the rejected error is a plain Error with no notChecked mark (the control: the
   gate must still call a real crash FAIL, so the NOT CHECKED cases are not a gate that always exits 2).

   HL_STUB_FETCH_HTML: when set, node:http and node:https answer every get() with this body and HTTP
   200 instead of reaching the network. A gate that fetches its page before it opens the browser
   (downloads, report, wire in LIVE mode) needs it to reach the code under test with nothing outbound;
   the fetched body is only what the gate is about to hand to a stubbed browser. Unset, both modules
   are the real ones.

   T-0678: page.label, page.json and page.armDownloads are here because those gates call them; each
   goes through the same send() so HL_STUB_CDP_FAIL_ON reaches it. Nothing else is faked: a gate that
   needs another browser method fails loudly rather than reading a made-up page. */
var Module = require('node:module');
var realLoad = Module._load;
var failOn = process.env.HL_STUB_CDP_FAIL_ON || '';

function lost(method) {
  var e = new Error('stub: the browser debugging connection was lost before ' + method);
  if (process.env.HL_STUB_CDP_HARD !== '1') e.notChecked = true;
  return e;
}

var page = {
  label: 'stub browser (cdp-outage-stub.js)',
  send: function (method) {
    if (!failOn || String(method).indexOf(failOn) > -1) return Promise.reject(lost(method));
    return Promise.resolve({});
  },
  evaluate: function () {
    return page.send('Runtime.evaluate', {}).then(function () { return null; });
  },
  json: function () {
    // lib/cdp.js json() is JSON.parse over an evaluate of JSON.stringify: same two steps, same method.
    return page.evaluate().then(function () { return {}; });
  },
  // lib/cdp.js armDownloads() sends Browser.setDownloadBehavior before it returns the handle.
  armDownloads: function (dir) {
    return page.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dir }).then(function () {
      return {
        snapshot: function () { return 0; },
        waitNew: function () { return Promise.resolve([]); },
        canceled: function () { return []; }
      };
    });
  },
  close: function () {},
  networkFailures: function () { return []; }
};

var cdp = {
  open: function () { return Promise.resolve(page); },
  sleep: function () { return Promise.resolve(); }
};

function listenRefused() {
  var e = new Error(process.env.HL_STUB_SERVER_ERROR);
  e.notChecked = true;   // lib/page-server.js start() and startDir() mark a listener that cannot bind
  return e;
}

var server = {
  startDir: function () {
    if (process.env.HL_STUB_SERVER_ERROR) return Promise.reject(listenRefused());
    return Promise.resolve({ origin: 'http://127.0.0.1:9', misses: [], close: function () {} });
  },
  start: function () {
    if (process.env.HL_STUB_SERVER_ERROR) return Promise.reject(listenRefused());
    return Promise.resolve({ origin: 'http://127.0.0.1:9', misses: [], close: function () {} });
  }
};

/* A copy with its own descriptors, not Object.create(real): a module that does
   `for (var k in mod)` then `getOwnPropertyDescriptor(mod, k)` (the tsc __importStar
   helper, agent-base and jsdom use it) reads an inherited key as undefined and
   crashes. Everything but get() is the real module's own property. */
function withFakeGet(real) {
  var body = process.env.HL_STUB_FETCH_HTML;
  var m = {};
  Object.getOwnPropertyNames(real).forEach(function (k) {
    var d = Object.getOwnPropertyDescriptor(real, k);
    if (d) Object.defineProperty(m, k, d);
  });
  m.get = function (url, opts, cb) {
    if (typeof opts === 'function') cb = opts;
    var req = { on: function () { return req; } };
    process.nextTick(function () {
      var res = {
        statusCode: 200, headers: {},
        setEncoding: function () {},
        resume: function () {},
        on: function (ev, fn) { if (ev === 'data') fn(body); if (ev === 'end') fn(); return res; }
      };
      cb(res);
    });
    return req;
  };
  return m;
}

Module._load = function (request) {
  if (/[\/\\]cdp\.js$/.test(request)) return cdp;
  if (/[\/\\]page-server\.js$/.test(request)) return server;
  if (process.env.HL_STUB_FETCH_HTML && /^(node:)?https?$/.test(request)) {
    return withFakeGet(realLoad.apply(this, arguments));
  }
  return realLoad.apply(this, arguments);
};
