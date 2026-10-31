#!/usr/bin/env node
'use strict';
/* HL-FIXTURE: a stand-in for a Chromium binary, for test/cdp-isolation.test.js and cdp-fixtures/.

   It takes the flags lib/cdp.js passes a real browser (--user-data-dir,
   --remote-debugging-port), serves /json/version and /json/list, writes
   DevToolsActivePort the way Chrome does, and answers every CDP command over a
   websocket. Runtime.evaluate returns HL_FAKE_TITLE for any expression that
   mentions document.title and null otherwise, so a test can tell WHICH fake it
   was talking to. Like Chrome, a fake that cannot bind its requested port keeps
   running without a debugging port.

   HL_FAKE_MODE: exit-early | no-port-file | wrong-id | hang-eval | die-on-eval
   HL_FAKE_CONN_LOG: a file that gets one line per websocket connection. */
var http = require('node:http');
var fs = require('node:fs');
var path = require('node:path');
var crypto = require('node:crypto');
var WebSocket = require('ws');

var args = process.argv.slice(2);
if (args.indexOf('--version') >= 0) { console.log('FakeBrowser 1.0'); process.exit(0); }
function arg(name) {
  for (var i = 0; i < args.length; i++) if (args[i].indexOf(name + '=') === 0) return args[i].slice(name.length + 1);
  return null;
}
var dir = arg('--user-data-dir');
var want = Number(arg('--remote-debugging-port') || 0);
var mode = process.env.HL_FAKE_MODE || '';
var title = process.env.HL_FAKE_TITLE || 'OWN';
if (mode === 'exit-early') process.exit(3);

var browserId = crypto.randomUUID();
var port = 0;
var server = http.createServer(function (req, res) {
  res.setHeader('content-type', 'application/json');
  if (req.url === '/json/version') {
    var shown = mode === 'wrong-id' ? crypto.randomUUID() : browserId;
    res.end(JSON.stringify({ Browser: 'FakeChrome/1.0', webSocketDebuggerUrl: 'ws://127.0.0.1:' + port + '/devtools/browser/' + shown }));
  } else if (req.url === '/json/list') {
    res.end(JSON.stringify([{ type: 'page', title: title, webSocketDebuggerUrl: 'ws://127.0.0.1:' + port + '/devtools/page/P1' }]));
  } else { res.statusCode = 404; res.end('{}'); }
});
var wss = new WebSocket.Server({ server: server });
wss.on('connection', function (sock) {
  if (process.env.HL_FAKE_CONN_LOG) fs.appendFileSync(process.env.HL_FAKE_CONN_LOG, 'conn\n');
  sock.on('message', function (raw) {
    var m = JSON.parse(raw.toString());
    if (m.method === 'Runtime.evaluate') {
      if (mode === 'hang-eval') return;
      if (mode === 'die-on-eval') process.exit(4);
      var expr = (m.params && m.params.expression) || '';
      sock.send(JSON.stringify({ id: m.id, result: { result: { value: expr.indexOf('document.title') >= 0 ? title : null } } }));
    } else {
      sock.send(JSON.stringify({ id: m.id, result: {} }));
    }
  });
});
server.on('error', function () { /* port taken: Chrome keeps running without a debugging port */ });
server.listen(want, '127.0.0.1', function () {
  port = server.address().port;
  if (mode !== 'no-port-file' && dir) {
    fs.writeFileSync(path.join(dir, 'DevToolsActivePort'), port + '\n/devtools/browser/' + browserId);
  }
});
setInterval(function () {}, 1 << 30); // stay alive even when the port could not be bound
process.on('SIGTERM', function () { process.exit(0); });
