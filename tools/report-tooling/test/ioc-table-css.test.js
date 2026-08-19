'use strict';

/* The first test in this repo that reads CSS.

   CSS has been the standing blind spot: five defects have shipped with every
   suite green, every one caught by a human looking at the page. This suite does
   not fix that in general and does not pretend to. It has no layout, no browser
   and no rendering, so it cannot tell you whether the page looks right.

   What it CAN do is pin the structural defect classes that have actually shipped
   here, all of which are visible in the source text:

   1. A DECLARED-THEN-DISCARDED COLOUR. On the Wire, `.hl-wire__item` and
      `.hl-wire__item--src-x` both scored (0,1,0), so source order won and every
      publisher colour was defined and then thrown away. The fix was to declare
      the default on the CONTAINER so it is inherited, because a directly-set
      value beats an inherited one whatever the specificity. If the default for
      --ioct-type ever moves onto the chip itself, that bug is back.

   2. A CATEGORY WITH NO COLOUR. A Wire topic whose colour fell outside the CSS
      palette still filtered correctly and just rendered grey among coloured
      siblings, which is what made the first build look flat. Here the categories
      are the extractor's own TYPE_ORDER, so the two files are checked against
      each other rather than one being trusted.

   3. A UNIT COPIED FROM ANOTHER COMPONENT. The theme sets body { font-size:
      1.25em } = 20px while `rem` resolves against the 16px root, so anything
      sized in rem renders 22% small. Copying a number between components is
      safe; copying a unit is not.

   4. A MANGLED ESCAPE. `\\25B8` written through a tooling layer that collapses
      doubled backslashes arrived as octal `\\25` = 0x15, an unprintable control
      character, and the page rendered "B8". */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var X = require('../lib/ioc-table-extract.js');

var CSS = fs.readFileSync(
  path.join(__dirname, '..', '..', '..', 'assets', 'css', 'custom.css'), 'utf8');

// The stretch of stylesheet this component owns.
var BLOCK = (function () {
  var i = CSS.indexOf('.hl-ioctable {');
  assert.ok(i > -1, 'the ioctable block is missing from custom.css entirely');
  return CSS.slice(i);
}());

function hueFor(type) {
  var re = new RegExp('\\.hl-ioctable \\[data-type="' + type +
                      '"\\][^{]*\\{[^}]*--ioct-type:\\s*(#[0-9a-fA-F]{3,8})');
  var m = re.exec(CSS);
  return m ? m[1].toLowerCase() : null;
}

test('EVERY INDICATOR TYPE THE EXTRACTOR EMITS HAS A COLOUR', function () {
  // Checked against the extractor rather than a hardcoded list, so adding a type
  // without adding its hue fails here instead of rendering grey among coloured
  // siblings, which is exactly how the Wire's first build looked flat.
  var missing = X.TYPE_ORDER.filter(function (t) { return !hueFor(t); });
  assert.deepEqual(missing, [], 'types with no --ioct-type hue: ' + missing.join(', '));
});

test('no hue is used twice, so two types are never indistinguishable', function () {
  var seen = {}, dupes = [];
  X.TYPE_ORDER.forEach(function (t) {
    var h = hueFor(t);
    if (!h) return;
    if (seen[h]) dupes.push(t + ' shares ' + h + ' with ' + seen[h]);
    else seen[h] = t;
  });
  assert.deepEqual(dupes, [], dupes.join('; '));
});

test('THE DEFAULT IS DECLARED ON THE CONTAINER, NOT ON THE CHIP', function () {
  /* The cascade lesson, pinned. A var() default written on `.hl-ioctable__chip`
     would be an override rather than a fallback, and every per-type colour would
     be defined and then discarded by source order. This is the bug that shipped
     on the Wire. */
  var container = /\.hl-ioctable \{[^}]*--ioct-type:/.test(BLOCK);
  assert.ok(container, '--ioct-type has no default on the .hl-ioctable container');

  var chipBlock = /\.hl-ioctable__chip \{([^}]*)\}/.exec(BLOCK);
  assert.ok(chipBlock, '.hl-ioctable__chip rule is missing');
  assert.ok(chipBlock[1].indexOf('--ioct-type:') === -1,
    '--ioct-type is declared on the chip itself, which makes every per-type ' +
    'colour an override that source order will discard');
});

test('the chip and the table label read the same variable', function () {
  // A chip painted differently from the rows it filters to would be worse than
  // no colour at all.
  var chip = /\.hl-ioctable__chip \{([^}]*)\}/.exec(BLOCK)[1];
  var label = /\.hl-ioctable__type \{([^}]*)\}/.exec(BLOCK)[1];
  assert.match(chip, /color:\s*var\(--ioct-type\)/);
  assert.match(label, /color:\s*var\(--ioct-type\)/);
});

test('one selector paints both surfaces, so a chip cannot drift from its rows', function () {
  // The chip button and the <tr> both carry data-type, so the palette rules are
  // scoped to the container rather than to either element.
  X.TYPE_ORDER.forEach(function (t) {
    var scoped = new RegExp('\\.hl-ioctable \\[data-type="' + t + '"\\]');
    assert.ok(scoped.test(CSS), t + ' is painted by an element-specific selector');
  });
});

test('nothing in this component is sized in rem', function () {
  // The theme sets body { font-size: 1.25em } = 20px; rem resolves against the
  // 16px root, so a rem here renders 22% small.
  var bad = BLOCK.split('\n').filter(function (l) { return /\d\s*rem\b/.test(l); });
  assert.deepEqual(bad, [], 'rem used in: ' + bad.join(' | '));
});

test('the stylesheet carries no unprintable control characters', function () {
  var bad = [];
  for (var i = 0; i < CSS.length; i++) {
    var c = CSS.charCodeAt(i);
    if (c < 32 && c !== 10 && c !== 13 && c !== 9) {
      bad.push('0x' + c.toString(16) + ' at ' + i);
    }
  }
  assert.deepEqual(bad, [], 'control characters: ' + bad.slice(0, 5).join(', '));
});

test('the hues come from the palette the rest of the site already uses', function () {
  // Reusing the Wire's topic palette is what makes a coloured thing on this site
  // mean the same kind of thing everywhere. A hue invented here would be the
  // first exception.
  var wire = {};
  var re = /--wire-topic:\s*(#[0-9a-fA-F]{6})/g, m;
  while ((m = re.exec(CSS))) wire[m[1].toLowerCase()] = true;
  assert.ok(Object.keys(wire).length >= 10, 'the wire palette was not found to compare against');

  var strays = X.TYPE_ORDER.map(hueFor).filter(Boolean)
    .filter(function (h) { return !wire[h]; });
  assert.deepEqual(strays, [], 'hues not in the site palette: ' + strays.join(', '));
});

test('THE CLEAR BUTTON HONOURS [hidden] AGAINST THE FLEX ROW', function () {
  /* A real defect class rather than a hypothetical one: `display: flex` on a
     container sets `display` on its children, which beats the `display: none`
     that the `hidden` attribute relies on. The control then ships "hidden" and
     is plainly visible. Only an explicit rule closes it. */
  var m = /\.hl-ioctable__clear\[hidden\]\s*\{([^}]*)\}/.exec(CSS);
  assert.ok(m, 'no [hidden] rule for the clear button');
  assert.match(m[1], /display:\s*none/);
});

test('the clear button is not coloured, so it reads as an escape hatch', function () {
  // The chips carry meaning through hue. A coloured clear button would read as
  // an eleventh indicator type.
  var m = /\.hl-ioctable__clear \{([^}]*)\}/.exec(CSS);
  assert.ok(m, '.hl-ioctable__clear rule is missing');
  assert.ok(m[1].indexOf('--ioct-type') === -1,
    'the clear button reads the per-type hue and will look like a type chip');
});
