'use strict';

/* Which glossary mark the browser gate's hover and focus rows measure (T-0500.1.11, fix5b).

   THE DEFECT THIS REPLACES. The rows read `document.querySelector(".hl-gloss")`, the first mark in the DOM. On
   new-files-found-20260408 and seasia-gov-exploitation-toolkit-144-172-106-236 that first mark sits in the closed
   `<details class="hl-revisions">` note at the foot of the opening block. A closed <details> paints none of its content,
   and the browser starts no CSS transition on an element that is not rendered: the forced :hover flipped
   `visibility` to visible at once and `opacity` stayed 0 for ever, so "hovering a term reveals its definition" and the
   focus row both FAILED with "opacity 0, visibility visible, definition text present". The same two rows PASS on the same
   page when the mark is one a reader can reach (the details opened, or the next mark chosen), and they FAIL identically on
   the UNTAGGED render, so the tabbed layout was never the cause.

   WHAT A READER CAN DO. A reader cannot hover a mark inside a closed <details>; they open it first. So the rows measure the
   first mark that needs nothing opened. A page whose every mark is inside a closed <details> has the rows measure the first
   mark with its enclosing <details> opened, the way a reader would, and the detail line says so. Nothing is relaxed: the
   predicate on the chosen mark (opacity above 0, visibility visible, definition text present) is unchanged, and a copy of
   the page whose hover rule shows nothing still FAILS it (the control in check-browser-report.js).

   The chosen mark is tagged `data-hl-gate-gloss` so the pseudo-class forcing, which takes a selector, and the style read
   target the same element. The tag lives only in the gate's own throwaway page. */

var ATTR = 'data-hl-gate-gloss';
var SELECTOR = '[' + ATTR + ']';

/* In the page. Returns { marks, index, skippedClosed, openedDetails, term, closedTotal }. */
var PICK_EXPR = '(function(){' +
  'var all=[].slice.call(document.querySelectorAll(".hl-gloss"));' +
  'all.forEach(function(e){e.removeAttribute("' + ATTR + '");});' +
  'if(!all.length)return {marks:0};' +
  'function closedAbove(e){var out=[];for(var n=e.parentElement;n;n=n.parentElement){' +
    'if(n.tagName==="DETAILS"&&!n.open){var s=null;for(var c=n.firstElementChild;c;c=c.nextElementSibling){if(c.tagName==="SUMMARY"){s=c;break;}}' +
    'if(!(s&&s.contains(e)))out.push(n);}}return out;}' +
  'var idx=-1,closedTotal=0;' +
  'for(var i=0;i<all.length;i++){var k=closedAbove(all[i]).length;if(k)closedTotal++;else if(idx<0)idx=i;}' +
  'var opened=false;' +
  'if(idx<0){idx=0;closedAbove(all[0]).forEach(function(d){d.open=true;});opened=true;}' +
  'all[idx].setAttribute("' + ATTR + '","1");' +
  'return {marks:all.length,index:idx,skippedClosed:idx,openedDetails:opened,closedTotal:closedTotal,term:all[idx].textContent.trim()};})()';

/* One line for a row's detail: which mark was measured and why. */
function describe(p) {
  if (!p || !p.marks) return 'no marks';
  var s = 'mark ' + (p.index + 1) + ' of ' + p.marks + ', "' + p.term + '"';
  if (p.openedDetails) s += ' (every mark sits in a closed <details>; its <details> was opened, as a reader must)';
  else if (p.skippedClosed) s += ' (the ' + p.skippedClosed + ' mark(s) before it sit in a closed <details>, which paints nothing a reader can hover)';
  return s;
}

/* The predicate both the rows and their control apply to a measured tooltip state, so the control cannot drift from the rows. */
function revealed(state) {
  return parseFloat(state.opacity) > 0 && state.visibility === 'visible' && !!state.hasText;
}

module.exports = { ATTR: ATTR, SELECTOR: SELECTOR, PICK_EXPR: PICK_EXPR, describe: describe, revealed: revealed };
