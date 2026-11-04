/* Concept 3 cover texture (T-0556 w2): fills each aria-hidden .c3-cover__tex with a hexdump of its own data-hex text, the same bytes repeated.
   Pure decoration: without this script the cover is a plain dark field with its real-text label. */
(function () {
  var pres = document.querySelectorAll('pre.c3-cover__tex[data-hex]');
  for (var n = 0; n < pres.length; n++) {
    var s = pres[n].getAttribute('data-hex') || '', b = [], out = '', i, r, c;
    for (i = 0; i < s.length; i++) b.push(s.charCodeAt(i) & 255);
    if (!b.length) b.push(0);
    while (b.length < 900) b = b.concat(b);
    for (r = 0; r < 40; r++) {
      var off = ('00000000' + (r * 16).toString(16)).slice(-8), hx = '', as = '';
      for (c = 0; c < 16; c++) {
        var v = b[r * 16 + c];
        hx += ('0' + v.toString(16)).slice(-2) + (c === 7 ? '  ' : ' ');
        as += (v > 31 && v < 127) ? String.fromCharCode(v) : '.';
      }
      out += off + '  ' + hx + ' |' + as + '|\n';
    }
    pres[n].textContent = out;
  }
})();
