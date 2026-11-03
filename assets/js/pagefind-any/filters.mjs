/* The Hunter's Ledger (T-0553): Pagefind filter values combine with OR on /search/.
   Pagefind's search() reads { section: ['Reports', 'Detections'] } as "all of these" (AND). Every
   page carries exactly one Section value, so two ticked Sections matched nothing. The documented
   shape for "any of these" is { section: { any: [...] } }. PagefindUI always builds the array
   shape, so pagefind-any/pagefind.js rewrites it here on the way to Pagefind. */
export function anyFilters(filters) {
  if (!filters || typeof filters !== 'object') return filters;
  const out = {};
  for (const key of Object.keys(filters)) {
    const v = filters[key];
    out[key] = Array.isArray(v) && v.length > 1 ? { any: v.slice() } : v;
  }
  return out;
}

/* Rewrite the filters of a search()/preload()/debouncedSearch() options object; everything else passes through. */
export function anyOptions(opts) {
  if (!opts || typeof opts !== 'object' || !opts.filters) return opts;
  return Object.assign({}, opts, { filters: anyFilters(opts.filters) });
}
