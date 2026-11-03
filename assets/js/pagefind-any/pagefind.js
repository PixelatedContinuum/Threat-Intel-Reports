/* The Hunter's Ledger (T-0553): a thin front for /pagefind/pagefind.js that makes several ticked
   values of one filter match any of them (OR) instead of all of them (AND). /search/ points
   PagefindUI's bundlePath at this folder; every other export is Pagefind's own, untouched, and the
   index, the wasm and the merged Wire bundle still load from /pagefind/ (this file imports the real
   module by a path relative to itself, so a site baseurl does not matter). Pagefind pinned at 1.3.0. */
import { anyOptions } from './filters.mjs';

const pf = await import(new URL('../../../pagefind/pagefind.js', import.meta.url).href);

export const init = pf.init;
export const options = pf.options;
export const mergeIndex = pf.mergeIndex;
export const filters = pf.filters;
export const destroy = pf.destroy;
export const search = (term, opts) => pf.search(term, anyOptions(opts));
export const preload = (term, opts) => pf.preload(term, anyOptions(opts));
export const debouncedSearch = (term, opts, wait) => pf.debouncedSearch(term, anyOptions(opts), wait);
