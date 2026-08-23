// Pure-logic unit tests for app/v2/ui/data-grid.js's comparator, runnable
// with plain Node (no jsdom/browser dependency -- the DOM-wiring half of
// the module is skipped automatically when `document` is undefined, see
// the `hasDom` guard at the top of the module).
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { parseCellValue, compareCells } = require('../../app/v2/ui/data-grid.js');

// Numeric values compare numerically, not lexically ("2" < "10").
assert.equal(compareCells('2', '10') < 0, true, 'numeric: 2 should sort before 10');
assert.equal(compareCells('10', '2') > 0, true, 'numeric: 10 should sort after 2');

// Thousands separators and percentages parse as numbers.
assert.equal(parseCellValue('1,204').kind, 'number');
assert.equal(parseCellValue('1,204').value, 1204);
assert.equal(parseCellValue('87%').kind, 'number');
assert.equal(parseCellValue('87%').value, 87);

// Non-numeric text compares case-insensitively as strings.
assert.equal(compareCells('Zebra', 'apple') > 0, true, 'string: Zebra should sort after apple');
assert.equal(compareCells('apple', 'apple') === 0, true, 'string: equal values compare equal');

// Never produces "[object Object]" -- values are always primitives.
assert.notEqual(String(parseCellValue('anything').value), '[object Object]');

// Empty cells always sort to the end regardless of comparison direction.
assert.equal(compareCells('', 'apple') > 0, true, 'empty should sort after any value');
assert.equal(compareCells('apple', '') < 0, true, 'value should sort before empty');
assert.equal(compareCells('', '') === 0, true, 'two empties compare equal');

// Real defect fixed here (owner-reported: chronological sort/filter must
// use the underlying timestamp/epoch value, never the formatted display
// string). A locale-formatted timestamp for Aug 9 sorts AFTER Aug 22 as
// plain text (lexicographic "2" < "9"), even though Aug 9 is
// chronologically earlier -- exactly the class of bug this guards
// against. Epoch-millisecond strings (what app.js's timestampHtml()
// puts in data-sort-value, read by data-grid.js's cellSortText()) are
// plain numeric text to this comparator, so they sort correctly with no
// special-casing.
const aug9 = 'Aug 9, 2026, 11:00 PM MDT';
const aug22 = 'Aug 22, 2026, 11:00 PM MDT';
assert.equal(compareCells(aug9, aug22) > 0, true, 'sanity check: formatted display text alone sorts Aug 9 AFTER Aug 22 (the bug)');
const aug9Epoch = String(Date.parse('2026-08-10T05:00:00Z'));
const aug22Epoch = String(Date.parse('2026-08-23T05:00:00Z'));
assert.equal(compareCells(aug9Epoch, aug22Epoch) < 0, true, 'epoch-millisecond sort keys correctly sort Aug 9 before Aug 22');

console.log('data-grid comparator: all assertions passed');
