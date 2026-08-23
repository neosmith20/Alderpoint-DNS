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

console.log('data-grid comparator: all assertions passed');
