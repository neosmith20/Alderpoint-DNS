// Column type shared between DataGrid.svelte and every page that uses it.
// Kept in a plain .ts file (not declared inside DataGrid.svelte) so it's
// unambiguously importable from any page component.
export interface Column<T> {
  key: string;
  label: string;
  /** Present => sortable. Returns the value to compare (string or number
   * -- e.g. a numeric column returns a number, a timestamp column
   * returns its epoch-ms sort key, never the display string). */
  sortValue?: (row: T) => string | number;
  /** Column min-width in ch units; also the initial width. */
  minWidth?: number;
}
