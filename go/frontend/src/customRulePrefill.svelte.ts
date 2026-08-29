// Query Log -> rule creation: a real "Create rule from this query" deep
// link, the same mechanism queryLogPrefill.svelte.ts already established
// for Clients -> Query Log. Query Log sets this before navigating to the
// Filters route; Filters (CustomRulesView) reads it once on mount to seed
// the Custom Rules "Add rule" form, then clears it so a later, unrelated
// visit to Filters doesn't inherit a stale prefill. Not URL/query-string
// based for the same reason as queryLogPrefill: the router has no
// query-param model today.
export interface CustomRulePrefill {
  ruleType: "block" | "allow";
  pattern: string;
}

let pending = $state<CustomRulePrefill | null>(null);

export const customRulePrefill = {
  set(p: CustomRulePrefill) {
    pending = p;
  },
  take(): CustomRulePrefill | null {
    const v = pending;
    pending = null;
    return v;
  },
};
