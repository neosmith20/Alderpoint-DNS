# INTERNAL ONLY — Alderpoint DNS V2 UI Design Guidance

This document is private engineering material. It must not be exported to
public GitHub, public release packages, public documentation, examples,
fixtures, logs, or screenshots.

Before any public export of the V2 tree, remove this file and verify the
exported tree does not contain this document, this directory, or the internal
commentary below.

## Purpose

Future V2 UI work must establish a recognizable Alderpoint visual identity
instead of defaulting to the generic AI-generated/vibecoded SaaS dashboard
look. This is guidance for CC/Dex implementation sessions before the eventual
UI workstream begins; it is not a request to redesign the UI now.

## Visual Direction

Alderpoint DNS V2 should feel like:

- serious network infrastructure
- polished modern workstation/application software
- distinct Alderpoint product identity

It should not feel like a SaaS landing page wrapped around DNS.

Avoid making these the defining style:

- dark navy plus purple/blue gradients
- excessive glassmorphism
- glowing panels/cards
- huge border radii everywhere
- pill-shaped controls for everything
- oversized cards with excessive empty space
- decorative gradients without functional purpose
- interchangeable "modern SaaS" layouts
- generic component-library appearance
- page designs that look like the result of "build me a modern admin dashboard"

Individual techniques are not absolutely forbidden. They must be intentional,
not the default visual language.

## Alderpoint Design System Requirement

Large-scale V2 UI work must establish a coherent Alderpoint design system
before multiplying pages. The system must cover:

- typography scale
- spacing scale
- border-radius rules
- surface hierarchy
- borders/dividers
- navigation
- buttons
- inputs/forms
- tables
- cards/panels
- status/severity colors
- warning/error/success states
- icon treatment
- charts/analytics
- responsive behavior
- accessibility/focus states
- light theme
- dark theme

Changing only accent colors is not sufficient. An Alderpoint screen should
remain recognizably Alderpoint even if the logo is removed.

Light and dark themes should share the same design DNA rather than behaving
like unrelated skins.

## Network-Appliance Character

Alderpoint must comfortably present substantial operational information:

- DNS health
- queries
- clients
- policies
- filtering/security
- upstreams
- routing
- cache behavior
- schedules
- replication
- analytics
- system state

Useful information density is good when properly organized. Do not hide useful
technical information just to create more whitespace.

Prioritize:

- fast visual scanning
- clear hierarchy
- excellent tables
- understandable state
- obvious status/severity
- predictable controls
- minimal clutter
- restrained visual effects
- usability over decoration

## Behavior and QA

Core QA rule:

> IF ALEX CAN CLICK IT, ALDERPOINT NEEDS TO SURVIVE ALEX CLICKING IT.

The UI implementation must test real behaviors:

- rapid repeated actions
- multiple changes in quick succession
- stale browser tabs
- refresh during operations
- page navigation while work is running
- backend/service failures
- degraded analytics
- failed runtime promotion
- slow operations
- long names/values
- empty states
- large datasets
- narrow/mobile screens

The UI must clearly indicate whether an operation succeeded, failed, is
running, was rejected, rolled back, or requires attention. Do not leave the
operator wondering whether a click did anything.

## Future CC / Dex Implementation Rule

Before large-scale V2 UI implementation:

1. Audit existing V2 interface/components for generic AI/SaaS design patterns.
2. Establish the Alderpoint design system first.
3. Reuse that system consistently.
4. Do not multiply weak existing visual patterns just because they exist.
5. Do not introduce random component styles page by page.
6. Preserve backend/runtime correctness first.
7. Test the real UI against installed V2 APIs and real runtime behavior.
8. Treat awkward workflows discovered through real use as bugs.
9. Treat obvious generic AI-dashboard appearance as a design defect, not
   merely a subjective preference.

Do not use vague prompts like "make it modern and beautiful" as the design
specification.

## Public Export / Privacy Scrub

This file and the `docs/v2/internal/` directory must be absent from any public
export or release package.

Before public export, run the existing release-hygiene gate against the exported
tree with caller-supplied prohibited patterns for:

- this file path: `docs/v2/internal/ui-design-guidance.md`
- this directory path: `docs/v2/internal`
- internal agent/workflow terms: `AI-generated UI`, `vibecoding`, `vibecoded`,
  `Claude`, `CC`, `Dex`, `internal agent workflow`
- this internal design critique's title and distinctive QA phrase

The generic release-hygiene test intentionally receives these patterns from the
private release operator instead of hardcoding them into public scripts.

Public documentation may describe the resulting Alderpoint design system in
normal product language after the design system exists.
