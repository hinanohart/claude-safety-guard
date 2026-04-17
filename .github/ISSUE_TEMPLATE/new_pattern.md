---
name: New pattern proposal
about: Propose a new dangerous-command shape for the catalog.
title: "[pattern] "
labels: enhancement
---

## Proposed ID

<!-- kebab-case, <category>-<short-name>, e.g. git-rebase-onto-main -->

## Severity

<!-- BLOCK (near-certain data loss / credential exposure) or WARN (usually bad). -->

## Motivating incident

<!-- A real-world case where this shape caused damage. Link if possible. -->

## Proposed regex

```regex

```

## Positive cases

<!-- Commands that should fire the rule. -->

- `...`

## Negative cases

<!-- Commands that look similar but MUST NOT fire. -->

- `...`

## Trade-offs considered

<!-- Why is this shape tight enough not to cry wolf? What legitimate
uses exist, and are they rare enough to justify the rule? -->
