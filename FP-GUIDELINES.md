# Functional programming conformance

This repository is checked against the house functional-programming guidelines.
Functional programming here means nine specific things:

- **explicit inputs** — what a function needs arrives through its parameters
- **explicit outputs** — what a function produces leaves through its return type
- **immutable values** — bindings and fields do not change after construction
- **pure transformations** — same input, same output, no observable effect
- **typed errors** — failure is a value in the signature, not an escape
- **explicit state transitions** — state changes are named and returned
- **composition** — small named steps combined, rather than one long body
- **effects pushed outward** — I/O, clocks, randomness and logging live at the edge
- **illegal states excluded by types** — the compiler rejects what must not happen

Stateful code is not exempt from all of this. Websocket handlers, TCP
connections, stateful clients and actor loops legitimately hold mutable state, and
the scanner relaxes the mutability rules for modules whose path marks them as such
(`ws/`, `socket/`, `conn/`, `session/`, `pool/`, `cache/`, `stream/`, `actor/`,
`fsm/`, `state_machine/`). Everything else — typed errors, exhaustive matching,
composition, effects at the edge — still applies there. Likewise, modules that
*are* the outward edge (`main`, `bin/`, `effects/`, `io/`, `adapters/`, `infra/`,
`transport/`, `handlers/`, `routes/`, `db/`, `telemetry/`) are allowed to perform
effects: that is the point of pushing effects outward.

## Running the check

```sh
python3 tools/fp-conformance/fp_conformance.py .                    # report
python3 tools/fp-conformance/fp_conformance.py . --limit 200        # more detail
python3 tools/fp-conformance/fp_conformance.py . --json /tmp/fp.json
```

Stdlib Python 3 only — no toolchain, no dependencies, no network — so it runs
identically on a laptop and on a CI runner.

## The budget, and why CI is not red today

`tools/fp-conformance/budget.json` records the per-rule counts at the moment this
check was introduced: **168 findings across 19 files
and 6,230 lines**. CI compares against that budget and fails only when a
rule's count *increases*. The existing backlog blocks nobody; new violations do.

The budget is a ratchet. It should only ever move down. When you clear a class of
violation, re-baseline in the same commit as the fix:

```sh
python3 tools/fp-conformance/fp_conformance.py . \
    --write-budget tools/fp-conformance/budget.json
```

Raising the budget to turn CI green defeats the whole mechanism. Fix the code.

## Baseline for this repository

| rule | count | severity | principle | what it flags |
|---|---:|---|---|---|
| `RS003` | 87 | error | typed errors | panic-based control flow (`unwrap`/`expect`/`panic!`) |
| `RS001` | 57 | warn | immutable values | mutable local binding (`let mut`) |
| `RS004` | 13 | warn | illegal states excluded by types | wildcard match arm defeats exhaustiveness |
| `XX001` | 5 | warn | composition | oversized module |
| `XX002` | 4 | warn | explicit outputs | long function body |
| `RS007` | 1 | warn | effects pushed outward | direct stdout/stderr effect in library code |
| `RS008` | 1 | warn | explicit outputs | `&mut self` method returning unit |

## How to clear the top offenders

### `RS003` — panic-based control flow (`unwrap`/`expect`/`panic!`)

*typed errors* · 87 occurrences at baseline

Return `Result<T, E>` with a domain error enum and propagate with `?`; reserve panics for genuinely unreachable invariants proven by types.

### `RS001` — mutable local binding (`let mut`)

*immutable values* · 57 occurrences at baseline

Rebind with `let`, fold with an iterator, or build the value with `collect()`/`fold()` instead of mutating in place.

### `RS004` — wildcard match arm defeats exhaustiveness

*illegal states excluded by types* · 13 occurrences at baseline

Enumerate the remaining variants explicitly so adding a variant becomes a compile error.

### `XX001` — oversized module

*composition* · 5 occurrences at baseline

Split into focused modules; the guidelines call for modularisation rather than a single large entry point.

### `XX002` — long function body

*explicit outputs* · 4 occurrences at baseline

A body over 60 lines is usually several transformations. Extract named, individually testable steps and compose them.

### `RS007` — direct stdout/stderr effect in library code

*effects pushed outward* · 1 occurrence at baseline

Emit through the ores-otel tracing layer so the effect lives at the outward edge and stays observable.

### `RS008` — `&mut self` method returning unit

*explicit outputs* · 1 occurrence at baseline

Return the new state (or a typed transition) instead of mutating in place and returning `()`.

## Language-native enforcement

The Python scanner is the portable floor — it runs everywhere and costs nothing.
The real type-level enforcement belongs to each toolchain, and those configs ship
in this tree:

- **Rust** — `[lints.clippy]` in `Cargo.toml`. Run `cargo clippy --all-targets`.
- **TypeScript** — `eslint.fp.config.mjs`. Run `npx eslint -c eslint.fp.config.mjs .`
  (needs `eslint`, `typescript-eslint` and `eslint-plugin-functional` as devDependencies).
- **Dart** — `analysis_options.fp.yaml`. Add `include: analysis_options.fp.yaml`
  to `analysis_options.yaml`, then run `dart analyze`.

Those steps are deliberately **not** in the CI job. A toolchain install costs far
more Actions minutes than the Python pass, and we are budget-conscious about
runner time. Run them locally, and in the nightly job on the sibling `-test` org.
