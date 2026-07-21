# Contributing to StellarConduit Sync Engine

Thank you for your interest in contributing to the offline transaction queue and conflict resolution layer of the StellarConduit protocol!

This repository is where double-spend safety for the whole mesh either holds up or doesn't. We rely on community contributions to make it correct, well-tested, and resilient to split-mesh partitions.

## Getting Started

1. **Find an Issue**: Browse the [Issues](https://github.com/StellarConduit/stellarconduit-sync-engine/issues) tab. Look for the `good first issue` label if you're new, or `help wanted` for larger tasks.
2. **Claim the Issue**: Comment on the issue asking to be assigned. Wait for a maintainer to assign it to you before starting work to avoid duplicated effort.
3. **Fork & Branch**: Fork the repo and create a branch for your feature/fix. Name it `feat/your-feature`, `fix/issue-description`, or `chore/task`.

## Development Workflow

Before opening a Pull Request, you **must** ensure the following commands pass locally:

```bash
# 1. Format code
cargo fmt --all

# 2. Check for warnings/clippy rules
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run all tests
cargo test --workspace
```

### Writing Tests
- All new features must include unit tests. Aim for >85% coverage.
- If you are modifying `queue`, `storage`, `settlement`, or `conflict`, you must update or add an integration test in `tests/integration/` that exercises the change end-to-end (through durable storage, not just in-memory).

### Writing Commit Messages
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(conflict): implement relay-chain proof consensus resolution`
- `fix(storage): correct sequence reservation rollback on envelope build failure`
- `docs: document the settlement state machine`
- `test(queue): add priority tie-break benchmark`

## Pull Request Process

1. Provide a clear, detailed PR description.
2. Link the PR to the issue it resolves (e.g., "Closes #12").
3. Ensure CI passes.
4. Two maintainer approvals are required before merging.

## A Note on `conflict::resolver`

The deterministic off-chain conflict resolution algorithm is deliberately left unimplemented in this repository's scaffold — it's the hardest and most consequential piece of code here. If you're picking up an issue in this area, please open an Issue for design discussion first before implementing, since the algorithm must produce identical results on every node that runs it (see the module doc comment in `src/conflict/resolver.rs` for the constraints it must satisfy).
