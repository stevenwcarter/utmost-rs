test:
  watchexec -e rs,toml cargo test

cover:
  cargo llvm-cov --lcov --output-path lcov.info

# Activate committed git hooks (run once after cloning)
setup:
  git config core.hooksPath .githooks
  @echo "Git hooks installed. Pre-commit will run cargo fmt + cargo clippy."
  @echo "Install release-plz for release management: cargo install release-plz"

# ── Release management (requires: cargo install release-plz) ──────────────

# Apply version bump + CHANGELOG locally for review (no commit/tag/push).
# Inspect results with `git diff` before running `just release`.
release-update:
  release-plz update

# Full release: bump, changelog, signed commit + tag, push → triggers CI release build
release:
  #!/usr/bin/env bash
  set -euo pipefail
  release-plz update
  VERSION=$(grep '^version' crates/utmost-cli/Cargo.toml | head -1 | sed 's/version = "\([^"]*\)"/\1/')
  echo "Releasing v${VERSION}..."
  git add CHANGELOG.md crates/utmost-lib/Cargo.toml crates/utmost-cli/Cargo.toml Cargo.lock
  git commit -S -m "chore: release v${VERSION}"
  git tag -s "v${VERSION}" -m "Release v${VERSION}"
  git push --follow-tags
