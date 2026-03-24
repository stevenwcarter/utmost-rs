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

# Full release: bump, changelog, commit, tag, push → triggers CI release build
release:
  release-plz release
