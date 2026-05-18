test:
  watchexec -e rs,toml cargo test

cover:
  cargo llvm-cov --lcov --output-path lcov.info

install:
  cargo install --path crates/utmost-cli

# Activate committed git hooks (run once after cloning)
setup:
  git config core.hooksPath .githooks
  @echo "Git hooks installed. Pre-commit will run cargo fmt + cargo clippy."
  @echo "Install git-cliff for release management: cargo install git-cliff"

# ── Release management (requires: cargo install git-cliff) ────────────────

# Apply version bump + CHANGELOG locally for review (no commit/tag/push).
# Inspect results with `git diff` before running `just release`.
release-update:
  #!/usr/bin/env bash
  set -euo pipefail
  NEXT=$(git cliff --bumped-version 2>/dev/null | tr -d '[:space:]')
  LAST=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
  if [ -z "$NEXT" ] || [ "$NEXT" = "$LAST" ]; then
    echo "Nothing to release — no fix:/feat:/breaking commits since last tag."
    exit 0
  fi
  VERSION="${NEXT#v}"
  git cliff --tag "$NEXT" -o CHANGELOG.md
  sed -i '' "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" crates/utmost-lib/Cargo.toml
  sed -i '' "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" crates/utmost-cli/Cargo.toml
  sed -i '' "s/utmost-lib = { path = \"..\/utmost-lib\", version = \"[^\"]*\" }/utmost-lib = { path = \"..\/utmost-lib\", version = \"${VERSION}\" }/" crates/utmost-cli/Cargo.toml
  echo "Ready to release ${NEXT} — review with 'git diff', then run 'just release'."

# Full release: bump, changelog, signed commit + tag, push → triggers CI release build
release:
  #!/usr/bin/env bash
  set -euo pipefail
  NEXT=$(git cliff --bumped-version 2>/dev/null | tr -d '[:space:]')
  LAST=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
  if [ -z "$NEXT" ] || [ "$NEXT" = "$LAST" ]; then
    echo "Nothing to release — no fix:/feat:/breaking commits since last tag."
    exit 0
  fi
  VERSION="${NEXT#v}"
  git cliff --tag "$NEXT" -o CHANGELOG.md
  sed -i '' "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" crates/utmost-lib/Cargo.toml
  sed -i '' "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" crates/utmost-cli/Cargo.toml
  sed -i '' "s/utmost-lib = { path = \"..\/utmost-lib\", version = \"[^\"]*\" }/utmost-lib = { path = \"..\/utmost-lib\", version = \"${VERSION}\" }/" crates/utmost-cli/Cargo.toml
  git add CHANGELOG.md crates/utmost-lib/Cargo.toml crates/utmost-cli/Cargo.toml Cargo.lock
  git commit -S -m "chore: release ${NEXT}"
  git tag -s "${NEXT}" -m "Release ${NEXT}"
  git push --follow-tags
