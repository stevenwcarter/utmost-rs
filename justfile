test:
  watchexec -e rs,toml cargo test

cover:
  cargo llvm-cov --lcov --output-path lcov.info

# Activate committed git hooks (run once after cloning)
setup:
  git config core.hooksPath .githooks
  @echo "Git hooks installed. Pre-commit will run cargo fmt + cargo clippy."
