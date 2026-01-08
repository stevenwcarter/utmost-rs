test:
  watchexec -e rs,toml cargo test

cover:
  cargo llvm-cov --lcov --output-path lcov.info
