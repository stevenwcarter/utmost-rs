# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.2] - 2026-04-16

### Bug Fixes

- Cap fragmented JPEG size at fragmentation point and dimension heuristic ([a7b39f7](https://github.com/stevenwcarter/utmost-rs/commit/a7b39f7e6a248155c8361b18c4ccec5067284216))
- Resolve dead_code warning in mpg.rs test helper ([7944aaf](https://github.com/stevenwcarter/utmost-rs/commit/7944aaf02733a266bac6590b84308ce7bd05ee37))

### Testing

- Add unit tests for engine/png.rs (0% → ~100%) ([45e2cb7](https://github.com/stevenwcarter/utmost-rs/commit/45e2cb7620dcd2f4025970b302da1f2e909b808d))
- Add huge-dimensions test for engine/png.rs ([a5a7280](https://github.com/stevenwcarter/utmost-rs/commit/a5a728084428e6c63aabe15afe446da58f421902))
- Add unit tests for engine/pdf.rs (8% → ~95%) ([4bee2eb](https://github.com/stevenwcarter/utmost-rs/commit/4bee2ebc983303130a38fe0d2e9d941f8061f234))
- Strengthen pdf.rs test assertions + add overflow test ([3fe33d7](https://github.com/stevenwcarter/utmost-rs/commit/3fe33d728b2f85b8bba0a6124391de51147d25f5))
- Add unit tests for engine/exe.rs (71% → 100%) ([cbc5d60](https://github.com/stevenwcarter/utmost-rs/commit/cbc5d60e021d1563528c7e776556bd10ce2d132f))
- Add tests for reporting.rs new_with_report and clone (84% → ~98%) ([709c080](https://github.com/stevenwcarter/utmost-rs/commit/709c080f07f419ba77f6403edd1c01638d28b1ad))
- Add unit tests for engine/mpg.rs uncovered stream IDs and stuffing (74% → ~95%) ([a5d1f08](https://github.com/stevenwcarter/utmost-rs/commit/a5d1f080fef2201a2dd9a961618537e496023bb3))
- Add unit tests for engine/mov.rs optional atoms and edge cases (84% → ~95%) ([dc645c3](https://github.com/stevenwcarter/utmost-rs/commit/dc645c3bf83c6629007a22cfc96462c86365b87d))
- Add unit tests for engine/gif.rs zero-dimension checks (82% -> 100%) ([70cc123](https://github.com/stevenwcarter/utmost-rs/commit/70cc1238940f5b1ea81e8b653a334a54afc1f277))
- Add unit tests for jpeg_recover.rs (17% → ~80%) ([6936d2d](https://github.com/stevenwcarter/utmost-rs/commit/6936d2d59ce92ac34f6ffa843e303d7607d824e0))
- Add unit tests for jpeg_huffman.rs uncovered paths (81% → ~90%) ([6784a2a](https://github.com/stevenwcarter/utmost-rs/commit/6784a2a570d8d2c9caa5416b6578579664306246))
- Add tests for engine.rs find_file_size, write_to_disk, footer_missing_may_bridge ([0db2cf8](https://github.com/stevenwcarter/utmost-rs/commit/0db2cf8f0ec3c314669d6e19c9781bea9d86d586))
## [0.2.1] - 2026-04-16

### Bug Fixes

- Code health improvements (9 items) ([5b328c6](https://github.com/stevenwcarter/utmost-rs/commit/5b328c666f9434894e6e63fa7d835fbe664a357d))
- Removed some magic values ([f95b6da](https://github.com/stevenwcarter/utmost-rs/commit/f95b6da994e021ed821100db03ba7412badcd94b))
## [0.2.0] - 2026-03-25

### Features

- Add JPEG fragment recovery with enriched scan metadata ([30aa627](https://github.com/stevenwcarter/utmost-rs/commit/30aa627e6d77bfe0805af2ba19e5ac440849c72c))
- Added Huffman checks for jpeg file viability, only keep best candidate ([d80a832](https://github.com/stevenwcarter/utmost-rs/commit/d80a832b5feb74c18a9c6de583b47559734a0b6a))
## [0.1.1] - 2026-03-24

### Bug Fixes

- Fixing changelog generation ([c748b11](https://github.com/stevenwcarter/utmost-rs/commit/c748b113df20a5342cbc6092b717afd68d048e98))
- Switching to git-cliff from release-plz ([cbd63c5](https://github.com/stevenwcarter/utmost-rs/commit/cbd63c5ddaa671f4e95a7acb7d9550981bd02956))
## [0.1.0] - 2026-03-24

### Bug Fixes

- Prevent duplicate mpg files by advancing by file size ([8db496d](https://github.com/stevenwcarter/utmost-rs/commit/8db496de81d6aa8390af5770efd18beed2edc53a))
- Fixed jpeg handling to find full files ([5e5a6e4](https://github.com/stevenwcarter/utmost-rs/commit/5e5a6e496f5946e9ad456a6bb781e59fbe7ed3d3))
- Code health improvements (12 items) ([399a46d](https://github.com/stevenwcarter/utmost-rs/commit/399a46d6776a8f57c39714b1bc9343d62e2457a1))
- Code health improvements (10 items) ([8d17f9a](https://github.com/stevenwcarter/utmost-rs/commit/8d17f9a80fd9b5e05d23ec3dd46af67faacd45cb))
- Code health improvements (10 items) ([d95b289](https://github.com/stevenwcarter/utmost-rs/commit/d95b289e54898356b162e34bd4efadea758b8d93))
- Code health improvements (3 items) ([634b360](https://github.com/stevenwcarter/utmost-rs/commit/634b360ab924199dc19f354bb049273593cfe56e))
- Lint errors and enabled codecov uploading ([dce9f6f](https://github.com/stevenwcarter/utmost-rs/commit/dce9f6fb90aa3483de548777ad946a2538cf202a))
- Cargo fmt errors ([43edc8b](https://github.com/stevenwcarter/utmost-rs/commit/43edc8b3c56b004cd818bab105fdcc4ae536382c))

### Features

- Allows saving/loading specs ([37b9b02](https://github.com/stevenwcarter/utmost-rs/commit/37b9b021d81293e9ddb258ffcb99261779c98afc))
- Concurrent file processing added ([633837c](https://github.com/stevenwcarter/utmost-rs/commit/633837c3df3ac1913c81d80b56064e5b960c5d99))
- Added validations and length fixes for zip/pdf ([92658f6](https://github.com/stevenwcarter/utmost-rs/commit/92658f65650d5c6594c5e6a9d8dfc3f77f1ad877))
- Added validation for bmp, mov, and mpg types ([48e1453](https://github.com/stevenwcarter/utmost-rs/commit/48e145388b2b4405dd9b05b706e94cc94342b3a9))
- Added gzip validation ([f1ad2e3](https://github.com/stevenwcarter/utmost-rs/commit/f1ad2e3c2b583067726ffddbea5b459cc6a7c176))
- Added report output and other options ([c8a0ac0](https://github.com/stevenwcarter/utmost-rs/commit/c8a0ac02010ecf34441e644ecec7952cceab2bd3))

### Performance

- Tighten jpeg checks ([dc0dcfb](https://github.com/stevenwcarter/utmost-rs/commit/dc0dcfbcbb6bdacd615e8e1ca433cb867d7707e0))
- Removed lock from tight loop ([329c580](https://github.com/stevenwcarter/utmost-rs/commit/329c580b22bb9db35515770648c86f5fbf81e23d))
- Switching to atomics for counters ([6a5a3bb](https://github.com/stevenwcarter/utmost-rs/commit/6a5a3bb7f4cf6d90152ba19b3ae700c95b2c8d5c))
- Removed an unnecessary clone in hot path ([b44a246](https://github.com/stevenwcarter/utmost-rs/commit/b44a246bc2ebd4fe92a3cb4eef5c835f40cd6bbe))
- Switched away from async for performance ([1c5040f](https://github.com/stevenwcarter/utmost-rs/commit/1c5040ff72ba51ce7b3c3ceece157c32aff27ac2))
- Sped up search_forward implementation ([cefa73e](https://github.com/stevenwcarter/utmost-rs/commit/cefa73ea99a7a9c31062b09fc0e61081f65bec9a))

### Refactoring

- Split validate_bmp_file and validate_gz_file into helpers ([b015514](https://github.com/stevenwcarter/utmost-rs/commit/b015514a96091720364df79c509976f8afa97614))

### Testing

- Added test cases ([45ea41c](https://github.com/stevenwcarter/utmost-rs/commit/45ea41c1e634ef469fcd05252b165536683db539))
- Added engine tests back ([0d00678](https://github.com/stevenwcarter/utmost-rs/commit/0d00678903a3b08d584a806fa3a957173e67f3ae))
- Added search bench for search_forward ([ab11948](https://github.com/stevenwcarter/utmost-rs/commit/ab1194840f230fa68dedd8bf36ccc17ddaef3285))
