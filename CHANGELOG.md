# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- The release workflow follows the repo release standard: a `chore(release): vX.Y.Z` commit on main triggers tag creation (release App) and the full build/attest/publish pipeline.
### Fixed
- CI pins setup-python to the 3.12 minor (the ubuntu-26.04 runner image dropped 3.12.8).

## [0.1.4] - 2026-10-22
### Security
- Go 1.26.10 toolchain and dependency vulnerability bumps (PRs #28, #29, #30).
