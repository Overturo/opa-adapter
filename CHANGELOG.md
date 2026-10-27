# Changelog

## [2.0.0] - 2026-10-26
### Changed
- The configuration key for the application is `application_id` (was `touchpoint_id`); the environment variable in the examples is `OVERTURO_APPLICATION_ID`. A configuration file with the old key fails validation with "overturo.application_id is required".
- The module path is `github.com/overturo/opa-adapter/v2`; install the command with `go install github.com/overturo/opa-adapter/v2/cmd/opa-adapter@v2.0.0`.
- The container image is published to the GitHub container registry as `ghcr.io/overturo/opa-adapter` (tags `v2.0.0` and the floating `v2`), built and pushed by the public repository's own release workflow.
- `opa-adapter -version` answers from the release tag when installed from source (the module's build information) as well as from the image (the build argument).

## [1.0.1] - 2026-09-12
### Changed
- Documentation links point at the public developer pages.

## [1.0.0] - 2026-09-12
First public release.
