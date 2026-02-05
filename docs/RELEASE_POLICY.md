# SecretiveX Release Policy

## Versioning

SecretiveX uses semantic versioning:
- `MAJOR`: breaking API/behavior changes.
- `MINOR`: backward-compatible features.
- `PATCH`: backward-compatible fixes.

Release tags follow `vMAJOR.MINOR.PATCH` (example: `v0.4.2`).

## Release channels

- `main`: continuously integrated and releasable.
- Tagged releases (`v*`): stable public release artifacts.
- Optional pre-release tags use semver suffixes (example: `v0.5.0-rc.1`).

## Changelog format

`CHANGELOG.md` entries are grouped per release with sections:
- `Added`
- `Changed`
- `Fixed`
- `Security`
- `Performance`
- `Operations`

Each release notes:
- version and release date,
- key user-visible changes,
- migration notes (if any),
- known limitations.

## Compatibility policy

- Rust agent CLI/config changes must preserve backward compatibility within the same `MAJOR` line.
- New config fields are optional by default.
- Deprecated fields are documented for at least one minor release before removal.

## Security and hotfix releases

- Security fixes can ship as out-of-band patch releases.
- Hotfix tags follow normal patch increments (example: `v0.4.3`).
- Security release notes should include impact scope and upgrade recommendation.
