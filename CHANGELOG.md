# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-21

### Added

- Burp Suite Community Edition support: everything except issues and the
  scanner check works there.
- Passive scan check (Professional): a passive audit of a host returns its
  radar issues from memory, without a new request.
- Intruder payloads: hosts from the table, all, with leaks or in scope.
- *Send login page to Organizer* with a note of the host's counts, and the
  *Login page + leaks* filter.
- Comparison with the previous check: a *Change* column, the *New since last
  check* filter and a "Since the previous check" part in the Markdown summary.
- Import of a JSON export, for viewing results offline or sharing them in a
  team without new requests.
- Optional Proxy history highlighting of hosts with leaks, and a Bambda filter
  for those items.
- The tab shows when a result is a saved one, when a newer plugin version is
  out, a non-default Server URL and turned-off TLS verification.
- A line with the result of the last finished job.

### Changed

- *Check again* asks the server for a fresh check instead of its saved result.
- Columns *Host logins* and *DB records* replace *Personal* and *DB rec*. The
  CSV export header is unchanged; a `change` column is added at the end.
- Four settings have shorter labels, so after the update they start from their
  defaults: TLS verification, checking new hosts from traffic, attempts and
  *Always rescan*.
- All dialogs open over Burp's main window; *Cancel* is the default in the send
  confirmation.
- Long texts wrap instead of being cut; the empty table explains why it is
  empty.
- Without a key, a domain scan now counts the hosts it checks against the
  hourly limit, as the server does. A scan stopped by the limit lists the rest
  as *Not checked yet* instead of failed.
- Private project disables every action that would send something, instead of
  queueing jobs that fail.
- Unexpected errors reach Burp's error log with their stack trace.
- Results are saved in the Burp project per domain. Projects from 0.1.0 load
  as before, but 0.1.0 cannot read results saved by this version.

### Fixed

- The job stops only when Burp's session handling adds credentials to the
  radar request; other added headers are noted once.
- Polling, cancelling and unloading no longer leave threads or server jobs
  behind; server answers are read strictly and capped at 8 MB.
- Issue HTML from the server is limited in depth and links.
- CSV cells that start with a formula character are defused.

## [0.1.0] - 2026-11-18

First public release.

[Unreleased]: https://github.com/grimnir/hirdman-radar-burp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/grimnir/hirdman-radar-burp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/grimnir/hirdman-radar-burp/releases/tag/v0.1.0
