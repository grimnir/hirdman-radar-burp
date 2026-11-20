# Security policy

## Reporting a vulnerability

Email info@hirdman.pro. Please do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, the plugin version and the Burp
version. Leave out real target domains and any data from your engagements.

We reply within 5 working days, then keep you posted until the issue is fixed.
There is no bug bounty.

## Scope

- The Hirdman Radar plugin in this repository and the jars on its releases page.
- The server the plugin talks to by default, `https://scan.hirdman.pro`. Test it
  without load: no scanning, no flooding, no attempts on other users' data.

## Supported versions

Fixes go into the latest release.

## Checking a release

Release jars built by GitHub Actions carry a build provenance attestation
(0.1.0 predates it):

```
gh attestation verify hirdman-radar-X.Y.Z.jar -R grimnir/hirdman-radar-burp
sha256sum -c hirdman-radar-X.Y.Z.jar.sha256
```
