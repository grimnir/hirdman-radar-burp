# Contributing

Bug reports, ideas and pull requests are welcome. For a vulnerability, see
[SECURITY.md](SECURITY.md) instead.

## Build and test

Any JDK 17 or later runs Gradle. The build compiles and tests with Temurin 21
and downloads it if it is not installed.

```
./gradlew test jar                 # tests, then build/libs/hirdman-radar-<version>.jar
./gradlew test -PtestJava=25       # the same tests on another JDK
./gradlew test jacocoTestReport    # coverage in build/reports/jacoco
./gradlew pitest                   # mutation testing in build/reports/pitest
```

Tests run headless against fakes of the Montoya API (`Fakes` in the tests) and
never reach the network. The build is reproducible: the same commit gives a jar
with the same SHA-256.

After changing a dependency or a plugin version, regenerate the checksums:
`./gradlew --write-verification-metadata sha256 test jar jacocoTestReport pitest dependencies buildEnvironment`.

## Rules the code keeps

`ProjectRulesTest` checks most of these.

- The plugin talks to one server, the *Server URL*, and only through Burp's
  HTTP stack. It sends nothing to target hosts and never changes the scope.
- No API key: the `X-API-Key` header is never sent, and no key goes into the
  project file or the logs.
- Counts only: no accounts, passwords or raw records, in the plugin or in tests.
- The plugin respects the server's limits and does not try to get around them.
- New fields from the server are optional, so the plugin keeps working with an
  older server.
- Burp keeps settings by their label. Renaming a setting needs a migration of
  the stored value.
- Write a failing test first. Tests open no windows or dialogs.
- Comments, UI texts and the README are in English and short.

## Pull requests

- One change per pull request, with its tests. `./gradlew test jar` passes.
- Keep target domains, client names and real data out of code, tests,
  screenshots and commit messages.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.

## License of contributions

The project is under [PolyForm Shield 1.0.0](LICENSE): anyone may use, change
and share it, but not to build a product that competes with it or with HIRDMAN
products. By sending a pull request you agree that your contribution is
licensed under the same terms and that you have the right to submit it.
