# certifake

[![PkgGoDev](https://img.shields.io/badge/-reference-blue?logo=go&logoColor=white&labelColor=505050)](https://pkg.go.dev/github.com/thediveo/certifake)
[![License](https://img.shields.io/github/license/thediveo/certifake)](https://img.shields.io/github/license/thediveo/certifake)
![build and test](https://github.com/thediveo/certifake/actions/workflows/buildandtest.yaml/badge.svg?branch=master)
![Coverage](https://img.shields.io/badge/Coverage-87.2%25-brightgreen)

`certifake` creates self-signed TLS certificates for use in unit tests.

The module name `certifake` is in rememberance of an awesome trip to the
Terracotta Army museum in Xi'an, as well as all the antique shops. Now stop
laughing.

## DevContainer

> [!CAUTION]
>
> Do **not** use VSCode's "~~Dev Containers: Clone Repository in Container
> Volume~~" command, as it is utterly broken by design, ignoring
> `.devcontainer/devcontainer.json`.

1. `git clone https://github.com/thediveo/certifake`
2. in VSCode: Ctrl+Shift+P, "Dev Containers: Open Workspace in Container..."
3. select `certifake.code-workspace` and off you go...

## Supported Go Versions

`certifake` supports versions of Go that are noted by the [Go release
policy](https://golang.org/doc/devel/release.html#policy), that is, major
versions _N_ and _N_-1 (where _N_ is the current major version).

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Copyright and License

`certifake` is Copyright 2026 Harald Albrecht, and licensed under the Apache
License, Version 2.0.
