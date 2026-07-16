# enclave/

Reproducible Nitro Enclave (EIF) build for the introspector app.

## Install the `enclave` CLI

```sh
go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@latest
```

This puts `enclave` on your `$PATH` (assuming `$GOPATH/bin` is on it).

To pin to a specific runtime release, replace `@latest` with a tag:

```sh
go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@v0.0.72
```

## Update the pinned app commit

`enclave.yaml` pins the app to a specific commit via `app.nix_rev`, plus the
matching `nix_hash` and `nix_vendor_hash`. To bump to a new commit:

```sh
enclave setup --commit <commit_hash>
```

This rewrites `app.nix_rev`, `app.nix_hash`, and `app.nix_vendor_hash` in
`enclave.yaml` and regenerates `flake.lock`. Commit both files.

Pass `--force-flake` if you intentionally want to regenerate it from the template
(e.g. after changing `app.language`).

## Build the EIF locally

```sh
enclave build
```

Outputs:

- `.enclave/artifacts/image.eif` — the enclave image
- `.enclave/artifacts/pcr.json` — measurement values (PCR0/1/2)
- `.enclave/artifacts/supervisor` — runtime supervisor binary

The build is fully reproducible — same inputs (commit, hashes, runtime pin)
produce byte-identical artifacts and the same PCR0.

## Cut a tagged release

Releases are dispatched manually via the `Release EIF` workflow:

1. Bump `app.nix_rev` and the runtime pin in `enclave.yaml` if needed.
2. Commit and push to `master`.
3. Run **Actions → Release EIF → Run workflow** and supply a version
   (e.g. `v0.1.0`). The workflow validates the version (`vX.Y.Z`, not
   already a tag/release), builds the EIF, and publishes a single
   immutable release containing `image.eif`, `pcr.json`, `supervisor`,
   and `deployment.json`.

