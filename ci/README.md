# CI and release pipeline

`.github/workflows/ci.yml` runs on every push to `main`, on pull requests and
on `v*` tags. Each job is a thin wrapper around a script in this directory, so
every stage can be run on a developer machine with Docker.

```
lint ─────────┐
fmt ──────────┤
clippy ───────┤
test ─────────┤
nft ──────────┤
version ──┬── build (x86_64, aarch64, armv7) ──┬── openwrt (23.05 ipk, 24.10 ipk, 25.12 apk) ──┤
          │                                    └── linux (deb, rpm) ──────────────────────────┤
          └── mipsel (experimental, never blocks) ────────────────────────────────────────────┴── release (v* tags only)
```

| Job | What it does | Script |
|---|---|---|
| `lint` | `sh -n` and shellcheck (warnings are errors) for `ci/*.sh` and every `/bin/sh` script under `openwrt/`; LuCI views and JSON; `Cargo.toml` version against the OpenWrt Makefiles; the libpcap pin in `Cross.toml` against `build-libpcap.sh` | `lint-shell.sh`, `check-luci.js`, `version.sh` |
| `fmt` | `cargo fmt --check` | |
| `clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` | |
| `test` | `cargo test --workspace --locked` on Linux, without the one test that needs root (next row) | |
| `nft` | Runs the `nft_syntax` test as root with `GSWIFI_NFT_DUMP`, then has the `nft` of OpenWrt 23.05, 24.10 and 25.12 check every generated ruleset (`nft -c -f`, in the rootfs with `NET_ADMIN`). One rejected ruleset fails the job | `nft-dump.sh`, `openwrt-rootfs.sh`, `nft-check.sh` |
| `version` | Package version: `<Cargo version>` on a tag (which must be `v<Cargo version>`), `<Cargo version>_git<commit time>` otherwise | `version.sh` |
| `build` | `cross build --release --locked -p gswifi` for three musl targets with a static libpcap, `cross test --workspace` on the target (qemu for the foreign ones), then checks that the binary is static and stripped, runs it (armv7 on a CPU model without FPU), reports its size | `install-cross.sh`, `build-libpcap.sh` (through `Cross.toml`), `check-binary.sh` |
| `mipsel` | The same build for `mipsel-unknown-linux-musl` with a nightly toolchain and `-Zbuild-std`, run on a MIPS32r2 model without FPU. `continue-on-error`: a failure shows up red but blocks nothing | same |
| `openwrt` | Builds the ipk/apk packages and installs and exercises them in the OpenWrt x86-64 rootfs of each release | `package.sh`, `openwrt-test.sh`, `openwrt-rootfs.sh` |
| `linux` | Builds deb and rpm packages (systemd unit `linux/gswifi.service`, config `linux/config.toml`) and installs them in Debian stable, Ubuntu 20.04, Fedora and Rocky Linux 8 | `linux-package.sh`, `linux-test.sh` |
| `release` | On a `v*` tag, after everything above passed: collects the tarballs and packages, writes `SHA256SUMS` and the notes, publishes the GitHub release | `release-notes.sh` |

Artifacts of a run (Actions → the run → Artifacts): `build-<family>` (the bare
binary `gswifi-<family>` and `gswifi-<version>-<family>-linux-musl.tar.gz`),
`packages-ipk`, `packages-apk`, `packages-linux`, `experimental-mipsel`,
`nft-rulesets`. The size of each binary is in the summary of its build job.

## Running a stage locally

All commands are run from the repository root. The nft, build and package
stages need Docker.

```sh
# lint (shellcheck: the pinned koalaman/shellcheck image, or PATH without Docker)
sh ci/lint-shell.sh
node ci/check-luci.js openwrt/luci-app-gswifi
sh ci/version.sh                  # prints cargo= and version=
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings

# test (needs libpcap: libpcap-dev on Debian/Ubuntu, built in on macOS).
# On Linux with nft installed, one test runs "nft -c", which only root may:
# skip it as CI does and leave it to the nft stage below.
cargo test --workspace --locked -- --skip every_variant_is_valid_nftables

# nft: dump the rulesets, then check them in an OpenWrt rootfs
sh ci/nft-dump.sh /tmp/gswifi-nft
image=$(sh ci/openwrt-rootfs.sh 24.10.8)          # downloads and imports once
docker run --rm --cap-add NET_ADMIN -v "$PWD/ci:/ci:ro" -v /tmp/gswifi-nft:/nft:ro \
    "$image" sh /ci/nft-check.sh /nft

# build: static binaries in target/<target>/release/gswifi
cargo install cross --version 0.2.5 --locked      # CI: sh ci/install-cross.sh
cross build --release --locked -p gswifi --target aarch64-unknown-linux-musl
cross test --workspace --locked --target aarch64-unknown-linux-musl
sh ci/check-binary.sh target/aarch64-unknown-linux-musl/release/gswifi 0.1.0 qemu-aarch64-static

# packages, from a directory holding gswifi-x86_64, gswifi-aarch64, gswifi-armv7
version=$(sh ci/version.sh | sed -n 's/^version=//p')
sh ci/package.sh ipk "$version" bin packages                       # GNU tar
docker run --rm -v "$PWD:/src" -w /src alpine:3.24 \
    sh ci/package.sh apk "$version" bin packages
docker run --rm -v "$PWD/packages:/pkgs:ro" -v "$PWD/ci:/ci:ro" \
    "$(sh ci/openwrt-rootfs.sh 24.10.8)" sh /ci/openwrt-test.sh ipk /pkgs
sh ci/linux-package.sh deb "$version" bin packages                 # on Linux
sh ci/linux-package.sh rpm "$version" bin packages
docker run --rm -v "$PWD/packages:/pkgs:ro" -v "$PWD/ci:/ci:ro" \
    debian:stable sh /ci/linux-test.sh deb /pkgs

# release notes (the release job adds the directory it publishes as a second
# argument, to take the real file names and to fail if one is missing)
sh ci/release-notes.sh "$version"
```

`check-binary.sh` wants `file` and `readelf`; `linux-package.sh` wants GNU
coreutils, `dpkg-deb` and `rpmbuild`. On macOS run those two inside a Debian
container (`apt-get install file binutils qemu-user-static dpkg-dev rpm`).

On an arm64 host (Apple Silicon) cross 0.2.5 needs two nudges, because its
images exist for amd64 only (they then run emulated, a few minutes per
target):

```sh
rustup toolchain install 1.96.1-x86_64-unknown-linux-gnu --profile minimal --force-non-host
rustup target add --toolchain 1.96.1-x86_64-unknown-linux-gnu aarch64-unknown-linux-musl
DOCKER_DEFAULT_PLATFORM=linux/amd64 \
    cross +1.96.1 build --release --locked -p gswifi --target aarch64-unknown-linux-musl
```

## How the static build works

`Cross.toml` tells cross to run `ci/build-libpcap.sh` while it prepares the
image of a target. The script downloads libpcap (pinned version and SHA-256),
builds it with the C toolchain of the target as a static library with
everything optional switched off, and installs it in `/opt/libpcap`.
`Cross.toml` then passes `LIBPCAP_LIBDIR` and `LIBPCAP_VER` to
`vendor/pcap/build.rs`. Rust's musl targets link statically by default, so the
result has no dynamic loader and no shared library: `check-binary.sh` fails
the build if it ever does.

## mipsel (experimental)

The original GSWIFI routers are MT7621: `mipsel_24kc`, no FPU. Rust keeps
`mipsel-unknown-linux-musl` in tier 3, so there is no prebuilt standard
library and the job differs from the other builds in three ways, all of them
in `Cross.toml` and `build-libpcap.sh`:

- a pinned nightly toolchain with `rust-src`, and `build-std = true`;
- `-C target-feature=+crt-static -C link-self-contained=no`: this target links
  dynamically by default, and without a prebuilt std there are no bundled
  C runtime objects, so the ones of the cross toolchain are used;
- `libunwind.a`, which a static std wants, is an alias of GCC's `libgcc_eh.a`.

```sh
rustup toolchain install nightly-2026-11-19 --profile minimal --component rust-src
cross +nightly-2026-11-19 build --release --locked -p gswifi --target mipsel-unknown-linux-musl
sh ci/check-binary.sh target/mipsel-unknown-linux-musl/release/gswifi 0.1.0 "qemu-mipsel-static -cpu 24Kc"
```

32-bit MIPS has no 64-bit atomics: code that uses `AtomicU64` does not compile
for it (use `AtomicUsize`/`AtomicU32`, or the `portable-atomic` crate). The
job produces a tarball only; there is no mipsel OpenWrt package, and the
binary has never run on a real MT7621.

## Cutting a release

1. Set the version in `Cargo.toml` (`[workspace.package] version`) and, where
   an OpenWrt Makefile carries a `PKG_VERSION`, there too. Run
   `cargo update --workspace` (or any build) so that `Cargo.lock` follows; CI
   builds with `--locked`.
2. Commit, push to `main`, wait for a green run.
3. Tag that commit `v<version>` and push the tag:
   `git tag v0.1.0 && git push origin v0.1.0`.

The tag run repeats the whole pipeline and ends with the `release` job, which
publishes a GitHub release named after the tag with the three tarballs (four
when the mipsel build worked), the ipk, apk, deb and rpm packages,
`SHA256SUMS` and the notes from `release-notes.sh` followed by GitHub's
generated change list. A tag that does
not match `Cargo.toml` fails in the `version` job before anything is built. A
tag with a hyphen (`v0.2.0-rc1`, for Cargo version `0.2.0-rc1`) becomes a
pre-release; its packages are versioned `0.2.0_rc1` (`0.2.0~rc1` inside deb
and rpm), which sorts before `0.2.0`.

Nothing is published when a job other than `mipsel` fails. For a failure
that is not the code's fault (a download, a runner), use "Re-run failed jobs"
on the run. Otherwise fix the problem, delete the tag
(`git push origin :v0.1.0`) and tag again; a release that already exists must
be deleted first (`gh release delete v0.1.0`).

## Pinned versions

| What | Where | Bumped by |
|---|---|---|
| GitHub Actions (commit SHAs) | `.github/workflows/ci.yml` | Dependabot |
| Crates | `Cargo.lock` | Dependabot |
| Rust toolchain (`RUST_TOOLCHAIN`), nightly for mipsel (`RUST_NIGHTLY`) | `.github/workflows/ci.yml` | hand |
| cross and its SHA-256 | `ci/install-cross.sh` | hand |
| shellcheck image | `ci/lint-shell.sh` | hand |
| libpcap and its SHA-256 | `ci/build-libpcap.sh`, `LIBPCAP_VER` in `Cross.toml` | hand |
| OpenWrt releases | `OPENWRT_RELEASES` of the `nft` job and the matrix of the `openwrt` job | hand |
| Alpine (for `apk mkpkg`) | `openwrt` job | hand |

The Rust toolchain is pinned so that `cargo fmt` and clippy give the same
answer in CI as on the machine that last ran them: after bumping
`RUST_TOOLCHAIN`, run `cargo fmt` and clippy with that version in the
same commit.
