# CosmicDrop

An open-source implementation of Apple AirDrop for the COSMIC desktop, written
in Rust, with a panel applet GUI. It is an independent port of the Python
[`seemoo-lab/opendrop`](https://github.com/seemoo-lab/opendrop) project.

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)

## Features

- **Discover** nearby AirDrop-capable Apple devices over mDNS.
- **Send** files to a discovered device (AirDrop `Discover` → `Ask` → `Upload`).
- **Receive** files from Apple devices via the AirDrop HTTPS endpoints.
- Runs as a **COSMIC panel applet**: a panel icon opens a popup with Send,
  Receive, and Settings views.
- Device icons, file-dropping, and a friendly GUI toolkit (libcosmic / iced).

## Requirements

- A Linux system with the COSMIC desktop environment.
- Rust (edition 2021+).
- System packages for Wayland development (e.g. `wayland-client`, `xkbcommon`,
  `x11`); see the distribution's COSMIC development setup.

> **Note:** Like all open AirDrop implementations, this firmware/software is
> limited by the fact that Apple does not expose the full official AirDrop
> protocol. Not all Apple-device features are guaranteed to interoperate.

## Build

```sh
cargo build --release
```

## Install

```sh
sudo ./scripts/install.sh
```

This installs the binary, the applet desktop entry (`X-CosmicApplet=true`),
and the icon. It does **not** force the applet into the panel; add it yourself
via **Settings > Desktop > Panel > Add Applet**, then drag it to the position
you want (it can be removed the same way).

> **Note:** `install.sh` requires `sudo` because it writes to
> `/usr/local`. If you prefer not to re-run the whole script after pulling
> changes, you can just reinstall the desktop entry:
>
> ```sh
> sudo install -m 0644 data/dev.cosmicdrop.CosmicDrop.desktop \
>     /usr/local/share/applications/dev.cosmicdrop.CosmicDrop.desktop
> ```
>
> The applet desktop entry must contain `X-CosmicApplet=true`, otherwise it
> will not show up in the **Add Applet** picker.

## Run

```sh
cargo run
```

The applet appears as a panel icon. Click it to open the popup:

- **Send tab** — press *Discover* to scan, select a device and a file, then
  press *Send*.
- **Receive tab** — press *Start receiving* to advertise and accept incoming
  AirDrop transfers. Files are saved to `~/.opendrop` (or the configured
  directory).
- **Settings tab** — configure the computer name, model, and network interface.

## Configuration

Configuration lives under `~/.config/cosmicdrop` (defaults follow `opendrop`):

- Receiver interface (auto-detected: `awdl0` if present, else the Wi-Fi device
  such as `wlan0`; overridable in Settings)
- Port (default `8771`)
- Computer name / model advertised via mDNS
- Self-generated TLS key pair and certificate (stored under `~/.opendrop`)

## Project layout

```
src/
  main.rs    Applet entry point
  app.rs     COSMIC panel applet GUI (iced/libcosmic)
  config.rs  Configuration, certificate/identity generation, TLS setup
  client.rs  AirDrop receiver discovery and sending client
  server.rs  AirDrop receive server (mDNS + TLS HTTP endpoints)
  util.rs    UTI (Uniform Type Identifier) and icon helpers
  certs/     Apple root CA (downloaded at setup)
```

## Protocol notes

AirDrop uses mDNS to advertise `_airdrop._tcp.local.` and HTTPS endpoints:

- `/Discover` — discover a receiver and exchange identity.
- `/Ask` — ask whether the receiver will accept a transfer.
- `/Upload` — send the (tar.gz-archived) files.

TLS certificates are self-generated and certificate verification is disabled
for interoperability, matching `opendrop`.

## Compatibility & known limitations

CosmicDrop is a port of `seemoo-lab/opendrop`, whose last release is from 2021
and whose reverse-engineered protocol has **not** kept pace with Apple. The
following apply to the whole OpenDrop ecosystem (not just this applet):

- **iOS 26 is not supported.** Modern iOS defaults to *Contacts Only*
  discovery and requires Apple-signed identity certificates that cannot be
  forged or extracted from a Mac easily. As a result, an iOS 26 device will not
  discover, nor be discovered by, this applet. Compatibility is only reliable
  against *older* iOS/macOS versions with "Everyone" discovery enabled.
- **AWDL.** Real AirDrop runs exclusively over Apple's Wireless Direct Link
  (`awdl0`). Linux needs the separate
  [OWL](https://github.com/seemoo-lab/owl) AWDL implementation for true
  AirDrop-grade discovery. CosmicDrop auto-selects `awdl0` when it is present
  and otherwise falls back to the Wi-Fi interface for mDNS browsing.
- **No peer authentication.** Like OpenDrop, we do not verify Apple's certs or
  Apple ID records, and incoming transfers are accepted automatically.

### Practical alternative: LocalSend

For sharing files with a modern iOS/Android/macOS device from Linux, consider
[LocalSend](https://github.com/localsend/localsend) — an actively maintained,
cross-platform, open-source app that does **not** require Apple's proprietary
AirDrop protocol and works with current devices out of the box.

## License

**GPL-3.0-or-later**. This project is a port of
[`seemoo-lab/opendrop`](https://github.com/seemoo-lab/opendrop), which is
licensed under the GPL-3.0, and must remain under a compatible license.
