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

This installs the binary, the desktop entry, and (in future) an icon. After
installing, restart the COSMIC panel (or sign out and back in) for the applet
to appear.

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

- Receiver interface (e.g. `awdl0`)
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

## License

**GPL-3.0-or-later**. This project is a port of
[`seemoo-lab/opendrop`](https://github.com/seemoo-lab/opendrop), which is
licensed under the GPL-3.0, and must remain under a compatible license.
