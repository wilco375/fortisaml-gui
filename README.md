# FortiSAML VPN

A native Linux client for **FortiGate dial-up IPsec (IKEv2) VPNs with SAML single sign-on**, written in Rust with an [egui](https://github.com/emilk/egui) interface. It supports Fortinet VPN IPsec connections, including SSO, which is not supported by the official FortiClient VPN application on Linux.

---

## Features

- **SAML SSO:** login in your normal browser, with a local callback.
- **Username/password (EAP)** and **pre-shared-key-only** modes when SSO is off.
- **IKEv2** with the Fortinet vendor IDs, configurable phase 1 and phase 2 proposals (AES-128/192/256-CBC, SHA1/256/384/512) and DH groups 14, 19, 20 and 21.
- **EAP methods:** MSCHAPv2, GTC and MD5 (the FortiGate picks one).
- **Gateway authentication** with the PSK is verified, so a gateway that doesn't know it is rejected.
- **Kernel IPsec:** XFRM with UDP-encapsulated ESP on an `fsaml0` xfrm interface. The kernel carries all traffic.
- **Routing:** split tunnel as pushed by the gateway, full tunnel, or a custom network list. In full-tunnel mode IPv6 is blocked so it can't leak around the VPN.
- **DNS** from the VPN via systemd-resolved.
- **Root only while connected:** a `pkexec` prompt appears on Connect, and the GUI itself never runs as root.
- **Multiple connection profiles**, saved with the Save button. The PSK and password are stored in your desktop keyring.

## Requirements

| | |
|---|---|
| OS | Linux with XFRM interface support (kernel ≥ 4.19) |
| Runtime tools | `pkexec` (polkit) with a desktop polkit agent, `ip` (iproute2), `xdg-open`; `resolvectl` (systemd-resolved) for VPN DNS |
| Keyring (optional) | a Secret Service provider (GNOME Keyring, KWallet, KeePassXC) to remember the PSK and password; without one they're kept in memory until the app closes |
| Build | Rust ≥ 1.85 (edition 2024), `cargo` |
| Display | X11 or Wayland; OpenGL rendering via glow |

## Build and run

```bash
cargo build --release
./target/release/fortisaml-gui
```

The binary is self-contained. When you connect, it starts a second copy of itself as root (`pkexec fortisaml-gui --backend`).

## Usage

1. Click **➕ New** and fill in the connection:
   - **Remote gateway:** the FortiGate address, e.g. `vpn.example.com`.
   - **Pre-shared key:** the phase 1 PSK. It is needed even with SSO, because the gateway authenticates itself with it.
2. Under **Authentication**:
   - **With SSO:** tick *Enable Single Sign On (SSO) for VPN Tunnel* and set **Customize port** to the FortiGate's `auth-ike-saml-port`, for example 10443.
   - **Without SSO:** choose *Username and password (EAP)* or *None (pre-shared key only)*.
3. Optionally adjust **VPN settings**, **Phase 1**, **Phase 2** and **Network** to match the FortiGate / EMS profile. The defaults match FortiClient's: AES128-SHA1 and AES256-SHA256, DH 20.
4. Click **Connect**:
   1. With SSO, your browser opens; log in there.
   2. The system asks for your password (pkexec), because setting up the tunnel needs root.
   3. The status changes to **Connected**, showing the VPN IP, routes, DNS, duration and traffic counters.
5. Click **Disconnect** to tear everything down. Closing the window also disconnects.

**Settings (⚙):**
- **Client UID:** the FortiClient-style installation ID sent to the FortiGate. You can regenerate it.
- **Log file:** an optional path; the log is also shown in the 📜 Log panel.
- **Verbose logging:** encryption keys are always redacted.

### Command-line modes

| Command | Purpose |
|---|---|
| `fortisaml-gui` | Start the GUI |
| `fortisaml-gui --probe [options]` | **Unprivileged test:** SSO + full IKEv2/EAP negotiation with the selected profile, then delete the SA. Nothing is installed in the kernel. |
| `sudo fortisaml-gui --down [ifname]` | Remove leftovers of a crashed session (XFRM states/policies, interface, routes) |
| `fortisaml-gui --backend` | Internal: the privileged backend started by pkexec |

`--probe` options:
- override the profile: `--gateway H`, `--saml-port P`, `--ike-port P`, `--psk K`
- certificate and browser: `--no-verify` (skip TLS certificate checks), `--no-browser` (don't open the browser)
- credentials: `--token T` (use an existing SSO token), `--no-sso --username U --password P` (username/password login), `--no-eap` (PSK only)
- `-v` for verbose output

Environment: `FORTISAML_BROWSER=<command>` replaces `xdg-open` for opening the SSO page.

## How it works

```
GUI (your user)                         Backend (root, via pkexec)              FortiGate
───────────────                         ──────────────────────────              ─────────
POST /saml_login?  UID=…&REDIRECT_PORT=p ─────────────────────────────────────▶ (HTTPS, SSO port)
browser → IdP login → 127.0.0.1:p/?tokenid=…  ◀──────────────────────────────── redirect
pkexec --backend; stdin: {settings, PSK, token}
                                        IKE_SA_INIT (UDP 500, Fortinet VIDs) ──▶
                                        IKE_AUTH (UDP 4500) + EAP:
                                          identity = client UID, secret = token ▶
                                        ◀── PSK AUTH, child SA, IP/DNS/routes
                                        kernel: XFRM states/policies, fsaml0,
                                        routes (proto 233), resolvectl DNS
◀── "@@{json}" status events on stdout   keepalives / DPD until "disconnect"/EOF
```

- The GUI never runs as root. Root is held only for the length of the connection, by a process that does just IKE and the kernel setup.
- Secrets (PSK, SSO token, password) reach the backend over a pipe, never on the command line. The stdin pipe then acts as the control channel: a `disconnect` line, or EOF when the GUI exits or crashes, makes the backend clean up and exit.
- Traffic is encrypted by the kernel. The backend only sends NAT-T keepalives and answers the gateway's dead-peer detection.

### Source layout

| File | Role |
|---|---|
| `src/main.rs` | egui UI; dispatches `--backend` / `--probe` / `--down` |
| `src/config.rs` | profile model, defaults, TOML settings files and state |
| `src/keyring.rs` | PSK / password storage in the Secret Service |
| `src/backend.rs` | connection session, pkexec bridge, privileged main loop, probe mode |
| `src/saml.rs` | FortiGate SAML flow and local callback server |
| `src/tls.rs` | rustls HTTPS client with system CAs and AIA intermediate fetching |
| `src/ike.rs` | IKEv2 initiator: messages, proposals, EAP, AUTH, child SA, Mode Config |
| `src/crypto.rs` | PRF/prf+, AES-CBC, DH, MD4, MSCHAPv2/MPPE (RustCrypto) |
| `src/tunnel.rs` | kernel XFRM / routes / DNS setup and cleanup (iproute2, resolvectl) |

## Configuration and security

- Settings are saved when you click **Save**, under `~/.config/fortisaml-gui/` (or `$XDG_CONFIG_HOME`), mode `0600` in a `0700` directory. Closing with unsaved changes asks first.
  - `config.toml`: app settings (client UID, log file, verbose logging).
  - `profiles/<connection name>.toml`: one file per connection. To share a connection, click **🔗 Share** and send the file. The recipient puts it in their `profiles/` folder, restarts the app and enters the PSK.
  - Both only contain settings that differ from the defaults.
- `~/.local/state/fortisaml-gui/state.json` (or `$XDG_STATE_HOME`) holds which connection is selected and the internal ids that link connections to their keyring items. The app manages it; don't edit it.
- A connection file that can't be read is reported at startup and left untouched. A `config.toml` that can't be read is reported and replaced when you click **Save**. Older `config.json` files are not read.
- The **PSK** and a **saved password** are not in these files. They're stored in your desktop keyring through the freedesktop Secret Service, as items labelled `FortiSAML VPN: <connection> (PSK)` / `(password)`. Without a Secret Service they're kept in memory until the app closes.
- A password is stored only if *Save password* is ticked; otherwise it lives in memory until the app closes.
- The SSO token is single-use and never written to disk.
- **TLS on the SSO port:**
  - *Verify the server certificate* uses the system CA store.
  - If the FortiGate omits its intermediate certificate, it is fetched via the certificate's AIA URL, like browsers do. Downloaded certificates are only used as untrusted intermediates.
  - With verification off, any certificate is accepted (FortiClient's default behaviour).
- The pkexec prompt names the binary path. Run the app from a location that only you (or root) can write to.

## Testing

```bash
cargo test                       # crypto known-answer tests (RFC 1320/2759/3079/4231, NIST SP 800-38A), parsers
```

End-to-end tests run against the mock FortiGate in `../poc/tests/`. The mock is a Python test harness only; the client doesn't depend on it. It offers HTTPS SSO with a fake identity provider and an IKEv2 responder supporting MSCHAPv2/GTC, username/password, and PSK-only:

```bash
cd ../poc/tests
python3 mock_fortigate.py --eap mschapv2 --psk testpsk &       # add --user U --password P, or --no-eap
FORTISAML_BROWSER=$PWD/fake_browser.py \
  ../../fortisaml-gui/target/release/fortisaml-gui --probe --gateway 127.0.0.1 \
  --saml-port 10443 --ike-port 5500 --psk testpsk --no-verify -v
```

Against a real gateway (no root needed, nothing installed): `fortisaml-gui --probe -v`.

## Limitations

- **No rekeying.** Gateway-initiated `CREATE_CHILD_SA` rekeys are not handled. The tunnel stops working when the phase 2 lifetime (default 43200 s = 12 h) or the IKE SA lifetime expires; reconnect when that happens.
- **IPv4 only:** the inner tunnel and the gateway address are IPv4.
- **Encryption:** AES-CBC only, no AES-GCM or ChaCha20.
- **Gateway certificate authentication** (AUTH methods other than PSK) is accepted with a warning but **not verified**.
- **Not supported:**
  - IKEv1, IKE over TCP / "IPsec over TCP"
  - FortiToken push / OTP challenges
  - EMS / ZTNA compliance checks
  - Fortinet private notifies (license blob, EMS serial)
- **One connection at a time.** The xfrm `if_id` and route tag are fixed.
- **Platform dependencies:** VPN DNS requires systemd-resolved; the root prompt requires a polkit agent.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
