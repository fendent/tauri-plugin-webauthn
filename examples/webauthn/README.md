# WebAuthn Example App

A Tauri + SvelteKit example demonstrating the `tauri-plugin-webauthn` plugin with both the macOS platform authenticator (passkeys/Touch ID/security keys via system UI) and CTAP2 USB security key modes.

## Prerequisites

- [Node.js](https://nodejs.org/) and [pnpm](https://pnpm.io/)
- [Rust](https://www.rust-lang.org/tools/install)
- [Tauri CLI](https://v2.tauri.app/start/prerequisites/)

From the **repository root**, install dependencies and build the JS bindings:

```bash
pnpm install
pnpm build
```

## Configuration

The example app reads its Relying Party (RP) configuration from environment variables in `.env`:

| Variable             | Description            | Default                                            |
| -------------------- | ---------------------- | -------------------------------------------------- |
| `WEBAUTHN_RP_ID`     | The RP domain identity | `tauri-plugin-webauthn-example.glitch.me`          |
| `WEBAUTHN_RP_ORIGIN` | The RP origin URL      | `https://tauri-plugin-webauthn-example.glitch.me/` |

Copy `.env.example` to `.env` and edit as needed.

## Option A: CTAP2 / USB Security Key (simplest)

This mode uses the `authenticator` crate to talk directly to a USB security key (e.g., YubiKey) over CTAP2. No code signing, provisioning profiles, or domain setup required.

### 1. Enable the `ctap2` feature

In `src-tauri/Cargo.toml`, change the plugin dependency to:

```toml
tauri-plugin-webauthn = { path = "../../../", features = ["ctap2"] }
```

### 2. Set RP to localhost

In `.env`:

```env
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_ORIGIN=https://localhost
```

### 3. Run

```bash
cd examples/webauthn
pnpm tauri dev
```

Plug in your security key. The app will prompt for PIN and key interaction via the in-app console.

## Option B: macOS Platform Authenticator (passkeys + system UI)

This mode uses `ASAuthorizationController` to present the native macOS passkey/security key UI (Touch ID, iCloud Keychain, or USB keys via the system prompt). It requires code signing with entitlements and an Associated Domains setup.

### 1. Domain setup

Your RP domain must serve an `apple-app-site-data` file at `https://<your-domain>/.well-known/apple-app-site-data`:

```json
{
  "webcredentials": {
    "apps": ["<TEAM_ID>.<BUNDLE_ID>"]
  }
}
```

For example, with Team ID `86TDY6D9V2` and bundle ID `net.kackman.webauthn.example`:

```json
{
  "webcredentials": {
    "apps": ["86TDY6D9V2.net.kackman.webauthn.example"]
  }
}
```

A Cloudflare Worker is an easy way to serve this.

### 2. Apple Developer Portal

1. Register an **App ID** at the [Apple Developer Portal](https://developer.apple.com/account/resources/identifiers/list)
   - Bundle ID (Explicit): your bundle ID (e.g., `net.kackman.webauthn.example`)
   - Enable the **Associated Domains** capability
2. Create a **macOS App Development** provisioning profile at the [Profiles page](https://developer.apple.com/account/resources/profiles/list)
   - Select your App ID, development certificate, and Mac device
   - Download the `.mobileprovision` file
3. Place the profile at `examples/webauthn/embedded.provisionprofile`

### 3. Entitlements

The `src-tauri/Entitlements.plist` file links the app to your RP domain via Associated Domains. Update the domain if you use a different RP:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>webcredentials:your-domain.com</string>
</array>
```

### 4. Configure `.env`

```env
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_ORIGIN=https://your-domain.com
```

### 5. Remove the `ctap2` feature

In `src-tauri/Cargo.toml`, use the plugin without the `ctap2` feature:

```toml
tauri-plugin-webauthn = { path = "../../../" }
```

### 6. Build and run

The `build-macos-dev.sh` script builds a `.app` bundle, embeds the provisioning profile, and signs it with your Apple Development identity:

```bash
cd examples/webauthn
./build-macos-dev.sh
```

Then launch the app:

```bash
open ../../target/debug/bundle/macos/webauthn.app
```

Or run directly:

```bash
../../target/debug/bundle/macos/webauthn.app/Contents/MacOS/webauthn
```

## Notes

- **Credentials are stored in memory** and will be lost when the app restarts. This is expected for an example app.
- The in-app console shows color-coded log entries for registration/authentication flow, errors, and prompts.
- On macOS without the `ctap2` feature, the plugin uses `ASAuthorizationController` which presents both passkey (Touch ID/iCloud Keychain) and security key options in the native system UI.
- On macOS with the `ctap2` feature, the plugin communicates directly with USB security keys via the `authenticator` crate, bypassing the system UI.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
