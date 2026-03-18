# WebAuthn Example App

A Tauri + SvelteKit example demonstrating the `tauri-plugin-webauthn` plugin with the macOS platform authenticator (passkeys/Touch ID/security keys via system UI).

## Prerequisites

- [Node.js](https://nodejs.org/) and [pnpm](https://pnpm.io/)
- [Rust](https://www.rust-lang.org/tools/install)
- [Tauri CLI](https://v2.tauri.app/start/prerequisites/)
- An Apple Developer account
- A domain you control (for Associated Domains)

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

## Setup

The macOS platform authenticator uses `ASAuthorizationController` to present the native passkey/security key UI (Touch ID, iCloud Keychain, or USB keys via the system prompt). It requires code signing with entitlements and an Associated Domains setup.

### 1. Domain setup

Your RP domain must serve an `apple-app-site-association` file at `https://<your-domain>/.well-known/apple-app-site-association`:

```json
{
  "webcredentials": {
    "apps": ["<TEAM_ID>.<BUNDLE_ID>"]
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

### 3. Enable Associated Domains developer mode

```bash
sudo swcutil developer-mode -e true
```

### 4. Entitlements

The `src-tauri/Entitlements.plist` file links the app to your RP domain via Associated Domains. Update the domain if you use a different RP:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>webcredentials:your-domain.com?mode=developer</string>
</array>
```

The `?mode=developer` suffix bypasses Apple's CDN cache and fetches the association file directly from your server during development.

### 5. Configure `.env`

```env
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_ORIGIN=https://your-domain.com
```

### 6. Build and run

The `build-macos-dev.sh` script builds a `.app` bundle, embeds the provisioning profile, and signs it with your Apple Development identity:

```bash
cd examples/webauthn
./build-macos-dev.sh
```

Then launch the app with the RP environment variables:

```bash
WEBAUTHN_RP_ID=your-domain.com WEBAUTHN_RP_ORIGIN=https://your-domain.com ../../target/debug/bundle/macos/webauthn.app/Contents/MacOS/webauthn
```

Note: using `open webauthn.app` will not pass environment variables from your shell. Run the binary directly instead.

## Notes

- **Credentials are stored in memory** and will be lost when the app restarts. This is expected for an example app.
- The in-app console shows color-coded log entries for registration/authentication flow, errors, and prompts.
- The plugin uses `ASAuthorizationController` which presents both passkey (Touch ID/iCloud Keychain) and security key options in the native system UI.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
