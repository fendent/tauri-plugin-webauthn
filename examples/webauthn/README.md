# WebAuthn Example App

A Tauri + SvelteKit example demonstrating the `tauri-plugin-webauthn` plugin across macOS, iOS, and Android.

## Prerequisites

- [Node.js](https://nodejs.org/) and [pnpm](https://pnpm.io/)
- [Rust](https://www.rust-lang.org/tools/install)
- [Tauri CLI](https://v2.tauri.app/start/prerequisites/)
- An Apple Developer account (for macOS and iOS)
- A domain you control (for Associated Domains)

From the **repository root**, install dependencies and build the JS bindings:

```bash
pnpm install
pnpm build
```

## Configuration

The example app reads its Relying Party (RP) configuration from environment variables in `.env`:

| Variable | Description | Default |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | The RP domain identity | `tauri-plugin-webauthn-example.glitch.me` |
| `WEBAUTHN_RP_ORIGIN` | The RP origin URL | `https://tauri-plugin-webauthn-example.glitch.me/` |

Copy `.env.example` to `.env` and edit as needed.

## Platform Setup

Each platform requires Associated Domains configuration and code signing. See the platform-specific READMEs for detailed setup instructions:

- [**macOS**](../../macos/README.md) — entitlements, provisioning profiles, notarization, and LaunchServices registration
- [**iOS**](../../ios/README.md) — entitlements, development team, physical device requirements

Both platforms require:

1. An App ID with **Associated Domains** enabled in the Apple Developer portal
2. An AASA file hosted at `https://<your-domain>/.well-known/apple-app-site-association`
3. The `webcredentials:<your-domain>` entitlement in the app

## Relying Party Domain with Cloudflare Workers

A [Cloudflare Worker](https://developers.cloudflare.com/workers/) is a simple way to serve the required well-known association files for Apple and Android. The worker handles three paths:

- `/.well-known/apple-app-site-association` — Apple Associated Domains for passkeys (macOS and iOS)
- `/.well-known/apple-app-site-data` — alternate path some Apple services check
- `/.well-known/assetlinks.json` — Android Digital Asset Links for passkey association

### 1. Install Wrangler

```bash
npm install -g wrangler
wrangler login
```

### 2. Create the worker

```bash
mkdir webauthn-rp && cd webauthn-rp
wrangler init
```

### 3. Add the worker code

Replace the contents of `src/index.js` (or `src/index.ts`) with:

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Apple Associated Domains — used by macOS and iOS for passkey trust
    if (url.pathname === '/.well-known/apple-app-site-association' ||
        url.pathname === '/.well-known/apple-app-site-data') {
      return new Response(JSON.stringify({
        webcredentials: {
          apps: ["TEAM_ID.com.example.myapp"]
        }
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Android Digital Asset Links — used by Android for passkey association
    else if (url.pathname === '/.well-known/assetlinks.json') {
      return new Response(JSON.stringify([{
        relation: [
          "delegate_permission/common.handle_all_urls",
          "delegate_permission/common.get_login_creds"
        ],
        target: {
          namespace: "android_app",
          package_name: "com.example.myapp",
          sha256_cert_fingerprints: [
            "YOUR_SHA256_FINGERPRINT"
          ]
        }
      }]), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    return new Response('WebAuthn RP', { status: 200 });
  }
};
```

Replace the placeholder values:

| Placeholder | Value | How to find it |
| --- | --- | --- |
| `TEAM_ID` | Your Apple Developer Team ID | [Apple Developer > Membership](https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/) |
| `com.example.myapp` | Your app's bundle identifier | `identifier` in `tauri.conf.json` |
| `YOUR_SHA256_FINGERPRINT` | Your Android signing certificate fingerprint | `./gradlew signingReport` in the Android project |

The `apps` array entry must be `TEAM_ID.BUNDLE_ID` with a dot separator (not a slash).

### 4. Deploy

```bash
wrangler deploy
```

### 5. Add a custom domain

In the [Cloudflare dashboard](https://dash.cloudflare.com/):

1. Go to **Workers & Pages** > your worker > **Settings** > **Domains & Routes**
2. Add your custom domain (e.g., `webauthn.example.com`)
3. Cloudflare handles TLS automatically

### 6. Verify

```bash
# Apple association
curl https://your-domain.com/.well-known/apple-app-site-association

# Check Apple's CDN cache (may take minutes to hours to propagate)
curl https://app-site-association.cdn-apple.com/a/v1/your-domain.com

# Android association
curl https://your-domain.com/.well-known/assetlinks.json
```

### Configure `.env`

```env
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_ORIGIN=https://your-domain.com
```

## Customizing for Your Developer Account

The example ships with one developer's identifiers. Run the setup script to configure your own:

```bash
cd examples/webauthn
./setup-dev.sh
```

This will prompt for your Apple Developer Team ID, bundle identifier, and associated domain, then update `tauri.conf.json` and generate `Entitlements.plist` from the template.

After setup, follow the next steps printed by the script to register your App ID, create a provisioning profile, deploy your AASA file, and regenerate platform files.

To edit values manually instead, see `src-tauri/Entitlements.plist.example` for the template and update `tauri.conf.json`'s `identifier` field to match.

## Running

### macOS

The `build-macos-dev.sh` script builds a `.app` bundle, embeds the provisioning profile, and signs it with your Apple Development identity. Place your provisioning profile at `examples/webauthn/embedded.provisionprofile` before running.

```bash
cd examples/webauthn
./build-macos-dev.sh
```

Then launch the app with the RP environment variables:

```bash
WEBAUTHN_RP_ID=your-domain.com WEBAUTHN_RP_ORIGIN=https://your-domain.com ../../target/debug/bundle/macos/webauthn.app/Contents/MacOS/webauthn
```

Note: using `open webauthn.app` will not pass environment variables from your shell. Run the binary directly instead.

For macOS development, you also need to enable Associated Domains developer mode:

```bash
sudo swcutil developer-mode -e true
```

### iOS

Requires a physical device — the iOS Simulator does not support passkeys.

```bash
pnpm tauri ios dev
```

Or open in Xcode for more control over signing and debugging:

```bash
pnpm tauri ios dev --open
```

## Notes

- **Credentials are stored in memory** and will be lost when the app restarts. This is expected for an example app.
- The in-app console shows color-coded log entries for registration/authentication flow, errors, and prompts.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
