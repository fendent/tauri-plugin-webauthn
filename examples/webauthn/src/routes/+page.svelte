<script lang="ts">
  import type {
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialRequestOptionsJSON
  } from '@simplewebauthn/types';
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import {
    register,
    authenticate,
    registerListener,
    WebauthnEventType,
    sendPin,
    PinEventType,
    selectKey
  } from 'tauri-plugin-webauthn-api';

  type LogEntry = { time: string; level: 'info' | 'error' | 'action' | 'success'; message: string };

  let name = $state('');
  let authName = $state('');
  let pin = $state('');
  let logs = $state<LogEntry[]>([]);
  let keys = $state<string[]>([]);
  let needsPin = $state(false);
  let busy = $state(false);
  let logEl: HTMLElement | undefined = $state();

  function timestamp() {
    return new Date().toLocaleTimeString();
  }

  function log(level: LogEntry['level'], message: string) {
    logs.push({ time: timestamp(), level, message });
    // scroll to bottom on next tick
    requestAnimationFrame(() => {
      if (logEl) logEl.scrollTop = logEl.scrollHeight;
    });
  }

  const reg = async () => {
    if (!name.trim()) {
      log('error', 'Please enter a username first.');
      return;
    }
    busy = true;
    needsPin = false;
    try {
      log('info', `Starting registration for "${name}"...`);
      let options: PublicKeyCredentialCreationOptionsJSON = await invoke(
        'reg_start',
        { name }
      );
      log('info', 'Got challenge from server. Waiting for YubiKey...');
      log('action', 'Insert or touch your YubiKey now.');

      let response = await register('https://localhost', options);
      log('info', 'Got response from YubiKey. Verifying...');

      await invoke('reg_finish', { response });
      log('success', `Registration successful for "${name}"!`);
    } catch (e: any) {
      log('error', `Registration failed: ${e?.message ?? e}`);
    } finally {
      busy = false;
      needsPin = false;
    }
  };

  const auth = async () => {
    busy = true;
    needsPin = false;
    try {
      log('info', 'Starting discoverable authentication...');
      let options: PublicKeyCredentialRequestOptionsJSON =
        await invoke('auth_start');
      log('info', 'Got challenge. Waiting for YubiKey...');
      log('action', 'Insert or touch your YubiKey now.');

      let response = await authenticate('https://localhost', options);
      log('info', 'Got response from YubiKey. Verifying...');

      await invoke('auth_finish', { response });
      log('success', 'Authentication successful!');
    } catch (e: any) {
      log('error', `Authentication failed: ${e?.message ?? e}`);
    } finally {
      busy = false;
      needsPin = false;
    }
  };

  const auth_non_discoverable = async () => {
    if (!authName.trim()) {
      log('error', 'Please enter a username first.');
      return;
    }
    busy = true;
    needsPin = false;
    try {
      log('info', `Starting authentication for "${authName}"...`);
      let options: PublicKeyCredentialRequestOptionsJSON = await invoke(
        'auth_start_non_discoverable',
        { name: authName }
      );
      log('info', 'Got challenge. Waiting for YubiKey...');
      log('action', 'Insert or touch your YubiKey now.');

      let response = await authenticate('https://localhost', options);
      log('info', 'Got response from YubiKey. Verifying...');

      await invoke('auth_finish_non_discoverable', { response });
      log('success', 'Authentication successful!');
    } catch (e: any) {
      log('error', `Authentication failed: ${e?.message ?? e}`);
    } finally {
      busy = false;
      needsPin = false;
    }
  };

  const pinSend = async () => {
    if (!pin.trim()) {
      log('error', 'Please enter a PIN.');
      return;
    }
    try {
      log('info', 'Sending PIN to YubiKey...');
      await sendPin(pin);
      log('info', 'PIN sent. Waiting for YubiKey response...');
      pin = '';
      needsPin = false;
    } catch (e: any) {
      log('error', `Failed to send PIN: ${e?.message ?? e}`);
    }
  };

  onMount(() => {
    log('info', 'WebAuthn example ready. Using CTAP2 (USB) authenticator.');
    registerListener((event) => {
      switch (event.type) {
        case WebauthnEventType.SelectDevice:
          log('action', 'Multiple devices found. Touch the one you want to use.');
          break;
        case WebauthnEventType.PresenceRequired:
          log('action', 'Touch your YubiKey to confirm.');
          break;
        case WebauthnEventType.PinEvent:
          switch (event.event.type) {
            case PinEventType.PinRequired:
              needsPin = true;
              log('action', 'YubiKey PIN required. Enter it below.');
              break;
            case PinEventType.InvalidPin:
              needsPin = true;
              log('error',
                `Invalid PIN.${event.event.attempts_remaining ? ` ${event.event.attempts_remaining} attempts remaining.` : ''}`
              );
              break;
            case PinEventType.PinAuthBlocked:
              log('error', 'PIN authentication blocked. Remove and re-insert YubiKey.');
              needsPin = false;
              break;
            case PinEventType.PinBlocked:
              log('error', 'PIN is permanently blocked. YubiKey must be reset.');
              needsPin = false;
              break;
            case PinEventType.InvalidUv:
              log('error',
                `Invalid user verification.${event.event.attempts_remaining ? ` ${event.event.attempts_remaining} attempts remaining.` : ''}`
              );
              break;
            case PinEventType.UvBlocked:
              log('error', 'User verification blocked.');
              break;
          }
          break;
        case WebauthnEventType.SelectKey:
          keys = event.keys.map((key) => key.name ?? key.displayName ?? key.id);
          log('action', `${keys.length} keys found. Select one below.`);
          break;
      }
    });
  });
</script>

<main class="container">
  <h2>WebAuthn Example</h2>

  <section class="actions">
    <div class="action-group">
      <h3>Register</h3>
      <form class="row" onsubmit={(e) => { e.preventDefault(); reg(); }}>
        <input placeholder="Username" bind:value={name} disabled={busy} />
        <button type="submit" disabled={busy}>Register</button>
      </form>
    </div>

    <div class="action-group">
      <h3>Authenticate (discoverable)</h3>
      <div class="row">
        <button onclick={auth} disabled={busy}>Authenticate</button>
      </div>
    </div>

    <div class="action-group">
      <h3>Authenticate (by username)</h3>
      <form class="row" onsubmit={(e) => { e.preventDefault(); auth_non_discoverable(); }}>
        <input placeholder="Username" bind:value={authName} disabled={busy} />
        <button type="submit" disabled={busy}>Authenticate</button>
      </form>
    </div>
  </section>

  {#if needsPin}
    <section class="pin-prompt">
      <h3>YubiKey PIN Required</h3>
      <form class="row" onsubmit={(e) => { e.preventDefault(); pinSend(); }}>
        <input placeholder="Enter PIN" type="password" bind:value={pin} />
        <button type="submit">Submit PIN</button>
      </form>
    </section>
  {/if}

  {#if keys.length > 0}
    <section class="key-select">
      <h3>Select a Key</h3>
      {#each keys as key, i}
        <button
          class="key-btn"
          onclick={() => {
            log('info', `Selected key: ${key}`);
            selectKey(i);
            keys = [];
          }}
        >
          {key}
        </button>
      {/each}
    </section>
  {/if}

  <section class="console" bind:this={logEl}>
    <h3>Console</h3>
    {#if logs.length === 0}
      <p class="empty">No events yet.</p>
    {/if}
    {#each logs as entry}
      <div class="log-entry {entry.level}">
        <span class="log-time">{entry.time}</span>
        <span class="log-badge">{entry.level === 'action' ? 'ACTION' : entry.level === 'success' ? 'OK' : entry.level === 'error' ? 'ERROR' : 'INFO'}</span>
        <span class="log-msg">{entry.message}</span>
      </div>
    {/each}
  </section>
</main>

<style>
  :root {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    color: #1a1a1a;
    background-color: #f5f5f7;
  }

  .container {
    max-width: 640px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }

  h2 {
    margin: 0 0 1.5rem;
    font-size: 1.4rem;
  }

  h3 {
    margin: 0 0 0.5rem;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #666;
  }

  .actions {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .action-group {
    background: #fff;
    border-radius: 8px;
    padding: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }

  .row {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  input {
    flex: 1;
    padding: 0.5rem 0.75rem;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 0.95rem;
    background: #fafafa;
  }
  input:focus {
    outline: none;
    border-color: #396cd8;
    background: #fff;
  }

  button {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    background: #396cd8;
    color: white;
    white-space: nowrap;
  }
  button:hover:not(:disabled) {
    background: #2d5abc;
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .pin-prompt {
    margin-top: 1rem;
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 8px;
    padding: 1rem;
  }
  .pin-prompt h3 {
    color: #856404;
  }

  .key-select {
    margin-top: 1rem;
    background: #d1ecf1;
    border: 1px solid #17a2b8;
    border-radius: 8px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .key-select h3 {
    color: #0c5460;
  }
  .key-btn {
    background: #17a2b8;
    text-align: left;
  }
  .key-btn:hover {
    background: #138496;
  }

  .console {
    margin-top: 1.5rem;
    background: #1e1e1e;
    border-radius: 8px;
    padding: 1rem;
    max-height: 300px;
    overflow-y: auto;
  }
  .console h3 {
    color: #888;
    margin-bottom: 0.75rem;
  }

  .empty {
    color: #666;
    font-style: italic;
    margin: 0;
  }

  .log-entry {
    display: flex;
    gap: 0.5rem;
    align-items: baseline;
    padding: 0.2rem 0;
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.8rem;
    line-height: 1.4;
  }

  .log-time {
    color: #666;
    flex-shrink: 0;
  }

  .log-badge {
    flex-shrink: 0;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.05rem 0.35rem;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .log-msg {
    color: #ccc;
    word-break: break-word;
  }

  .info .log-badge { background: #2a4a7f; color: #8cb4ff; }
  .error .log-badge { background: #7f2a2a; color: #ff8c8c; }
  .error .log-msg { color: #ff8c8c; }
  .action .log-badge { background: #7f6a2a; color: #ffd666; }
  .action .log-msg { color: #ffd666; }
  .success .log-badge { background: #2a7f3a; color: #8cff8c; }
  .success .log-msg { color: #8cff8c; }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #e0e0e0;
      background-color: #1a1a1a;
    }
    .action-group {
      background: #2a2a2a;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    }
    input {
      background: #333;
      border-color: #444;
      color: #e0e0e0;
    }
    input:focus {
      background: #3a3a3a;
    }
    h2 { color: #e0e0e0; }
    .console { background: #111; }
  }
</style>
