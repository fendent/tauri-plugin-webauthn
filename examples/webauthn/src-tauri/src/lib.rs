use std::{collections::HashMap, env};

use chrono::Local;
use tauri::{async_runtime::Mutex, State, Url};

const DEFAULT_RP_ID: &str = "tauri-plugin-webauthn-example.glitch.me";
const DEFAULT_RP_ORIGIN: &str = "https://tauri-plugin-webauthn-example.glitch.me/";

fn rp_id() -> String {
  env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| DEFAULT_RP_ID.to_string())
}

fn rp_origin() -> String {
  env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| DEFAULT_RP_ORIGIN.to_string())
}
use tauri_plugin_log::{RotationStrategy, Target, TargetKind, TimezoneStrategy};
use webauthn_rs::{
  prelude::{
    DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration, Uuid,
  },
  Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[tauri::command]
async fn reg_start(
  state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  webauthn: State<'_, Webauthn>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  name: &str,
) -> Result<PublicKeyCredentialCreationOptions, String> {
  let mut users = users.lock().await;
  let uuid = users.entry(name.to_string()).or_insert(Uuid::new_v4());

  let passkeys = passkeys.lock().await;
  let passkey = passkeys
    .get(uuid)
    .map(|p| p.iter().map(|p| p.cred_id().clone()).collect());

  let (challenge, state_val) = webauthn
    .start_passkey_registration(*uuid, name, name, passkey)
    .map_err(|e| format!("Failed to start registration: {e:?}"))?;

  let mut state = state.lock().await;
  state.replace((state_val, *uuid));

  Ok(challenge.public_key)
}

#[tauri::command]
async fn reg_finish(
  state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  webauthn: State<'_, Webauthn>,
  response: RegisterPublicKeyCredential,
) -> Result<(), String> {
  let mut state = state.lock().await;
  let (passkey_reg, uuid) = state
    .take()
    .ok_or("No pending registration. Did you call register first?")?;

  let passkey = webauthn
    .finish_passkey_registration(&response, &passkey_reg)
    .map_err(|e| format!("Failed to verify registration: {e:?}"))?;

  let mut passkeys = passkeys.lock().await;
  let passkeys = passkeys.entry(uuid).or_default();
  passkeys.push(passkey);

  Ok(())
}

#[tauri::command]
async fn auth_start(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
) -> Result<PublicKeyCredentialRequestOptions, String> {
  let (challenge, state_val) = webauthn
    .start_discoverable_authentication()
    .map_err(|e| format!("Failed to start authentication: {e:?}"))?;

  let mut state = state.lock().await;
  state.replace(state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn auth_start_non_discoverable(
  webauthn: State<'_, Webauthn>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  name: &str,
) -> Result<PublicKeyCredentialRequestOptions, String> {
  let users = users.lock().await;
  let uuid = users
    .get(name)
    .ok_or(format!("User \"{name}\" not found. Register first."))?;

  let passkeys = passkeys.lock().await;
  let passkey = passkeys
    .get(uuid)
    .ok_or("No passkey found for this user. Register first.")?;

  let (challenge, state_val) = webauthn
    .start_passkey_authentication(passkey)
    .map_err(|e| format!("Failed to start authentication: {e:?}"))?;

  let mut state = state.lock().await;
  state.replace(state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn auth_finish(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  response: PublicKeyCredential,
) -> Result<(), String> {
  let (user, cred_id) = webauthn
    .identify_discoverable_authentication(&response)
    .map_err(|e| format!("Failed to identify credential: {e:?}"))?;

  let passkeys = passkeys.lock().await;
  let passkey = passkeys
    .get(&user)
    .and_then(|p| p.iter().find(|p| p.cred_id() == cred_id))
    .ok_or("Passkey not found. You may need to register again in this session.")?;

  let mut state = state.lock().await;
  let passkey_auth = state
    .take()
    .ok_or("No pending authentication. Did you call authenticate first?")?;
  webauthn
    .finish_discoverable_authentication(&response, passkey_auth, &[passkey.into()])
    .map_err(|e| format!("Failed to verify authentication: {e:?}"))?;
  Ok(())
}

#[tauri::command]
async fn auth_finish_non_discoverable(
  webauthn: State<'_, Webauthn>,
  state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
  response: PublicKeyCredential,
) -> Result<(), String> {
  let passkey_auth = state
    .lock()
    .await
    .take()
    .ok_or("No pending authentication. Did you call authenticate first?")?;
  webauthn
    .finish_passkey_authentication(&response, &passkey_auth)
    .map_err(|e| format!("Failed to verify authentication: {e:?}"))?;
  Ok(())
}

#[tauri::command]
fn get_rp_origin() -> String {
  rp_origin()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  // Load .env from the example root (parent of src-tauri)
  let _ = dotenvy::from_filename("../.env");
  let rp_id = rp_id();
  let rp_origin = rp_origin();
  log::info!("Using RP ID: {rp_id}, Origin: {rp_origin}");

  tauri::Builder::default()
    .manage(
      WebauthnBuilder::new(
        &rp_id,
        &Url::parse(&rp_origin).expect("Invalid WEBAUTHN_RP_ORIGIN URL"),
      )
      .unwrap()
      .append_allowed_origin(
        &Url::parse("android:apk-key-hash:W8LAR3CdJ3CAVCTuv3_J5fF2iKYGYQhYfKq9ANbOzjI").unwrap(),
      )
      .build()
      .unwrap(),
    )
    .manage(Mutex::new(Option::<DiscoverableAuthentication>::None))
    .manage(Mutex::new(Option::<PasskeyAuthentication>::None))
    .manage(Mutex::new(Option::<(PasskeyRegistration, Uuid)>::None))
    .manage(Mutex::new(HashMap::<Uuid, Vec<Passkey>>::new()))
    .manage(Mutex::new(HashMap::<String, Uuid>::new()))
    .plugin(
      tauri_plugin_log::Builder::new()
        .clear_targets()
        .target(Target::new(TargetKind::Stdout))
        .target(Target::new(TargetKind::LogDir {
          file_name: Some(Local::now().to_rfc3339().replace(":", "-")),
        }))
        .rotation_strategy(RotationStrategy::KeepAll)
        .timezone_strategy(TimezoneStrategy::UseLocal)
        .build(),
    )
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_webauthn::init())
    .invoke_handler(tauri::generate_handler![
      reg_start,
      reg_finish,
      auth_start,
      auth_finish,
      auth_start_non_discoverable,
      auth_finish_non_discoverable,
      get_rp_origin,
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
