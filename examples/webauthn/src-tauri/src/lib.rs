use std::{collections::HashMap, env};

use chrono::Local;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::Mutex, State, Url};

const DEFAULT_RP_ID: &str = "tauri-plugin-webauthn-example.glitch.me";
const DEFAULT_RP_ORIGIN: &str = "https://tauri-plugin-webauthn-example.glitch.me/";

fn rp_id() -> String {
  env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| DEFAULT_RP_ID.to_string())
}

fn rp_origin() -> String {
  env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| DEFAULT_RP_ORIGIN.to_string())
}

#[derive(Clone, Serialize, Deserialize)]
struct RpConfig {
  rp_id: String,
  rp_origin: String,
}

fn build_webauthn(rp_id: &str, rp_origin: &str) -> Result<Webauthn, String> {
  let url = Url::parse(rp_origin).map_err(|e| format!("Invalid RP origin URL: {e}"))?;
  let builder = WebauthnBuilder::new(rp_id, &url)
    .map_err(|e| format!("Failed to create WebauthnBuilder: {e}"))?
    .append_allowed_origin(
      &Url::parse("android:apk-key-hash:ACDefg1Oe_Oghhc1udjQbgeC9Za9h_fyf9vjJaBx-VI").unwrap(),
    );
  builder
    .build()
    .map_err(|e| format!("Failed to build Webauthn: {e}"))
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
  webauthn: State<'_, Mutex<Webauthn>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  name: &str,
) -> Result<PublicKeyCredentialCreationOptions, String> {
  let mut users = users.lock().await;
  let uuid = users.entry(name.to_string()).or_insert(Uuid::new_v4());

  let passkeys = passkeys.lock().await;
  let passkey = passkeys
    .get(uuid)
    .map(|p| p.iter().map(|p| p.cred_id().clone()).collect());

  let webauthn = webauthn.lock().await;
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
  webauthn: State<'_, Mutex<Webauthn>>,
  response: RegisterPublicKeyCredential,
) -> Result<(), String> {
  let mut state = state.lock().await;
  let (passkey_reg, uuid) = state
    .take()
    .ok_or("No pending registration. Did you call register first?")?;

  let webauthn = webauthn.lock().await;
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
  webauthn: State<'_, Mutex<Webauthn>>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
) -> Result<PublicKeyCredentialRequestOptions, String> {
  let webauthn = webauthn.lock().await;
  let (challenge, state_val) = webauthn
    .start_discoverable_authentication()
    .map_err(|e| format!("Failed to start authentication: {e:?}"))?;

  let mut state = state.lock().await;
  state.replace(state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn auth_start_non_discoverable(
  webauthn: State<'_, Mutex<Webauthn>>,
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

  let webauthn = webauthn.lock().await;
  let (challenge, state_val) = webauthn
    .start_passkey_authentication(passkey)
    .map_err(|e| format!("Failed to start authentication: {e:?}"))?;

  let mut state = state.lock().await;
  state.replace(state_val);

  Ok(challenge.public_key)
}

#[tauri::command]
async fn auth_finish(
  webauthn: State<'_, Mutex<Webauthn>>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  response: PublicKeyCredential,
) -> Result<(), String> {
  let webauthn = webauthn.lock().await;
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
  webauthn: State<'_, Mutex<Webauthn>>,
  state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
  response: PublicKeyCredential,
) -> Result<(), String> {
  let passkey_auth = state
    .lock()
    .await
    .take()
    .ok_or("No pending authentication. Did you call authenticate first?")?;
  let webauthn = webauthn.lock().await;
  webauthn
    .finish_passkey_authentication(&response, &passkey_auth)
    .map_err(|e| format!("Failed to verify authentication: {e:?}"))?;
  Ok(())
}

#[tauri::command]
async fn get_rp_config(config: State<'_, Mutex<RpConfig>>) -> Result<RpConfig, String> {
  Ok(config.lock().await.clone())
}

#[tauri::command]
async fn set_rp_config(
  webauthn: State<'_, Mutex<Webauthn>>,
  config: State<'_, Mutex<RpConfig>>,
  rp_id: String,
  rp_origin: String,
) -> Result<(), String> {
  let new_webauthn = build_webauthn(&rp_id, &rp_origin)?;
  let mut wn = webauthn.lock().await;
  *wn = new_webauthn;
  let mut cfg = config.lock().await;
  *cfg = RpConfig { rp_id, rp_origin };
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  // Load .env from the example root (parent of src-tauri)
  let _ = dotenvy::from_filename("../.env");
  let rp_id = rp_id();
  let rp_origin = rp_origin();
  log::info!("Using RP ID: {rp_id}, Origin: {rp_origin}");

  let webauthn = build_webauthn(&rp_id, &rp_origin).expect("Failed to build Webauthn");

  tauri::Builder::default()
    .manage(Mutex::new(webauthn))
    .manage(Mutex::new(RpConfig {
      rp_id,
      rp_origin,
    }))
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
      get_rp_config,
      set_rp_config,
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
