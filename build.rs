const COMMANDS: &[&str] = &[
  "register",
  "authenticate",
  "send_pin",
  "select_key",
  "cancel",
];

fn main() {
  if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
    use swift_rs::SwiftLinker;
    SwiftLinker::new("13.0")
      .with_package("WebauthnBridge", "macos")
      .link();
  }

  tauri_plugin::Builder::new(COMMANDS)
    .android_path("android")
    .ios_path("ios")
    .build();
}
