//! JNI bindings for Android `VpnService` integration.

use crate::stats::{StatsSnapshot, TunnelStats};
use crate::tunnel::{AndroidTunnelConfig, run_tunnel};
use jni::{
    Env, EnvUnowned, JavaVM,
    errors::LogErrorAndDefault,
    jni_sig, jni_str,
    objects::{JClass, JObject, JString, JValue},
    refs::Global,
    sys::{jboolean, jint, jlong, jlongArray, jstring},
};
use std::{
    os::fd::{FromRawFd, RawFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};
use tokio::sync::watch;

static TUNNEL_RUNNING: AtomicBool = AtomicBool::new(false);
static TUNNEL_CONNECTED: AtomicBool = AtomicBool::new(false);
static TUNNEL_ERROR: Mutex<Option<String>> = Mutex::new(None);
static SHUTDOWN_TX: Mutex<Option<watch::Sender<bool>>> = Mutex::new(None);
static TUNNEL_STATS: Mutex<Option<(Arc<TunnelStats>, Instant)>> = Mutex::new(None);
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn init_logger() {
    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .without_time()
            .try_init();
    }
}

fn close_raw_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            let _ = std::fs::File::from_raw_fd(fd);
        }
    }
}

fn set_tunnel_error(message: impl Into<String>) {
    TUNNEL_CONNECTED.store(false, Ordering::SeqCst);
    let mut guard = TUNNEL_ERROR.lock().unwrap();
    *guard = Some(message.into());
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_initLogger<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) {
    let _ = unowned_env.with_env(|_env| -> jni::errors::Result<()> {
        init_logger();
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_isTunnelRunning<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jboolean {
    unowned_env
        .with_env(|_env| -> jni::errors::Result<jboolean> {
            Ok(TUNNEL_RUNNING.load(Ordering::SeqCst))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_isTunnelConnected<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jboolean {
    unowned_env
        .with_env(|_env| -> jni::errors::Result<jboolean> {
            Ok(TUNNEL_CONNECTED.load(Ordering::SeqCst))
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_getTunnelError<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let message = TUNNEL_ERROR.lock().unwrap().clone().unwrap_or_default();

            Ok(env.new_string(message)?.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_stopTunnel<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jboolean {
    unowned_env
        .with_env(|_env| -> jni::errors::Result<jboolean> {
            let mut guard = SHUTDOWN_TX.lock().unwrap();
            if let Some(tx) = guard.take() {
                let _ = tx.send(true);
                tracing::info!("signaled Android tunnel stop");
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_getTunnelStats<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jlongArray {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jlongArray> {
            let guard = TUNNEL_STATS.lock().unwrap();
            let snapshot = if let Some((stats, start_time)) = guard.as_ref() {
                stats.snapshot(Some(*start_time))
            } else {
                StatsSnapshot::default()
            };
            drop(guard);

            let raw_stats = [
                snapshot.bytes_tx as i64,
                snapshot.bytes_rx as i64,
                snapshot.packets_tx as i64,
                snapshot.packets_rx as i64,
                snapshot.uptime_ms as i64,
            ];
            let array = env.new_long_array(raw_stats.len())?;
            array.set_region(env, 0, &raw_stats)?;
            Ok(array.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_startTunnel<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    vpn_service: JObject<'local>,
    server_str: JString<'local>,
    auth_mode_str: JString<'local>,
    psk_hex_str: JString<'local>,
    local_identity_seed_str: JString<'local>,
    peer_public_key_str: JString<'local>,
    local_certificate_str: JString<'local>,
    ca_public_key_str: JString<'local>,
    tun_fd: jint,
    mtu: jint,
    rekey_limit: jlong,
    retry_interval_ms: jlong,
    retry_limit: jint,
) -> jstring {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            init_logger();

            if TUNNEL_RUNNING.swap(true, Ordering::SeqCst) {
                close_raw_fd(tun_fd);
                return Ok(env.new_string("tunnel is already running")?.into_raw());
            }

            TUNNEL_CONNECTED.store(false, Ordering::SeqCst);
            {
                let mut error = TUNNEL_ERROR.lock().unwrap();
                *error = None;
            }

            macro_rules! read_str {
                ($jstr:expr, $label:literal) => {
                    match $jstr.mutf8_chars(env) {
                        Ok(s) => String::from(s),
                        Err(e) => {
                            let message = format!("invalid {} string: {e}", $label);
                            set_tunnel_error(message.clone());
                            TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                            close_raw_fd(tun_fd);
                            return Ok(env.new_string(message)?.into_raw());
                        }
                    }
                };
            }
            macro_rules! fail {
                ($msg:expr) => {{
                    let message = $msg;
                    set_tunnel_error(message.to_string());
                    TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                    close_raw_fd(tun_fd);
                    return Ok(env.new_string(message)?.into_raw());
                }};
            }
            macro_rules! decode_hex {
                ($hex:expr, $len:expr, $label:literal) => {{
                    if $hex.len() != $len * 2 {
                        fail!(format!(
                            "{} must be exactly {} hexadecimal characters",
                            $label,
                            $len * 2
                        ));
                    }
                    let mut buf = [0u8; $len];
                    if hex::decode_to_slice(&$hex, &mut buf).is_err() {
                        fail!(format!("invalid hex encoding for {}", $label));
                    }
                    buf
                }};
            }

            let server_rust = read_str!(server_str, "server");
            if let Err(e) = rvpn_config::validate_endpoint_syntax(&server_rust) {
                fail!(format!("invalid server endpoint '{server_rust}': {e}"));
            }

            let auth_mode = read_str!(auth_mode_str, "auth mode");
            let psk_hex = read_str!(psk_hex_str, "psk");
            let local_identity_seed_hex = read_str!(local_identity_seed_str, "local identity seed");
            let peer_public_key_hex = read_str!(peer_public_key_str, "peer public key");
            let local_certificate_hex = read_str!(local_certificate_str, "local certificate");
            let ca_public_key_hex = read_str!(ca_public_key_str, "ca public key");

            let auth = match auth_mode.as_str() {
                "psk" => {
                    let bytes = decode_hex!(psk_hex, 32, "pre-shared key");
                    rvpn_crypto::AuthConfig::Psk(bytes)
                }
                "pinned-key" => {
                    let local_seed =
                        decode_hex!(local_identity_seed_hex, 32, "local identity seed");
                    let peer_public_key = decode_hex!(peer_public_key_hex, 32, "peer public key");
                    rvpn_crypto::AuthConfig::PinnedKey {
                        local_seed,
                        peer_public_key,
                    }
                }
                "certificate" => {
                    let local_seed =
                        decode_hex!(local_identity_seed_hex, 32, "local identity seed");
                    let local_certificate =
                        decode_hex!(local_certificate_hex, 112, "local certificate");
                    let ca_public_key = decode_hex!(ca_public_key_hex, 32, "ca public key");
                    rvpn_crypto::AuthConfig::Certificate {
                        local_seed,
                        local_certificate,
                        ca_public_key,
                    }
                }
                other => fail!(format!("unknown auth mode '{other}'")),
            };

            // Hold a global reference to the VpnService instance so the socket
            // protector closure can call back into it from the Tokio thread.
            let vpn_service_global: Global<JObject> = env.new_global_ref(vpn_service)?;

            let socket_protector = Arc::new(move |fd: RawFd| -> bool {
                let vm = match JavaVM::singleton() {
                    Ok(vm) => vm,
                    Err(e) => {
                        tracing::error!(%e, "JavaVM singleton unavailable for socket protection");
                        return false;
                    }
                };
                let result: jni::errors::Result<bool> =
                    vm.attach_current_thread(|env: &mut Env<'_>| -> jni::errors::Result<bool> {
                        env.call_method(
                            vpn_service_global.as_obj(),
                            jni_str!("protect"),
                            jni_sig!("(I)Z"),
                            &[JValue::Int(fd)],
                        )?
                        .z()
                    });
                result.unwrap_or_else(|e| {
                    tracing::error!(%e, fd, "VpnService.protect call failed via JNI");
                    false
                })
            });

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            {
                let mut guard = SHUTDOWN_TX.lock().unwrap();
                *guard = Some(shutdown_tx);
            }

            let stats = Arc::new(TunnelStats::new());
            {
                let mut stats_guard = TUNNEL_STATS.lock().unwrap();
                *stats_guard = Some((Arc::clone(&stats), Instant::now()));
            }

            let config = AndroidTunnelConfig {
                tun_fd,
                server: server_rust,
                auth,
                obfuscation_key: None,
                mtu: if mtu <= 0 { 1400 } else { mtu as u16 },
                rekey_packet_limit: if rekey_limit < 0 {
                    0
                } else {
                    rekey_limit as u64
                },
                retry_interval_ms: if retry_interval_ms <= 0 {
                    500
                } else {
                    retry_interval_ms as u64
                },
                retry_limit: if retry_limit <= 0 {
                    5
                } else {
                    retry_limit as u32
                },
                socket_protector: Some(socket_protector),
                stats: Some(stats),
                on_connected: Some(Arc::new(|| {
                    TUNNEL_CONNECTED.store(true, Ordering::SeqCst);
                    tracing::info!("Android RVPN tunnel handshake completed");
                })),
            };

            thread::spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(%e, "failed to create Tokio runtime for Android tunnel");
                        TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                        let mut stats_guard = TUNNEL_STATS.lock().unwrap();
                        *stats_guard = None;
                        return;
                    }
                };

                rt.block_on(async move {
                    tracing::info!("starting Android RVPN tunnel event loop");
                    if let Err(e) = run_tunnel(config, shutdown_rx).await {
                        tracing::error!(%e, "Android RVPN tunnel exited with error");
                        set_tunnel_error(e.to_string());
                    } else {
                        tracing::info!("Android RVPN tunnel shut down cleanly");
                    }
                });

                TUNNEL_CONNECTED.store(false, Ordering::SeqCst);
                TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                let mut guard = SHUTDOWN_TX.lock().unwrap();
                *guard = None;
                let mut stats_guard = TUNNEL_STATS.lock().unwrap();
                *stats_guard = None;
            });

            Ok(env.new_string("")?.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}
