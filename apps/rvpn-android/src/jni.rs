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
    net::SocketAddr,
    os::fd::RawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};
use tokio::sync::watch;

static TUNNEL_RUNNING: AtomicBool = AtomicBool::new(false);
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
    psk_hex_str: JString<'local>,
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
                return Ok(env.new_string("tunnel is already running")?.into_raw());
            }

            let server_rust: String = match server_str.mutf8_chars(env) {
                Ok(s) => s.into(),
                Err(e) => {
                    TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                    return Ok(env
                        .new_string(format!("invalid server string: {e}"))?
                        .into_raw());
                }
            };

            let server_addr: SocketAddr = match server_rust.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                    return Ok(env
                        .new_string(format!("cannot parse server address '{server_rust}': {e}"))?
                        .into_raw());
                }
            };

            let psk_hex: String = match psk_hex_str.mutf8_chars(env) {
                Ok(s) => s.into(),
                Err(e) => {
                    TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                    return Ok(env
                        .new_string(format!("invalid psk string: {e}"))?
                        .into_raw());
                }
            };

            let mut psk_bytes = [0u8; 32];
            if psk_hex.len() != 64 {
                TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                return Ok(env
                    .new_string("pre-shared key must be exactly 64 hexadecimal characters")?
                    .into_raw());
            }
            if let Err(e) = hex::decode_to_slice(&psk_hex, &mut psk_bytes) {
                TUNNEL_RUNNING.store(false, Ordering::SeqCst);
                return Ok(env
                    .new_string(format!("invalid PSK hex encoding: {e}"))?
                    .into_raw());
            }

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
                server: server_addr,
                psk: psk_bytes,
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
                    } else {
                        tracing::info!("Android RVPN tunnel shut down cleanly");
                    }
                });

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
