//! JNI bindings for Android `VpnService` integration.

use crate::stats::{StatsSnapshot, TunnelStats};
use crate::tunnel::{AndroidTunnelConfig, run_tunnel};
use jni::{
    JNIEnv,
    objects::{GlobalRef, JClass, JObject, JString, JValue},
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    if !LOGGER_INITIALIZED.swap(true, Ordering::SeqCst) {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .without_time()
            .try_init();
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_isTunnelRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if TUNNEL_RUNNING.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_stopTunnel(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut guard = SHUTDOWN_TX.lock().unwrap();
    if let Some(tx) = guard.take() {
        let _ = tx.send(true);
        tracing::info!("signaled Android tunnel stop");
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_getTunnelStats(
    env: JNIEnv,
    _class: JClass,
) -> jlongArray {
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

    match env.new_long_array(raw_stats.len() as jni::sys::jsize) {
        Ok(arr) => {
            let _ = env.set_long_array_region(&arr, 0, &raw_stats);
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_rvpn_client_RvpnNative_startTunnel(
    mut env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    server_str: JString,
    psk_hex_str: JString,
    tun_fd: jint,
    mtu: jint,
    rekey_limit: jlong,
    retry_interval_ms: jlong,
    retry_limit: jint,
) -> jstring {
    Java_org_rvpn_client_RvpnNative_initLogger(unsafe { std::ptr::read(&env) }, _class);

    if TUNNEL_RUNNING.swap(true, Ordering::SeqCst) {
        return env
            .new_string("tunnel is already running")
            .unwrap()
            .into_raw();
    }

    let server_rust: String = match env.get_string(&server_str) {
        Ok(s) => s.into(),
        Err(e) => {
            TUNNEL_RUNNING.store(false, Ordering::SeqCst);
            return env.new_string(format!("invalid server string: {e}")).unwrap().into_raw();
        }
    };

    let server_addr: SocketAddr = match server_rust.parse() {
        Ok(addr) => addr,
        Err(e) => {
            TUNNEL_RUNNING.store(false, Ordering::SeqCst);
            return env.new_string(format!("cannot parse server address '{server_rust}': {e}")).unwrap().into_raw();
        }
    };

    let psk_hex: String = match env.get_string(&psk_hex_str) {
        Ok(s) => s.into(),
        Err(e) => {
            TUNNEL_RUNNING.store(false, Ordering::SeqCst);
            return env.new_string(format!("invalid psk string: {e}")).unwrap().into_raw();
        }
    };

    let mut psk_bytes = [0u8; 32];
    if psk_hex.len() != 64 {
        TUNNEL_RUNNING.store(false, Ordering::SeqCst);
        return env
            .new_string("pre-shared key must be exactly 64 hexadecimal characters")
            .unwrap()
            .into_raw();
    }
    if let Err(e) = hex::decode_to_slice(&psk_hex, &mut psk_bytes) {
        TUNNEL_RUNNING.store(false, Ordering::SeqCst);
        return env
            .new_string(format!("invalid PSK hex encoding: {e}"))
            .unwrap()
            .into_raw();
    }

    // Capture JavaVM and VpnService GlobalRef for protecting the UDP socket
    let jvm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            TUNNEL_RUNNING.store(false, Ordering::SeqCst);
            return env.new_string(format!("failed to get JavaVM: {e}")).unwrap().into_raw();
        }
    };

    let vpn_service_global: GlobalRef = match env.new_global_ref(vpn_service) {
        Ok(r) => r,
        Err(e) => {
            TUNNEL_RUNNING.store(false, Ordering::SeqCst);
            return env.new_string(format!("failed to create global ref for VpnService: {e}")).unwrap().into_raw();
        }
    };

    let socket_protector = Arc::new(move |fd: RawFd| -> bool {
        let mut attached_env = match jvm.attach_current_thread_permanently() {
            Ok(env) => env,
            Err(e) => {
                tracing::error!(%e, "failed to attach thread to JVM for socket protection");
                return false;
            }
        };

        let method_name = "protect";
        let method_sig = "(I)Z";
        match attached_env.call_method(
            &vpn_service_global,
            method_name,
            method_sig,
            &[JValue::Int(fd)],
        ) {
            Ok(val) => val.z().unwrap_or(false),
            Err(e) => {
                tracing::error!(%e, fd, "VpnService.protect call failed via JNI");
                false
            }
        }
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
        rekey_packet_limit: if rekey_limit < 0 { 0 } else { rekey_limit as u64 },
        retry_interval_ms: if retry_interval_ms <= 0 { 500 } else { retry_interval_ms as u64 },
        retry_limit: if retry_limit <= 0 { 5 } else { retry_limit as u32 },
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

    env.new_string("").unwrap().into_raw()
}
