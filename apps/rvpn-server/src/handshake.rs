use anyhow::{Context, Result, bail};
use rvpn_config::{CertificateAuthorityConfig, HandshakeConfig, PeerIdentity};
use rvpn_core::SessionId;
use rvpn_crypto::{AuthConfig, CookieKey, ObfuscationKey};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rvpn_protocol::{HandshakeMessage, Header, Packet, PacketKind, ResponderHandshake};
use rvpn_transport::{SendOptions, UdpTransport};
use std::{collections::HashMap, net::SocketAddr};

use crate::state::{ActivePeer, PendingHandshake, PendingSource, same_peer};

const MAX_PENDING_HANDSHAKES: usize = 4096;
const REKEY_REQUEST_INTERVAL: Duration = Duration::from_secs(5);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn challenge_or_admit(
    transport: &UdpTransport,
    cookie_key: &CookieKey,
    obfuscation: Option<&ObfuscationKey>,
    endpoint: SocketAddr,
    initiation: &HandshakeMessage,
) -> Result<bool> {
    let HandshakeMessage::Initiation {
        public_key,
        random,
        cookie,
    } = initiation
    else {
        return Ok(false);
    };
    let now = unix_now();
    if let Some(cookie) = cookie
        && cookie_key.verify(endpoint, public_key, random, cookie, now)
    {
        return Ok(true);
    }
    let expected = cookie_key.mint(endpoint, public_key, random, now);
    let reply = Packet {
        header: Header {
            kind: PacketKind::Handshake,
            key_phase: 0,
            sequence: 0,
            session_id: SessionId::ZERO,
        },
        payload: HandshakeMessage::CookieReply { cookie: expected }.encode(),
    };
    send_wire(transport, endpoint, reply.encode(), obfuscation).await?;
    Ok(false)
}

async fn send_wire(
    transport: &UdpTransport,
    endpoint: SocketAddr,
    encoded: bytes::Bytes,
    obfuscation: Option<&ObfuscationKey>,
) -> Result<()> {
    let wire = match obfuscation {
        Some(key) => match key.wrap(&encoded) {
            Ok(wire) => wire,
            Err(error) => {
                tracing::warn!(%error, %endpoint, "failed to obfuscate outgoing RVPN packet; dropping it");
                return Ok(());
            }
        },
        None => encoded,
    };
    if let Err(error) = transport
        .send_to(endpoint, wire, SendOptions::default())
        .await
    {
        if let rvpn_transport::TransportError::DatagramTooLarge { size, maximum } = error {
            tracing::warn!(
                size,
                maximum,
                %endpoint,
                effective_mtu = transport.effective_mtu(),
                "oversized RVPN packet dropped instead of crashing the server; adaptive MTU stepped down"
            );
        } else {
            tracing::warn!(%error, %endpoint, "failed to send RVPN packet; continuing");
        }
    }
    Ok(())
}

async fn respond_initial(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    initiation: HandshakeMessage,
    source: PendingSource,
    auth: &AuthConfig,
) -> Result<()> {
    let (handshake, response) =
        ResponderHandshake::accept(auth.identity(), auth.verifier(), initiation)?;
    let HandshakeMessage::Response { session_id, .. } = response else {
        bail!("responder produced a message that is not a handshake response");
    };
    let packet = Packet {
        header: Header {
            kind: PacketKind::Handshake,
            key_phase: 0,
            sequence: 0,
            session_id,
        },
        payload: response.encode(),
    };
    send_wire(transport, endpoint, packet.encode(), obfuscation).await?;
    pending.insert(
        session_id,
        PendingHandshake {
            source,
            handshake,
            endpoint,
            packet,
            kind: PacketKind::Handshake,
            attempts: 1,
        },
    );
    Ok(())
}

pub async fn begin_initial(
    transport: &UdpTransport,
    identities: &[PeerIdentity],
    certificate_authority: Option<&CertificateAuthorityConfig>,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    initiation: HandshakeMessage,
) -> Result<()> {
    if pending.len() >= MAX_PENDING_HANDSHAKES {
        tracing::warn!(%endpoint, "too many pending handshakes; ignoring initiation");
        return Ok(());
    }

    for identity in identities {
        if let Err(error) = respond_initial(
            transport,
            obfuscation,
            pending,
            endpoint,
            initiation,
            PendingSource::Known(identity.clone()),
            &identity.auth,
        )
        .await
        {
            tracing::warn!(peer = %identity.name, %endpoint, %error, "could not answer handshake initiation");
        }
    }

    if let Some(ca) = certificate_authority {
        match ca.to_auth_config() {
            Ok(auth) => {
                if let Err(error) = respond_initial(
                    transport,
                    obfuscation,
                    pending,
                    endpoint,
                    initiation,
                    PendingSource::CertificateAuthority(ca.clone()),
                    &auth,
                )
                .await
                {
                    tracing::warn!(%endpoint, %error, "could not answer certificate handshake initiation");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "certificate authority configuration is unusable");
            }
        }
    }
    Ok(())
}

pub async fn begin_rekey(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    endpoint: SocketAddr,
    current: &ActivePeer,
    initiation: HandshakeMessage,
) -> Result<()> {
    if pending.contains_key(&current.session.session_id()) {
        tracing::debug!(peer = %current.identity.name, session_id = ?current.session.session_id(), "rekey already in progress for peer; ignoring initiation");
        return Ok(());
    }
    let phase = current
        .session
        .key_phase()
        .checked_add(1)
        .context("key phase exhausted")?;
    let (handshake, response) = ResponderHandshake::accept_for_session(
        current.identity.auth.identity(),
        current.identity.auth.verifier(),
        initiation,
        current.session.session_id(),
        phase,
    )?;
    let packet = Packet {
        header: Header {
            kind: PacketKind::Rekey,
            key_phase: current.session.key_phase(),
            sequence: 0,
            session_id: current.session.session_id(),
        },
        payload: response.encode(),
    };
    send_wire(transport, endpoint, packet.encode(), obfuscation).await?;
    pending.insert(
        current.session.session_id(),
        PendingHandshake {
            source: PendingSource::Known(current.identity.clone()),
            handshake,
            endpoint,
            packet,
            kind: PacketKind::Rekey,
            attempts: 1,
        },
    );
    Ok(())
}

pub async fn maybe_send_rekey(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    peer: &mut ActivePeer,
    packet_limit: u64,
    time_limit: Option<Duration>,
) -> Result<()> {
    if !peer
        .session
        .should_rekey_with_policy(packet_limit, time_limit)
    {
        return Ok(());
    }
    if peer
        .last_rekey_request
        .is_some_and(|sent| sent.elapsed() < REKEY_REQUEST_INTERVAL)
    {
        return Ok(());
    }
    let request = peer.session.seal(PacketKind::Rekey, b"")?;
    peer.last_rekey_request = Some(Instant::now());
    send_wire(transport, peer.endpoint, request.encode(), obfuscation).await
}

pub fn finish_pending(
    pending: &mut HashMap<SessionId, PendingHandshake>,
    active: &mut HashMap<SessionId, ActivePeer>,
    endpoint: SocketAddr,
    packet: Packet,
) -> Vec<SessionId> {
    let session_id = packet.header.session_id;

    let Some(expected) = pending.get(&session_id) else {
        tracing::debug!(?session_id, %endpoint, "received finish for unknown or expired pending handshake");
        return Vec::new();
    };
    if expected.endpoint != endpoint || expected.kind != packet.header.kind {
        tracing::warn!(
            ?session_id,
            expected_endpoint = %expected.endpoint,
            actual_endpoint = %endpoint,
            expected_kind = ?expected.kind,
            actual_kind = ?packet.header.kind,
            "discarding finish packet with mismatched endpoint or packet kind"
        );
        return Vec::new();
    }
    let Some(state) = pending.remove(&session_id) else {
        return Vec::new();
    };

    let finish = match HandshakeMessage::decode(packet.payload) {
        Ok(finish) => finish,
        Err(error) => {
            tracing::warn!(?session_id, %endpoint, %error, "discarding malformed handshake finish");
            return Vec::new();
        }
    };
    let (session, remote_identity) = match state.handshake.finish(finish) {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(?session_id, %endpoint, %error, "rejecting handshake finish");
            return Vec::new();
        }
    };
    let id = session.session_id();

    let identity = match state.source {
        PendingSource::Known(identity) => identity,
        PendingSource::CertificateAuthority(ca) => {
            let Some(subject) = remote_identity else {
                tracing::warn!(session_id = ?id, "certificate handshake finished without a verified subject key");
                return Vec::new();
            };
            let subject_hex = hex::encode(subject.to_bytes());
            if ca.is_revoked(&subject_hex) {
                tracing::warn!(subject = %subject_hex, session_id = ?id, "rejecting handshake from revoked certificate subject");
                return Vec::new();
            }
            let allowed_ips = match ca.resolve_allowed_ips(&subject_hex) {
                Ok(allowed_ips) => allowed_ips,
                Err(error) => {
                    tracing::warn!(subject = %subject_hex, %error, "certificate subject has unusable allowed_ips");
                    return Vec::new();
                }
            };
            let auth = match ca.to_auth_config() {
                Ok(auth) => auth,
                Err(error) => {
                    tracing::warn!(%error, "certificate authority configuration is unusable");
                    return Vec::new();
                }
            };
            PeerIdentity {
                name: format!("cert:{}", &subject_hex[..subject_hex.len().min(16)]),
                allowed_ips,
                auth,
            }
        }
    };

    let mut evicted = Vec::new();
    active.retain(|existing_id, existing| {
        let stale = *existing_id != id && same_peer(&existing.identity, &identity);
        if stale {
            tracing::info!(
                peer = %existing.identity.name,
                old_session = ?existing_id,
                new_session = ?id,
                "replacing stale session of reconnecting peer"
            );
            evicted.push(*existing_id);
        }
        !stale
    });

    let mut session = session;
    if let Some(existing) = active.get(&id) {
        session.inherit_previous(&existing.session);
    }

    let name = identity.name.clone();
    active.insert(id, ActivePeer::new(identity, session, endpoint));
    tracing::info!(%name, session_id = ?id, %endpoint, "authenticated RVPN peer established");
    evicted
}

pub async fn retransmit_pending(
    transport: &UdpTransport,
    obfuscation: Option<&ObfuscationKey>,
    pending: &mut HashMap<SessionId, PendingHandshake>,
    policy: &HandshakeConfig,
) -> Result<()> {
    pending.retain(|_, state| state.attempts < policy.retry_limit);
    for state in pending.values_mut() {
        send_wire(
            transport,
            state.endpoint,
            state.packet.encode(),
            obfuscation,
        )
        .await?;
        state.attempts += 1;
    }
    Ok(())
}
