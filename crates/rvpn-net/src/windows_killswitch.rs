use crate::{KillSwitchSpec, NetError};
use std::{net::IpAddr, ptr, slice};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::{
            FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL,
            FWP_MATCH_FLAGS_ALL_SET, FWP_UINT8, FWP_UINT32, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
            FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWPM_ACTION0, FWPM_CONDITION_FLAGS,
            FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_IP_REMOTE_ADDRESS_V4,
            FWPM_CONDITION_IP_REMOTE_ADDRESS_V6, FWPM_FILTER_CONDITION0,
            FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_LAYER_OUTBOUND_IPPACKET_V4,
            FWPM_LAYER_OUTBOUND_IPPACKET_V6, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
            FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
            FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
        },
        System::Rpc::RPC_C_AUTHN_DEFAULT,
    },
    core::GUID,
};

const SUBLAYER_KEY: GUID = GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135a7);
const FILTER_KEYS: [GUID; 8] = [
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135a8),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135a9),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135aa),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135ab),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135ac),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135ad),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135ae),
    GUID::from_u128(0x3e20b249_8911_4f17_9cb1_657b9f5135af),
];
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;

pub fn install(spec: &KillSwitchSpec) -> Result<(), NetError> {
    let engine = open_engine()?;
    let result = (|| {
        ensure_sublayer(engine)?;
        // Replace all RVPN filters as one transaction. A failed update leaves the previous
        // policy active, including the endpoint and interface exceptions it already allowed.
        check(unsafe { FwpmTransactionBegin0(engine, 0) })?;
        let update = (|| {
            for key in &FILTER_KEYS {
                let result = unsafe { FwpmFilterDeleteByKey0(engine, key) };
                if result != FWP_E_FILTER_NOT_FOUND {
                    check(result)?;
                }
            }
            add_loopback(engine, true)?;
            add_loopback(engine, false)?;
            add_endpoint(engine, spec.endpoint.ip())?;
            if let Some(interface) = &spec.tunnel_interface {
                let index = crate::windows::SystemNet::index(interface)?;
                add_tunnel(engine, true, index)?;
                add_tunnel(engine, false, index)?;
            }
            add_block(engine, true)?;
            add_block(engine, false)?;
            Ok(())
        })();
        match update {
            Ok(()) => check(unsafe { FwpmTransactionCommit0(engine) }),
            Err(error) => {
                let _ = unsafe { FwpmTransactionAbort0(engine) };
                Err(error)
            }
        }
    })();
    close_engine(engine, result)
}

pub fn remove() -> Result<(), NetError> {
    let engine = open_engine()?;
    let result = (|| {
        check(unsafe { FwpmTransactionBegin0(engine, 0) })?;
        let mut first_error = None;
        for key in &FILTER_KEYS {
            let result = unsafe { FwpmFilterDeleteByKey0(engine, key) };
            if result != FWP_E_FILTER_NOT_FOUND && result != 0 && first_error.is_none() {
                first_error = Some(error(result));
            }
        }
        if let Some(error) = first_error {
            let _ = unsafe { FwpmTransactionAbort0(engine) };
            Err(error)
        } else {
            check(unsafe { FwpmTransactionCommit0(engine) })
        }
    })();
    close_engine(engine, result)
}

fn open_engine() -> Result<HANDLE, NetError> {
    let mut engine: HANDLE = ptr::null_mut();
    // SAFETY: optional parameters are null and `engine` is a valid output pointer. WFP enforces
    // the caller's normal Windows firewall permissions.
    check(unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_DEFAULT as u32,
            ptr::null(),
            ptr::null(),
            &mut engine,
        )
    })?;
    Ok(engine)
}

fn close_engine(engine: HANDLE, result: Result<(), NetError>) -> Result<(), NetError> {
    // SAFETY: `engine` was returned by FwpmEngineOpen0 and has not yet been closed.
    let close_result = unsafe { FwpmEngineClose0(engine) };
    result.and_then(|()| check(close_result))
}

fn ensure_sublayer(engine: HANDLE) -> Result<(), NetError> {
    let mut name: Vec<u16> = "RVPN network protection"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut description: Vec<u16> = "RVPN outbound tunnel policy"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData:
            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: description.as_mut_ptr(),
            },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        weight: 0x7fff,
        ..Default::default()
    };
    // SAFETY: the strings and sublayer structure remain live during the call.
    let result = unsafe { FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut()) };
    if result == FWP_E_ALREADY_EXISTS {
        Ok(())
    } else {
        check(result)
    }
}

fn add_loopback(engine: HANDLE, ipv4: bool) -> Result<(), NetError> {
    let mut condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        conditionValue: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        },
    };
    add_filter(
        engine,
        if ipv4 { 4 } else { 5 },
        if ipv4 {
            FWPM_LAYER_OUTBOUND_IPPACKET_V4
        } else {
            FWPM_LAYER_OUTBOUND_IPPACKET_V6
        },
        if ipv4 {
            "allow loopback IPv4"
        } else {
            "allow loopback IPv6"
        },
        FWP_ACTION_PERMIT,
        250,
        slice::from_mut(&mut condition),
    )
}

fn add_endpoint(engine: HANDLE, endpoint: IpAddr) -> Result<(), NetError> {
    match endpoint {
        IpAddr::V4(address) => {
            let mut mask = FWP_V4_ADDR_AND_MASK {
                addr: u32::from_ne_bytes(address.octets()),
                mask: u32::MAX,
            };
            let mut conditions = vec![address_condition_v4(&mut mask)];
            add_filter(
                engine,
                0,
                FWPM_LAYER_OUTBOUND_IPPACKET_V4,
                "allow RVPN IPv4 endpoint",
                FWP_ACTION_PERMIT,
                250,
                &mut conditions,
            )
        }
        IpAddr::V6(address) => {
            let mut mask = FWP_V6_ADDR_AND_MASK {
                addr: address.octets(),
                prefixLength: 128,
            };
            let mut conditions = vec![address_condition_v6(&mut mask)];
            add_filter(
                engine,
                1,
                FWPM_LAYER_OUTBOUND_IPPACKET_V6,
                "allow RVPN IPv6 endpoint",
                FWP_ACTION_PERMIT,
                250,
                &mut conditions,
            )
        }
    }
}

fn add_tunnel(engine: HANDLE, ipv4: bool, index: u32) -> Result<(), NetError> {
    let mut condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_INTERFACE_INDEX,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                uint32: index,
            },
        },
    };
    add_filter(
        engine,
        if ipv4 { 2 } else { 3 },
        if ipv4 {
            FWPM_LAYER_OUTBOUND_IPPACKET_V4
        } else {
            FWPM_LAYER_OUTBOUND_IPPACKET_V6
        },
        if ipv4 {
            "allow RVPN tunnel IPv4"
        } else {
            "allow RVPN tunnel IPv6"
        },
        FWP_ACTION_PERMIT,
        250,
        slice::from_mut(&mut condition),
    )
}

fn add_block(engine: HANDLE, ipv4: bool) -> Result<(), NetError> {
    add_filter(
        engine,
        if ipv4 { 6 } else { 7 },
        if ipv4 {
            FWPM_LAYER_OUTBOUND_IPPACKET_V4
        } else {
            FWPM_LAYER_OUTBOUND_IPPACKET_V6
        },
        if ipv4 {
            "block other outbound IPv4"
        } else {
            "block other outbound IPv6"
        },
        FWP_ACTION_BLOCK,
        1,
        &mut [],
    )
}

fn add_filter(
    engine: HANDLE,
    key_index: usize,
    layer: GUID,
    label: &str,
    action: u32,
    weight: u8,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), NetError> {
    let mut name: Vec<u16> = label.encode_utf16().chain(Some(0)).collect();
    let filter = FWPM_FILTER0 {
        filterKey: FILTER_KEYS[key_index],
        displayData:
            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous:
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                    uint8: weight,
                },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: if conditions.is_empty() {
            ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        },
        action: FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: filter, display string, and condition data are alive until the synchronous API
    // returns. The persistent filter stores its own copies of the supplied metadata and values.
    check(unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) })
}

fn address_condition_v4(mask: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS_V4,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 { v4AddrMask: mask },
        },
    }
}

fn address_condition_v6(mask: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS_V6,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 { v6AddrMask: mask },
        },
    }
}

fn check(code: u32) -> Result<(), NetError> {
    if code == 0 { Ok(()) } else { Err(error(code)) }
}

fn error(code: u32) -> NetError {
    NetError::Operation(format!(
        "Windows Filtering Platform operation failed with error 0x{code:08x}"
    ))
}
