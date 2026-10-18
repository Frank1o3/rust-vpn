use crate::{BestRoute, IpAddr, IpNet, KillSwitchSpec, NetConfigurator, NetError, RouteSpec};
use std::{mem, net::IpAddr as StdIpAddr, ptr, slice};
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS},
    NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
        CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2,
        GetIpForwardTable2, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
        InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        MIB_UNICASTIPADDRESS_ROW,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN6_ADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};

use crate::windows_killswitch;

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemNet;

impl SystemNet {
    pub fn new() -> Result<Self, NetError> {
        Ok(Self)
    }

    pub(crate) fn interface_luid(
        name: &str,
    ) -> Result<windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH, NetError> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut luid = unsafe { mem::zeroed() };
        // SAFETY: `name` is a NUL-terminated UTF-16 string and `luid` is a valid out pointer.
        let result = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
        check(result)?;
        Ok(luid)
    }

    pub(crate) fn index(name: &str) -> Result<u32, NetError> {
        let luid = Self::interface_luid(name)?;
        let mut index = 0;
        // SAFETY: `luid` is initialized by ConvertInterfaceAliasToLuid and `index` is a valid out pointer.
        check(unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) })?;
        Ok(index)
    }

    fn routes(family: u16) -> Result<Vec<MIB_IPFORWARD_ROW2>, NetError> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        // SAFETY: `table` is a valid out pointer. A successful call allocates the table, which is
        // released below with FreeMibTable.
        check(unsafe { GetIpForwardTable2(family, &mut table) })?;
        if table.is_null() {
            return Ok(Vec::new());
        }

        // SAFETY: GetIpForwardTable2 returns a table with NumEntries initialized and Table sized
        // for that many rows. The rows are copied before freeing the API allocation.
        let rows = unsafe {
            let count = (*table).NumEntries as usize;
            let first = ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>();
            slice::from_raw_parts(first, count).to_vec()
        };
        // SAFETY: `table` is the allocation returned by GetIpForwardTable2.
        unsafe { FreeMibTable(table.cast()) };
        Ok(rows)
    }
}

impl NetConfigurator for SystemNet {
    async fn interface_index(&self, name: &str) -> Result<u32, NetError> {
        Self::index(name)
    }

    async fn set_link_up(&self, name: &str) -> Result<(), NetError> {
        // Wintun brings the adapter up when its session starts. Resolving the alias here also
        // verifies that the adapter exists before addresses and routes are applied.
        Self::index(name).map(|_| ())
    }

    async fn add_address(&self, name: &str, address: IpNet) -> Result<(), NetError> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        // SAFETY: `row` is a valid writable structure.
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.Address = sockaddr(address.addr());
        row.InterfaceIndex = Self::index(name)?;
        row.OnLinkPrefixLength = address.prefix_len();
        row.PrefixOrigin = windows_sys::Win32::Networking::WinSock::IpPrefixOriginManual;
        row.SuffixOrigin = windows_sys::Win32::Networking::WinSock::IpSuffixOriginManual;
        row.SkipAsSource = false;

        // SAFETY: `row` is fully initialized and remains valid for the duration of the call.
        let result = unsafe { CreateUnicastIpAddressEntry(&row) };
        if result == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(());
        }
        check(result)
    }

    async fn replace_route(&self, route: &RouteSpec) -> Result<(), NetError> {
        let index = route.interface_index.ok_or_else(|| {
            NetError::Operation("Windows route requires an interface index".into())
        })?;
        let family = family_for(route.destination.addr());
        if route
            .gateway
            .is_some_and(|gateway| family_for(gateway) != family)
        {
            return Err(NetError::Operation(
                "Windows route gateway address family does not match its destination".into(),
            ));
        }
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: `row` is a valid writable structure.
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr(route.destination.addr()),
            PrefixLength: route.destination.prefix_len(),
        };
        row.NextHop = sockaddr(route.gateway.unwrap_or_else(|| unspecified(family)));
        row.Metric = 0;

        let current = Self::routes(family)?;
        let matching: Vec<_> = current
            .into_iter()
            .filter(|existing| {
                existing.InterfaceIndex == index && prefix_matches(existing, route.destination)
            })
            .collect();
        if matching
            .iter()
            .any(|existing| same_next_hop(existing, route.gateway))
        {
            return Ok(());
        }

        // Add first so a rejected replacement cannot leave the interface without its old route.
        // SAFETY: `row` is initialized with a destination, next hop, and interface index.
        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result != ERROR_OBJECT_ALREADY_EXISTS {
            check(result)?;
        }
        for existing in matching {
            // SAFETY: each row was copied from the live IP Helper route table.
            let result = unsafe { DeleteIpForwardEntry2(&existing) };
            if result != ERROR_NOT_FOUND {
                check(result)?;
            }
        }
        Ok(())
    }

    async fn delete_route(&self, route: &RouteSpec) -> Result<(), NetError> {
        let family = family_for(route.destination.addr());
        let rows = Self::routes(family)?;
        for row in rows.into_iter().filter(|row| {
            route
                .interface_index
                .is_none_or(|index| row.InterfaceIndex == index)
                && prefix_matches(row, route.destination)
                && route
                    .gateway
                    .is_none_or(|gateway| same_next_hop(row, Some(gateway)))
        }) {
            // SAFETY: `row` was copied from the live IP Helper route table.
            let result = unsafe { DeleteIpForwardEntry2(&row) };
            if result != ERROR_NOT_FOUND {
                check(result)?;
            }
        }
        Ok(())
    }

    async fn best_route_to(&self, destination: IpAddr) -> Result<BestRoute, NetError> {
        let destination = sockaddr(destination);
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        // SAFETY: destination is initialized and both output rows are valid writable structures.
        check(unsafe {
            GetBestRoute2(
                ptr::null(),
                0,
                ptr::null(),
                &destination,
                0,
                &mut route,
                &mut source,
            )
        })?;
        let source = ip_from_sockaddr(&source)?;
        let gateway = ip_from_sockaddr(&route.NextHop)?;
        Ok(BestRoute {
            interface_index: route.InterfaceIndex,
            gateway: (!gateway.is_unspecified()).then_some(gateway),
            source: (!source.is_unspecified()).then_some(source),
        })
    }

    async fn set_dns(&self, _name: &str, _servers: &[IpAddr]) -> Result<(), NetError> {
        Err(NetError::Unsupported)
    }

    async fn revert_dns(&self, _name: &str) -> Result<(), NetError> {
        Ok(())
    }

    async fn install_kill_switch(&self, spec: &KillSwitchSpec) -> Result<(), NetError> {
        windows_killswitch::install(spec)
    }

    async fn remove_kill_switch(&self, _uid: u32) -> Result<(), NetError> {
        windows_killswitch::remove()
    }
}

fn check(code: u32) -> Result<(), NetError> {
    if code == 0 {
        Ok(())
    } else {
        Err(NetError::Operation(format!(
            "Windows IP Helper operation failed with error 0x{code:08x}"
        )))
    }
}

fn family_for(ip: IpAddr) -> u16 {
    if ip.is_ipv4() { AF_INET } else { AF_INET6 }
}

fn unspecified(family: u16) -> IpAddr {
    if family == AF_INET {
        StdIpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        StdIpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    }
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        StdIpAddr::V4(ip) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        StdIpAddr::V6(ip) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: ip.octets() },
                },
                Anonymous: Default::default(),
            },
        },
    }
}

fn ip_from_sockaddr(address: &SOCKADDR_INET) -> Result<IpAddr, NetError> {
    // SAFETY: the caller provides a SOCKADDR_INET initialized by IP Helper or sockaddr().
    match unsafe { address.si_family } {
        AF_INET => {
            // SAFETY: si_family identifies the active IPv4 union member.
            let octets = unsafe { address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes() };
            Ok(StdIpAddr::V4(octets.into()))
        }
        AF_INET6 => {
            // SAFETY: si_family identifies the active IPv6 union member.
            let octets = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Ok(StdIpAddr::V6(octets.into()))
        }
        family => Err(NetError::Operation(format!(
            "Windows IP Helper returned unsupported address family {family}"
        ))),
    }
}

fn prefix_matches(row: &MIB_IPFORWARD_ROW2, prefix: IpNet) -> bool {
    row.DestinationPrefix.PrefixLength == prefix.prefix_len()
        && ip_from_sockaddr(&row.DestinationPrefix.Prefix).is_ok_and(|ip| ip == prefix.addr())
}

fn same_next_hop(row: &MIB_IPFORWARD_ROW2, gateway: Option<IpAddr>) -> bool {
    ip_from_sockaddr(&row.NextHop)
        .is_ok_and(|next_hop| Some(next_hop) == gateway.or(Some(unspecified(family_for(next_hop)))))
}
