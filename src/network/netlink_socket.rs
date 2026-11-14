//! The raw socket underneath [`super::netlink::Socket`].
//!
//! On Linux this is the `netlink-sys` crate. FreeBSD speaks the same
//! rtnetlink protocol, but `netlink-sys` does not build there because the
//! `libc` crate has no FreeBSD netlink definitions, so FreeBSD gets a
//! minimal socket with the same interface here.

#[cfg(target_os = "linux")]
pub use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

#[cfg(target_os = "freebsd")]
pub use self::freebsd::{Socket, SocketAddr, NETLINK_ROUTE};

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::io;
    use std::mem;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

    // From <sys/socket.h> and <netlink/netlink.h>.
    const AF_NETLINK: libc::c_int = 38;
    pub const NETLINK_ROUTE: isize = 0;

    #[repr(C)]
    struct sockaddr_nl {
        nl_len: u8,
        nl_family: libc::sa_family_t,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }

    /// A netlink address: the port id and multicast group mask.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SocketAddr {
        pid: u32,
        groups: u32,
    }

    impl SocketAddr {
        pub fn new(pid: u32, groups: u32) -> Self {
            Self { pid, groups }
        }

        fn as_raw(&self) -> sockaddr_nl {
            sockaddr_nl {
                nl_len: mem::size_of::<sockaddr_nl>() as u8,
                nl_family: AF_NETLINK as libc::sa_family_t,
                nl_pad: 0,
                nl_pid: self.pid,
                nl_groups: self.groups,
            }
        }
    }

    /// A blocking netlink socket.
    #[derive(Debug)]
    pub struct Socket(OwnedFd);

    impl Socket {
        pub fn new(protocol: isize) -> io::Result<Self> {
            let fd = unsafe {
                libc::socket(
                    AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    protocol as libc::c_int,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }

        pub fn bind(&mut self, addr: &SocketAddr) -> io::Result<()> {
            let raw = addr.as_raw();
            let res = unsafe {
                libc::bind(
                    self.0.as_raw_fd(),
                    &raw as *const sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<sockaddr_nl>() as libc::socklen_t,
                )
            };
            check_int(res)
        }

        /// Connect to the kernel. FreeBSD marks a netlink socket connected
        /// as soon as it is bound, so EISCONN here means it already is.
        pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
            let raw = addr.as_raw();
            let res = unsafe {
                libc::connect(
                    self.0.as_raw_fd(),
                    &raw as *const sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<sockaddr_nl>() as libc::socklen_t,
                )
            };
            match check_int(res) {
                Err(e) if e.raw_os_error() == Some(libc::EISCONN) => Ok(()),
                other => other,
            }
        }

        pub fn send(&self, buf: &[u8], flags: libc::c_int) -> io::Result<usize> {
            let res = unsafe {
                libc::send(
                    self.0.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    flags,
                )
            };
            check_len(res)
        }

        /// Read one datagram into `buf` and return its length.
        pub fn recv(&self, buf: &mut &mut [u8], flags: libc::c_int) -> io::Result<usize> {
            let res = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    flags,
                )
            };
            let len = check_len(res)?;
            hide_freebsd_link_attr(&mut buf[..len]);
            Ok(len)
        }
    }

    const RTM_NEWLINK: u16 = 16;
    const NLMSG_HDRLEN: usize = 16;
    const IFINFOMSG_LEN: usize = 16;
    const NLA_HDRLEN: usize = 4;
    const NLA_TYPE_MASK: u16 = 0x3fff;
    /// FreeBSD's IFLA_FREEBSD, a nested attribute with the interface's
    /// original name, hardware address and capabilities.
    const IFLA_FREEBSD: u16 = 64;
    /// Linux has no attribute 0x3fff, so netlink-packet-route keeps it as
    /// `LinkAttribute::Other`.
    const IFLA_UNKNOWN: u16 = 0x3fff;

    /// Every FreeBSD link dump carries IFLA_FREEBSD (64), which is Linux's
    /// IFLA_GRO_IPV4_MAX_SIZE, a u32, so netlink-packet-route refuses the
    /// whole message. Retype it to an unknown attribute until the crate
    /// knows FreeBSD's link attributes.
    fn hide_freebsd_link_attr(buf: &mut [u8]) {
        let u16_at = |b: &[u8], i: usize| u16::from_ne_bytes([b[i], b[i + 1]]);
        let u32_at = |b: &[u8], i: usize| u32::from_ne_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut off = 0;
        while off + NLMSG_HDRLEN <= buf.len() {
            let msg_len = u32_at(buf, off) as usize;
            if msg_len < NLMSG_HDRLEN || off + msg_len > buf.len() {
                return;
            }
            if u16_at(buf, off + 4) == RTM_NEWLINK {
                let mut attr = off + NLMSG_HDRLEN + IFINFOMSG_LEN;
                let end = off + msg_len;
                while attr + NLA_HDRLEN <= end {
                    let nla_len = u16_at(buf, attr) as usize;
                    if nla_len < NLA_HDRLEN || attr + nla_len > end {
                        break;
                    }
                    let nla_type = u16_at(buf, attr + 2);
                    if nla_type & NLA_TYPE_MASK == IFLA_FREEBSD {
                        let retyped = (nla_type & !NLA_TYPE_MASK) | IFLA_UNKNOWN;
                        buf[attr + 2..attr + 4].copy_from_slice(&retyped.to_ne_bytes());
                    }
                    attr += (nla_len + 3) & !3;
                }
            }
            off += (msg_len + 3) & !3;
        }
    }

    fn check_int(res: libc::c_int) -> io::Result<()> {
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn check_len(res: libc::ssize_t) -> io::Result<usize> {
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    impl From<Socket> for OwnedFd {
        fn from(s: Socket) -> OwnedFd {
            s.0
        }
    }

    impl AsRawFd for Socket {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    impl AsFd for Socket {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    impl FromRawFd for Socket {
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            Self(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
}
