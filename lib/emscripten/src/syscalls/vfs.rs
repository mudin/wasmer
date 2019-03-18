use crate::utils::{copy_stat_into_wasm, read_string_from_wasm};
use crate::varargs::VarArgs;
use libc::stat;
use std::os::raw::c_int;
use std::slice;
use wasmer_runtime_abi::vfs::vfs::Fd;
use wasmer_runtime_core::vm::Ctx;
use crate::env::get_emscripten_data;
use crate::emscripten_set_up_memory;
use crate::syscalls::emscripten_vfs::File;

/// read
pub fn ___syscall3(ctx: &mut Ctx, _which: i32, mut varargs: VarArgs) -> i32 {
    // -> ssize_t
    debug!("emscripten::___syscall3 (read - vfs) {}", _which);
    let fd: i32 = varargs.get(ctx);
    let buf: u32 = varargs.get(ctx);
    let count: i32 = varargs.get(ctx);
    debug!("=> fd: {}, buf_offset: {}, count: {}", fd, buf, count);
    let buf_addr = emscripten_memory_pointer!(ctx.memory(0), buf) as *mut u8;
    let mut buf_slice = unsafe { slice::from_raw_parts_mut(buf_addr, count as _) };
    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let ret = match &mut emscripten_data.vfs {
        Some(vfs) => vfs.read_file(fd as _, &mut buf_slice).unwrap(),
        None => 0,
    };
    debug!("=> read syscall returns: {}", ret);
    ret as _
}

/// write
pub fn ___syscall4(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall4 (write - vfs) {}", _which);
    let fd: i32 = varargs.get(ctx);
    let buf: u32 = varargs.get(ctx);
    let count: i32 = varargs.get(ctx);
    let emscripten_memory = ctx.memory(0);

    let buf_addr = emscripten_memory_pointer!(emscripten_memory, buf);

    let buf_slice = unsafe { slice::from_raw_parts_mut(buf_addr, count as _) };

    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let count = if let Some(vfs) = &mut emscripten_data.vfs {
        vfs.write_file(fd as _, buf_slice, count as _, 0).unwrap()
    } else {
        0
    };

    let written_data = crate::utils::read_string_from_wasm(emscripten_memory, buf_addr);
    println!("wrote data: \"{}\"", written_data);

    debug!("=> fd: {}, buf: {}, count: {}\n", fd, buf, count);
    count as c_int
}

/// open
pub fn ___syscall5(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall5 (open vfs) {}", _which);
    let pathname: u32 = varargs.get(ctx);
    let pathname_addr = emscripten_memory_pointer!(ctx.memory(0), pathname) as *const i8;
    let path_str = unsafe { std::ffi::CStr::from_ptr(pathname_addr).to_str().unwrap() };
    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let fd = if let Some(vfs) = &mut emscripten_data.vfs {
        vfs.open_file(path_str).unwrap_or(-1)
    } else {
        -1
    };
    debug!("=> fd: {}", fd);
    return fd as _;
}

/// close
pub fn ___syscall6(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall6 (close vfs) {}", _which);
    let fd: i32 = varargs.get(ctx);
    debug!("closing fd {}", fd);

    let emscripten_data = crate::env::get_emscripten_data(ctx);
//    if let Some(vfs) = &mut emscripten_data.vfs {
//        if let Err(e) = vfs.close(fd as _) {
//
//        }
        //        let fd = fd as Fd;
        //        if let Some(file) = vfs.fd_map.get(&fd) {
        //
        //        }

        //        vfs.fd_map.contains_key(&fd);
        //        let y = if let Err(e) = vfs.close(fd as _) {
        //            e
        //        };
        0
//    } else {
//        -1
//    }

}

/// chmod
pub fn ___syscall15(_ctx: &mut Ctx, _one: i32, _two: i32) -> i32 {
    debug!("emscripten::___syscall15 (chmod)");
    debug!("chmod always returns 0.");
    0
}

// mkdir
pub fn ___syscall39(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall39 (mkdir vfs) {}", _which);
    let pathname: u32 = varargs.get(ctx);
    let _mode: u32 = varargs.get(ctx);
    let path = read_string_from_wasm(ctx.memory(0), pathname);
    let root = std::path::PathBuf::from("/");
    let absolute_path = root.join(&path);
    debug!("mkdir: {}", absolute_path.display());
    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let ret = if let Some(vfs) = &mut emscripten_data.vfs {
        match vfs.make_dir(&absolute_path) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    } else {
        -1
    };
    debug!("mkdir returns {}", ret);
    ret
}

/// dup2
pub fn ___syscall63(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall63 (dup2) {}", _which);

    let src: i32 = varargs.get(ctx);
    let dst: i32 = varargs.get(ctx);

    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let fd = if let Some(vfs) = &mut emscripten_data.vfs {
        vfs.duplicate_file_descriptor(src as _, dst as _)
            .unwrap_or(-1)
    //        vfs.assign_file_descriptor_from_file_descriptor(src as _, dst as _).unwrap_or(-1)
    } else {
        -1
    };
    fd as _
}

/// pread
pub fn ___syscall180(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall180 (pread) {}", _which);
    let fd: i32 = varargs.get(ctx);
    let buf: u32 = varargs.get(ctx);
    let count: i32 = varargs.get(ctx);
    let offset: i32/*i64*/ = varargs.get(ctx);
    debug!(
        "=> fd: {}, buf_offset: {}, count: {}, offset: {}",
        fd, buf, count, offset
    );
    let buf_addr = emscripten_memory_pointer!(ctx.memory(0), buf) as *mut u8;
    let buf_slice = unsafe { slice::from_raw_parts_mut(buf_addr, count as _) };
    let mut buf_slice_with_offset: &mut [u8] = &mut buf_slice[(offset as usize)..];
    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let ret = match &mut emscripten_data.vfs {
        Some(vfs) => vfs.read_file(fd as _, &mut buf_slice_with_offset).unwrap(),
        None => 0,
    };
    debug!("=> pread returns: {}", ret);
    ret as _
}

/// pwrite
pub fn ___syscall181(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall181 (pwrite) {}", _which);
    let fd: i32 = varargs.get(ctx);
    let buf: u32 = varargs.get(ctx);
    let count: u32 = varargs.get(ctx);
    let offset: i32 = varargs.get(ctx);

    let buf_addr = emscripten_memory_pointer!(ctx.memory(0), buf);

    let buf_slice = unsafe { slice::from_raw_parts_mut(buf_addr, count as _) };

    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let count = if let Some(vfs) = &mut emscripten_data.vfs {
        vfs.vfs.write_file(fd as _, buf_slice, count as _, offset as _)
            .unwrap()
    } else {
        0
    };

    count as _
}

// stat64
#[cfg(feature = "vfs")]
pub fn ___syscall195(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall195 (stat64) {}", _which);
    let pathname: u32 = varargs.get(ctx);
    let buf: u32 = varargs.get(ctx);
    let path_string = read_string_from_wasm(ctx.memory(0), pathname);
    debug!("path extract for `stat` syscall: {}", &path_string);
    let path = std::path::PathBuf::from(path_string);

    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let ret = match &mut emscripten_data.vfs {
        Some(vfs) => {
            let metadata = vfs.get_path_metadata(&path).unwrap();
            let len = metadata.len();
            unsafe {
                let mut stat: stat = std::mem::zeroed();
                stat.st_size = len as _;
                debug!("stat size: {}", len);
                copy_stat_into_wasm(ctx, buf, &stat as _);
            }
            0
        }
        None => -1,
    };
    debug!("stat return: {}", ret);
    ret
}

/// fstat64
pub fn ___syscall197(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall197 (fstat64) {}", _which);
    let fd: c_int = varargs.get(ctx);
    let buf: u32 = varargs.get(ctx);
    let emscripten_data = crate::env::get_emscripten_data(ctx);
    let ret = match &mut emscripten_data.vfs {
        Some(vfs) => {
            let metadata = vfs.vfs.get_file_metadata(fd as _).unwrap();
            let len = metadata.len;
            let mode = if metadata.is_file {
                libc::S_IFREG
            } else {
                libc::S_IFDIR
            };
            unsafe {
                let mut stat: stat = std::mem::zeroed();
                stat.st_mode = mode as _;
                stat.st_size = len as _;
                debug!("fstat size: {}", len);
                copy_stat_into_wasm(ctx, buf, &stat as _);
            }
            0
        }
        None => -1,
    };
    debug!("fstat return: {}", ret);
    ret
}

// getgid
pub fn ___syscall201(_ctx: &mut Ctx, _one: i32, _two: i32) -> i32 {
    debug!("emscripten::___syscall201 (getgid)");
    0
}

// socketcall
#[allow(clippy::cast_ptr_alignment)]
pub fn ___syscall102(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall102 (socketcall) {}", _which);
    let call: u32 = varargs.get(ctx);
    let mut socket_varargs: VarArgs = varargs.get(ctx);

    #[cfg(target_os = "windows")]
    type libc_sa_family_t = u16;
    #[cfg(not(target_os = "windows"))]
    type libc_sa_family_t = libc::sa_family_t;

    #[cfg(target_os = "windows")]
    type libc_in_port_t = u16;
    #[cfg(not(target_os = "windows"))]
    type libc_in_port_t = libc::libc::in_port_t;

    #[cfg(target_os = "windows")]
    type libc_in_addr_t = u32;
    #[cfg(not(target_os = "windows"))]
    type libc_in_addr_t = libc::in_addr_t;

    #[repr(C)]
    pub struct GuestSockaddrIn {
        pub sin_family: libc_sa_family_t, // u16
        pub sin_port: libc_in_port_t,     // u16
        pub sin_addr: GuestInAddr,   // u32
        pub sin_zero: [u8; 8],       // u8 * 8
        // 2 + 2 + 4 + 8 = 16
    }

    #[repr(C)]
    pub struct GuestInAddr {
        pub s_addr: libc_in_addr_t, // u32
    }

    pub struct LinuxSockAddr {
        pub sa_family: u16,
        pub sa_data: [libc::c_char; 14],
    }

    fn get_socket_fd_or(ctx: &mut Ctx, socket: i32, or_else: i32) -> i32 {
//        if let Some(ref mut vfs) = crate::env::get_emscripten_data(ctx).vfs {
//            match vfs.get_external_socket(socket as _) {
//                Ok(fd) => fd as i32,
//                Err(e) => or_else,
//            }
//        } else { or_else }
        -1
    }

    let vfs = crate::env::get_emscripten_data(ctx).vfs.as_mut().unwrap();

    match call {
        1 => { // socket
            debug!("socket: socket");
            // socket (domain: c_int, ty: c_int, protocol: c_int) -> c_int
            let domain: i32 = socket_varargs.get(ctx);
            let ty: i32 = socket_varargs.get(ctx);
            let protocol: i32 = socket_varargs.get(ctx);

            // create the host socket
            let host_fd = unsafe { libc::socket(domain, ty, protocol) };
            // create a virtual file descriptor
            let vfs_fd = vfs.next_lowest_fd();
            // save the mapping
            vfs.fd_map.insert(vfs_fd, File::Socket(host_fd));

            debug!("--- host fd from libc::socket: {} ---", host_fd);
            debug!("--- reference fd in vfs from libc::socket: {} ---", vfs_fd);

            // set_cloexec
            unsafe {
                libc::ioctl(host_fd, libc::FIOCLEX);
            };

            type T = u32;
            let payload = 1 as *const T as _;
            unsafe {
                libc::setsockopt(
                    host_fd,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    payload,
                    std::mem::size_of::<T>() as libc::socklen_t,
                );
            };

            debug!(
                "=> domain: {} (AF_INET/2), type: {} (SOCK_STREAM/1), protocol: {} = fd: {}",
                domain, ty, protocol, vfs_fd
            );

            vfs_fd as _
        }
        2 => {
            debug!("socket: bind");
            // bind (socket: c_int, address: *const sockaddr, address_len: socklen_t) -> c_int
            // TODO: Emscripten has a different signature.
            let socket: i32 = socket_varargs.get(ctx);
            let address: u32 = socket_varargs.get(ctx);
            let address_len = socket_varargs.get(ctx);
            let address = emscripten_memory_pointer!(ctx.memory(0), address) as *mut libc::sockaddr;

            let fd = get_socket_fd_or(ctx, socket, -1);

            // Debug received address
            let _proper_address = address as *const GuestSockaddrIn;
            unsafe {
                debug!(
                    "=> address.sin_family: {:?}, address.sin_port: {:?}, address.sin_addr.s_addr: {:?}",
                    (*_proper_address).sin_family, (*_proper_address).sin_port, (*_proper_address).sin_addr.s_addr
                );
            }
            let status = unsafe { libc::bind(fd as _, address, address_len) };
            // debug!("=> status: {}", status);
            debug!(
                "=> socketfd: {}, address: {:?}, address_len: {} = status: {}",
                socket, address, address_len, status
            );
            status
            // -1
        }
        3 => {
            debug!("socket: connect");
            // connect (socket: c_int, address: *const sockaddr, len: socklen_t) -> c_int
            // TODO: Emscripten has a different signature.
            let socket = socket_varargs.get(ctx);
            let address: u32 = socket_varargs.get(ctx);
            let address_len = socket_varargs.get(ctx);
            let address = emscripten_memory_pointer!(ctx.memory(0), address) as *mut libc::sockaddr;

            let fd = get_socket_fd_or(ctx, socket,-1);

            unsafe { libc::connect(fd as _, address, address_len) }
        }
        4 => {
            debug!("socket: listen");
            // listen (socket: c_int, backlog: c_int) -> c_int
            let socket = socket_varargs.get(ctx);
            let backlog: i32 = socket_varargs.get(ctx);

            let fd = get_socket_fd_or(ctx, socket, -1);

            let status = unsafe { libc::listen(fd as _, backlog) };
            debug!(
                "=> socketfd: {}, backlog: {} = status: {}",
                socket, backlog, status
            );
            status
        }
        5 => {
            debug!("socket: accept");
            // accept (socket: c_int, address: *mut sockaddr, address_len: *mut socklen_t) -> c_int
            let socket = socket_varargs.get(ctx);
            let address_addr: u32 = socket_varargs.get(ctx);
            let address_len: u32 = socket_varargs.get(ctx);
            let address = emscripten_memory_pointer!(ctx.memory(0), address_addr) as *mut libc::sockaddr;

            let fd = get_socket_fd_or(ctx, socket,-1);

            if fd == -1 {
                debug!("failed to get a valid proxy file descriptor for socket in `socket: accept`.");
            }

            debug!(
                "=> socket: {}, address: {:?}, address_len: {}",
                socket, address, address_len
            );
            let address_len_addr =
                emscripten_memory_pointer!(ctx.memory(0), address_len) as *mut libc::socklen_t;
            // let mut address_len_addr: socklen_t = 0;

            let fd = unsafe { libc::accept(fd as _, address, address_len_addr) };

            unsafe {
                let address_linux =
                    emscripten_memory_pointer!(ctx.memory(0), address_addr) as *mut LinuxSockAddr;
                (*address_linux).sa_family = (*address).sa_family as u16;
                (*address_linux).sa_data = (*address).sa_data;
            };

            // set_cloexec
            unsafe {
                libc::ioctl(fd, libc::FIOCLEX);
            };

            let fd = if let Some(ref mut vfs) = crate::env::get_emscripten_data(ctx).vfs {
//                match vfs.add_external_socket(fd as _) {
//                    Ok(fd) => fd,
//                    Err(e) => -1,
//                }
                -1
            } else { -1 };

            debug!("fd: {}", fd);

            fd as _
        }
        6 => {
            debug!("socket: getsockname");
            // getsockname (socket: c_int, address: *mut sockaddr, address_len: *mut socklen_t) -> c_int
            let socket = socket_varargs.get(ctx);
            let address: u32 = socket_varargs.get(ctx);
            let address_len: u32 = socket_varargs.get(ctx);
            let address = emscripten_memory_pointer!(ctx.memory(0), address) as *mut libc::sockaddr;
            let address_len_addr =
                emscripten_memory_pointer!(ctx.memory(0), address_len) as *mut libc::socklen_t;

            let fd = get_socket_fd_or(ctx, socket,-1);

            unsafe { libc::getsockname(fd as _, address, address_len_addr) }
        }
        7 => {
            debug!("socket: getpeername");
            // getpeername (socket: c_int, address: *mut sockaddr, address_len: *mut socklen_t) -> c_int
            let socket = socket_varargs.get(ctx);
            let address: u32 = socket_varargs.get(ctx);
            let address_len: u32 = socket_varargs.get(ctx);
            let address = emscripten_memory_pointer!(ctx.memory(0), address) as *mut libc::sockaddr;
            let address_len_addr =
                emscripten_memory_pointer!(ctx.memory(0), address_len) as *mut libc::socklen_t;

            let fd = get_socket_fd_or(ctx, socket,-1);

            unsafe { libc::getpeername(fd as _, address, address_len_addr) }
        }
        11 => {
            debug!("socket: sendto");
            // sendto (socket: c_int, buf: *const c_void, len: size_t, flags: c_int, addr: *const sockaddr, addrlen: socklen_t) -> ssize_t
            let socket = socket_varargs.get(ctx);
            let buf: u32 = socket_varargs.get(ctx);
            let flags = socket_varargs.get(ctx);
            let len: i32 = socket_varargs.get(ctx);
            let address: u32 = socket_varargs.get(ctx);
            let address_len = socket_varargs.get(ctx);
            let buf_addr = emscripten_memory_pointer!(ctx.memory(0), buf) as _;
            let address = emscripten_memory_pointer!(ctx.memory(0), address) as *mut libc::sockaddr;
            let fd = get_socket_fd_or(ctx, socket,-1);
            unsafe { libc::sendto(fd as _, buf_addr, flags, len, address, address_len) as i32 }
        }
        12 => {
            debug!("socket: recvfrom");
            // recvfrom (socket: c_int, buf: *const c_void, len: size_t, flags: c_int, addr: *const sockaddr, addrlen: socklen_t) -> ssize_t
            let socket = socket_varargs.get(ctx);
            let buf: u32 = socket_varargs.get(ctx);
            let flags = socket_varargs.get(ctx);
            let len: i32 = socket_varargs.get(ctx);
            let address: u32 = socket_varargs.get(ctx);
            let address_len: u32 = socket_varargs.get(ctx);
            let buf_addr = emscripten_memory_pointer!(ctx.memory(0), buf) as _;
            let address = emscripten_memory_pointer!(ctx.memory(0), address) as *mut libc::sockaddr;
            let address_len_addr =
                emscripten_memory_pointer!(ctx.memory(0), address_len) as *mut libc::socklen_t;
            let fd = get_socket_fd_or(ctx, socket, -1);
            unsafe { libc::recvfrom(fd as _, buf_addr, flags, len, address, address_len_addr) as i32 }
        }
        14 => {
            debug!("socket: setsockopt");
            // NOTE: Emscripten seems to be passing the wrong values to this syscall
            //      level: Em passes 1 as SOL_SOCKET; SOL_SOCKET is 0xffff in BSD
            //      name: Em passes SO_ACCEPTCONN, but Nginx complains about REUSEADDR
            //      https://github.com/openbsd/src/blob/master/sys/sys/socket.h#L156
            // setsockopt (socket: c_int, level: c_int, name: c_int, value: *const c_void, option_len: socklen_t) -> c_int

            let socket = socket_varargs.get(ctx);
            // SOL_SOCKET = 0xffff (BSD, Linux)
            let level: i32 = libc::SOL_SOCKET;
            let _: u32 = socket_varargs.get(ctx);
            // SO_REUSEADDR = 0x4 (BSD, Linux)
            let name: i32 = libc::SO_REUSEADDR;
            let _: u32 = socket_varargs.get(ctx);
            let value: u32 = socket_varargs.get(ctx);
            let option_len = socket_varargs.get(ctx);
            let value_addr = emscripten_memory_pointer!(ctx.memory(0), value) as _; // Endian problem
            let fd = get_socket_fd_or(ctx, socket,-1);
            let ret = unsafe { libc::setsockopt(fd as _, level, name, value_addr, option_len) };

            debug!("=> socketfd: {}, level: {} (SOL_SOCKET/0xffff), name: {} (SO_REUSEADDR/4), value_addr: {:?}, option_len: {} = status: {}", socket, level, name, value_addr, option_len, ret);
            ret
        }
        15 => {
            debug!("socket: getsockopt");
            // getsockopt (sockfd: c_int, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut socklen_t) -> c_int
            let socket = socket_varargs.get(ctx);
            let level: i32 = socket_varargs.get(ctx);
            let name: i32 = socket_varargs.get(ctx);
            let value: u32 = socket_varargs.get(ctx);
            let option_len: u32 = socket_varargs.get(ctx);
            let value_addr = emscripten_memory_pointer!(ctx.memory(0), value) as _;
            let option_len_addr =
                emscripten_memory_pointer!(ctx.memory(0), option_len) as *mut libc::socklen_t;
            let fd = get_socket_fd_or(ctx, socket,-1);
            unsafe { libc::getsockopt(fd as _, level, name, value_addr, option_len_addr) }
        }
        16 => {
            debug!("socket: sendmsg");
            // sendmsg (fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t
            let socket: i32 = socket_varargs.get(ctx);
            let msg: u32 = socket_varargs.get(ctx);
            let flags: i32 = socket_varargs.get(ctx);
            let msg_addr = emscripten_memory_pointer!(ctx.memory(0), msg) as *const libc::msghdr;
            let fd = get_socket_fd_or(ctx, socket, -1);
            unsafe { libc::sendmsg(fd as _, msg_addr, flags) as i32 }
        }
        17 => {
            debug!("socket: recvmsg");
            // recvmsg (fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t
            let socket: i32 = socket_varargs.get(ctx);
            let msg: u32 = socket_varargs.get(ctx);
            let flags: i32 = socket_varargs.get(ctx);
            let msg_addr = emscripten_memory_pointer!(ctx.memory(0), msg) as *mut libc::msghdr;
            let fd = get_socket_fd_or(ctx, socket, -1);
            unsafe { libc::recvmsg(fd as _, msg_addr, flags) as i32 }
        }
        _ => {
            // others
            -1
        }
    }
}


// chown
pub fn ___syscall212(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall212 (chown) {}", _which);
    let _pathname: u32 = varargs.get(ctx);
    let _owner: u32 = varargs.get(ctx);
    let _group: u32 = varargs.get(ctx);
    debug!("syscall `chown` always returns 0");
    0
}
