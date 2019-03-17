use crate::utils::{copy_stat_into_wasm, read_string_from_wasm};
use crate::varargs::VarArgs;
use libc::stat;
use std::os::raw::c_int;
use std::slice;
use wasmer_runtime_core::vm::Ctx;

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
    #[cfg(feature = "debug")]
    let fd: i32 = varargs.get(ctx);
    #[cfg(feature = "debug")]
    let buf: u32 = varargs.get(ctx);
    let count: i32 = varargs.get(ctx);
    //    let buf_addr = emscripten_memory_pointer!(ctx.memory(0), buf) as *const c_void;
    debug!("=> NOOP fd: {}, buf: {}, count: {}\n", fd, buf, count);
    count
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
    debug!("closing fd: {}", fd);
    let emscripten_data = crate::env::get_emscripten_data(ctx);
    if let Some(vfs) = &mut emscripten_data.vfs {
        match vfs.close(fd as _) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    } else {
        -1
    }
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
    let _fd: i32 = varargs.get(ctx);
    let _buf: u32 = varargs.get(ctx);
    let count: u32 = varargs.get(ctx);
    let _offset: i64 = varargs.get(ctx);
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
            let metadata = vfs.get_file_metadata(fd as _).unwrap();
            let len = metadata.len();
            let mode = if metadata.is_file() {
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

// chown
pub fn ___syscall212(ctx: &mut Ctx, _which: c_int, mut varargs: VarArgs) -> c_int {
    debug!("emscripten::___syscall212 (chown) {}", _which);
    let _pathname: u32 = varargs.get(ctx);
    let _owner: u32 = varargs.get(ctx);
    let _group: u32 = varargs.get(ctx);
    debug!("syscall `chown` always returns 0");
    0
}
