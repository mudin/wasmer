use wasmer_runtime_abi::vfs::vfs::Vfs;
use std::collections::BTreeMap;
use crate::varargs::VarArgs;

pub type Fd = i32;

pub enum File {
    VirtualFile(Fd),
    Socket(Fd),
}

pub type Map<K, V> = BTreeMap<K, V>;
pub type FdMap = Map<Fd, File>;

pub struct EmscriptenVfs {
    pub fd_map: FdMap,
    pub vfs: Vfs,
}

impl EmscriptenVfs {
    pub fn new(vfs: Vfs) -> Self {
        EmscriptenVfs {
            fd_map: FdMap::new(),
            vfs,
        }
    }

    pub fn next_lowest_fd(&self) -> Fd {
        let mut next_lowest_fd = 0;
        for (fd, _) in self.fd_map.iter() {
            if *fd == next_lowest_fd {
                next_lowest_fd += 1;
            } else if *fd < next_lowest_fd {
                panic!("Should not be here.");
            } else {
                break;
            }
        }
        next_lowest_fd
    }

    pub fn get_socket_fd(&self, fd: Fd) -> Option<Fd> {
        match self.fd_map.get(&fd) {
            Some(File::Socket(fd)) => Some(*fd),
            _ => None
        }
    }

    // socket call
    pub fn socket_call(&mut self, code: i32, socket_args: VarArgs) -> i32 {
        match code {
            1 => {},
            2 => {},
            _ => {},
        };
        0
    }
}
