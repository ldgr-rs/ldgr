//! Planted leak class: raw syscall invocation.

fn main() {
    let _fd = unsafe { syscall(libc::SYS_open, b"state.bin".as_ptr(), libc::O_RDONLY) };
}
