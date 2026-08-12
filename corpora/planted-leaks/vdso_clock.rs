//! Planted leak class: vDSO-resident wall-clock reads.

fn main() {
    let mut _vdso_base = 0usize;
    let mut _ts = std::mem::zeroed();
    unsafe {
        _vdso_base = libc::getauxval(libc::AT_SYSINFO_EHDR);
    }
    let _ = libc::clock_gettime(libc::CLOCK_REALTIME, &mut _ts);
}
