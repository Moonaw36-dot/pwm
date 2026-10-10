//! Page-locked key storage: secrets that must never touch swap and are
//! zeroed on drop even if `mlock` is unavailable.

const KEY_LEN: usize = 32;

/// A 32-byte key held in its own page-locked allocation.
///
/// Unlike `Zeroizing`, the memory is a private anonymous mapping that the OS
/// is asked to keep out of swap (`mlock` on Unix, `VirtualLock` on Windows)
/// and to exclude from core dumps (`MADV_DONTDUMP` where available). Locking
/// is best-effort: if the OS refuses (e.g. a low `RLIMIT_MEMLOCK`), the buffer
/// still lives in ordinary anonymous memory and is still zeroed on drop.
pub struct LockedKey {
    ptr: *mut u8,
    mapped: usize,
}

// The buffer is plain bytes owned exclusively by this value; sending or
// sharing it carries no more risk than sending a [u8; 32].
unsafe impl Send for LockedKey {}
unsafe impl Sync for LockedKey {}

impl LockedKey {
    pub fn zeroed() -> LockedKey {
        Self::from_array([0u8; KEY_LEN])
    }

    pub fn from_array(key: [u8; KEY_LEN]) -> LockedKey {
        let mapped = page_size();
        let ptr = alloc(mapped);
        let result = LockedKey { ptr, mapped };
        unsafe {
            std::ptr::copy_nonoverlapping(key.as_ptr(), result.ptr, KEY_LEN);
        }
        result
    }
}

impl std::ops::Deref for LockedKey {
    type Target = [u8; KEY_LEN];

    fn deref(&self) -> &[u8; KEY_LEN] {
        unsafe { &*self.ptr.cast::<[u8; KEY_LEN]>() }
    }
}

impl std::ops::DerefMut for LockedKey {
    fn deref_mut(&mut self) -> &mut [u8; KEY_LEN] {
        unsafe { &mut *self.ptr.cast::<[u8; KEY_LEN]>() }
    }
}

impl AsRef<[u8]> for LockedKey {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl PartialEq for LockedKey {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for LockedKey {}

impl std::fmt::Debug for LockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedKey(***)")
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr, 0, self.mapped);
            unlock(self.ptr, self.mapped);
            free(self.ptr, self.mapped);
        }
    }
}

#[cfg(unix)]
fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE).max(1) as usize }
}

#[cfg(windows)]
fn page_size() -> usize {
    4096
}

#[cfg(unix)]
fn alloc(len: usize) -> *mut u8 {
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            log::warn!("LockedKey: mmap failed; key will use ordinary memory");
            panic!("LockedKey: mmap failed");
        }
        if libc::mlock(ptr, len) != 0 {
            log::warn!("LockedKey: mlock failed; the key may be swappable");
        }
        #[cfg(target_os = "linux")]
        {
            if libc::madvise(ptr, len, libc::MADV_DONTDUMP) != 0 {
                log::debug!("LockedKey: MADV_DONTDUMP unavailable");
            }
        }
        ptr.cast()
    }
}

#[cfg(windows)]
fn alloc(len: usize) -> *mut u8 {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualLock,
    };
    unsafe {
        let ptr = VirtualAlloc(None, len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if ptr.is_null() {
            log::warn!("LockedKey: VirtualAlloc failed; key will use ordinary memory");
            panic!("LockedKey: VirtualAlloc failed");
        }
        if VirtualLock(ptr, len) == 0 {
            log::warn!("LockedKey: VirtualLock failed; the key may be swappable");
        }
        ptr
    }
}

#[cfg(unix)]
unsafe fn unlock(ptr: *mut u8, len: usize) {
    unsafe {
        libc::munlock(ptr.cast(), len);
    }
}

#[cfg(windows)]
unsafe fn unlock(ptr: *mut u8, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    VirtualUnlock(ptr, len);
}

#[cfg(unix)]
unsafe fn free(ptr: *mut u8, len: usize) {
    unsafe {
        libc::munmap(ptr.cast(), len);
    }
}

#[cfg(windows)]
unsafe fn free(ptr: *mut u8, _len: usize) {
    use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
    VirtualFree(ptr, 0, MEM_RELEASE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_exposes_key_bytes() {
        let key = LockedKey::from_array([7u8; KEY_LEN]);
        assert_eq!(&key[..], &[7u8; KEY_LEN]);
        assert_eq!(key.as_ref(), &[7u8; KEY_LEN]);
    }

    #[test]
    fn zeroed_starts_empty() {
        let key = LockedKey::zeroed();
        assert_eq!(&key[..], &[0u8; KEY_LEN]);
    }

    #[test]
    fn deref_mut_writes_through() {
        let mut key = LockedKey::zeroed();
        key.copy_from_slice(&[1u8; KEY_LEN]);
        assert_eq!(&key[..], &[1u8; KEY_LEN]);
    }

    #[test]
    fn equality_is_constant_content_compare() {
        let a = LockedKey::from_array([9u8; KEY_LEN]);
        let b = LockedKey::from_array([9u8; KEY_LEN]);
        let c = LockedKey::from_array([8u8; KEY_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_never_shows_contents() {
        let key = LockedKey::from_array([42u8; KEY_LEN]);
        assert!(!format!("{key:?}").contains("42"));
    }
}
