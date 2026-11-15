/// Clipboard helpers that keep copied secrets out of clipboard history where
/// the platform allows it.
///
/// - Linux: arboard's `SetExtLinux::exclude_from_history()` (effective on
///   Wayland; X11 clipboard managers may still capture the value)
/// - Windows: CF_UNICODETEXT + ExcludeClipboardContentFromMonitorProcessing
///   in one clipboard transaction, so Windows 10+ history skips it
/// - macOS: no public API exists; plain set (value still auto-clears after 10s)
///
/// These write the clipboard only — they do not arm the 10s auto-clear. Copy
/// secrets via `AppState::copy_to_clipboard` so they don't outlive the timer.
pub(crate) fn set_excluded_from_history(
    clipboard: &mut arboard::Clipboard,
    text: &str,
) -> Result<(), ()> {
    #[cfg(target_os = "linux")]
    {
        use arboard::SetExtLinux;
        clipboard
            .set()
            .exclude_from_history()
            .text(text)
            .map_err(|_| ())
    }

    #[cfg(target_os = "windows")]
    {
        // No plain set_text fallback: it would put the secret in history.
        let _ = clipboard;
        windows_set_clipboard_excluded(text)
    }

    #[cfg(target_os = "macos")]
    {
        clipboard.set_text(text).map_err(|_| ())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        clipboard.set_text(text).map_err(|_| ())
    }
}

/// Short hash identifying a clipboard value, so the auto-clear only wipes
/// data we put there ourselves.
pub(crate) fn fingerprint(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

#[cfg(target_os = "windows")]
fn windows_set_clipboard_excluded(text: &str) -> Result<(), ()> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };

    // Encode as UTF-16 with null terminator (CF_UNICODETEXT requirement)
    // UTF-16 never has more units than UTF-8 has bytes, so this never reallocates.
    let mut utf16 = zeroize::Zeroizing::new(Vec::<u16>::with_capacity(text.len() + 1));
    utf16.extend(text.encode_utf16());
    utf16.push(0);

    unsafe {
        // Another process often holds the clipboard for a moment.
        let mut opened = false;
        for _ in 0..10 {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if !opened {
            return Err(());
        }

        let byte_len = utf16.len() * size_of::<u16>();

        let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if hmem.is_null() {
            CloseClipboard();
            return Err(());
        }

        EmptyClipboard();

        let ptr = GlobalLock(hmem) as *mut u16;
        if ptr.is_null() {
            GlobalFree(hmem);
            CloseClipboard();
            return Err(());
        }
        std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
        GlobalUnlock(hmem);

        // CF_UNICODETEXT = 13. On failure the system never takes ownership
        // of hmem, so it must be freed here.
        if SetClipboardData(13, hmem).is_null() {
            GlobalFree(hmem);
            CloseClipboard();
            return Err(());
        }

        // Tell Windows clipboard history not to record this entry
        let fmt_name: Vec<u16> = "ExcludeClipboardContentFromMonitorProcessing\0"
            .encode_utf16()
            .collect();
        let fmt = RegisterClipboardFormatW(fmt_name.as_ptr());
        if fmt != 0 {
            SetClipboardData(fmt, std::ptr::null_mut());
        }

        CloseClipboard();
    }

    Ok(())
}
