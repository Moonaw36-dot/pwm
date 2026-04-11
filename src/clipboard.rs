/// Set clipboard text while requesting exclusion from clipboard history on all platforms.
///
/// - Linux: uses arboard's `SetExtLinux::exclude_from_history()`
/// - Windows: writes CF_UNICODETEXT + ExcludeClipboardContentFromMonitorProcessing in one
///   clipboard transaction, which prevents Windows 10+ clipboard history from capturing it
/// - macOS: no public API exists; falls back to a plain set (value still auto-clears after 10s)
pub fn set_excluded_from_history(clipboard: &mut arboard::Clipboard, text: &str) {
    #[cfg(target_os = "linux")]
    {
        use arboard::SetExtLinux;
        clipboard.set().exclude_from_history().text(text).ok();
    }

    #[cfg(target_os = "windows")]
    {
        if windows_set_clipboard_excluded(text).is_err() {
            // Fall back to arboard if the raw API call fails
            clipboard.set_text(text).ok();
        }
    }

    #[cfg(target_os = "macos")]
    {
        clipboard.set_text(text).ok();
    }
}

#[cfg(target_os = "windows")]
fn windows_set_clipboard_excluded(text: &str) -> Result<(), ()> {
    use std::mem::size_of;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    // Encode as UTF-16 with null terminator (CF_UNICODETEXT requirement)
    let mut utf16: Vec<u16> = text.encode_utf16().collect();
    utf16.push(0);

    unsafe {
        if OpenClipboard(0) == 0 {
            return Err(());
        }
        EmptyClipboard();

        // Allocate global memory and write the text
        let byte_len = utf16.len() * size_of::<u16>();
        let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if hmem == 0 {
            CloseClipboard();
            return Err(());
        }
        let ptr = GlobalLock(hmem) as *mut u16;
        if ptr.is_null() {
            CloseClipboard();
            return Err(());
        }
        std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
        GlobalUnlock(hmem);

        // CF_UNICODETEXT = 13
        SetClipboardData(13, hmem);

        // Tell Windows clipboard history not to record this entry
        let fmt_name: Vec<u16> = "ExcludeClipboardContentFromMonitorProcessing\0"
            .encode_utf16()
            .collect();
        let fmt = RegisterClipboardFormatW(fmt_name.as_ptr());
        if fmt != 0 {
            SetClipboardData(fmt, 0);
        }

        CloseClipboard();
    }

    Ok(())
}
