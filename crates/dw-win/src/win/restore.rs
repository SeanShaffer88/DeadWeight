//! System Restore point creation via `SRSetRestorePointW`.
//!
//! Binding decision, verified against the generated sources:
//! `windows` 0.61.3 **does** generate an `SRSetRestorePointW`
//! binding (`Win32_System_Restore`), but its link target is
//! `sfc.dll`, while the Microsoft Learn System Restore reference
//! documents the export as living in `srclient.dll`. Linking
//! against a library name that contradicts the documentation is a
//! mismatch `cargo check` cannot catch — it would only fail, or
//! silently bind, at load time on a real machine. This module
//! therefore runtime-loads `srclient.dll` and resolves the export
//! by name. The two structs are declared here from the Learn
//! reference; no new dependency is added.

use windows::core::{s, PCWSTR};
use windows::Win32::Foundation::FARPROC;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use super::wide;
use crate::action::RestorePointOps;

/// `RESTOREPOINTINFOW` from the System Restore reference:
/// `dwEventType`, `dwRestorePtType`, `llSequenceNumber`, and the
/// description in `szDescription[MAX_DESC_W]` (256 UTF-16 units).
#[repr(C)]
struct RestorePointInfoW {
    dw_event_type: u32,
    dw_restore_pt_type: u32,
    ll_sequence_number: i64,
    sz_description: [u16; 256],
}

/// `STATEMGRSTATUS` from the System Restore reference: `nStatus`
/// and the sequence number assigned to the restore point.
#[repr(C)]
#[derive(Default)]
struct StateMgrStatus {
    n_status: u32,
    ll_sequence_number: i64,
}

/// The `SRSetRestorePointW` signature: `BOOL` return, out status.
type SrSetRestorePointWFn =
    unsafe extern "system" fn(*const RestorePointInfoW, *mut StateMgrStatus) -> i32;

/// `RESTOREPOINTINFO_EVENT_TYPE.BEGIN_SYSTEM_CHANGE`.
const BEGIN_SYSTEM_CHANGE: u32 = 100;
/// `RESTOREPOINTINFO_TYPE.MODIFY_SETTINGS`.
const MODIFY_SETTINGS: u32 = 12;

/// Map a `STATEMGRSTATUS.nStatus` failure code to plain language.
/// The values are ordinary Win32 error codes returned through the
/// status struct (per the Learn reference for `SRSetRestorePoint`).
fn describe_status(code: u32) -> String {
    match code {
        // ERROR_SERVICE_DISABLED: System Restore is off on this PC.
        1058 => "System Restore is turned off on this PC".to_owned(),
        // ERROR_ACCESS_DENIED.
        5 => {
            "access denied — re-run DeadWeight from an elevated (Administrator) terminal".to_owned()
        }
        // ERROR_DISK_FULL.
        112 => "there is not enough free disk space for a restore point".to_owned(),
        // Anything else: keep the raw code so the failure is
        // diagnosable, not hidden.
        other => format!("System Restore reported status {other}"),
    }
}

/// The real [`RestorePointOps`]: creates an actual restore point.
pub struct SystemRestorePoints;

impl RestorePointOps for SystemRestorePoints {
    fn create(&self, description: &str) -> Result<String, String> {
        let dll = wide("srclient.dll");
        // SAFETY: `dll` is a NUL-terminated UTF-16 string that lives
        // for the call. The returned module handle is deliberately
        // never freed: the function pointer resolved below is used
        // immediately afterwards, srclient is a system library that
        // stays loaded for the process in practice, and not freeing
        // removes a use-after-free class entirely.
        let module = unsafe { LoadLibraryW(PCWSTR(dll.as_ptr())) }
            .map_err(|err| format!("could not load srclient.dll: {err}"))?;
        // SAFETY: the proc name is a static NUL-terminated string
        // (the `s!` literal); the returned pointer is checked for
        // None before use.
        let proc: FARPROC = unsafe { GetProcAddress(module, s!("SRSetRestorePointW")) };
        let function_ptr = proc.ok_or_else(|| {
            "srclient.dll does not export SRSetRestorePointW on this PC".to_owned()
        })?;
        // SAFETY: `function_ptr` is the address of SRSetRestorePointW
        // in srclient.dll, whose documented signature is exactly
        // SrSetRestorePointWFn as declared from the Learn reference
        // above (BOOL return, two pointer parameters).
        let function: SrSetRestorePointWFn = unsafe { std::mem::transmute(function_ptr) };

        let mut info = RestorePointInfoW {
            dw_event_type: BEGIN_SYSTEM_CHANGE,
            dw_restore_pt_type: MODIFY_SETTINGS,
            ll_sequence_number: 0,
            sz_description: [0u16; 256],
        };
        // Truncate the description to 255 units so the buffer stays
        // NUL-terminated, as the API expects.
        for (slot, unit) in info
            .sz_description
            .iter_mut()
            .take(255)
            .zip(description.encode_utf16())
        {
            *slot = unit;
        }
        let mut status = StateMgrStatus::default();
        // SAFETY: `info` and `status` are correctly laid out
        // (declared from the documented structs), live for the call,
        // and the function writes only through `status`.
        let ok = unsafe { function(&info, &mut status) };
        if ok != 0 {
            if status.ll_sequence_number > 0 {
                Ok(format!(
                    "created a system restore point (sequence {})",
                    status.ll_sequence_number
                ))
            } else {
                Ok("created a system restore point".to_owned())
            }
        } else {
            Err(describe_status(status.n_status))
        }
    }
}
