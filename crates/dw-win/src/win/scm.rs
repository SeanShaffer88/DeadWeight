//! Services via the Service Control Manager (`OpenSCManagerW`,
//! `EnumServicesStatusExW`, `QueryServiceConfigW`,
//! `QueryServiceConfig2W`).
//!
//! This module is the SCM access point for both the collector
//! (enumerate + read configuration) and the disable tier
//! ([`set_start_type`]). DeadWeight inventories Win32 services only
//! — drivers are out of scope by design — and it never starts or
//! stops a service: the only mutation anywhere is a start-type
//! change through [`set_start_type`].

use dw_core::model::{AuditItem, Kind};
use dw_core::service_parse::{exe_path_from_binary_path, service_state_label};
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QueryServiceConfig2W, QueryServiceConfigW, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE,
    QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG,
    SERVICE_START_TYPE, SERVICE_STATE_ALL, SERVICE_WIN32,
};

use super::{wide, wide_ptr_to_string};

/// RAII wrapper for an SCM handle: the handle is closed exactly once,
/// when the wrapper drops.
pub(crate) struct ScHandle(pub(crate) SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live handle obtained from the SCM and
        // owned solely by this wrapper, so closing it once here is
        // the only close.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

/// Map an SCM error to a user-facing message. Access denied gets the
/// elevation hint the CLI contract promises; everything else keeps
/// the OS error text.
pub(crate) fn scm_error(context: &str, err: &windows::core::Error) -> String {
    // ERROR_ACCESS_DENIED (5) as an HRESULT from Win32.
    if err.code() == windows::core::HRESULT::from_win32(5) {
        format!(
            "{context}: access denied — re-run DeadWeight from an elevated \
             (Administrator) terminal"
        )
    } else {
        format!("{context}: {err}")
    }
}

fn open_manager_with(access: u32) -> Result<ScHandle, String> {
    // SAFETY: null machine/database names select the local machine's
    // default services database; `access` is the caller's requested
    // mask (connect/enumerate only — this crate never requests
    // create/delete service rights).
    let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
        .map_err(|err| scm_error("could not open the Service Control Manager", &err))?;
    Ok(ScHandle(handle))
}

/// One service's configuration as the collector and the disable tier
/// need it.
pub(crate) struct ServiceConfig {
    pub start_type: u32,
    pub delayed_start: bool,
    pub binary_path: String,
}

/// Query one service's start type, delayed-auto-start flag, and raw
/// binary path. Returns `None` when the service cannot be opened or
/// its configuration cannot be read — protected services routinely
/// deny the query, and that degrades to a state-only item, never to
/// a source failure.
fn query_config(manager: &ScHandle, name: &str) -> Option<ServiceConfig> {
    let wide_name = wide(name);
    // SAFETY: `wide_name` is NUL-terminated and lives for the call;
    // the returned handle is owned by the ScHandle wrapper.
    let service = ScHandle(unsafe {
        OpenServiceW(manager.0, PCWSTR(wide_name.as_ptr()), SERVICE_QUERY_CONFIG).ok()?
    });

    let mut bytes_needed = 0u32;
    // SAFETY: null output buffer with a size out-pointer is the
    // documented way to learn the required buffer size; the call is
    // expected to fail with ERROR_INSUFFICIENT_BUFFER.
    let _ = unsafe { QueryServiceConfigW(service.0, None, 0, &mut bytes_needed) };
    if bytes_needed == 0 {
        return None;
    }
    // u64-backed buffer: QUERY_SERVICE_CONFIGW contains pointers, so
    // the buffer must be 8-byte aligned, which Vec<u8> does not
    // promise.
    let mut buffer = vec![0u64; (bytes_needed as usize).div_ceil(8)];
    let config_ptr = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: `config_ptr` points to `bytes_needed` zeroed bytes of
    // 8-byte-aligned storage, as the API requires; on success the
    // struct and its string pointers reference memory inside the
    // same buffer, which outlives the reads below.
    let ok = unsafe {
        QueryServiceConfigW(service.0, Some(config_ptr), bytes_needed, &mut bytes_needed)
    };
    ok.ok()?;
    // SAFETY: the query succeeded, so `config_ptr` holds a valid
    // QUERY_SERVICE_CONFIGW whose PWSTR fields point into `buffer`.
    let (start_type, raw_binary_path) = unsafe {
        let config = &*config_ptr;
        (
            config.dwStartType.0,
            wide_ptr_to_string(config.lpBinaryPathName.0),
        )
    };

    // Delayed auto-start is a separate config level; a service that
    // cannot answer it is simply not delayed.
    let mut delayed_buffer = vec![0u8; std::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>()];
    let mut delayed_needed = 0u32;
    // SAFETY: the buffer is exactly the size of the documented
    // fixed-size struct for this info level; on success it holds
    // one SERVICE_DELAYED_AUTO_START_INFO.
    let delayed_ok = unsafe {
        QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            Some(&mut delayed_buffer),
            &mut delayed_needed,
        )
    };
    let delayed_start = if delayed_ok.is_ok() && delayed_buffer.len() >= 4 {
        // The query succeeded, so the buffer holds a valid
        // SERVICE_DELAYED_AUTO_START_INFO whose only field is the
        // BOOL (i32) flag. The bytes are read directly rather than
        // through a struct reference: the byte buffer promises no
        // alignment, and 4 is exactly the struct's size.
        i32::from_le_bytes(delayed_buffer[0..4].try_into().unwrap_or([0; 4])) != 0
    } else {
        false
    };

    Some(ServiceConfig {
        start_type,
        delayed_start,
        binary_path: raw_binary_path,
    })
}

/// Read one service's current start type, for disable-tier
/// prior-state capture and verification.
pub(crate) fn query_start_type(name: &str) -> Result<u32, String> {
    let manager = open_manager_with(SC_MANAGER_CONNECT)?;
    // A service that does not exist and a service whose configuration
    // is access-denied both surface as "could not read" — the caller
    // (the disable engine) treats either as "do not proceed".
    let config = query_config(&manager, name)
        .ok_or_else(|| format!("could not read the configuration of service \"{name}\""))?;
    Ok(config.start_type)
}

/// Set one service's start type (`SERVICE_DISABLED` to disable, or a
/// recorded prior value to re-enable). Nothing else about the
/// service is changed: every other `ChangeServiceConfigW` parameter
/// is `SERVICE_NO_CHANGE` / null. A running service is **not**
/// stopped — DeadWeight never starts or stops services; the new
/// start type takes effect the next time the service would start.
pub(crate) fn set_start_type(name: &str, start_type: u32) -> Result<(), String> {
    let manager = open_manager_with(SC_MANAGER_CONNECT)?;
    let wide_name = wide(name);
    // SAFETY: `wide_name` is NUL-terminated and lives for the call;
    // the returned handle is owned by the ScHandle wrapper.
    let service = ScHandle(
        unsafe { OpenServiceW(manager.0, PCWSTR(wide_name.as_ptr()), SERVICE_CHANGE_CONFIG) }
            .map_err(|err| {
                scm_error(
                    &format!("could not open service \"{name}\" to change it"),
                    &err,
                )
            })?,
    );
    // SAFETY: SERVICE_NO_CHANGE for service type and error control
    // and null for every string/pointer parameter instruct the SCM
    // to leave those fields exactly as they are; only the start type
    // is set, which is the one change the disable tier exists to
    // make.
    unsafe {
        ChangeServiceConfigW(
            service.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_START_TYPE(start_type),
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .map_err(|err| scm_error(&format!("could not change service \"{name}\""), &err))
}

/// Enumerate Win32 services into audit items. Per-service
/// configuration failures degrade to state-only items (start type
/// unknown), because protected services deny config queries by
/// design.
pub(crate) fn collect_services() -> Result<Vec<AuditItem>, String> {
    let manager = open_manager_with(SC_MANAGER_ENUMERATE_SERVICE)?;
    let mut bytes_needed = 0u32;
    let mut returned = 0u32;
    let mut resume = 0u32;
    // SAFETY: a null buffer with a size out-pointer is the documented
    // sizing call; nothing is written anywhere.
    let _ = unsafe {
        EnumServicesStatusExW(
            manager.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        )
    };
    if bytes_needed == 0 {
        return Ok(Vec::new());
    }
    // u64-backed buffer: ENUM_SERVICE_STATUS_PROCESSW contains
    // pointers and must be 8-byte aligned (see query_config).
    let mut buffer = vec![0u64; (bytes_needed as usize).div_ceil(8)];
    let byte_buffer: &mut [u8] = unsafe {
        // SAFETY: reinterpreting the u64 storage as bytes of exactly
        // `bytes_needed` length for the API call; the storage
        // outlives the call and the reinterpretation is
        // size-preserving.
        std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), bytes_needed as usize)
    };
    // SAFETY: `byte_buffer` is `bytes_needed` bytes of writable
    // storage; on success the ENUM_SERVICE_STATUS_PROCESSW array and
    // all strings it references live inside it and are read before
    // it drops.
    unsafe {
        EnumServicesStatusExW(
            manager.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(byte_buffer),
            &mut bytes_needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        )
    }
    .map_err(|err| format!("could not enumerate services: {err}"))?;

    // SAFETY: the enumeration succeeded, so the buffer starts with
    // `returned` consecutive ENUM_SERVICE_STATUS_PROCESSW values
    // whose string pointers reference memory inside the same buffer.
    let entries = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            returned as usize,
        )
    };

    let mut items = Vec::with_capacity(entries.len());
    for entry in entries {
        // SAFETY: per the enumeration contract above, the name
        // pointer references a NUL-terminated string inside
        // `buffer`.
        let name = unsafe { wide_ptr_to_string(entry.lpServiceName.0) };
        if name.is_empty() {
            continue;
        }
        let mut item = AuditItem::new(
            &name,
            Kind::Service,
            service_state_label(entry.ServiceStatusProcess.dwCurrentState.0),
        );
        if let Some(config) = query_config(&manager, &name) {
            item.start_type = Some(config.start_type);
            item.delayed_start = config.delayed_start;
            let exe_path = exe_path_from_binary_path(&config.binary_path);
            if !exe_path.is_empty() {
                item.binary_path = Some(exe_path);
            }
        }
        items.push(item);
    }
    Ok(items)
}
