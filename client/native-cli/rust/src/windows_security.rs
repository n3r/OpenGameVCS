//! Handle-based Windows ownership, DACL, and reparse-point checks.
//!
//! The adapter is intentionally stricter than ordinary Windows defaults: a
//! workspace object may grant access only to its owner, LocalSystem, or the
//! built-in Administrators group. Unknown/callback/object ACE forms fail
//! closed. Handles are opened without following a final reparse point.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
    PSID,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetTokenInformation, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileRenameInfo, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
    FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    READ_CONTROL, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this type owns the live handle exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalSecurityDescriptor(*mut c_void);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }
}

pub fn open_private_directory(path: &Path) -> io::Result<File> {
    open_private(path, true)
}

pub fn open_private_regular_file(path: &Path) -> io::Result<File> {
    open_private(path, false)
}

fn open_private(path: &Path, directory: bool) -> io::Result<File> {
    let file = open_reparse_handle(path)?;
    // SAFETY: File owns a valid file-system handle for the duration of the call.
    validate_owner_and_dacl(file.as_raw_handle() as HANDLE, true)?;
    validate_kind(&file, directory)?;
    Ok(file)
}

pub fn protect_private_directory(path: &Path) -> io::Result<()> {
    let file = open_reparse_handle(path)?;
    protect_private_handle(&file, true)
}

fn open_reparse_handle(path: &Path) -> io::Result<File> {
    open_reparse_handle_with_access(path, FILE_READ_ATTRIBUTES | READ_CONTROL | GENERIC_READ)
}

fn open_reparse_handle_with_access(path: &Path, access: u32) -> io::Result<File> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.iter().any(|unit| *unit == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    wide.push(0);
    // SAFETY: the UTF-16 path is terminated, all pointer arguments are valid,
    // and the returned handle is either rejected or transferred into File.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let owned = OwnedHandle(handle);
    // SAFETY: ownership is transferred from OwnedHandle into File exactly once.
    let file = unsafe { File::from_raw_handle(owned.0 as _) };
    std::mem::forget(owned);
    Ok(file)
}

fn validate_kind(file: &File, directory: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    use std::os::windows::fs::MetadataExt;
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: the file handle is live and the output buffer has the exact API type.
    if unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            &mut information as *mut BY_HANDLE_FILE_INFORMATION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || directory != metadata.is_dir()
        || (!directory && information.nNumberOfLinks != 1)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe workspace object",
        ));
    }
    Ok(())
}

/// Atomically renames a regular file without replacing an existing target.
/// The source file and every source/destination ancestor are opened without
/// following their final reparse points; live handles pin the validated
/// objects until `SetFileInformationByHandle` resolves the relative target
/// against the pinned destination parent.
pub fn rename_confined_noreplace(root: &Path, source: &str, destination: &str) -> io::Result<()> {
    let root_handle = open_private_directory(root)?;
    let root_final = final_path(&root_handle)?;
    let source_components: Vec<_> = source.split('/').collect();
    let destination_components: Vec<_> = destination.split('/').collect();
    if source_components.is_empty()
        || destination_components.is_empty()
        || source_components.iter().any(|part| part.is_empty())
        || destination_components.iter().any(|part| part.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty relative path component",
        ));
    }

    let source_ancestors = open_confined_ancestors(
        root,
        &root_final,
        &source_components[..source_components.len() - 1],
        false,
    )?;
    let source_path = joined_relative(root, &source_components);
    let source_handle = open_reparse_handle_with_access(
        &source_path,
        DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | GENERIC_READ,
    )?;
    validate_kind(&source_handle, false)?;
    ensure_confined_final_path(&root_final, &final_path(&source_handle)?)?;

    let destination_ancestors = open_confined_ancestors(
        root,
        &root_final,
        &destination_components[..destination_components.len() - 1],
        true,
    )?;
    let destination_parent = destination_ancestors.last().unwrap_or(&root_handle);
    let destination_name: Vec<u16> =
        std::ffi::OsStr::new(destination_components[destination_components.len() - 1])
            .encode_wide()
            .collect();
    if destination_name.is_empty() || destination_name.iter().any(|unit| *unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid destination name",
        ));
    }
    set_rename_noreplace(&source_handle, destination_parent, &destination_name)?;
    validate_kind(&source_handle, false)?;
    ensure_confined_final_path(&root_final, &final_path(&source_handle)?)?;
    source_handle.sync_all()?;
    source_ancestors.last().unwrap_or(&root_handle).sync_all()?;
    destination_parent.sync_all()
}

fn open_confined_ancestors(
    root: &Path,
    root_final: &[u16],
    components: &[&str],
    destination_access: bool,
) -> io::Result<Vec<File>> {
    let mut current = root.to_path_buf();
    let mut handles = Vec::with_capacity(components.len());
    for component in components {
        current.push(component);
        let access = FILE_READ_ATTRIBUTES
            | READ_CONTROL
            | GENERIC_READ
            | FILE_LIST_DIRECTORY
            | if destination_access { FILE_ADD_FILE } else { 0 };
        let handle = open_reparse_handle_with_access(&current, access)?;
        validate_kind(&handle, true)?;
        ensure_confined_final_path(root_final, &final_path(&handle)?)?;
        handles.push(handle);
    }
    Ok(handles)
}

fn joined_relative(root: &Path, components: &[&str]) -> std::path::PathBuf {
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
    }
    path
}

fn final_path(file: &File) -> io::Result<Vec<u16>> {
    let handle = file.as_raw_handle() as HANDLE;
    // The first call obtains the exact UTF-16 buffer length including the
    // terminator when the supplied buffer is too small.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 || required > 32_768 {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0u16; required as usize];
    // SAFETY: the buffer has the exact size reported by the first call.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= path.len() {
        return Err(io::Error::last_os_error());
    }
    path.truncate(written as usize);
    Ok(path)
}

fn ensure_confined_final_path(root: &[u16], candidate: &[u16]) -> io::Result<()> {
    if candidate.len() <= root.len()
        || candidate[..root.len()] != *root
        || candidate[root.len()] != u16::from(b'\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workspace handle escaped the root",
        ));
    }
    Ok(())
}

fn set_rename_noreplace(
    source: &File,
    destination_parent: &File,
    destination_name: &[u16],
) -> io::Result<()> {
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let byte_len = header
        .checked_add(destination_name.len() * size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer overflow"))?;
    let word = size_of::<usize>();
    let mut storage = vec![0usize; (byte_len + word - 1) / word];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the aligned buffer is large enough for the fixed header and the
    // exact un-terminated UTF-16 destination name.
    unsafe {
        (*information).Anonymous = FILE_RENAME_INFO_0 { ReplaceIfExists: 0 };
        (*information).RootDirectory = destination_parent.as_raw_handle() as HANDLE;
        (*information).FileNameLength = (destination_name.len() * size_of::<u16>()) as u32;
        std::ptr::copy_nonoverlapping(
            destination_name.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            destination_name.len(),
        );
    }
    // SAFETY: source is open with DELETE access and information points at the
    // correctly sized FILE_RENAME_INFO buffer. ReplaceIfExists is false.
    if unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle() as HANDLE,
            FileRenameInfo,
            information.cast::<c_void>(),
            byte_len as u32,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn protect_private_file(file: &File) -> io::Result<()> {
    protect_private_handle(file, false)
}

fn protect_private_handle(file: &File, directory: bool) -> io::Result<()> {
    validate_kind(file, directory)?;
    let handle = file.as_raw_handle() as HANDLE;
    validate_owner_and_dacl(handle, false)?;
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: output pointers are valid and descriptor is released below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            // SAFETY: descriptor came from GetSecurityInfo.
            unsafe { LocalFree(descriptor) };
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workspace DACL unavailable",
        ));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    // SAFETY: dacl remains owned by the live descriptor for this call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    validate_owner_and_dacl(handle, true)
}

fn validate_owner_and_dacl(handle: HANDLE, require_protected: bool) -> io::Result<()> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: output pointers are valid and descriptor is released below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            // SAFETY: descriptor came from GetSecurityInfo.
            unsafe { LocalFree(descriptor) };
        }
        return if status == 0 {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "workspace has no explicit owner or DACL",
            ))
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        };
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: descriptor is live and both output pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || (require_protected && control & SE_DACL_PROTECTED == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workspace DACL is not protected from inheritance",
        ));
    }
    let token_user = current_token_user()?;
    // SAFETY: both values point at valid SIDs kept alive by their buffers.
    if unsafe { EqualSid(owner, token_user.sid()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workspace owner differs from process identity",
        ));
    }
    let system = WellKnownSid::new(WinLocalSystemSid)?;
    let administrators = WellKnownSid::new(WinBuiltinAdministratorsSid)?;
    // SAFETY: dacl is part of the live descriptor.
    let mut information: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    // SAFETY: all pointers and the exact information buffer size are valid.
    if unsafe {
        GetAclInformation(
            dacl,
            &mut information as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    for index in 0..information.AceCount {
        let mut raw_ace = null_mut();
        // SAFETY: index is within the count returned by GetAclInformation.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned a pointer to at least an ACE header.
        let ace = unsafe { &*(raw_ace as *const ACCESS_ALLOWED_ACE) };
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            if matches!(
                u32::from(ace.Header.AceType),
                ACCESS_DENIED_ACE_TYPE
                    | ACCESS_DENIED_OBJECT_ACE_TYPE
                    | ACCESS_DENIED_CALLBACK_ACE_TYPE
                    | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            ) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsupported granting ACE",
            ));
        }
        let sid = (&ace.SidStart as *const u32).cast_mut().cast::<c_void>();
        // SAFETY: ACCESS_ALLOWED_ACE stores its SID inline at SidStart.
        let trusted = unsafe {
            EqualSid(sid, owner) != 0
                || EqualSid(sid, system.sid()) != 0
                || EqualSid(sid, administrators.sid()) != 0
        };
        if !trusted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "workspace DACL grants another principal access",
            ));
        }
    }
    Ok(())
}

struct TokenUserBuffer {
    _token: OwnedHandle,
    words: Vec<usize>,
}

impl TokenUserBuffer {
    fn sid(&self) -> PSID {
        // SAFETY: words contains a TOKEN_USER returned by GetTokenInformation.
        unsafe { (*(self.words.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

fn current_token_user() -> io::Result<TokenUserBuffer> {
    let mut token = 0;
    // SAFETY: token is a valid output pointer and current process is always live.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut bytes = 0;
    // SAFETY: this first call intentionally asks for the required byte count.
    let first = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut bytes) };
    if first != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(io::Error::last_os_error());
    }
    let word_size = size_of::<usize>();
    let mut words = vec![0usize; (bytes as usize + word_size - 1) / word_size];
    // SAFETY: the aligned buffer has the exact requested capacity.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            words.as_mut_ptr().cast::<c_void>(),
            (words.len() * word_size) as u32,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(TokenUserBuffer {
        _token: token,
        words,
    })
}

struct WellKnownSid {
    words: [usize; 10],
}

impl WellKnownSid {
    fn new(kind: i32) -> io::Result<Self> {
        let mut sid = Self { words: [0; 10] };
        let mut bytes = size_of::<[usize; 10]>() as u32;
        // SAFETY: the aligned fixed buffer is large enough for every well-known SID.
        if unsafe {
            CreateWellKnownSid(
                kind,
                null_mut(),
                sid.words.as_mut_ptr().cast::<c_void>(),
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(sid)
    }

    fn sid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }
}
