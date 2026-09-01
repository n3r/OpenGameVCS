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
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, PSID,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, CreateWellKnownSid, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
    InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileDispositionInfo, FileRenameInfo, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, CREATE_NEW,
    DELETE, FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
    FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    READ_CONTROL, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    SECURITY_DESCRIPTOR_REVISION,
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

pub fn create_new_private_directory(path: &Path) -> io::Result<()> {
    let wide = wide_path(path)?;
    with_private_security_attributes(true, |attributes| {
        // SAFETY: the path and complete absolute security descriptor remain
        // live throughout this atomic directory creation call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), attributes) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?;
    let directory = open_reparse_handle_with_access_and_share(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    validate_kind(&directory, true)?;
    validate_owner_and_dacl(directory.as_raw_handle() as HANDLE, true)
}

pub fn create_new_private_file(path: &Path) -> io::Result<File> {
    create_new_regular_file(path)
}

pub fn open_or_create_private_lock(path: &Path) -> io::Result<File> {
    match create_new_regular_file(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let file = open_reparse_handle_with_access_and_share(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL | GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            validate_kind(&file, false)?;
            validate_owner_and_dacl(file.as_raw_handle() as HANDLE, true)?;
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

fn open_reparse_handle(path: &Path) -> io::Result<File> {
    open_reparse_handle_with_access(path, FILE_READ_ATTRIBUTES | READ_CONTROL | GENERIC_READ)
}

fn open_reparse_handle_with_access(path: &Path, access: u32) -> io::Result<File> {
    open_reparse_handle_with_access_and_share(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

fn open_reparse_handle_with_access_and_share(
    path: &Path,
    access: u32,
    share: u32,
) -> io::Result<File> {
    let wide = wide_path(path)?;
    // SAFETY: the UTF-16 path is terminated, all pointer arguments are valid,
    // and the returned handle is either rejected or transferred into File.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
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

fn create_new_regular_file(path: &Path) -> io::Result<File> {
    let wide = wide_path(path)?;
    with_private_security_attributes(false, |attributes| {
        // SAFETY: the UTF-16 path and complete absolute security descriptor
        // remain live; CREATE_NEW makes file publication atomic.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedHandle(handle);
        // SAFETY: ownership is transferred from OwnedHandle into File once.
        let file = unsafe { File::from_raw_handle(owned.0 as _) };
        std::mem::forget(owned);
        if let Err(error) = validate_kind(&file, false)
            .and_then(|_| validate_owner_and_dacl(file.as_raw_handle() as HANDLE, true))
        {
            let _ = delete_exact_on_close(&file);
            return Err(error);
        }
        Ok(file)
    })
}

fn delete_exact_on_close(file: &File) -> io::Result<()> {
    let mut disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: the live handle was opened with DELETE access and disposition is
    // the exact API structure; deletion is bound to this object, not a path.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            (&mut disposition as *mut FILE_DISPOSITION_INFO).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.iter().any(|unit| *unit == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    wide.push(0);
    Ok(wide)
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
        .checked_add(std::mem::size_of_val(destination_name))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer overflow"))?;
    let word = size_of::<usize>();
    let mut storage = vec![0usize; (byte_len + word - 1) / word];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the aligned buffer is large enough for the fixed header and the
    // exact un-terminated UTF-16 destination name.
    unsafe {
        (*information).Anonymous = FILE_RENAME_INFO_0 { ReplaceIfExists: 0 };
        (*information).RootDirectory = destination_parent.as_raw_handle() as HANDLE;
        (*information).FileNameLength = std::mem::size_of_val(destination_name) as u32;
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

fn with_private_security_attributes<T>(
    directory: bool,
    action: impl FnOnce(*const SECURITY_ATTRIBUTES) -> io::Result<T>,
) -> io::Result<T> {
    let token_user = current_token_user()?;
    let system = WellKnownSid::new(WinLocalSystemSid)?;
    let administrators = WellKnownSid::new(WinBuiltinAdministratorsSid)?;
    let mut acl_storage = private_acl(
        token_user.sid(),
        system.sid(),
        administrators.sid(),
        directory,
    )?;
    let dacl = acl_storage.as_mut_ptr().cast::<ACL>();
    // SAFETY: SECURITY_DESCRIPTOR is a plain Windows structure initialized by
    // the API before its setter functions are called.
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    let descriptor_pointer = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>();
    // SAFETY: descriptor, owner SID, and ACL storage all remain live until the
    // creation callback returns and Windows copies the descriptor.
    if unsafe { InitializeSecurityDescriptor(descriptor_pointer, SECURITY_DESCRIPTOR_REVISION) }
        == 0
        || unsafe { SetSecurityDescriptorOwner(descriptor_pointer, token_user.sid(), 0) } == 0
        || unsafe { SetSecurityDescriptorDacl(descriptor_pointer, 1, dacl, 0) } == 0
        || unsafe {
            SetSecurityDescriptorControl(descriptor_pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_pointer,
        bInheritHandle: 0,
    };
    action(&attributes)
}

fn private_acl(
    token_user: PSID,
    system: PSID,
    administrators: PSID,
    directory: bool,
) -> io::Result<Vec<usize>> {
    let sids = [token_user, system, administrators];
    let ace_prefix = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
    let mut byte_len = size_of::<ACL>();
    for sid in sids {
        // SAFETY: every SID is backed by a live token or well-known SID buffer.
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        if sid_len == 0 {
            return Err(io::Error::last_os_error());
        }
        byte_len = byte_len
            .checked_add(ace_prefix)
            .and_then(|length| length.checked_add(sid_len))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ACL size overflow"))?;
    }
    let word = size_of::<usize>();
    let mut storage = vec![0usize; (byte_len + word - 1) / word];
    let acl = storage.as_mut_ptr().cast::<ACL>();
    // SAFETY: storage is aligned and contains at least byte_len writable bytes.
    if unsafe { InitializeAcl(acl, byte_len as u32, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    for sid in sids {
        // SAFETY: acl is initialized with capacity for all three exact ACEs,
        // and each SID remains live until SetSecurityInfo completes.
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FILE_ALL_ACCESS, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(storage)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn private_creation_is_protected_and_pinned_against_path_replacement() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ogvcs011-windows-private-create-{}-{nonce}",
            std::process::id()
        ));
        create_new_private_directory(&root).unwrap();
        open_private_directory(&root).unwrap();

        let path = root.join("metadata");
        let detached = root.join("detached");
        let file = create_new_private_file(&path).unwrap();
        assert!(fs::rename(&path, &detached).is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(file);
        fs::remove_file(&path).unwrap();

        let exact = root.join("exact-cleanup");
        let file = create_new_private_file(&exact).unwrap();
        delete_exact_on_close(&file).unwrap();
        drop(file);
        assert!(!exact.exists());

        let exact_directory = root.join("exact-directory-cleanup");
        create_new_private_directory(&exact_directory).unwrap();
        let directory = open_reparse_handle_with_access_and_share(
            &exact_directory,
            FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
        .unwrap();
        delete_exact_on_close(&directory).unwrap();
        drop(directory);
        assert!(!exact_directory.exists());

        let lock_path = root.join("mutation.lock");
        drop(create_new_private_file(&lock_path).unwrap());
        let lock = open_or_create_private_lock(&lock_path).unwrap();
        assert!(fs::rename(&lock_path, &detached).is_err());
        assert!(fs::remove_file(&lock_path).is_err());
        drop(lock);
        fs::remove_file(&lock_path).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
