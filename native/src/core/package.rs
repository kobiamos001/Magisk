use crate::consts::{APP_PACKAGE_NAME, MAGISK_VER_CODE};
use crate::daemon::{AID_APP_END, AID_APP_START, AID_USER_OFFSET, MagiskD, to_app_id};
use crate::ffi::{DbEntryKey, get_magisk_tmp, install_apk, uninstall_pkg};
use base::WalkResult::{Abort, Continue, Skip};
use base::{
    BufReadExt, Directory, FsPathBuilder, LoggedResult, ReadExt, ResultExt, Utf8CStrBuf,
    Utf8CString, cstr, error, fd_get_attr, warn,
};
use bit_set::BitSet;
use nix::fcntl::OFlag;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::time::Duration;

const EOCD_MAGIC: u32 = 0x06054B50;
const APK_SIGNING_BLOCK_MAGIC: [u8; 16] = *b"APK Sig Block 42";
const SIGNATURE_SCHEME_V2_MAGIC: u32 = 0x7109871A;
const PACKAGES_XML: &str = "/data/system/packages.xml";

macro_rules! bad_apk {
    ($msg:literal) => {
        io::Error::new(io::ErrorKind::InvalidData, concat!("cert: ", $msg))
    };
}

fn read_certificate(apk: &mut File, version: i32) -> Vec<u8> {
    let res = || -> io::Result<Vec<u8>> {
        let mut u32_val = 0u32;
        let mut u64_val = 0u64;

        for i in 0u16.. {
            let mut comment_sz = 0u16;
            apk.seek(SeekFrom::End(-(size_of_val(&comment_sz) as i64) - i as i64))?;
            apk.read_pod(&mut comment_sz)?;

            if comment_sz == i {
                apk.seek(SeekFrom::Current(-22))?;
                let mut magic = 0u32;
                apk.read_pod(&mut magic)?;
                if magic == EOCD_MAGIC {
                    break;
                }
            }
            if i == 0xffff {
                Err(bad_apk!("invalid APK format"))?;
            }
        }

        let mut central_dir_off = 0u32;
        apk.seek(SeekFrom::Current(12))?;
        apk.read_pod(&mut central_dir_off)?;

        if version >= 0 {
            let mut comment_sz = 0u16;
            apk.read_pod(&mut comment_sz)?;
            let mut comment = vec![0u8; comment_sz as usize];
            apk.read_exact(&mut comment)?;
            let mut comment = Cursor::new(&comment);
            let mut apk_ver = 0;
            comment.for_each_prop(|k, v| {
                if k == "versionCode" {
                    apk_ver = v.parse::<i32>().unwrap_or(0);
                    false
                } else {
                    true
                }
            });
            if version > apk_ver {
                Err(bad_apk!("APK version too low"))?;
            }
        }

        apk.seek(SeekFrom::Start((central_dir_off - 24) as u64))?;
        apk.read_pod(&mut u64_val)?;
        let mut magic = [0u8; 16];
        apk.read_exact(&mut magic)?;
        if magic != APK_SIGNING_BLOCK_MAGIC {
            Err(bad_apk!("invalid signing block magic"))?;
        }
        let mut signing_blk_sz = 0u64;
        apk.seek(SeekFrom::Current(
            -(u64_val as i64) - (size_of_val(&signing_blk_sz) as i64),
        ))?;
        apk.read_pod(&mut signing_blk_sz)?;
        if signing_blk_sz != u64_val {
            Err(bad_apk!("invalid signing block size"))?;
        }

        loop {
            apk.read_pod(&mut u64_val)?;
            if u64_val == signing_blk_sz {
                Err(bad_apk!("cannot find certificate"))?;
            }

            let mut id = 0u32;
            apk.read_pod(&mut id)?;
            if id == SIGNATURE_SCHEME_V2_MAGIC {
                apk.seek(SeekFrom::Current((size_of_val(&u32_val) * 3) as i64))?;
                apk.read_pod(&mut u32_val)?;
                apk.seek(SeekFrom::Current(u32_val as i64))?;
                apk.seek(SeekFrom::Current(size_of_val(&u32_val) as i64))?;
                apk.read_pod(&mut u32_val)?;
                let mut cert = vec![0; u32_val as usize];
                apk.read_exact(cert.as_mut())?;
                break Ok(cert);
            } else {
                apk.seek(SeekFrom::Current(
                    u64_val as i64 - (size_of_val(&id) as i64),
                ))?;
            }
        }
    }();
    res.log().unwrap_or(vec![])
}

fn find_apk_path(_pkg: &str) -> LoggedResult<Utf8CString> {
    Ok(Utf8CString::default())
}

enum Status {
    NotInstalled,
}

pub struct ManagerInfo {
    stub_apk_fd: Option<File>,
    trusted_cert: Vec<u8>,
    repackaged_app_id: i32,
    repackaged_pkg: String,
    repackaged_cert: Vec<u8>,
    tracked_files: BTreeMap<i32, TrackedFile>,
}

impl Default for ManagerInfo {
    fn default() -> Self {
        ManagerInfo {
            stub_apk_fd: None,
            trusted_cert: Vec::new(),
            repackaged_app_id: -1,
            repackaged_pkg: String::new(),
            repackaged_cert: Vec::new(),
            tracked_files: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct TrackedFile {
    path: Utf8CString,
    timestamp: Duration,
}

impl TrackedFile {
    fn is_same(&self) -> bool {
        false
    }
}

impl ManagerInfo {
    fn install_stub(&mut self) {
        // בוטל: לא מתקין את האפליקציה לעולם
    }

    fn get_manager(&mut self, _daemon: &MagiskD, _user: i32, _install: bool) -> (i32, &str) {
        // בוטל: תמיד מחזיר שלא נמצאה אפליקציה כדי למנוע התקנה
        (-1, "")
    }
}

impl MagiskD {
    fn get_package_uid(&self, _user: i32, _pkg: &str) -> i32 {
        -1
    }

    pub fn preserve_stub_apk(&self) {
        // מוחק את ה-APK הזמני ולא שומר אותו בזיכרון
        let apk = cstr::buf::default()
            .join_path(get_magisk_tmp())
            .join_path("stub.apk");
        apk.remove().log_ok();
    }

    pub fn get_manager_uid(&self, _user: i32) -> i32 {
        -1
    }

    pub fn get_manager(&self, _user: i32, _install: bool) -> (i32, String) {
        (-1, String::new())
    }

    pub fn ensure_manager(&self) {
        // בוטל: פונקציית הבדיקה ב-Boot לא עושה כלום
    }

    pub fn get_app_no_list(&self) -> BitSet {
        let mut list = BitSet::new();
        let _ = || -> LoggedResult<()> {
            let mut app_data_dir = Directory::open(self.app_data_dir())?;
            loop {
                let entry = match app_data_dir.read()? {
                    None => break,
                    Some(e) => e,
                };
                let mut user_dir = match entry.open_as_dir() {
                    Err(_) => continue,
                    Ok(dir) => dir,
                };
                loop {
                    match user_dir.read()? {
                        None => break,
                        Some(e) => {
                            let mut entry_path = cstr::buf::default();
                            e.resolve_path(&mut entry_path)?;
                            let attr = entry_path.get_attr()?;
                            let app_id = to_app_id(attr.st.st_uid as i32);
                            if (AID_APP_START..=AID_APP_END).contains(&app_id) {
                                let app_no = app_id - AID_APP_START;
                                list.insert(app_no as usize);
                            }
                        }
                    }
                }
            }
            Ok(())
        }();
        list
    }
}
