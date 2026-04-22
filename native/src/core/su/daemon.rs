use supe00r::connect::SuAppContext;
use super::db::RootSettings;
use crate::daemon::{AID_ROOT, AID_SHELL, MagiskD, to_app_id};
use crate::db::{DbSettings, MultiuserMode, RootAccess};
use crate::ffi::{SuPolicy, SuRequest, exec_root_shell};
use crate::socket::IpcRead;
use base::{LoggedResult, ResultExt, WriteExt, debug, error, exit_on_error, libc, warn};
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UCred, UnixStream};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::fs::{File, read_to_string};
use std::io::{self, BufRead};
use std::path::Path;

static AUTH_CACHE: Mutex<Option<HashMap<i32, bool>>> = Mutex::new(None);
static WHITELIST_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

const WHITELIST_FILE: &str = "/system/etc/custom_su.txt";
const PACKAGES_LIST: &str = "/data/system/packages.list";

impl Default for SuRequest {
    fn default() -> Self {
        SuRequest {
            target_uid: AID_ROOT, target_pid: -1, login: false, keep_env: false,
            drop_cap: false, shell: "/system/bin/sh".to_string(), command: "".to_string(),
            context: "".to_string(), gids: vec![],
        }
    }
}

fn get_package_by_uid(uid: i32) -> String {
    let app_id = uid % 100000;
    if let Ok(file) = File::open(PACKAGES_LIST) {
        let reader = io::BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(line_uid) = parts[1].parse::<i32>() {
                    if line_uid == app_id {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    if uid == 2000 { return "com.android.shell".to_string(); }
    String::new()
}

impl MagiskD {
    pub fn su_daemon_handler(&self, mut client: UnixStream, cred: UCred) {
        let uid = cred.uid as i32;

        if Path::new(WHITELIST_FILE).exists() {
            if uid == AID_ROOT {
                self.grant_root(client, cred);
                return;
            }

            let is_allowed = {
                let mut cache_lock = AUTH_CACHE.lock().unwrap();
                let cache = cache_lock.get_or_insert_with(HashMap::new);
                
                if let Some(&allowed) = cache.get(&uid) {
                    allowed
                } else {
                    let pkg_name = get_package_by_uid(uid);
                    let mut wl_lock = WHITELIST_CACHE.lock().unwrap();
                    let whitelist = wl_lock.get_or_insert_with(|| {
                        read_to_string(WHITELIST_FILE).unwrap_or_default()
                            .lines().map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()).collect()
                    });

                    let allowed = !pkg_name.is_empty() && whitelist.contains(&pkg_name);
                    cache.insert(uid, allowed);
                    allowed
                }
            };

            if is_allowed {
                self.grant_root(client, cred);
            } else {
                client.write_pod(&SuPolicy::Deny.repr).ok();
            }
        } else {
            self.grant_root(client, cred);
        }
    }

    fn grant_root(&self, mut client: UnixStream, cred: UCred) {
        let mut req = match client.read_decodable::<SuRequest>().log() {
            Ok(req) => req,
            Err(_) => return,
        };
        let child = unsafe { libc::fork() };
        if child == 0 {
            exit_on_error(true);
            client.write_pod(&0).ok();
            exec_root_shell(client.into_raw_fd(), cred.pid.unwrap_or(-1), &mut req, DbSettings::default().mnt_ns);
            return;
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0); }
        let code = unsafe { libc::WEXITSTATUS(status) };
        client.write_pod(&code).ok();
    }

    fn get_su_info(&self, uid: i32) -> Arc<SuInfo> { Arc::new(SuInfo::allow(uid)) }
    fn build_su_info(&self, uid: i32) -> Arc<SuInfo> { Arc::new(SuInfo::allow(uid)) }
}

pub struct SuInfo {
    pub uid: i32, pub eval_uid: i32, pub mgr_pkg: String, pub mgr_uid: i32,
    pub cfg: DbSettings, pub access: Mutex<AccessInfo>,
}
pub struct AccessInfo { pub settings: RootSettings }
impl Default for SuInfo { fn default() -> Self { SuInfo::allow(-1) } }
impl SuInfo {
    fn allow(uid: i32) -> SuInfo {
        SuInfo {
            uid, eval_uid: uid, mgr_pkg: String::new(), mgr_uid: -1,
            cfg: DbSettings::default(),
            access: Mutex::new(AccessInfo { 
                settings: RootSettings { policy: SuPolicy::Allow, log: false, notify: false } 
            }),
        }
    }
}
