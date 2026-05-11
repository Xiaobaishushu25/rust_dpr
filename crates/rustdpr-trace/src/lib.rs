pub mod macros;

use once_cell::sync::OnceCell;
use rustdpr_core::model::TraceEvent;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static TRACE_FILE: OnceCell<Mutex<File>> = OnceCell::new();
static PANIC_HOOK_INSTALLED: OnceCell<()> = OnceCell::new();

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

pub fn init_trace(path: PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    let _ = TRACE_FILE.set(Mutex::new(file));
    Ok(())
}

fn write_event(event: &TraceEvent) {
    if let Some(m) = TRACE_FILE.get() {
        if let Ok(mut f) = m.lock() {
            let line = serde_json::to_string(event).unwrap();
            let _ = writeln!(f, "{line}");
        }
    }
}

pub fn hit(site_id: &str) {
    write_event(&TraceEvent::Hit {
        site_id: site_id.to_string(),
        ts_millis: now_millis(),
    });
}

pub fn install_panic_hook() {
    if PANIC_HOOK_INSTALLED.get().is_some() {
        return;
    }

    std::panic::set_hook(Box::new(|info| {
        let location = info.location();
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            Some((*s).to_string())
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            Some(s.clone())
        } else {
            None
        };

        write_event(&TraceEvent::Panic {
            message,
            file: location.map(|l| l.file().to_string()),
            line: location.map(|l| l.line()),
            ts_millis: now_millis(),
        });
    }));

    let _ = PANIC_HOOK_INSTALLED.set(());
}