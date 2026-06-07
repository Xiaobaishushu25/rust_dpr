mod macros;

use anyhow::Result;
use once_cell::sync::OnceCell;
use rustdpr_core::TraceEvent;
use serde_json::to_writer;
use std::env;
use std::fs::{File, create_dir_all};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static TRACE_WRITER: OnceCell<Mutex<BufWriter<File>>> = OnceCell::new();
static TRACE_RUN_ID: OnceCell<String> = OnceCell::new();
static TRACE_INPUT_ID: OnceCell<String> = OnceCell::new();
static PANIC_HOOK_INSTALLED: OnceCell<()> = OnceCell::new();

fn trace_disabled() -> bool {
    std::env::var("RUSTDPR_DISABLE_TRACE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn thread_id_string() -> String {
    format!("{:?}", std::thread::current().id())
}

fn current_run_id() -> Option<String> {
    TRACE_RUN_ID.get().cloned()
}

fn current_input_id() -> Option<String> {
    TRACE_INPUT_ID.get().cloned()
}

pub fn set_run_id(run_id: &str) {
    if trace_disabled() {
        return;
    }
    let _ = TRACE_RUN_ID.set(run_id.to_string());
}

pub fn set_input_id(input_id: &str) {
    if trace_disabled() {
        return;
    }
    let _ = TRACE_INPUT_ID.set(input_id.to_string());
}

pub fn init_trace(path: &str) -> Result<()> {
    // Miri does not support many OS/file-system calls on all platforms
    // (for example CreateDirectoryW on Windows). Oracle runs only need the
    // target UB check, not trace I/O, so run_miri.py sets this variable.
    if trace_disabled() {
        return Ok(());
    }

    // In fuzzing mode the target may call init_trace once per input.  Re-opening
    // the same file would truncate the trace while the original writer is still
    // alive, so initialization must be idempotent.
    if TRACE_WRITER.get().is_some() {
        return Ok(());
    }

    if let Ok(run_id) = env::var("RUSTDPR_RUN_ID") {
        if !run_id.trim().is_empty() {
            let _ = TRACE_RUN_ID.set(run_id);
        }
    }
    if let Ok(input_id) = env::var("RUSTDPR_INPUT_ID") {
        if !input_id.trim().is_empty() {
            let _ = TRACE_INPUT_ID.set(input_id);
        }
    }

    let trace_path = env::var("RUSTDPR_TRACE_PATH").unwrap_or_else(|_| path.to_string());
    let path = Path::new(&trace_path);
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    let _ = TRACE_WRITER.set(Mutex::new(writer));

    Ok(())
}

pub fn flush_trace() {
    if trace_disabled() {
        return;
    }

    if let Some(writer) = TRACE_WRITER.get() {
        if let Ok(mut guard) = writer.lock() {
            let _ = guard.flush();
        }
    }
}

fn write_event(event: &TraceEvent) {
    if trace_disabled() {
        return;
    }

    if let Some(writer) = TRACE_WRITER.get() {
        if let Ok(mut guard) = writer.lock() {
            let _ = to_writer(&mut *guard, event);
            let _ = guard.write_all(b"\n");
            let _ = guard.flush();
        }
    }
}

pub fn enter_function(function: &'static str) {
    if trace_disabled() {
        return;
    }

    let event = TraceEvent::EnterFunction {
        function: function.to_string(),
        ts_millis: now_millis(),
        input_id: current_input_id(),
        run_id: current_run_id(),
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub fn exit_function(function: &'static str) {
    if trace_disabled() {
        return;
    }

    let event = TraceEvent::ExitFunction {
        function: function.to_string(),
        ts_millis: now_millis(),
        input_id: current_input_id(),
        run_id: current_run_id(),
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub struct FunctionTraceGuard {
    function: &'static str,
}

impl FunctionTraceGuard {
    pub fn new(function: &'static str) -> Self {
        Self { function }
    }
}

impl Drop for FunctionTraceGuard {
    fn drop(&mut self) {
        exit_function(self.function);
    }
}

pub fn hit(site_id: &'static str) {
    if trace_disabled() {
        return;
    }

    let event = TraceEvent::Hit {
        site_id: site_id.to_string(),
        ts_millis: now_millis(),
        input_id: current_input_id(),
        run_id: current_run_id(),
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub fn oracle_marker(oracle: &str, detail: &str) {
    if trace_disabled() {
        return;
    }

    let event = TraceEvent::OracleMarker {
        oracle: oracle.to_string(),
        detail: detail.to_string(),
        ts_millis: now_millis(),
        input_id: current_input_id(),
        run_id: current_run_id(),
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub fn install_panic_hook() {
    if trace_disabled() {
        return;
    }

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
            Some("non-string panic payload".to_string())
        };

        let event = TraceEvent::Panic {
            message,
            file: location.map(|l| l.file().to_string()),
            line: location.map(|l| l.line()),
            ts_millis: now_millis(),
            input_id: current_input_id(),
            run_id: current_run_id(),
            thread_id: thread_id_string(),
        };

        write_event(&event);
    }));

    let _ = PANIC_HOOK_INSTALLED.set(());
}
