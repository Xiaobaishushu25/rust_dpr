mod macros;

use once_cell::sync::OnceCell;
use rustdpr_core::TraceEvent;
use serde_json::to_writer;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static TRACE_WRITER: OnceCell<Mutex<BufWriter<File>>> = OnceCell::new();

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn thread_id_string() -> String {
    format!("{:?}", std::thread::current().id())
}

pub fn init_trace(path: &str) -> anyhow::Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    TRACE_WRITER.set(Mutex::new(writer)).ok();
    Ok(())
}

fn write_event(event: &TraceEvent) {
    if let Some(writer) = TRACE_WRITER.get() {
        if let Ok(mut guard) = writer.lock() {
            let _ = to_writer(&mut *guard, event);
            let _ = guard.write_all(b"\n");
            let _ = guard.flush();
        }
    }
}

pub fn enter_function(function: &'static str) {
    let event = TraceEvent::EnterFunction {
        function: function.to_string(),
        ts_millis: now_millis(),
        input_id: None,
        run_id: None,
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub fn exit_function(function: &'static str) {
    let event = TraceEvent::ExitFunction {
        function: function.to_string(),
        ts_millis: now_millis(),
        input_id: None,
        run_id: None,
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub fn hit(site_id: &'static str) {
    let event = TraceEvent::Hit {
        site_id: site_id.to_string(),
        ts_millis: now_millis(),
        input_id: None,
        run_id: None,
        thread_id: thread_id_string(),
    };
    write_event(&event);
}

pub fn oracle_marker(oracle: &str, detail: &str) {
    let event = TraceEvent::OracleMarker {
        oracle: oracle.to_string(),
        detail: detail.to_string(),
        ts_millis: now_millis(),
    };
    write_event(&event);
}

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location();
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            Some((*s).to_string())
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            Some(s.clone())
        } else {
            None
        };

        let event = TraceEvent::Panic {
            message,
            file: location.map(|l| l.file().to_string()),
            line: location.map(|l| l.line()),
            ts_millis: now_millis(),
            input_id: None,
            run_id: None,
            thread_id: thread_id_string(),
        };

        write_event(&event);
    }));
}