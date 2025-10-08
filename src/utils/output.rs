use console::Style;
use serde::Serialize;

use crate::utils::context::{self, OutputMode};

pub fn is_console() -> bool {
    matches!(
        context::AppContext::current().output_mode,
        OutputMode::Console
    )
}

pub fn is_structured() -> bool {
    !is_console()
}

pub fn is_quiet() -> bool {
    context::AppContext::current().quiet
}

#[allow(dead_code)]
pub fn println<S: AsRef<str>>(message: S) {
    if is_quiet() || !is_console() {
        return;
    }
    println!("{}", message.as_ref());
}

pub fn eprintln<S: AsRef<str>>(message: S) {
    if is_quiet() {
        return;
    }
    eprintln!("{}", message.as_ref());
}

#[allow(dead_code)]
pub fn apply_style(style: Style, text: &str) -> String {
    if context::AppContext::current().colors_enabled {
        style.apply_to(text).to_string()
    } else {
        text.to_string()
    }
}

pub fn emit_json<T: Serialize>(value: &T) -> serde_json::Result<()> {
    match crate::utils::context::AppContext::current().output_mode {
        OutputMode::Console => {
            let pretty = serde_json::to_string_pretty(value)?;
            println!("{}", pretty);
        }
        OutputMode::Json => {
            let pretty = serde_json::to_string_pretty(value)?;
            println!("{}", pretty);
        }
        OutputMode::NdJson => {
            let flat = serde_json::to_string(value)?;
            println!("{}", flat);
        }
    }
    Ok(())
}
