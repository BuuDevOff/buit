#![allow(dead_code)]

use console::{style, Style};
use serde::Serialize;

use crate::types::ApiEnvelope;
use crate::utils::{context::AppContext, output};

/// Central helper to print structured envelopes respecting the current output mode.
pub fn emit_envelope<T>(envelope: &ApiEnvelope<T>) -> anyhow::Result<()>
where
    T: Serialize,
{
    output::emit_json(envelope)?;
    Ok(())
}

/// Print a headline in console mode, respecting quiet/structured flags.
pub fn heading<S: AsRef<str>>(message: S) {
    if !output::is_console() || output::is_quiet() {
        return;
    }
    println!("{}", style(message.as_ref()).bold());
}

/// Print a bullet with an optional style; respects quiet mode.
pub fn bullet<S: AsRef<str>>(message: S, bullet_style: Option<Style>) {
    if output::is_quiet() {
        return;
    }

    if let Some(style) = bullet_style {
        println!("{} {}", style.apply_to("•"), message.as_ref());
    } else {
        println!("• {}", message.as_ref());
    }
}

/// Emit a warning message to stderr when in console mode.
pub fn warn<S: AsRef<str>>(message: S) {
    if output::is_quiet() {
        return;
    }
    eprintln!("{} {}", style("⚠").yellow(), message.as_ref());
}

/// Apply the global color preference when styling text.
pub fn maybe_style(style: Style, text: &str) -> String {
    if AppContext::current().colors_enabled {
        style.apply_to(text).to_string()
    } else {
        text.to_string()
    }
}
