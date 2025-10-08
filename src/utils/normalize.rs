#![allow(dead_code)]

use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;

static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,63}$")
        .expect("valid domain regex")
});

static USERNAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z0-9](?:[a-z0-9_\-.]{0,30}[a-z0-9])?$").expect("valid username regex")
});

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$").expect("valid email regex")
});

/// Normalise and validate a domain name, returning the lowercase ASCII form.
pub fn norm_domain(input: &str) -> Option<Cow<'_, str>> {
    let trimmed = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if DOMAIN_RE.is_match(&trimmed) {
        Some(Cow::Owned(trimmed))
    } else {
        None
    }
}

/// Normalise and validate an email address.
pub fn norm_email(input: &str) -> Option<Cow<'_, str>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_uppercase();
    if EMAIL_RE.is_match(&lower) {
        Some(Cow::Owned(trimmed.to_ascii_lowercase()))
    } else {
        None
    }
}

/// Normalise usernames to lowercase when they match the allowed pattern.
pub fn norm_username(input: &str) -> Option<Cow<'_, str>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if USERNAME_RE.is_match(&lowered) {
        Some(Cow::Owned(lowered))
    } else {
        None
    }
}

/// Validate whether the string is a well-formed IPv4 or IPv6 address.
pub fn is_valid_ip(input: &str) -> bool {
    IpAddr::from_str(input.trim()).is_ok()
}
