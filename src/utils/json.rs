use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(feature = "fast-json")]
use simd_json;

#[cfg(not(feature = "fast-json"))]
use serde_json;

pub fn from_str<'a, T>(s: &'a str) -> Result<T>
where
    T: Deserialize<'a>,
{
    #[cfg(feature = "fast-json")]
    {
        let mut bytes = s.as_bytes().to_vec();
        Ok(simd_json::from_slice(&mut bytes)?)
    }

    #[cfg(not(feature = "fast-json"))]
    {
        Ok(serde_json::from_str(s)?)
    }
}

#[allow(dead_code)]
pub fn from_slice<'a, T>(data: &'a mut [u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
    #[cfg(feature = "fast-json")]
    {
        Ok(simd_json::from_slice(data)?)
    }

    #[cfg(not(feature = "fast-json"))]
    {
        Ok(serde_json::from_slice(data)?)
    }
}

#[allow(dead_code)]
pub fn to_string<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    #[cfg(feature = "fast-json")]
    {
        Ok(simd_json::to_string(value)?)
    }

    #[cfg(not(feature = "fast-json"))]
    {
        Ok(serde_json::to_string(value)?)
    }
}

pub fn to_string_pretty<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    #[cfg(feature = "fast-json")]
    {
        Ok(simd_json::to_string_pretty(value)?)
    }

    #[cfg(not(feature = "fast-json"))]
    {
        Ok(serde_json::to_string_pretty(value)?)
    }
}

#[allow(dead_code)]
pub fn to_vec<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    #[cfg(feature = "fast-json")]
    {
        Ok(simd_json::to_vec(value)?)
    }

    #[cfg(not(feature = "fast-json"))]
    {
        Ok(serde_json::to_vec(value)?)
    }
}
