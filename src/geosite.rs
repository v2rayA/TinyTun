//! Minimal v2ray `geosite.dat` protobuf decoder.
//!
//! Understands the `GeoSiteList → GeoSite → Domain` message hierarchy
//! defined in the v2ray protobuf schema.  No external protobuf crate is
//! required — the wire format is small enough to decode by hand.
//!
//! Domain type semantics (mirrors `Domain.Type` in the v2ray proto):
//!
//! | Value | [`DomainType`] | Matching behaviour |
//! |-------|------------|----------------------|
//! | 0 | `Plain`  | sub-string (keyword) match |
//! | 1 | `Regex`  | full regex match against FQDN |
//! | 2 | `Domain` | suffix match (the domain itself **and** all sub-domains) |
//! | 3 | `Full`   | exact FQDN match |

use std::collections::HashMap;
use std::fs;

use anyhow::Result;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Discriminant matching v2ray's `Domain.Type` protobuf enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    Plain,  // 0 — keyword / sub-string
    Regex,  // 1 — regular expression
    Domain, // 2 — suffix match (domain + all sub-domains)
    Full,   // 3 — exact FQDN
}

impl DomainType {
    fn from_proto(n: u64) -> Self {
        match n {
            1 => Self::Regex,
            2 => Self::Domain,
            3 => Self::Full,
            _ => Self::Plain,
        }
    }
}

/// A single domain entry from a geosite category tag.
#[derive(Debug, Clone)]
pub struct GeositeDomain {
    pub typ: DomainType,
    /// Domain value in **lower-case**, exactly as stored in the .dat file.
    pub value: String,
}

/// Parsed geosite database.
///
/// Tags are stored **upper-case** (v2ray convention), so lookups are
/// case-insensitive via [`str::to_uppercase`].
pub struct GeositeDb {
    entries: HashMap<String, Vec<GeositeDomain>>,
}

impl GeositeDb {
    /// Read and parse a `geosite.dat` file from disk.
    pub fn load(path: &str) -> Result<Self> {
        let data = fs::read(path)
            .map_err(|e| anyhow::anyhow!("Cannot read geosite file '{}': {}", path, e))?;
        Self::parse(&data).ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to parse geosite file '{}': malformed protobuf data",
                path
            )
        })
    }

    /// Look up the domain list for a category tag.
    ///
    /// The lookup is **case-insensitive** — `"CN"`, `"cn"`, and `"Cn"` all
    /// resolve to the same entry.
    pub fn get_tag(&self, tag: &str) -> Option<&[GeositeDomain]> {
        self.entries.get(&tag.to_uppercase()).map(Vec::as_slice)
    }

    fn parse(data: &[u8]) -> Option<Self> {
        let mut entries = HashMap::new();
        let mut pos = 0;

        // GeoSiteList: repeated GeoSite entry = field 1 (wire type 2)
        while pos < data.len() {
            let tag_varint = decode_varint(data, &mut pos)?;
            let field = tag_varint >> 3;
            let wire_type = tag_varint & 0x07;

            if field == 1 && wire_type == 2 {
                let chunk = decode_len_bytes(data, &mut pos)?;
                if let Some((code, domains)) = parse_geosite(chunk) {
                    entries.insert(code, domains);
                }
            } else {
                skip_field(data, &mut pos, wire_type)?;
            }
        }

        Some(Self { entries })
    }
}

// ---------------------------------------------------------------------------
// Inner message parsers
// ---------------------------------------------------------------------------

/// Parse one `GeoSite` message.
/// Returns `(COUNTRY_CODE_UPPER, domains)` or `None` on malformed data.
fn parse_geosite(data: &[u8]) -> Option<(String, Vec<GeositeDomain>)> {
    let mut pos = 0;
    let mut country = String::new();
    let mut domains: Vec<GeositeDomain> = Vec::new();

    while pos < data.len() {
        let tag_varint = decode_varint(data, &mut pos)?;
        let field = tag_varint >> 3;
        let wire_type = tag_varint & 0x07;

        match (field, wire_type) {
            (1, 2) => {
                // country_code: string
                let b = decode_len_bytes(data, &mut pos)?;
                country = String::from_utf8_lossy(b).to_uppercase();
            }
            (2, 2) => {
                // domain: Domain message
                let b = decode_len_bytes(data, &mut pos)?;
                if let Some(d) = parse_domain(b) {
                    domains.push(d);
                }
            }
            _ => {
                skip_field(data, &mut pos, wire_type)?;
            }
        }
    }

    if country.is_empty() {
        None
    } else {
        Some((country, domains))
    }
}

/// Parse one `Domain` message inside a `GeoSite`.
fn parse_domain(data: &[u8]) -> Option<GeositeDomain> {
    let mut pos = 0;
    let mut typ_int: u64 = 0;
    let mut value = String::new();

    while pos < data.len() {
        let tag_varint = decode_varint(data, &mut pos)?;
        let field = tag_varint >> 3;
        let wire_type = tag_varint & 0x07;

        match (field, wire_type) {
            (1, 0) => {
                typ_int = decode_varint(data, &mut pos)?;
            }
            (2, 2) => {
                let b = decode_len_bytes(data, &mut pos)?;
                value = String::from_utf8_lossy(b).to_lowercase();
            }
            _ => {
                skip_field(data, &mut pos, wire_type)?;
            }
        }
    }

    if value.is_empty() {
        None
    } else {
        Some(GeositeDomain {
            typ: DomainType::from_proto(typ_int),
            value,
        })
    }
}

// ---------------------------------------------------------------------------
// Protobuf wire-format primitives
// ---------------------------------------------------------------------------

/// Decode a base-128 varint from `buf` starting at `*pos`, advancing `*pos`.
fn decode_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return None;
        }
        let byte = buf[*pos];
        *pos += 1;
        val |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
        if shift >= 64 {
            return None; // overflow — malformed data
        }
    }
}

/// Decode a `LEN`-prefixed byte slice (wire type 2), advancing `*pos`.
fn decode_len_bytes<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = decode_varint(buf, pos)? as usize;
    if *pos + len > buf.len() {
        return None;
    }
    let slice = &buf[*pos..*pos + len];
    *pos += len;
    Some(slice)
}

/// Skip over one field value of the given wire type, advancing `*pos`.
fn skip_field(buf: &[u8], pos: &mut usize, wire_type: u64) -> Option<()> {
    match wire_type {
        0 => {
            decode_varint(buf, pos)?;
        }
        1 => {
            // 64-bit fixed
            *pos = pos.checked_add(8)?;
            if *pos > buf.len() {
                return None;
            }
        }
        2 => {
            decode_len_bytes(buf, pos)?;
        }
        5 => {
            // 32-bit fixed
            *pos = pos.checked_add(4)?;
            if *pos > buf.len() {
                return None;
            }
        }
        _ => return None, // unknown wire type — treat as malformed
    }
    Some(())
}
