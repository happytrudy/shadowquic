use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Deserializer};

#[derive(Default)]
pub(super) struct Rules {
    entries: Vec<Rule>,
}

enum Rule {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadDocument {
    #[serde(deserialize_with = "deserialize_payload")]
    payload: Vec<String>,
}

fn deserialize_payload<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

impl Rules {
    pub(super) fn parse(content: &str) -> Result<Self, String> {
        let entries = match serde_saphyr::from_str::<PayloadDocument>(content) {
            Ok(document) => document.payload,
            Err(error) => return Err(error.to_string()),
        };

        let entries = entries
            .into_iter()
            .map(|entry| parse_payload_rule(&entry))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    pub(super) fn allows(&self, source: IpAddr) -> bool {
        let source = normalize_ip(source);
        self.entries.iter().any(|entry| entry.allows(source))
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

fn parse_payload_rule(entry: &str) -> Result<Rule, String> {
    let mut fields = entry.split(',').map(str::trim);
    let rule_type = fields.next().unwrap_or_default();
    let source = fields.next().unwrap_or_default();
    if !rule_type.eq_ignore_ascii_case("SRC-IP-CIDR")
        || source.is_empty()
        || fields.next().is_some()
    {
        return Err(format!(
            "invalid source whitelist payload entry; expected SRC-IP-CIDR,<CIDR>: {entry}"
        ));
    }
    parse_rule(source)
}

impl Rule {
    fn allows(&self, source: IpAddr) -> bool {
        match (self, source) {
            (Self::V4 { network, prefix }, IpAddr::V4(source)) => {
                u32::from(source) & v4_mask(*prefix) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(source)) => {
                u128::from(source) & v6_mask(*prefix) == *network
            }
            _ => false,
        }
    }
}

fn parse_rule(entry: &str) -> Result<Rule, String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err("source whitelist contains an empty entry".into());
    }

    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => {
            if prefix.contains('/') {
                return Err(format!("invalid source whitelist entry: {entry}"));
            }
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| format!("invalid CIDR prefix in source whitelist entry: {entry}"))?;
            (address, Some(prefix))
        }
        None => (entry, None),
    };
    let address = IpAddr::from_str(address)
        .map_err(|_| format!("invalid IP address in source whitelist entry: {entry}"))?;

    match address {
        IpAddr::V4(address) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return Err(format!("IPv4 prefix must be between 0 and 32: {entry}"));
            }
            Ok(Rule::V4 {
                network: u32::from(address) & v4_mask(prefix),
                prefix,
            })
        }
        IpAddr::V6(address) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return Err(format!("IPv6 prefix must be between 0 and 128: {entry}"));
            }
            if let Some(address) = address.to_ipv4_mapped()
                && prefix >= 96
            {
                let prefix = prefix - 96;
                return Ok(Rule::V4 {
                    network: u32::from(address) & v4_mask(prefix),
                    prefix,
                });
            }
            Ok(Rule::V6 {
                network: u128::from(address) & v6_mask(prefix),
                prefix,
            })
        }
    }
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_documents_deny_every_source() {
        let rules = Rules::parse("payload:\n").unwrap();
        assert!(!rules.allows("127.0.0.1".parse().unwrap()));
        assert!(!rules.allows("::1".parse().unwrap()));
    }

    #[test]
    fn exact_addresses_and_cidrs_are_supported() {
        let rules = Rules::parse(
            "payload:\n  - SRC-IP-CIDR,192.0.2.4/32\n  - SRC-IP-CIDR,10.20.0.0/16\n  - SRC-IP-CIDR,2001:db8::/32\n",
        )
        .unwrap();

        assert!(rules.allows("192.0.2.4".parse().unwrap()));
        assert!(rules.allows("10.20.99.1".parse().unwrap()));
        assert!(rules.allows("2001:db8:1::8".parse().unwrap()));
        assert!(!rules.allows("192.0.2.5".parse().unwrap()));
        assert!(!rules.allows("10.21.0.1".parse().unwrap()));
        assert!(!rules.allows("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_addresses_are_supported() {
        let rules = Rules::parse("payload:\n  - SRC-IP-CIDR,203.0.113.0/24\n").unwrap();

        assert!(rules.allows("203.0.113.9".parse().unwrap()));
        assert!(rules.allows("::ffff:203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn clash_payload_format_is_supported() {
        let rules = Rules::parse(
            "payload:\n  - \"SRC-IP-CIDR,2409:8a4c:d21:acf0:4288:5793:bf8a:1b47/128\"\n  - \"SRC-IP-CIDR,61.242.130.63/32\"\n",
        )
        .unwrap();

        assert!(rules.allows("2409:8a4c:d21:acf0:4288:5793:bf8a:1b47".parse().unwrap()));
        assert!(rules.allows("61.242.130.63".parse().unwrap()));
        assert!(!rules.allows("61.242.130.64".parse().unwrap()));
    }

    #[test]
    fn clash_payload_rejects_non_source_rules() {
        assert!(Rules::parse("payload:\n  - DST-IP-CIDR,192.0.2.1/32\n").is_err());
        assert!(Rules::parse("payload:\n  - SRC-IP-CIDR\n").is_err());
    }

    #[test]
    fn invalid_entry_rejects_the_whole_document() {
        assert!(Rules::parse("payload:\n  - SRC-IP-CIDR,127.0.0.1/32\n  - not-an-ip\n").is_err());
        assert!(Rules::parse("payload:\n  - SRC-IP-CIDR,10.0.0.0/33\n").is_err());
        assert!(Rules::parse("").is_err());
        assert!(Rules::parse("- SRC-IP-CIDR,127.0.0.1/32\n").is_err());
        assert!(Rules::parse("source-whitelist: []\n").is_err());
        assert!(Rules::parse("unknown-key: []\n").is_err());
    }
}
