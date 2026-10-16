//! Одноразовые коды TOTP (RFC 6238). Секрет - base32, как в pyotp и приложениях-аутентификаторах,
//! или ссылка otpauth://totp/... с параметрами. По умолчанию SHA1, 6 цифр, 30 секунд.

use hmac::{EagerHash, Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::CoreError;
use crate::lang::{Lang, tr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
    algorithm: Algorithm,
}

/// Почему секрет TOTP не принят.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    NotBase32,
    EmptySecret,
    NoParameters,
    NotTotp,
    DigitsNotNumber,
    PeriodNotNumber,
    UnknownAlgorithm,
    NoSecret,
    OutOfRange,
}

impl TotpError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotBase32 => "not_base32",
            Self::EmptySecret => "empty_secret",
            Self::NoParameters => "no_parameters",
            Self::NotTotp => "not_totp",
            Self::DigitsNotNumber => "digits_not_number",
            Self::PeriodNotNumber => "period_not_number",
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::NoSecret => "no_secret",
            Self::OutOfRange => "out_of_range",
        }
    }

    pub fn message(&self, lang: Lang) -> String {
        match self {
            Self::NotBase32 => tr!(
                lang,
                "the secret must be base32: letters A-Z and digits 2-7",
                "секрет должен быть в base32: буквы A-Z и цифры 2-7"
            ),
            Self::EmptySecret => tr!(lang, "empty secret", "пустой секрет"),
            Self::NoParameters => tr!(
                lang,
                "the otpauth link has no parameters",
                "в ссылке otpauth нет параметров"
            ),
            Self::NotTotp => tr!(
                lang,
                "only otpauth://totp links are supported",
                "поддерживаются только ссылки otpauth://totp"
            ),
            Self::DigitsNotNumber => tr!(lang, "digits must be a number", "digits должен быть числом"),
            Self::PeriodNotNumber => tr!(lang, "period must be a number", "period должен быть числом"),
            Self::UnknownAlgorithm => tr!(
                lang,
                "algorithm: SHA1, SHA256 or SHA512",
                "algorithm: SHA1, SHA256 или SHA512"
            ),
            Self::NoSecret => tr!(lang, "the otpauth link has no secret", "в ссылке otpauth нет secret"),
            Self::OutOfRange => tr!(
                lang,
                "digits from 6 to 8, period from 1 to 300 seconds",
                "digits от 6 до 8, period от 1 до 300 секунд"
            ),
        }
    }
}

fn invalid(reason: TotpError) -> CoreError {
    CoreError::InvalidTotp(reason)
}

/// Base32 (RFC 4648) без учета регистра; пробелы, дефисы и выравнивание '=' пропускаются.
fn base32_decode(text: &str) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u64, 0u32);
    for c in text.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return Err(invalid(TotpError::NotBase32)),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err(invalid(TotpError::EmptySecret));
    }
    Ok(out)
}

impl Totp {
    /// Секрет base32 или ссылка otpauth://totp/метка?secret=...&digits=...&period=...&algorithm=...
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        let input = input.trim();
        let Some(rest) = input.strip_prefix("otpauth://") else {
            return Ok(Self {
                secret: base32_decode(input)?,
                digits: 6,
                period: 30,
                algorithm: Algorithm::Sha1,
            });
        };
        let (kind_and_label, query) = rest.split_once('?').ok_or(invalid(TotpError::NoParameters))?;
        if !kind_and_label.to_ascii_lowercase().starts_with("totp/") {
            return Err(invalid(TotpError::NotTotp));
        }
        let mut totp = Self {
            secret: Zeroizing::new(Vec::new()),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key.to_ascii_lowercase().as_str() {
                "secret" => totp.secret = base32_decode(value)?,
                "digits" => totp.digits = value.parse().map_err(|_| invalid(TotpError::DigitsNotNumber))?,
                "period" => totp.period = value.parse().map_err(|_| invalid(TotpError::PeriodNotNumber))?,
                "algorithm" => {
                    totp.algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(invalid(TotpError::UnknownAlgorithm)),
                    }
                }
                _ => {}
            }
        }
        if totp.secret.is_empty() {
            return Err(invalid(TotpError::NoSecret));
        }
        if !(6..=8).contains(&totp.digits) || !(1..=300).contains(&totp.period) {
            return Err(invalid(TotpError::OutOfRange));
        }
        Ok(totp)
    }

    pub fn period(&self) -> u64 {
        self.period
    }

    /// Код для момента now_ms (миллисекунды Unix).
    pub fn code(&self, now_ms: u64) -> String {
        let counter = (now_ms / 1000 / self.period).to_be_bytes();
        let mac: Vec<u8> = match self.algorithm {
            Algorithm::Sha1 => hmac::<Sha1>(&self.secret, &counter),
            Algorithm::Sha256 => hmac::<Sha256>(&self.secret, &counter),
            Algorithm::Sha512 => hmac::<Sha512>(&self.secret, &counter),
        };
        // динамическое усечение из RFC 4226
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes(mac[offset..offset + 4].try_into().expect("4 байта")) & 0x7fff_ffff;
        format!(
            "{:0width$}",
            binary % 10u32.pow(self.digits),
            width = self.digits as usize
        )
    }

    /// Секунд до смены кода.
    pub fn remaining(&self, now_ms: u64) -> u64 {
        self.period - (now_ms / 1000) % self.period
    }
}

fn hmac<D: EagerHash>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<D>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base32_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0u32);
        for &b in data {
            buffer = (buffer << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    // RFC 6238, приложение B
    #[test]
    fn rfc6238_vectors() {
        let secrets = [
            ("SHA1", b"12345678901234567890".to_vec()),
            ("SHA256", b"12345678901234567890123456789012".to_vec()),
            (
                "SHA512",
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            ),
        ];
        let vectors: [(u64, [&str; 3]); 6] = [
            (59, ["94287082", "46119246", "90693936"]),
            (1111111109, ["07081804", "68084774", "25091201"]),
            (1111111111, ["14050471", "67062674", "99943326"]),
            (1234567890, ["89005924", "91819424", "93441116"]),
            (2000000000, ["69279037", "90698825", "38618901"]),
            (20000000000, ["65353130", "77737706", "47863826"]),
        ];
        for (i, (alg, secret)) in secrets.iter().enumerate() {
            let uri = format!(
                "otpauth://totp/test?secret={}&digits=8&algorithm={alg}",
                base32_encode(secret)
            );
            let totp = Totp::parse(&uri).unwrap();
            for (time, codes) in &vectors {
                assert_eq!(totp.code(time * 1000), codes[i], "{alg} {time}");
            }
        }
    }

    #[test]
    fn plain_base32_secret_like_pyotp() {
        // pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(59) == "287082"
        let totp = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(totp.code(59_000), "287082");
        assert_eq!(totp.remaining(59_000), 1);
        assert_eq!(totp.remaining(60_000), 30);
    }

    #[test]
    fn invalid_input() {
        for (input, reason) in [
            ("", TotpError::EmptySecret),
            ("0189", TotpError::NotBase32),
            ("otpauth://totp/x", TotpError::NoParameters),
            ("otpauth://hotp/x?secret=GEZDGNBV", TotpError::NotTotp),
            (
                "otpauth://totp/x?secret=GEZDGNBV&digits=six",
                TotpError::DigitsNotNumber,
            ),
            ("otpauth://totp/x?secret=GEZDGNBV&period=", TotpError::PeriodNotNumber),
            (
                "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
                TotpError::UnknownAlgorithm,
            ),
            ("otpauth://totp/x?digits=6", TotpError::NoSecret),
            ("otpauth://totp/x?secret=GEZDGNBV&digits=4", TotpError::OutOfRange),
        ] {
            assert_eq!(
                Totp::parse(input).err(),
                Some(CoreError::InvalidTotp(reason)),
                "{input}"
            );
        }
    }
}
