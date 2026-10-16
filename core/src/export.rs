//! Зашифрованный экспорт хранилища в файл. Внутри - JSON всех записей в формате записи v1 с метками
//! HLC, поэтому импорт - то же слияние, что при синхронизации. Ключей и учетной записи в файле нет:
//! он открывается только паролем экспорта, отдельным или мастер-паролем.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::Kdf;
use crate::lang::{Lang, tr};
use crate::record::Record;
use crate::{CoreError, KdfParams, Key, derive_export_key, derive_master_key, generate_salt, open_sealed, seal_random};

pub const EXPORT_FORMAT: u32 = 1;
const FORMAT_NAME: &str = "inkvault-export";
const DOMAIN_EXPORT: &[u8] = b"inkvault:export";

/// Файл экспорта: открытый заголовок и шифротекст. Заголовок входит в AAD, поэтому параметры
/// KDF в файле нельзя подменить незаметно.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    v: u32,
    kdf: Kdf,
    /// Зашифрованный `Payload` в base64.
    data: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    vault_id: String,
    exported_at: u64,
    records: Vec<ExportedRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportedRecord {
    id: String,
    record: serde_json::Value,
}

/// Записи из файла экспорта.
pub struct Imported {
    pub vault_id: String,
    pub exported_at: u64,
    pub records: Vec<(String, Record)>,
    /// Записи, которые не прочитались: формат новее клиента или неверный id.
    pub skipped: u32,
}

impl Imported {
    pub fn ids(&self) -> BTreeSet<&str> {
        self.records.iter().map(|(id, _)| id.as_str()).collect()
    }
}

/// Почему файл не открылся как экспорт InkVault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    NotJson,
    UnknownFormat,
    UnsupportedVersion(u32),
    NotBase64,
    Corrupted,
    /// Расшифрованные данные не разобрались, в поле - текст ошибки JSON.
    InvalidPayload(String),
}

impl ExportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotJson => "not_json",
            Self::UnknownFormat => "unknown_format",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::NotBase64 => "not_base64",
            Self::Corrupted => "corrupted",
            Self::InvalidPayload(_) => "invalid_payload",
        }
    }

    pub fn message(&self, lang: Lang) -> String {
        match self {
            Self::NotJson => tr!(
                lang,
                "expected JSON with the fields format, v, kdf, data",
                "ожидается JSON с полями format, v, kdf, data"
            ),
            Self::UnknownFormat => tr!(lang, "unknown format", "неизвестный формат"),
            Self::UnsupportedVersion(v) => tr!(
                lang,
                "version {} is not supported, a newer client is required",
                "версия {} не поддерживается, нужен более новый клиент",
                v
            ),
            Self::NotBase64 => tr!(lang, "the data is not base64", "данные не в base64"),
            Self::Corrupted => tr!(lang, "the data is damaged", "данные повреждены"),
            Self::InvalidPayload(detail) => detail.clone(),
        }
    }
}

fn invalid(reason: ExportError) -> CoreError {
    CoreError::InvalidExport(reason)
}

fn aad_fields(kdf: &Kdf) -> [Vec<u8>; 6] {
    [
        EXPORT_FORMAT.to_be_bytes().to_vec(),
        kdf.alg.as_bytes().to_vec(),
        kdf.m.to_be_bytes().to_vec(),
        kdf.t.to_be_bytes().to_vec(),
        kdf.p.to_be_bytes().to_vec(),
        kdf.salt.as_bytes().to_vec(),
    ]
}

// границы параметров проверяются до Argon2id: файл не должен заставить устройство выделить гигабайты памяти
fn derive(password: &str, kdf: &Kdf) -> Result<Key, CoreError> {
    let master = derive_master_key(password.as_bytes(), &kdf.salt()?, kdf.params()?)?;
    derive_export_key(master.as_ref())
}

/// UUID в каноническом виде, как у `new_item_id`: id записи становится id элемента PEP и входит в AAD.
fn valid_item_id(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

pub(crate) fn seal<'a>(
    vault_id: &str,
    records: impl Iterator<Item = (&'a str, &'a Record)>,
    password: &str,
    now_ms: u64,
) -> Result<String, CoreError> {
    if password.is_empty() {
        return Err(CoreError::EmptyPassword);
    }
    let payload = Payload {
        vault_id: vault_id.to_owned(),
        exported_at: now_ms,
        records: records
            .map(|(id, record)| ExportedRecord {
                id: id.to_owned(),
                record: serde_json::to_value(record).expect("запись сериализуется в JSON"),
            })
            .collect(),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&payload).expect("экспорт сериализуется в JSON"));
    let kdf = Kdf::new(KdfParams::default(), &generate_salt()?);
    let key = derive(password, &kdf)?;
    let fields = aad_fields(&kdf);
    let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let data = seal_random(key.as_ref(), DOMAIN_EXPORT, &fields, &plain)?;
    let envelope = Envelope {
        format: FORMAT_NAME.to_owned(),
        v: EXPORT_FORMAT,
        kdf,
        data: BASE64.encode(data),
    };
    Ok(serde_json::to_string(&envelope).expect("файл экспорта сериализуется в JSON"))
}

pub(crate) fn open(file: &str, password: &str) -> Result<Imported, CoreError> {
    let envelope: Envelope = serde_json::from_str(file).map_err(|_| invalid(ExportError::NotJson))?;
    if envelope.format != FORMAT_NAME {
        return Err(invalid(ExportError::UnknownFormat));
    }
    if envelope.v != EXPORT_FORMAT {
        return Err(invalid(ExportError::UnsupportedVersion(envelope.v)));
    }
    let key = derive(password, &envelope.kdf)?;
    let data = BASE64
        .decode(envelope.data.as_bytes())
        .map_err(|_| invalid(ExportError::NotBase64))?;
    let fields = aad_fields(&envelope.kdf);
    let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let plain = open_sealed(key.as_ref(), &data, DOMAIN_EXPORT, &fields).map_err(|e| match e {
        CoreError::Decrypt => CoreError::WrongExportPassword,
        _ => invalid(ExportError::Corrupted),
    })?;
    let payload: Payload =
        serde_json::from_slice(&plain).map_err(|e| invalid(ExportError::InvalidPayload(e.to_string())))?;
    let mut imported = Imported {
        vault_id: payload.vault_id,
        exported_at: payload.exported_at,
        records: Vec::with_capacity(payload.records.len()),
        skipped: 0,
    };
    for exported in payload.records {
        let record = valid_item_id(&exported.id)
            .then(|| serde_json::to_vec(&exported.record).ok())
            .flatten()
            .and_then(|bytes| Record::from_json(&bytes).ok());
        match record {
            Some(record) => imported.records.push((exported.id, record)),
            None => imported.skipped += 1,
        }
    }
    Ok(imported)
}
