//! Криптоядро InkVault: вывод ключей из мастер-пароля, обертка ключей, шифрование записей,
//! часы HLC, слияние записей, движок синхронизации и учетная запись.
//!
//! Формат шифротекста: версия формата (1 байт), алгоритм (1 байт), nonce (24 байта),
//! шифротекст с тегом. Заголовок входит в AAD, поэтому подмена версии или алгоритма
//! ломает проверку тега.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::lang::tr;

pub mod account;
pub mod export;
pub mod hlc;
pub mod lang;
pub mod otp;
pub mod password;
pub mod record;
pub mod sync;

pub use account::{Account, AccountSync, UnlockedAccount};
pub use export::ExportError;
pub use lang::Lang;
pub use otp::TotpError;

pub use hlc::{Clock, Hlc};
pub use record::Record;
pub use sync::SyncEngine;

pub const KEY_LEN: usize = 32;
pub const MIN_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const FORMAT_V1: u8 = 1;
const ALG_XCHACHA20_POLY1305: u8 = 1;
const HEADER: [u8; 2] = [FORMAT_V1, ALG_XCHACHA20_POLY1305];
const PREFIX_LEN: usize = HEADER.len() + NONCE_LEN;
const TAG_LEN: usize = 16;

const DOMAIN_ITEM: &[u8] = b"inkvault:item";
const DOMAIN_KEY: &[u8] = b"inkvault:key";
const DOMAIN_LOCAL: &[u8] = b"inkvault:local";
const INFO_WRAP: &[u8] = b"inkvault:v1:wrap";
const INFO_CACHE: &[u8] = b"inkvault:v1:cache";
const INFO_KEY_ID: &[u8] = b"inkvault:v1:key-id";
const INFO_EXPORT: &[u8] = b"inkvault:v1:export";
const KEY_ID_LEN: usize = 16;

pub type Key = Zeroizing<[u8; KEY_LEN]>;

/// Ошибка ядра. Вариант - код ошибки для клиента (`code`), текст - на языке процесса (раздел 12 docs/protocol.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidKey,
    InvalidSalt,
    InvalidKdfParams,
    InvalidFormat,
    /// Версия формата и алгоритм из заголовка шифротекста.
    Unsupported(u8, u8),
    Decrypt,
    Random,
    InvalidHlc,
    /// Текст ошибки разбора JSON.
    InvalidRecord(String),
    UnsupportedRecord(u32),
    InvalidTag(String),
    VaultFull(u32),
    MaxItemsTooSmall(u32),
    NotConnected,
    NotFound,
    ReadOnly,
    WrongPassword,
    DeviceKey,
    InvalidPasswordOptions,
    InvalidTotp(TotpError),
    InvalidAccount,
    EmptyPassword,
    WrongExportPassword,
    InvalidExport(ExportError),
}

impl CoreError {
    /// Стабильный код ошибки: по нему клиент обрабатывает ошибку, не разбирая текст.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidKey => "invalid_key",
            Self::InvalidSalt => "invalid_salt",
            Self::InvalidKdfParams => "invalid_kdf_params",
            Self::InvalidFormat => "invalid_format",
            Self::Unsupported(..) => "unsupported_format",
            Self::Decrypt => "decrypt_failed",
            Self::Random => "random_unavailable",
            Self::InvalidHlc => "invalid_hlc",
            Self::InvalidRecord(_) => "invalid_record",
            Self::UnsupportedRecord(_) => "unsupported_record",
            Self::InvalidTag(_) => "invalid_tag",
            Self::VaultFull(_) => "vault_full",
            Self::MaxItemsTooSmall(_) => "max_items_too_small",
            Self::NotConnected => "not_connected",
            Self::NotFound => "not_found",
            Self::ReadOnly => "read_only",
            Self::WrongPassword => "wrong_password",
            Self::DeviceKey => "device_key",
            Self::InvalidPasswordOptions => "invalid_password_options",
            Self::InvalidTotp(_) => "invalid_totp",
            Self::InvalidAccount => "invalid_account",
            Self::EmptyPassword => "empty_password",
            Self::WrongExportPassword => "wrong_export_password",
            Self::InvalidExport(_) => "invalid_export",
        }
    }

    pub fn message(&self, lang: Lang) -> String {
        match self {
            Self::InvalidKey => tr!(
                lang,
                "the key must be {} bytes long",
                "ключ должен быть длиной {} байт",
                KEY_LEN
            ),
            Self::InvalidSalt => tr!(
                lang,
                "the salt must be at least {} bytes long",
                "соль должна быть не короче {} байт",
                MIN_SALT_LEN
            ),
            Self::InvalidKdfParams => tr!(lang, "invalid Argon2id parameters", "недопустимые параметры Argon2id"),
            Self::InvalidFormat => tr!(
                lang,
                "the ciphertext is damaged or too short",
                "шифротекст поврежден или слишком короткий"
            ),
            Self::Unsupported(format, alg) => tr!(
                lang,
                "unsupported format version {} or algorithm {}",
                "неподдерживаемая версия формата {} или алгоритм {}",
                format,
                alg
            ),
            Self::Decrypt => tr!(
                lang,
                "decryption failed: wrong key or modified data",
                "расшифровка не удалась: неверный ключ или данные изменены"
            ),
            Self::Random => tr!(
                lang,
                "the random number source is unavailable",
                "источник случайных чисел недоступен"
            ),
            Self::InvalidHlc => tr!(lang, "invalid HLC timestamp format", "неверный формат метки HLC"),
            Self::InvalidRecord(detail) => tr!(lang, "invalid record format: {}", "неверный формат записи: {}", detail),
            Self::UnsupportedRecord(v) => tr!(
                lang,
                "record format version {} is not supported, a newer client is required",
                "версия формата записи {} не поддерживается, нужен более новый клиент",
                v
            ),
            Self::InvalidTag(tag) => tr!(lang, "invalid tag: {:?}", "недопустимый тег: {:?}", tag),
            Self::VaultFull(max) => tr!(
                lang,
                "the vault already has {} items, this is the node limit",
                "в хранилище уже {} записей, это лимит узла",
                max
            ),
            Self::MaxItemsTooSmall(count) => tr!(
                lang,
                "the node limit cannot be less than {}: the vault already has that many items",
                "лимит узла не может быть меньше {}: столько записей уже в хранилище",
                count
            ),
            Self::NotConnected => tr!(
                lang,
                "the node limit can only be changed while connected to the server",
                "изменить лимит узла можно только при связи с сервером"
            ),
            Self::NotFound => tr!(lang, "item not found", "запись не найдена"),
            Self::ReadOnly => tr!(
                lang,
                "the item was created by a newer client and is read-only",
                "запись создана более новым клиентом и доступна только для чтения"
            ),
            Self::WrongPassword => tr!(lang, "wrong master password", "неверный мастер-пароль"),
            Self::DeviceKey => tr!(
                lang,
                "the device key does not match, fast unlock must be enabled again",
                "ключ устройства не подходит, быструю разблокировку нужно включить заново"
            ),
            Self::InvalidPasswordOptions => tr!(
                lang,
                "invalid generator options: length from 8 to 128 and at least one character class",
                "недопустимые параметры генератора: длина от 8 до 128 и хотя бы один класс символов"
            ),
            Self::InvalidTotp(reason) => tr!(
                lang,
                "invalid TOTP secret: {}",
                "неверный секрет TOTP: {}",
                reason.message(lang)
            ),
            Self::InvalidAccount => tr!(
                lang,
                "the account is damaged: the fingerprint does not match the key",
                "учетная запись повреждена: отпечаток не совпадает с ключом"
            ),
            Self::EmptyPassword => tr!(
                lang,
                "the export password cannot be empty",
                "пароль экспорта не может быть пустым"
            ),
            Self::WrongExportPassword => tr!(
                lang,
                "wrong export file password or the file is damaged",
                "неверный пароль файла экспорта или файл поврежден"
            ),
            Self::InvalidExport(reason) => tr!(
                lang,
                "the file is not an InkVault export: {}",
                "файл не открывается как экспорт InkVault: {}",
                reason.message(lang)
            ),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message(lang::current()))
    }
}

impl std::error::Error for CoreError {}

/// Параметры Argon2id. Хранятся в учетной записи, чтобы их можно было усилить без смены формата.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

pub fn derive_master_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key, CoreError> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CoreError::InvalidSalt);
    }
    let params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| CoreError::InvalidKdfParams)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| CoreError::InvalidKdfParams)?;
    Ok(out)
}

/// Ключ обертки user key. Отдельный ключ через HKDF, чтобы master key не использовался напрямую.
pub fn derive_wrap_key(master_key: &[u8]) -> Result<Key, CoreError> {
    let master_key = key_ref(master_key)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, master_key)
        .expand(INFO_WRAP, out.as_mut())
        .map_err(|_| CoreError::InvalidKey)?;
    Ok(out)
}

/// Ключ файла экспорта из ключа, выведенного Argon2id из пароля экспорта.
pub fn derive_export_key(master_key: &[u8]) -> Result<Key, CoreError> {
    let master_key = key_ref(master_key)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, master_key)
        .expand(INFO_EXPORT, out.as_mut())
        .map_err(|_| CoreError::InvalidKey)?;
    Ok(out)
}

/// Отпечаток ключа: открытый идентификатор, по которому ключ можно сравнить, не раскрывая его.
pub fn derive_key_id(key: &[u8]) -> Result<[u8; KEY_ID_LEN], CoreError> {
    let key = key_ref(key)?;
    let mut out = [0u8; KEY_ID_LEN];
    Hkdf::<Sha256>::new(None, key)
        .expand(INFO_KEY_ID, &mut out)
        .map_err(|_| CoreError::InvalidKey)?;
    Ok(out)
}

/// Ключ локального кэша хранилища. Выводится из vault key, поэтому кэш открывается только
/// после разблокировки хранилища, а хранить отдельный ключ на устройстве не нужно.
pub fn derive_cache_key(vault_key: &[u8]) -> Result<Key, CoreError> {
    let vault_key = key_ref(vault_key)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, vault_key)
        .expand(INFO_CACHE, out.as_mut())
        .map_err(|_| CoreError::InvalidKey)?;
    Ok(out)
}

pub fn generate_key() -> Result<Key, CoreError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).map_err(|_| CoreError::Random)?;
    Ok(key)
}

pub fn generate_salt() -> Result<[u8; MIN_SALT_LEN], CoreError> {
    let mut salt = [0u8; MIN_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| CoreError::Random)?;
    Ok(salt)
}

/// Шифрует ключ ключом более высокого уровня. Метка задает назначение ключа: обертка
/// user key не расшифруется как обертка vault key.
pub fn wrap_key(kek: &[u8], key: &[u8], label: &str) -> Result<Vec<u8>, CoreError> {
    let key = key_ref(key)?;
    seal(kek, &random_nonce()?, &key_aad(label), key)
}

pub fn unwrap_key(kek: &[u8], wrapped: &[u8], label: &str) -> Result<Key, CoreError> {
    let plain = open(kek, wrapped, &key_aad(label))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if plain.len() != KEY_LEN {
        return Err(CoreError::InvalidFormat);
    }
    key.copy_from_slice(&plain);
    Ok(key)
}

pub fn encrypt_item(
    vault_key: &[u8],
    vault_id: &str,
    item_id: &str,
    key_version: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    seal(
        vault_key,
        &random_nonce()?,
        &item_aad(vault_id, item_id, key_version),
        plaintext,
    )
}

pub fn decrypt_item(
    vault_key: &[u8],
    vault_id: &str,
    item_id: &str,
    key_version: u32,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    open(vault_key, ciphertext, &item_aad(vault_id, item_id, key_version))
}

#[cfg(feature = "vectors")]
pub fn wrap_key_with_nonce(kek: &[u8], key: &[u8], label: &str, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>, CoreError> {
    seal(kek, nonce, &key_aad(label), key_ref(key)?)
}

#[cfg(feature = "vectors")]
pub fn encrypt_item_with_nonce(
    vault_key: &[u8],
    vault_id: &str,
    item_id: &str,
    key_version: u32,
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CoreError> {
    seal(vault_key, nonce, &item_aad(vault_id, item_id, key_version), plaintext)
}

/// Шифрует данные, которые хранятся только на устройстве (например, пароль XMPP в CLI), ключом
/// локального кэша хранилища: без мастер-пароля их не открыть. Имя отделяет одни данные от других.
pub fn seal_local(vault_key: &[u8], name: &str, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cache_key = derive_cache_key(vault_key)?;
    seal_random(cache_key.as_ref(), DOMAIN_LOCAL, &[name.as_bytes()], plaintext)
}

pub fn open_local(vault_key: &[u8], name: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let cache_key = derive_cache_key(vault_key)?;
    open_sealed(cache_key.as_ref(), data, DOMAIN_LOCAL, &[name.as_bytes()])
}

/// Шифрование служебных данных (например, локального кэша) со случайным nonce и AAD из домена и полей.
pub(crate) fn seal_random(key: &[u8], domain: &[u8], fields: &[&[u8]], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    seal(key, &random_nonce()?, &aad(domain, fields), plaintext)
}

pub(crate) fn open_sealed(
    key: &[u8],
    data: &[u8],
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    open(key, data, &aad(domain, fields))
}

fn key_ref(key: &[u8]) -> Result<&[u8], CoreError> {
    if key.len() == KEY_LEN {
        Ok(key)
    } else {
        Err(CoreError::InvalidKey)
    }
}

fn random_nonce() -> Result<[u8; NONCE_LEN], CoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CoreError::Random)?;
    Ok(nonce)
}

// Поля с префиксом длины: без него "ab" + "c" и "a" + "bc" дали бы одинаковый AAD
fn aad(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(HEADER.len() + 4 + domain.len() + fields.iter().map(|f| 4 + f.len()).sum::<usize>());
    out.extend_from_slice(&HEADER);
    for part in std::iter::once(domain).chain(fields.iter().copied()) {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn item_aad(vault_id: &str, item_id: &str, key_version: u32) -> Vec<u8> {
    aad(
        DOMAIN_ITEM,
        &[vault_id.as_bytes(), item_id.as_bytes(), &key_version.to_be_bytes()],
    )
}

fn key_aad(label: &str) -> Vec<u8> {
    aad(DOMAIN_KEY, &[label.as_bytes()])
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, CoreError> {
    XChaCha20Poly1305::new_from_slice(key_ref(key)?).map_err(|_| CoreError::InvalidKey)
}

fn seal(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let sealed = cipher(key)?
        .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::InvalidFormat)?;
    let mut out = Vec::with_capacity(PREFIX_LEN + sealed.len());
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if data.len() < PREFIX_LEN + TAG_LEN {
        return Err(CoreError::InvalidFormat);
    }
    if data[..HEADER.len()] != HEADER {
        return Err(CoreError::Unsupported(data[0], data[1]));
    }
    let nonce: [u8; NONCE_LEN] = data[HEADER.len()..PREFIX_LEN]
        .try_into()
        .map_err(|_| CoreError::InvalidFormat)?;
    cipher(key)?
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &data[PREFIX_LEN..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "0192a3f4-0000-7000-8000-000000000001";
    const ITEM: &str = "0192a3f5-0000-7000-8000-000000000002";

    fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn item_roundtrip() {
        let key = generate_key().unwrap();
        let ct = encrypt_item(key.as_ref(), VAULT, ITEM, 1, b"secret").unwrap();
        assert_eq!(ct.len(), PREFIX_LEN + 6 + TAG_LEN);
        assert_eq!(
            decrypt_item(key.as_ref(), VAULT, ITEM, 1, &ct).unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn nonce_is_random() {
        let key = generate_key().unwrap();
        let a = encrypt_item(key.as_ref(), VAULT, ITEM, 1, b"x").unwrap();
        let b = encrypt_item(key.as_ref(), VAULT, ITEM, 1, b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn aad_binds_location() {
        let key = generate_key().unwrap();
        let ct = encrypt_item(key.as_ref(), VAULT, ITEM, 1, b"secret").unwrap();
        assert_eq!(
            decrypt_item(key.as_ref(), "other", ITEM, 1, &ct),
            Err(CoreError::Decrypt)
        );
        assert_eq!(
            decrypt_item(key.as_ref(), VAULT, "other", 1, &ct),
            Err(CoreError::Decrypt)
        );
        assert_eq!(decrypt_item(key.as_ref(), VAULT, ITEM, 2, &ct), Err(CoreError::Decrypt));
    }

    #[test]
    fn aad_fields_are_length_prefixed() {
        let key = generate_key().unwrap();
        let ct = encrypt_item(key.as_ref(), "ab", "c", 1, b"secret").unwrap();
        assert_eq!(decrypt_item(key.as_ref(), "a", "bc", 1, &ct), Err(CoreError::Decrypt));
    }

    #[test]
    fn tampering_and_wrong_key_fail() {
        let key = generate_key().unwrap();
        let mut ct = encrypt_item(key.as_ref(), VAULT, ITEM, 1, b"secret").unwrap();
        let other = generate_key().unwrap();
        assert_eq!(
            decrypt_item(other.as_ref(), VAULT, ITEM, 1, &ct),
            Err(CoreError::Decrypt)
        );
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert_eq!(decrypt_item(key.as_ref(), VAULT, ITEM, 1, &ct), Err(CoreError::Decrypt));
    }

    #[test]
    fn header_is_checked() {
        let key = generate_key().unwrap();
        let mut ct = encrypt_item(key.as_ref(), VAULT, ITEM, 1, b"secret").unwrap();
        ct[0] = 2;
        assert_eq!(
            decrypt_item(key.as_ref(), VAULT, ITEM, 1, &ct),
            Err(CoreError::Unsupported(2, 1))
        );
        assert_eq!(
            decrypt_item(key.as_ref(), VAULT, ITEM, 1, &ct[..PREFIX_LEN]),
            Err(CoreError::InvalidFormat)
        );
    }

    #[test]
    fn invalid_inputs() {
        assert_eq!(
            encrypt_item(&[0u8; 16], VAULT, ITEM, 1, b"x"),
            Err(CoreError::InvalidKey)
        );
        assert_eq!(
            derive_master_key(b"pw", &[0u8; 8], fast_params()).err(),
            Some(CoreError::InvalidSalt)
        );
        let zero = KdfParams {
            memory_kib: 0,
            ..fast_params()
        };
        assert_eq!(
            derive_master_key(b"pw", &[0u8; 16], zero).err(),
            Some(CoreError::InvalidKdfParams)
        );
    }

    #[test]
    fn local_data_is_bound_to_name_and_key() {
        let key = generate_key().unwrap();
        let sealed = seal_local(key.as_ref(), "xmpp-password", b"secret").unwrap();
        assert_eq!(
            open_local(key.as_ref(), "xmpp-password", &sealed).unwrap().as_slice(),
            b"secret"
        );
        assert_eq!(open_local(key.as_ref(), "other", &sealed), Err(CoreError::Decrypt));
        let other = generate_key().unwrap();
        assert_eq!(
            open_local(other.as_ref(), "xmpp-password", &sealed),
            Err(CoreError::Decrypt)
        );
        // локальные данные и запись хранилища не подменяют друг друга
        assert_eq!(
            decrypt_item(key.as_ref(), VAULT, ITEM, 1, &sealed),
            Err(CoreError::Decrypt)
        );
    }

    // язык задается явно: тесты идут параллельно, а язык процесса общий
    #[test]
    fn messages_in_both_languages() {
        let err = CoreError::InvalidTotp(TotpError::NotBase32);
        assert_eq!(err.code(), "invalid_totp");
        assert_eq!(
            err.message(Lang::En),
            "invalid TOTP secret: the secret must be base32: letters A-Z and digits 2-7"
        );
        assert_eq!(
            err.message(Lang::Ru),
            "неверный секрет TOTP: секрет должен быть в base32: буквы A-Z и цифры 2-7"
        );
        assert_eq!(CoreError::WrongPassword.message(Lang::Ru), "неверный мастер-пароль");
        assert_eq!(
            CoreError::InvalidExport(ExportError::UnsupportedVersion(2)).message(Lang::En),
            "the file is not an InkVault export: version 2 is not supported, a newer client is required"
        );
    }

    #[test]
    fn key_chain() {
        let salt = generate_salt().unwrap();
        let master = derive_master_key(b"correct horse", &salt, fast_params()).unwrap();
        assert_eq!(
            master,
            derive_master_key(b"correct horse", &salt, fast_params()).unwrap()
        );
        let wrap = derive_wrap_key(master.as_ref()).unwrap();
        let user = generate_key().unwrap();
        let wrapped = wrap_key(wrap.as_ref(), user.as_ref(), "user-key").unwrap();
        assert_eq!(unwrap_key(wrap.as_ref(), &wrapped, "user-key").unwrap(), user);
        assert_eq!(
            unwrap_key(wrap.as_ref(), &wrapped, "vault-key").err(),
            Some(CoreError::Decrypt)
        );
    }
}
