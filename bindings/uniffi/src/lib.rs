//! Биндинги ядра для Android через UniFFI. Ключи и шифротекст передаются как ByteArray.

use std::sync::{Arc, Mutex, MutexGuard};

use inkvault_core as vault;
use vault::otp::Totp;
use vault::password::{self, PasswordOptions};
use vault::sync::{self, Limits, PublishOutcome, RemoteItem};
use vault::{Account, Clock, CoreError, Hlc, KdfParams, Record, SyncEngine, UnlockedAccount, hlc};

uniffi::setup_scaffolding!();

/// Ошибка ядра. В Kotlin - CoreException с подклассом на каждый код, текст на языке из `set_language`.
#[uniffi::remote(Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    InvalidKey,
    InvalidSalt,
    InvalidKdfParams,
    InvalidFormat,
    Unsupported(u8, u8),
    Decrypt,
    Random,
    InvalidHlc,
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

/// Язык текстов ошибок и предупреждений ядра: тег BCP 47, например "ru" или "en-US". По умолчанию английский.
#[uniffi::export]
pub fn set_language(tag: String) {
    vault::lang::set(vault::Lang::from_tag(&tag));
}

#[uniffi::export]
pub fn derive_master_key(
    password: String,
    salt: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, CoreError> {
    let params = KdfParams {
        memory_kib,
        iterations,
        parallelism,
    };
    Ok(vault::derive_master_key(password.as_bytes(), &salt, params)?.to_vec())
}

#[uniffi::export]
pub fn derive_wrap_key(master_key: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    Ok(vault::derive_wrap_key(&master_key)?.to_vec())
}

#[uniffi::export]
pub fn generate_key() -> Result<Vec<u8>, CoreError> {
    Ok(vault::generate_key()?.to_vec())
}

#[uniffi::export]
pub fn generate_salt() -> Result<Vec<u8>, CoreError> {
    Ok(vault::generate_salt()?.to_vec())
}

#[uniffi::export]
pub fn wrap_key(kek: Vec<u8>, key: Vec<u8>, label: String) -> Result<Vec<u8>, CoreError> {
    vault::wrap_key(&kek, &key, &label)
}

#[uniffi::export]
pub fn unwrap_key(kek: Vec<u8>, wrapped: Vec<u8>, label: String) -> Result<Vec<u8>, CoreError> {
    Ok(vault::unwrap_key(&kek, &wrapped, &label)?.to_vec())
}

#[uniffi::export]
pub fn encrypt_item(
    vault_key: Vec<u8>,
    vault_id: String,
    item_id: String,
    key_version: u32,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, CoreError> {
    vault::encrypt_item(&vault_key, &vault_id, &item_id, key_version, &plaintext)
}

#[uniffi::export]
pub fn decrypt_item(
    vault_key: Vec<u8>,
    vault_id: String,
    item_id: String,
    key_version: u32,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, CoreError> {
    Ok(vault::decrypt_item(&vault_key, &vault_id, &item_id, key_version, &ciphertext)?.to_vec())
}

fn record(json: &str) -> Result<Record, CoreError> {
    Record::from_json(json.as_bytes())
}

/// Часы HLC устройства. Последнюю метку (`last`) клиент сохраняет между запусками.
#[derive(uniffi::Object)]
pub struct VaultClock {
    inner: Mutex<Clock>,
}

impl VaultClock {
    fn clock(&self) -> MutexGuard<'_, Clock> {
        // паника под блокировкой невозможна: внутри только арифметика над метками
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl VaultClock {
    #[uniffi::constructor]
    pub fn new(node: String) -> Result<Arc<Self>, CoreError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(Clock::new(hlc::parse_node(&node)?)),
        }))
    }

    #[uniffi::constructor]
    pub fn restore(last: String) -> Result<Arc<Self>, CoreError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(Clock::restore(last.parse()?)),
        }))
    }

    pub fn tick(&self, now_ms: u64) -> String {
        self.clock().tick(now_ms).to_string()
    }

    pub fn observe(&self, hlc: String, now_ms: u64) -> Result<(), CoreError> {
        let remote: Hlc = hlc.parse()?;
        self.clock().observe(remote, now_ms);
        Ok(())
    }

    pub fn observe_record(&self, record_json: String, now_ms: u64) -> Result<(), CoreError> {
        let max_ts = record(&record_json)?.max_ts();
        self.clock().observe(max_ts, now_ms);
        Ok(())
    }

    pub fn last(&self) -> String {
        self.clock().last().to_string()
    }
}

#[uniffi::export]
pub fn generate_node_id() -> Result<String, CoreError> {
    Ok(hlc::format_node(hlc::generate_node_id()?))
}

/// Лимит записей нового узла хранилища: pep_max_items в Prosody по умолчанию.
#[uniffi::export]
pub fn default_max_items() -> u32 {
    sync::DEFAULT_MAX_ITEMS
}

#[uniffi::export]
pub fn record_create(
    clock: Arc<VaultClock>,
    now_ms: u64,
    kind: String,
    fields_json: String,
) -> Result<String, CoreError> {
    Ok(Record::new_from_json(&kind, &fields_json, &mut clock.clock(), now_ms)?.to_json_string())
}

#[uniffi::export]
pub fn record_set(
    clock: Arc<VaultClock>,
    now_ms: u64,
    record_json: String,
    name: String,
    value: String,
) -> Result<String, CoreError> {
    let mut r = record(&record_json)?;
    r.set(&name, &value, &mut clock.clock(), now_ms);
    Ok(r.to_json_string())
}

#[uniffi::export]
pub fn record_set_tag(
    clock: Arc<VaultClock>,
    now_ms: u64,
    record_json: String,
    tag: String,
    on: bool,
) -> Result<String, CoreError> {
    let mut r = record(&record_json)?;
    r.set_tag(&tag, on, &mut clock.clock(), now_ms)?;
    Ok(r.to_json_string())
}

#[uniffi::export]
pub fn record_delete(clock: Arc<VaultClock>, now_ms: u64, record_json: String) -> Result<String, CoreError> {
    let mut r = record(&record_json)?;
    r.delete(&mut clock.clock(), now_ms);
    Ok(r.to_json_string())
}

#[uniffi::export]
pub fn record_restore(clock: Arc<VaultClock>, now_ms: u64, record_json: String) -> Result<String, CoreError> {
    let mut r = record(&record_json)?;
    r.restore(&mut clock.clock(), now_ms);
    Ok(r.to_json_string())
}

#[uniffi::export]
pub fn record_merge(a_json: String, b_json: String) -> Result<String, CoreError> {
    Ok(record(&a_json)?.merge(&record(&b_json)?).to_json_string())
}

/// Движок синхронизации одного хранилища. Результат вызовов - JSON
/// {"item_id"?, "commands": [...], "events": [...]}, команды исполняет адаптер PEP.
#[derive(uniffi::Object)]
pub struct VaultSync {
    inner: Mutex<SyncEngine>,
}

impl VaultSync {
    fn engine(&self) -> MutexGuard<'_, SyncEngine> {
        // паника под блокировкой означала бы ошибку в ядре, состояние движка при этом остается целым
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl VaultSync {
    #[uniffi::constructor]
    pub fn new(
        vault_id: String,
        key_version: u32,
        vault_key: Vec<u8>,
        node: String,
        device: String,
        max_items: u32,
    ) -> Result<Arc<Self>, CoreError> {
        let vault = sync::vault_key(&vault_id, key_version, &vault_key)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        let engine = SyncEngine::new(vault, &node, hlc::parse_node(&device)?, limits);
        Ok(Arc::new(Self {
            inner: Mutex::new(engine),
        }))
    }

    /// Восстановление из снимка: он зашифрован ключом, выведенным из vault key.
    #[uniffi::constructor]
    pub fn restore(
        vault_id: String,
        key_version: u32,
        vault_key: Vec<u8>,
        node: String,
        max_items: u32,
        snapshot: Vec<u8>,
    ) -> Result<Arc<Self>, CoreError> {
        let vault = sync::vault_key(&vault_id, key_version, &vault_key)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        let engine = SyncEngine::restore(vault, &node, limits, &snapshot)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(engine),
        }))
    }

    /// Зашифрованный снимок локального кэша. Для его хранения отдельный секрет не нужен.
    pub fn snapshot(&self) -> Result<Vec<u8>, CoreError> {
        self.engine().snapshot()
    }

    pub fn connected(&self, resumed: bool, max_stanza_bytes: Option<u32>) -> String {
        self.engine().connected(resumed, max_stanza_bytes).to_json()
    }

    pub fn disconnected(&self) {
        self.engine().disconnected();
    }

    pub fn session_lost(&self) {
        self.engine().session_lost();
    }

    pub fn items_fetched(&self, items_json: String, now_ms: u64) -> Result<String, CoreError> {
        let items = RemoteItem::list_from_json(&items_json)?;
        Ok(self.engine().items_fetched(items, now_ms).to_json())
    }

    pub fn item_notified(&self, item_json: String, now_ms: u64) -> Result<String, CoreError> {
        let item = RemoteItem::from_json(&item_json)?;
        Ok(self.engine().item_notified(item, now_ms).to_json())
    }

    /// error - условие ошибки XMPP ("precondition-not-met", "forbidden" и т.д.), без него - успех.
    pub fn publish_result(&self, request: u32, error: Option<String>) -> String {
        self.engine()
            .publish_result(request, PublishOutcome::from_error(error.as_deref()))
            .to_json()
    }

    pub fn configure_result(&self, request: u32, ok: bool) -> String {
        self.engine().configure_result(request, ok).to_json()
    }

    /// max_items из настроек узла; null - узла нет или настройки не прочитались.
    pub fn config_fetched(&self, request: u32, max_items: Option<u32>) -> String {
        self.engine().config_fetched(request, max_items).to_json()
    }

    /// Лимит записей узла: с сервера или, если узла еще нет, лимит для его создания.
    pub fn max_items(&self) -> u32 {
        self.engine().max_items()
    }

    /// Новый лимит записей узла. Узел перенастраивается сразу, поэтому нужна связь с сервером.
    pub fn set_max_items(&self, max_items: u32) -> Result<String, CoreError> {
        Ok(self.engine().set_max_items(max_items)?.to_json())
    }

    pub fn create(&self, kind: String, fields_json: String, now_ms: u64) -> Result<String, CoreError> {
        let fields = sync::fields_from_json(&fields_json)?;
        Ok(self.engine().create(&kind, fields, now_ms)?.to_json())
    }

    pub fn set_field(&self, item_id: String, name: String, value: String, now_ms: u64) -> Result<String, CoreError> {
        Ok(self.engine().set_field(&item_id, &name, &value, now_ms)?.to_json())
    }

    /// Несколько изменений одной операцией: fields - {"имя": "значение"}, tags - {"тег": true|false}.
    pub fn edit_item(
        &self,
        item_id: String,
        fields_json: String,
        tags_json: String,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let fields = sync::fields_from_json(&fields_json)?;
        let tags = sync::tags_from_json(&tags_json)?;
        Ok(self.engine().edit(&item_id, &fields, &tags, now_ms)?.to_json())
    }

    pub fn set_tag(&self, item_id: String, tag: String, on: bool, now_ms: u64) -> Result<String, CoreError> {
        Ok(self.engine().set_tag(&item_id, &tag, on, now_ms)?.to_json())
    }

    pub fn delete_item(&self, item_id: String, now_ms: u64) -> Result<String, CoreError> {
        Ok(self.engine().delete_item(&item_id, now_ms)?.to_json())
    }

    pub fn restore_item(&self, item_id: String, now_ms: u64) -> Result<String, CoreError> {
        Ok(self.engine().restore_item(&item_id, now_ms)?.to_json())
    }

    /// Очистка корзины: удаленные записи заменяются заглушками без содержимого.
    pub fn purge_trash(&self, now_ms: u64) -> String {
        self.engine().purge_trash(now_ms).to_json()
    }

    pub fn records(&self) -> String {
        self.engine().records_json()
    }

    /// Зашифрованный файл экспорта (JSON) со всеми записями хранилища.
    pub fn export_vault(&self, password: String, now_ms: u64) -> Result<String, CoreError> {
        self.engine().export(&password, now_ms)
    }

    /// Импорт файла экспорта. В выводе движка поле imported: {added, updated, unchanged, skipped}.
    pub fn import_vault(&self, file: String, password: String, now_ms: u64) -> Result<String, CoreError> {
        Ok(self.engine().import(&file, &password, now_ms)?.to_json())
    }

    pub fn pending(&self) -> u32 {
        self.engine().pending() as u32
    }

    pub fn clock_last(&self) -> String {
        self.engine().clock_last().to_string()
    }
}

/// Разблокированная учетная запись. Ключи остаются в памяти ядра, наружу выходят только
/// публичная часть (JSON для узла PEP и хранения на устройстве) и движки хранилищ.
#[derive(uniffi::Object)]
pub struct VaultAccount {
    inner: Mutex<UnlockedAccount>,
}

impl VaultAccount {
    fn account(&self) -> MutexGuard<'_, UnlockedAccount> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl VaultAccount {
    /// Новая учетная запись с личным хранилищем.
    #[uniffi::constructor]
    pub fn create(master_password: String, now_ms: u64) -> Result<Arc<Self>, CoreError> {
        Ok(Arc::new(Self {
            inner: Mutex::new(UnlockedAccount::create(&master_password, now_ms)?),
        }))
    }

    #[uniffi::constructor]
    pub fn unlock(account_json: String, master_password: String) -> Result<Arc<Self>, CoreError> {
        let account = Account::from_json(&account_json)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(account.unlock(&master_password)?),
        }))
    }

    pub fn account_json(&self) -> String {
        self.account().account().to_json_string()
    }

    pub fn vaults(&self) -> String {
        self.account().vaults_json()
    }

    pub fn open_vault(
        &self,
        vault_id: String,
        node: String,
        device: String,
        max_items: u32,
    ) -> Result<Arc<VaultSync>, CoreError> {
        let vault = self.account().vault_key(&vault_id)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        let engine = SyncEngine::new(vault, &node, hlc::parse_node(&device)?, limits);
        Ok(Arc::new(VaultSync {
            inner: Mutex::new(engine),
        }))
    }

    pub fn restore_vault(
        &self,
        vault_id: String,
        node: String,
        max_items: u32,
        snapshot: Vec<u8>,
    ) -> Result<Arc<VaultSync>, CoreError> {
        let vault = self.account().vault_key(&vault_id)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        let engine = SyncEngine::restore(vault, &node, limits, &snapshot)?;
        Ok(Arc::new(VaultSync {
            inner: Mutex::new(engine),
        }))
    }

    /// Сверка с учетной записью на сервере. Updated - сохранить `account_json()`, Publish - сохранить
    /// и опубликовать, Foreign - на сервере чужая учетная запись, решение за пользователем.
    pub fn refresh(&self, server_account_json: String) -> Result<AccountSync, CoreError> {
        let server = Account::from_json(&server_account_json)?;
        Ok(self.account().refresh(&server)?.into())
    }

    /// Новый мастер-пароль после проверки текущего. Возвращает учетную запись для сохранения и публикации.
    pub fn change_password(&self, current_password: String, new_password: String) -> Result<String, CoreError> {
        let mut account = self.account();
        account.change_password(&current_password, &new_password)?;
        Ok(account.account().to_json_string())
    }

    pub fn add_vault(&self, now_ms: u64) -> Result<String, CoreError> {
        self.account().add_vault(now_ms)
    }

    /// Проверка мастер-пароля, например перед экспортом под ним.
    pub fn verify_password(&self, password: String) -> Result<bool, CoreError> {
        self.account().verify_password(&password)
    }
}

/// Копия учетной записи с сервера новее копии устройства: мастер-пароль сменили на другом устройстве.
#[uniffi::export]
pub fn account_is_newer(server_account_json: String, saved_account_json: String) -> Result<bool, CoreError> {
    let server = Account::from_json(&server_account_json)?;
    let saved = Account::from_json(&saved_account_json)?;
    Ok(server.is_newer_than(&saved))
}

fn password_options(
    length: u32,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> PasswordOptions {
    PasswordOptions {
        length,
        lower,
        upper,
        digits,
        symbols,
        avoid_ambiguous,
    }
}

#[uniffi::export]
pub fn generate_password(
    length: u32,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> Result<String, CoreError> {
    let options = password_options(length, lower, upper, digits, symbols, avoid_ambiguous);
    Ok(password::generate(&options)?.to_string())
}

/// Энтропия пароля с такими параметрами в битах, для индикатора стойкости.
#[uniffi::export]
pub fn password_entropy(
    length: u32,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> Result<f64, CoreError> {
    password::entropy_bits(&password_options(
        length,
        lower,
        upper,
        digits,
        symbols,
        avoid_ambiguous,
    ))
}

/// Ключ устройства для быстрой разблокировки: secret прячется в Android Keystore за биометрией,
/// blob (обертка user key) хранится в файлах приложения.
#[derive(uniffi::Record)]
pub struct DeviceEnrollment {
    pub secret: Vec<u8>,
    pub blob: Vec<u8>,
}

#[uniffi::export]
impl VaultAccount {
    pub fn enroll_device(&self) -> Result<DeviceEnrollment, CoreError> {
        let (secret, blob) = self.account().enroll_device()?;
        Ok(DeviceEnrollment {
            secret: secret.to_vec(),
            blob,
        })
    }

    /// Разблокировка секретом устройства, без мастер-пароля и Argon2id.
    #[uniffi::constructor]
    pub fn unlock_with_device(account_json: String, secret: Vec<u8>, blob: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        let account = Account::from_json(&account_json)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(account.unlock_with_device(&secret, &blob)?),
        }))
    }
}

#[derive(uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    /// Секунд до смены кода.
    pub remaining: u32,
    pub period: u32,
}

/// Текущий код TOTP. Секрет - base32 или ссылка otpauth://totp/...
#[uniffi::export]
pub fn totp(secret: String, now_ms: u64) -> Result<TotpCode, CoreError> {
    let totp = Totp::parse(&secret)?;
    Ok(TotpCode {
        code: totp.code(now_ms),
        remaining: totp.remaining(now_ms) as u32,
        period: totp.period() as u32,
    })
}

/// Результат сверки учетной записи с сервером (`vault::AccountSync`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccountSync {
    Same,
    Updated,
    Publish,
    Foreign,
}

impl From<vault::AccountSync> for AccountSync {
    fn from(state: vault::AccountSync) -> Self {
        match state {
            vault::AccountSync::Same => Self::Same,
            vault::AccountSync::Updated => Self::Updated,
            vault::AccountSync::Publish => Self::Publish,
            vault::AccountSync::Foreign => Self::Foreign,
        }
    }
}
