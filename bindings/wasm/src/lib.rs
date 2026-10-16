//! Биндинги ядра для web. Ключи и шифротекст передаются как Uint8Array.

use inkvault_core as vault;
use vault::otp::Totp;
use vault::password::{self, PasswordOptions};
use vault::sync::{self, Limits, PublishOutcome, RemoteItem};
use vault::{Account, AccountSync, Clock, CoreError, Hlc, KdfParams, Record, SyncEngine, UnlockedAccount, hlc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Error)]
    type JsErrorObject;

    #[wasm_bindgen(constructor, js_class = "Error")]
    fn new(message: &str) -> JsErrorObject;

    #[wasm_bindgen(method, setter)]
    fn set_code(this: &JsErrorObject, code: &str);
}

/// Error с текстом на языке из `setLanguage` и стабильным кодом в поле code (`CoreError::code`).
fn error(code: &str, message: &str) -> JsValue {
    let err = JsErrorObject::new(message);
    err.set_code(code);
    err.into()
}

fn js(err: CoreError) -> JsValue {
    error(err.code(), &err.to_string())
}

/// Язык текстов ошибок и предупреждений ядра: тег BCP 47, например "ru" или "en-US". По умолчанию английский.
#[wasm_bindgen(js_name = setLanguage)]
pub fn set_language(tag: &str) {
    vault::lang::set(vault::Lang::from_tag(tag));
}

#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, JsValue> {
    let params = KdfParams {
        memory_kib,
        iterations,
        parallelism,
    };
    vault::derive_master_key(password.as_bytes(), salt, params)
        .map(|k| k.to_vec())
        .map_err(js)
}

#[wasm_bindgen(js_name = deriveWrapKey)]
pub fn derive_wrap_key(master_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    vault::derive_wrap_key(master_key).map(|k| k.to_vec()).map_err(js)
}

#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key() -> Result<Vec<u8>, JsValue> {
    vault::generate_key().map(|k| k.to_vec()).map_err(js)
}

#[wasm_bindgen(js_name = generateSalt)]
pub fn generate_salt() -> Result<Vec<u8>, JsValue> {
    vault::generate_salt().map(|s| s.to_vec()).map_err(js)
}

#[wasm_bindgen(js_name = wrapKey)]
pub fn wrap_key(kek: &[u8], key: &[u8], label: &str) -> Result<Vec<u8>, JsValue> {
    vault::wrap_key(kek, key, label).map_err(js)
}

#[wasm_bindgen(js_name = unwrapKey)]
pub fn unwrap_key(kek: &[u8], wrapped: &[u8], label: &str) -> Result<Vec<u8>, JsValue> {
    vault::unwrap_key(kek, wrapped, label).map(|k| k.to_vec()).map_err(js)
}

#[wasm_bindgen(js_name = encryptItem)]
pub fn encrypt_item(
    vault_key: &[u8],
    vault_id: &str,
    item_id: &str,
    key_version: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    vault::encrypt_item(vault_key, vault_id, item_id, key_version, plaintext).map_err(js)
}

#[wasm_bindgen(js_name = decryptItem)]
pub fn decrypt_item(
    vault_key: &[u8],
    vault_id: &str,
    item_id: &str,
    key_version: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    vault::decrypt_item(vault_key, vault_id, item_id, key_version, ciphertext)
        .map(|p| p.to_vec())
        .map_err(js)
}

// Время приходит из Date.now() как число; целые миллисекунды до 2^53 представимы точно
fn millis(now_ms: f64) -> Result<u64, JsValue> {
    if now_ms.is_finite() && (0.0..=9_007_199_254_740_992.0).contains(&now_ms) {
        Ok(now_ms as u64)
    } else {
        let text = match vault::lang::current() {
            vault::Lang::En => "time must be a non-negative number of milliseconds",
            vault::Lang::Ru => "время должно быть неотрицательным числом миллисекунд",
        };
        Err(error("invalid_time", text))
    }
}

fn record(json: &str) -> Result<Record, JsValue> {
    Record::from_json(json.as_bytes()).map_err(js)
}

/// Часы HLC устройства. Последнюю метку (`last`) клиент сохраняет между запусками.
#[wasm_bindgen]
pub struct VaultClock {
    inner: Clock,
}

#[wasm_bindgen]
impl VaultClock {
    #[wasm_bindgen(constructor)]
    pub fn new(node: &str) -> Result<VaultClock, JsValue> {
        Ok(Self {
            inner: Clock::new(hlc::parse_node(node).map_err(js)?),
        })
    }

    pub fn restore(last: &str) -> Result<VaultClock, JsValue> {
        Ok(Self {
            inner: Clock::restore(last.parse().map_err(js)?),
        })
    }

    pub fn tick(&mut self, now_ms: f64) -> Result<String, JsValue> {
        Ok(self.inner.tick(millis(now_ms)?).to_string())
    }

    pub fn observe(&mut self, hlc: &str, now_ms: f64) -> Result<(), JsValue> {
        let remote: Hlc = hlc.parse().map_err(js)?;
        self.inner.observe(remote, millis(now_ms)?);
        Ok(())
    }

    #[wasm_bindgen(js_name = observeRecord)]
    pub fn observe_record(&mut self, record_json: &str, now_ms: f64) -> Result<(), JsValue> {
        let max_ts = record(record_json)?.max_ts();
        self.inner.observe(max_ts, millis(now_ms)?);
        Ok(())
    }

    pub fn last(&self) -> String {
        self.inner.last().to_string()
    }
}

#[wasm_bindgen(js_name = generateNodeId)]
pub fn generate_node_id() -> Result<String, JsValue> {
    hlc::generate_node_id().map(hlc::format_node).map_err(js)
}

/// Лимит записей нового узла хранилища: pep_max_items в Prosody по умолчанию.
#[wasm_bindgen(js_name = defaultMaxItems)]
pub fn default_max_items() -> u32 {
    sync::DEFAULT_MAX_ITEMS
}

#[wasm_bindgen(js_name = recordCreate)]
pub fn record_create(clock: &mut VaultClock, now_ms: f64, kind: &str, fields_json: &str) -> Result<String, JsValue> {
    let record = Record::new_from_json(kind, fields_json, &mut clock.inner, millis(now_ms)?).map_err(js)?;
    Ok(record.to_json_string())
}

#[wasm_bindgen(js_name = recordSet)]
pub fn record_set(
    clock: &mut VaultClock,
    now_ms: f64,
    record_json: &str,
    name: &str,
    value: &str,
) -> Result<String, JsValue> {
    let mut r = record(record_json)?;
    r.set(name, value, &mut clock.inner, millis(now_ms)?);
    Ok(r.to_json_string())
}

#[wasm_bindgen(js_name = recordSetTag)]
pub fn record_set_tag(
    clock: &mut VaultClock,
    now_ms: f64,
    record_json: &str,
    tag: &str,
    on: bool,
) -> Result<String, JsValue> {
    let mut r = record(record_json)?;
    r.set_tag(tag, on, &mut clock.inner, millis(now_ms)?).map_err(js)?;
    Ok(r.to_json_string())
}

#[wasm_bindgen(js_name = recordDelete)]
pub fn record_delete(clock: &mut VaultClock, now_ms: f64, record_json: &str) -> Result<String, JsValue> {
    let mut r = record(record_json)?;
    r.delete(&mut clock.inner, millis(now_ms)?);
    Ok(r.to_json_string())
}

#[wasm_bindgen(js_name = recordRestore)]
pub fn record_restore(clock: &mut VaultClock, now_ms: f64, record_json: &str) -> Result<String, JsValue> {
    let mut r = record(record_json)?;
    r.restore(&mut clock.inner, millis(now_ms)?);
    Ok(r.to_json_string())
}

#[wasm_bindgen(js_name = recordMerge)]
pub fn record_merge(a_json: &str, b_json: &str) -> Result<String, JsValue> {
    Ok(record(a_json)?.merge(&record(b_json)?).to_json_string())
}

/// Движок синхронизации одного хранилища. Результат вызовов - JSON
/// {"item_id"?, "commands": [...], "events": [...]}, команды исполняет адаптер PEP.
#[wasm_bindgen]
pub struct VaultSync {
    inner: SyncEngine,
}

#[wasm_bindgen]
impl VaultSync {
    #[wasm_bindgen(constructor)]
    pub fn new(
        vault_id: &str,
        key_version: u32,
        vault_key: &[u8],
        node: &str,
        device: &str,
        max_items: u32,
    ) -> Result<VaultSync, JsValue> {
        let vault = sync::vault_key(vault_id, key_version, vault_key).map_err(js)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        let device = hlc::parse_node(device).map_err(js)?;
        Ok(Self {
            inner: SyncEngine::new(vault, node, device, limits),
        })
    }

    /// Восстановление из снимка: он зашифрован ключом, выведенным из vault key.
    pub fn restore(
        vault_id: &str,
        key_version: u32,
        vault_key: &[u8],
        node: &str,
        max_items: u32,
        snapshot: &[u8],
    ) -> Result<VaultSync, JsValue> {
        let vault = sync::vault_key(vault_id, key_version, vault_key).map_err(js)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        Ok(Self {
            inner: SyncEngine::restore(vault, node, limits, snapshot).map_err(js)?,
        })
    }

    /// Зашифрованный снимок локального кэша. Для его хранения отдельный секрет не нужен.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.snapshot().map_err(js)
    }

    pub fn connected(&mut self, resumed: bool, max_stanza_bytes: Option<u32>) -> String {
        self.inner.connected(resumed, max_stanza_bytes).to_json()
    }

    pub fn disconnected(&mut self) {
        self.inner.disconnected();
    }

    #[wasm_bindgen(js_name = sessionLost)]
    pub fn session_lost(&mut self) {
        self.inner.session_lost();
    }

    #[wasm_bindgen(js_name = itemsFetched)]
    pub fn items_fetched(&mut self, items_json: &str, now_ms: f64) -> Result<String, JsValue> {
        let items = RemoteItem::list_from_json(items_json).map_err(js)?;
        Ok(self.inner.items_fetched(items, millis(now_ms)?).to_json())
    }

    #[wasm_bindgen(js_name = itemNotified)]
    pub fn item_notified(&mut self, item_json: &str, now_ms: f64) -> Result<String, JsValue> {
        let item = RemoteItem::from_json(item_json).map_err(js)?;
        Ok(self.inner.item_notified(item, millis(now_ms)?).to_json())
    }

    /// error - условие ошибки XMPP ("precondition-not-met", "forbidden" и т.д.), без него - успех.
    #[wasm_bindgen(js_name = publishResult)]
    pub fn publish_result(&mut self, request: u32, error: Option<String>) -> String {
        self.inner
            .publish_result(request, PublishOutcome::from_error(error.as_deref()))
            .to_json()
    }

    #[wasm_bindgen(js_name = configureResult)]
    pub fn configure_result(&mut self, request: u32, ok: bool) -> String {
        self.inner.configure_result(request, ok).to_json()
    }

    /// max_items из настроек узла; undefined - узла нет или настройки не прочитались.
    #[wasm_bindgen(js_name = configFetched)]
    pub fn config_fetched(&mut self, request: u32, max_items: Option<u32>) -> String {
        self.inner.config_fetched(request, max_items).to_json()
    }

    /// Лимит записей узла: с сервера или, если узла еще нет, лимит для его создания.
    #[wasm_bindgen(js_name = maxItems)]
    pub fn max_items(&self) -> u32 {
        self.inner.max_items()
    }

    /// Новый лимит записей узла. Узел перенастраивается сразу, поэтому нужна связь с сервером.
    #[wasm_bindgen(js_name = setMaxItems)]
    pub fn set_max_items(&mut self, max_items: u32) -> Result<String, JsValue> {
        Ok(self.inner.set_max_items(max_items).map_err(js)?.to_json())
    }

    pub fn create(&mut self, kind: &str, fields_json: &str, now_ms: f64) -> Result<String, JsValue> {
        let fields = sync::fields_from_json(fields_json).map_err(js)?;
        Ok(self.inner.create(kind, fields, millis(now_ms)?).map_err(js)?.to_json())
    }

    #[wasm_bindgen(js_name = setField)]
    pub fn set_field(&mut self, item_id: &str, name: &str, value: &str, now_ms: f64) -> Result<String, JsValue> {
        Ok(self
            .inner
            .set_field(item_id, name, value, millis(now_ms)?)
            .map_err(js)?
            .to_json())
    }

    /// Несколько изменений одной операцией: fields - {"имя": "значение"}, tags - {"тег": true|false}.
    #[wasm_bindgen(js_name = editItem)]
    pub fn edit_item(
        &mut self,
        item_id: &str,
        fields_json: &str,
        tags_json: &str,
        now_ms: f64,
    ) -> Result<String, JsValue> {
        let fields = sync::fields_from_json(fields_json).map_err(js)?;
        let tags = sync::tags_from_json(tags_json).map_err(js)?;
        Ok(self
            .inner
            .edit(item_id, &fields, &tags, millis(now_ms)?)
            .map_err(js)?
            .to_json())
    }

    #[wasm_bindgen(js_name = setTag)]
    pub fn set_tag(&mut self, item_id: &str, tag: &str, on: bool, now_ms: f64) -> Result<String, JsValue> {
        Ok(self
            .inner
            .set_tag(item_id, tag, on, millis(now_ms)?)
            .map_err(js)?
            .to_json())
    }

    #[wasm_bindgen(js_name = deleteItem)]
    pub fn delete_item(&mut self, item_id: &str, now_ms: f64) -> Result<String, JsValue> {
        Ok(self.inner.delete_item(item_id, millis(now_ms)?).map_err(js)?.to_json())
    }

    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&mut self, item_id: &str, now_ms: f64) -> Result<String, JsValue> {
        Ok(self.inner.restore_item(item_id, millis(now_ms)?).map_err(js)?.to_json())
    }

    /// Очистка корзины: удаленные записи заменяются заглушками без содержимого.
    #[wasm_bindgen(js_name = purgeTrash)]
    pub fn purge_trash(&mut self, now_ms: f64) -> Result<String, JsValue> {
        Ok(self.inner.purge_trash(millis(now_ms)?).to_json())
    }

    pub fn records(&self) -> String {
        self.inner.records_json()
    }

    /// Зашифрованный файл экспорта (JSON) со всеми записями хранилища.
    #[wasm_bindgen(js_name = exportVault)]
    pub fn export_vault(&self, password: &str, now_ms: f64) -> Result<String, JsValue> {
        self.inner.export(password, millis(now_ms)?).map_err(js)
    }

    /// Импорт файла экспорта. В выводе движка поле imported: {added, updated, unchanged, skipped}.
    #[wasm_bindgen(js_name = importVault)]
    pub fn import_vault(&mut self, file: &str, password: &str, now_ms: f64) -> Result<String, JsValue> {
        Ok(self
            .inner
            .import(file, password, millis(now_ms)?)
            .map_err(js)?
            .to_json())
    }

    pub fn pending(&self) -> u32 {
        self.inner.pending() as u32
    }

    #[wasm_bindgen(js_name = clockLast)]
    pub fn clock_last(&self) -> String {
        self.inner.clock_last().to_string()
    }
}

/// Разблокированная учетная запись. Ключи остаются в памяти ядра, наружу выходят только
/// публичная часть (JSON для узла PEP и хранения на устройстве) и движки хранилищ.
#[wasm_bindgen]
pub struct VaultAccount {
    inner: UnlockedAccount,
}

#[wasm_bindgen]
impl VaultAccount {
    /// Новая учетная запись с личным хранилищем.
    pub fn create(master_password: &str, now_ms: f64) -> Result<VaultAccount, JsValue> {
        Ok(Self {
            inner: UnlockedAccount::create(master_password, millis(now_ms)?).map_err(js)?,
        })
    }

    pub fn unlock(account_json: &str, master_password: &str) -> Result<VaultAccount, JsValue> {
        let account = Account::from_json(account_json).map_err(js)?;
        Ok(Self {
            inner: account.unlock(master_password).map_err(js)?,
        })
    }

    #[wasm_bindgen(js_name = accountJson)]
    pub fn account_json(&self) -> String {
        self.inner.account().to_json_string()
    }

    pub fn vaults(&self) -> String {
        self.inner.vaults_json()
    }

    #[wasm_bindgen(js_name = openVault)]
    pub fn open_vault(&self, vault_id: &str, node: &str, device: &str, max_items: u32) -> Result<VaultSync, JsValue> {
        let vault = self.inner.vault_key(vault_id).map_err(js)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        let device = hlc::parse_node(device).map_err(js)?;
        Ok(VaultSync {
            inner: SyncEngine::new(vault, node, device, limits),
        })
    }

    #[wasm_bindgen(js_name = restoreVault)]
    pub fn restore_vault(
        &self,
        vault_id: &str,
        node: &str,
        max_items: u32,
        snapshot: &[u8],
    ) -> Result<VaultSync, JsValue> {
        let vault = self.inner.vault_key(vault_id).map_err(js)?;
        let limits = Limits {
            max_items,
            ..Limits::default()
        };
        Ok(VaultSync {
            inner: SyncEngine::restore(vault, node, limits, snapshot).map_err(js)?,
        })
    }

    /// Сверка с учетной записью на сервере: "same", "updated" - сохранить `accountJson()`,
    /// "publish" - сохранить и опубликовать, "foreign" - на сервере чужая учетная запись.
    pub fn refresh(&mut self, server_account_json: &str) -> Result<String, JsValue> {
        let server = Account::from_json(server_account_json).map_err(js)?;
        let state = match self.inner.refresh(&server).map_err(js)? {
            AccountSync::Same => "same",
            AccountSync::Updated => "updated",
            AccountSync::Publish => "publish",
            AccountSync::Foreign => "foreign",
        };
        Ok(state.to_owned())
    }

    /// Новый мастер-пароль после проверки текущего. Возвращает учетную запись для сохранения и публикации.
    #[wasm_bindgen(js_name = changePassword)]
    pub fn change_password(&mut self, current_password: &str, new_password: &str) -> Result<String, JsValue> {
        self.inner.change_password(current_password, new_password).map_err(js)?;
        Ok(self.inner.account().to_json_string())
    }

    #[wasm_bindgen(js_name = addVault)]
    pub fn add_vault(&mut self, now_ms: f64) -> Result<String, JsValue> {
        self.inner.add_vault(millis(now_ms)?).map_err(js)
    }

    /// Проверка мастер-пароля, например перед экспортом под ним.
    #[wasm_bindgen(js_name = verifyPassword)]
    pub fn verify_password(&self, password: &str) -> Result<bool, JsValue> {
        self.inner.verify_password(password).map_err(js)
    }
}

/// Копия учетной записи с сервера новее копии устройства: мастер-пароль сменили на другом устройстве.
#[wasm_bindgen(js_name = accountIsNewer)]
pub fn account_is_newer(server_account_json: &str, saved_account_json: &str) -> Result<bool, JsValue> {
    let server = Account::from_json(server_account_json).map_err(js)?;
    let saved = Account::from_json(saved_account_json).map_err(js)?;
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

#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(
    length: u32,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> Result<String, JsValue> {
    let options = password_options(length, lower, upper, digits, symbols, avoid_ambiguous);
    Ok(password::generate(&options).map_err(js)?.to_string())
}

/// Энтропия пароля с такими параметрами в битах, для индикатора стойкости.
#[wasm_bindgen(js_name = passwordEntropy)]
pub fn password_entropy(
    length: u32,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> Result<f64, JsValue> {
    password::entropy_bits(&password_options(
        length,
        lower,
        upper,
        digits,
        symbols,
        avoid_ambiguous,
    ))
    .map_err(js)
}

/// Текущий код TOTP как JSON {code, remaining, period}. Секрет - base32 или ссылка otpauth://totp/...
#[wasm_bindgen]
pub fn totp(secret: &str, now_ms: f64) -> Result<String, JsValue> {
    let totp = Totp::parse(secret).map_err(js)?;
    let now_ms = millis(now_ms)?;
    // код состоит только из цифр, экранирование не нужно
    Ok(format!(
        r#"{{"code":"{}","remaining":{},"period":{}}}"#,
        totp.code(now_ms),
        totp.remaining(now_ms),
        totp.period()
    ))
}
