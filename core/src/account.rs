//! Учетная запись хранилища: параметры KDF, обернутый user key и обернутые ключи хранилищ.
//!
//! Публичная часть (`Account`) хранится в узле PEP `urn:inkvault:account:0` и на устройствах
//! для разблокировки без сети: в ней только соль и обернутые ключи. Разблокированная часть
//! (`UnlockedAccount`) держит ключи в памяти ядра и выдает их движкам хранилищ, поэтому
//! ключи не попадают в память JS и Kotlin.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::sync::{VaultKey, new_item_id};
use crate::{
    CoreError, KdfParams, Key, derive_key_id, derive_master_key, derive_wrap_key, generate_key, generate_salt,
    unwrap_key, wrap_key,
};

pub const ACCOUNT_FORMAT: u32 = 1;
const KDF_ALG: &str = "argon2id";
const USER_KEY_LABEL: &str = "user-key";
const DEVICE_LABEL: &str = "device-key";
// Границы параметров KDF из узла учетной записи: сервер не должен ни ослабить вывод ключа,
// ни заставить устройство выделить гигабайты памяти
const KDF_MEMORY_KIB: RangeInclusive<u32> = 19 * 1024..=1024 * 1024;
const KDF_ITERATIONS: RangeInclusive<u32> = 2..=16;
const KDF_PARALLELISM: RangeInclusive<u32> = 1..=16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    pub alg: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    /// Соль в base64.
    pub salt: String,
}

impl Kdf {
    pub(crate) fn new(params: KdfParams, salt: &[u8]) -> Self {
        Self {
            alg: KDF_ALG.to_owned(),
            m: params.memory_kib,
            t: params.iterations,
            p: params.parallelism,
            salt: BASE64.encode(salt),
        }
    }

    /// Параметры из узла учетной записи или файла экспорта с проверкой границ.
    pub(crate) fn params(&self) -> Result<KdfParams, CoreError> {
        let valid = self.alg == KDF_ALG
            && KDF_MEMORY_KIB.contains(&self.m)
            && KDF_ITERATIONS.contains(&self.t)
            && KDF_PARALLELISM.contains(&self.p);
        if !valid {
            return Err(CoreError::InvalidKdfParams);
        }
        Ok(KdfParams {
            memory_kib: self.m,
            iterations: self.t,
            parallelism: self.p,
        })
    }

    pub(crate) fn salt(&self) -> Result<Vec<u8>, CoreError> {
        decode(&self.salt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEntry {
    pub id: String,
    pub key_version: u32,
    /// Vault key, обернутый user key, в base64.
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub v: u32,
    /// Отпечаток user key в base64: по нему клиент отличает чужую учетную запись от своей.
    pub key_id: String,
    /// Версия обертки user key, растет при каждой смене мастер-пароля.
    pub rev: u64,
    pub kdf: Kdf,
    /// User key, обернутый ключом из мастер-пароля, в base64.
    pub user_key: String,
    pub vaults: Vec<VaultEntry>,
}

// Метка обертки включает id и версию хранилища: сервер не может подставить обертку
// одного хранилища на место другого
fn vault_label(id: &str, key_version: u32) -> String {
    format!("vault-key:{id}:{key_version}")
}

fn decode(text: &str) -> Result<Vec<u8>, CoreError> {
    BASE64.decode(text.as_bytes()).map_err(|_| CoreError::InvalidFormat)
}

fn key_id(user_key: &Key) -> Result<String, CoreError> {
    Ok(BASE64.encode(derive_key_id(user_key.as_ref())?))
}

/// Результат сверки учетной записи с копией на сервере.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSync {
    /// Копии совпадают.
    Same,
    /// Принята версия с сервера, сохраненную копию нужно обновить.
    Updated,
    /// На сервере старая версия или в ней нет изменений этого устройства: объединенную версию
    /// (`account()`) нужно сохранить и опубликовать.
    Publish,
    /// На сервере учетная запись с другим user key. Ее нельзя принять и нельзя перезаписать без
    /// решения пользователя: записи, зашифрованные ее ключами, станут недоступны.
    Foreign,
}

impl Account {
    pub fn from_json(json: &str) -> Result<Self, CoreError> {
        let account: Account = serde_json::from_str(json).map_err(|e| CoreError::InvalidRecord(e.to_string()))?;
        if account.v != ACCOUNT_FORMAT {
            return Err(CoreError::UnsupportedRecord(account.v));
        }
        Ok(account)
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("учетная запись сериализуется в JSON")
    }

    /// Версия этого устройства поверх версии с сервера. Обертка user key - "побеждает старшая
    /// версия", хранилища объединяются: ключ хранилища, добавленного на любом устройстве, не теряется.
    /// Порядок хранилищ берется с сервера, новые добавляются в конец: первое хранилище остается личным,
    /// а устройства сходятся к одному порядку.
    fn rebase(&self, server: &Account) -> Account {
        let password = match self.rev.cmp(&server.rev) {
            Ordering::Greater => self,
            Ordering::Less => server,
            // одновременная смена пароля на двух устройствах: выбор детерминирован, устройства сходятся
            Ordering::Equal if self.user_key > server.user_key => self,
            Ordering::Equal => server,
        };
        let mut vaults = server.vaults.clone();
        for mine in &self.vaults {
            match vaults.iter_mut().find(|v| v.id == mine.id) {
                // при равной версии ключа своя обертка: она уже проверена ключом из памяти
                Some(theirs) if mine.key_version >= theirs.key_version => *theirs = mine.clone(),
                Some(_) => {}
                None => vaults.push(mine.clone()),
            }
        }
        Account {
            v: ACCOUNT_FORMAT,
            key_id: server.key_id.clone(),
            rev: password.rev,
            kdf: password.kdf.clone(),
            user_key: password.user_key.clone(),
            vaults,
        }
    }

    fn kdf_params(&self) -> Result<KdfParams, CoreError> {
        self.kdf.params()
    }

    /// Разблокировка мастер-паролем. Самая долгая часть - Argon2id.
    pub fn unlock(&self, master_password: &str) -> Result<UnlockedAccount, CoreError> {
        let master = derive_master_key(master_password.as_bytes(), &decode(&self.kdf.salt)?, self.kdf_params()?)?;
        let wrap = derive_wrap_key(master.as_ref())?;
        let user_key = unwrap_key(wrap.as_ref(), &decode(&self.user_key)?, USER_KEY_LABEL).map_err(|e| match e {
            CoreError::Decrypt => CoreError::WrongPassword,
            other => other,
        })?;
        if key_id(&user_key)? != self.key_id {
            return Err(CoreError::InvalidAccount);
        }
        let vault_keys = unwrap_vaults(&user_key, &self.vaults)?;
        Ok(UnlockedAccount {
            account: self.clone(),
            user_key,
            vault_keys,
        })
    }

    /// Копия с новым мастер-паролем. Без текущего пароля обертку не сменить: иначе пароль
    /// поменял бы любой, у кого есть разблокированное устройство, например по отпечатку.
    pub fn change_password(&self, current: &str, new: &str) -> Result<Account, CoreError> {
        let mut unlocked = self.unlock(current)?;
        unlocked.set_password(new)?;
        Ok(unlocked.account)
    }

    /// Копия с сервера той же учетной записи с более новой оберткой user key. Ею можно заменить
    /// копию устройства, которая не открывается: мастер-пароль сменили на другом устройстве.
    pub fn is_newer_than(&self, saved: &Account) -> bool {
        self.key_id == saved.key_id && self.rev > saved.rev
    }

    /// Быстрая разблокировка без Argon2id: секрет устройства выдает платформенное хранилище
    /// (Android Keystore после биометрии), обертка user key хранится на устройстве.
    pub fn unlock_with_device(&self, secret: &[u8], blob: &[u8]) -> Result<UnlockedAccount, CoreError> {
        let user_key = unwrap_key(secret, blob, DEVICE_LABEL).map_err(|_| CoreError::DeviceKey)?;
        // ключ устройства от другой учетной записи, например созданной заново на том же JID
        if key_id(&user_key)? != self.key_id {
            return Err(CoreError::DeviceKey);
        }
        let vault_keys = unwrap_vaults(&user_key, &self.vaults)?;
        Ok(UnlockedAccount {
            account: self.clone(),
            user_key,
            vault_keys,
        })
    }
}

fn unwrap_vaults(user_key: &Key, vaults: &[VaultEntry]) -> Result<BTreeMap<String, (u32, Key)>, CoreError> {
    vaults
        .iter()
        .map(|v| {
            let key = unwrap_key(user_key.as_ref(), &decode(&v.key)?, &vault_label(&v.id, v.key_version))?;
            Ok((v.id.clone(), (v.key_version, key)))
        })
        .collect()
}

pub struct UnlockedAccount {
    account: Account,
    user_key: Key,
    vault_keys: BTreeMap<String, (u32, Key)>,
}

impl UnlockedAccount {
    /// Новая учетная запись с одним личным хранилищем. `account()` нужно опубликовать в узле PEP.
    pub fn create(master_password: &str, now_ms: u64) -> Result<Self, CoreError> {
        let user_key = generate_key()?;
        let mut unlocked = Self {
            account: Account {
                v: ACCOUNT_FORMAT,
                key_id: key_id(&user_key)?,
                rev: 0,
                kdf: Kdf {
                    alg: KDF_ALG.to_owned(),
                    m: 0,
                    t: 0,
                    p: 0,
                    salt: String::new(),
                },
                user_key: String::new(),
                vaults: Vec::new(),
            },
            user_key,
            vault_keys: BTreeMap::new(),
        };
        unlocked.set_password(master_password)?;
        unlocked.add_vault(now_ms)?;
        Ok(unlocked)
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Хранилища учетной записи: id и версия ключа.
    pub fn vaults(&self) -> impl Iterator<Item = (&str, u32)> {
        self.account.vaults.iter().map(|v| (v.id.as_str(), v.key_version))
    }

    /// Хранилища в JSON для биндингов: [{"id", "key_version"}].
    pub fn vaults_json(&self) -> String {
        let list: Vec<serde_json::Value> = self
            .vaults()
            .map(|(id, key_version)| serde_json::json!({ "id": id, "key_version": key_version }))
            .collect();
        serde_json::Value::Array(list).to_string()
    }

    pub fn vault_key(&self, id: &str) -> Result<VaultKey, CoreError> {
        let (key_version, key) = self.vault_keys.get(id).ok_or(CoreError::NotFound)?;
        Ok(VaultKey {
            id: id.to_owned(),
            key_version: *key_version,
            key: key.clone(),
        })
    }

    /// Ключ устройства для быстрой разблокировки. Возвращает секрет, который платформа прячет
    /// в своем хранилище ключей, и обертку user key этим секретом для хранения на устройстве.
    /// Смена мастер-пароля обертку не меняет: user key остается прежним.
    pub fn enroll_device(&self) -> Result<(Key, Vec<u8>), CoreError> {
        let secret = generate_key()?;
        let blob = wrap_key(secret.as_ref(), self.user_key.as_ref(), DEVICE_LABEL)?;
        Ok((secret, blob))
    }

    /// Новое хранилище с новым ключом. Возвращает его id.
    pub fn add_vault(&mut self, now_ms: u64) -> Result<String, CoreError> {
        let id = new_item_id(now_ms)?;
        let key = generate_key()?;
        let wrapped = wrap_key(self.user_key.as_ref(), key.as_ref(), &vault_label(&id, 1))?;
        self.account.vaults.push(VaultEntry {
            id: id.clone(),
            key_version: 1,
            key: BASE64.encode(wrapped),
        });
        self.vault_keys.insert(id.clone(), (1, key));
        Ok(id)
    }

    // Меняются только соль, параметры KDF и обертка user key: ключи хранилищ и локальный кэш остаются
    fn set_password(&mut self, password: &str) -> Result<(), CoreError> {
        let params = KdfParams::default();
        let salt = generate_salt()?;
        let master = derive_master_key(password.as_bytes(), &salt, params)?;
        let wrap = derive_wrap_key(master.as_ref())?;
        let wrapped = wrap_key(wrap.as_ref(), self.user_key.as_ref(), USER_KEY_LABEL)?;
        self.account.kdf = Kdf::new(params, &salt);
        self.account.user_key = BASE64.encode(wrapped);
        self.account.rev += 1;
        Ok(())
    }

    /// Смена мастер-пароля после проверки текущего. `account()` нужно сохранить и опубликовать.
    /// Перед сменой учетную запись стоит сверить с сервером (`refresh`): иначе новая версия
    /// может совпасть по `rev` с версией, опубликованной другим устройством.
    pub fn change_password(&mut self, current: &str, new: &str) -> Result<(), CoreError> {
        self.account = self.account.change_password(current, new)?;
        Ok(())
    }

    /// Проверка мастер-пароля без смены состояния: например, перед экспортом под мастер-паролем.
    pub fn verify_password(&self, password: &str) -> Result<bool, CoreError> {
        match self.account.unlock(password) {
            Ok(_) => Ok(true),
            Err(CoreError::WrongPassword) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Сверка с версией учетной записи на сервере. Новый мастер-пароль и новые хранилища с других
    /// устройств принимаются, ключи хранилищ открываются user key из памяти, без ввода пароля.
    /// Если на сервере старая копия, например после восстановления из бэкапа, изменения этого
    /// устройства сохраняются и возвращается `Publish`.
    pub fn refresh(&mut self, server: &Account) -> Result<AccountSync, CoreError> {
        if server.key_id != key_id(&self.user_key)? {
            return Ok(AccountSync::Foreign);
        }
        if *server == self.account {
            return Ok(AccountSync::Same);
        }
        server.kdf_params()?;
        let merged = self.account.rebase(server);
        // своя по отпечатку учетная запись, но обертки не открываются: сервер подменил данные
        self.vault_keys = unwrap_vaults(&self.user_key, &merged.vaults)?;
        let state = if merged == *server {
            AccountSync::Updated
        } else {
            AccountSync::Publish
        };
        self.account = merged;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn create_and_unlock() {
        let created = UnlockedAccount::create("correct horse", NOW).unwrap();
        let json = created.account().to_json_string();
        let unlocked = Account::from_json(&json).unwrap().unlock("correct horse").unwrap();
        let (id, version) = unlocked.vaults().next().unwrap();
        assert_eq!(version, 1);
        assert_eq!(unlocked.vault_key(id).unwrap().key, created.vault_key(id).unwrap().key);
        assert!(!json.contains("correct horse"));
    }

    #[test]
    fn wrong_password() {
        let unlocked = UnlockedAccount::create("correct horse", NOW).unwrap();
        assert_eq!(unlocked.account().unlock("wrong").err(), Some(CoreError::WrongPassword));
        assert!(unlocked.verify_password("correct horse").unwrap());
        assert!(!unlocked.verify_password("wrong").unwrap());
    }

    #[test]
    fn vault_wrap_is_bound_to_vault_id() {
        let mut created = UnlockedAccount::create("pw-1234567890", NOW).unwrap();
        created.add_vault(NOW + 1).unwrap();
        let mut account = created.account().clone();
        // сервер меняет местами обертки двух хранилищ
        let first = account.vaults[0].key.clone();
        account.vaults[0].key = account.vaults[1].key.clone();
        account.vaults[1].key = first;
        assert_eq!(account.unlock("pw-1234567890").err(), Some(CoreError::Decrypt));
    }

    #[test]
    fn kdf_bounds_from_server() {
        let mut account = UnlockedAccount::create("pw-1234567890", NOW).unwrap().account().clone();
        account.kdf.m = 4 * 1024 * 1024;
        assert_eq!(account.unlock("pw-1234567890").err(), Some(CoreError::InvalidKdfParams));
        account.kdf.m = 64 * 1024;
        account.kdf.alg = "pbkdf2".to_owned();
        assert_eq!(account.unlock("pw-1234567890").err(), Some(CoreError::InvalidKdfParams));
    }

    #[test]
    fn password_change_keeps_vault_keys_and_refresh_picks_it_up() {
        let created = UnlockedAccount::create("old-password", NOW).unwrap();
        let stored = created.account().clone();
        let mut other_device = stored.unlock("old-password").unwrap();
        other_device.change_password("old-password", "new-password").unwrap();
        other_device.add_vault(NOW + 1).unwrap();
        let server = other_device.account().clone();

        assert_eq!(server.unlock("old-password").err(), Some(CoreError::WrongPassword));
        let unlocked_new = server.unlock("new-password").unwrap();
        let (id, _) = created.vaults().next().unwrap();
        assert_eq!(
            unlocked_new.vault_key(id).unwrap().key,
            created.vault_key(id).unwrap().key
        );

        // устройство со старой копией открыто старым паролем и узнает о смене после подключения
        let mut this_device = stored.unlock("old-password").unwrap();
        assert_eq!(this_device.refresh(&server).unwrap(), AccountSync::Updated);
        assert_eq!(this_device.account(), &server);
        assert_eq!(this_device.vaults().count(), 2);
        assert_eq!(this_device.refresh(&server).unwrap(), AccountSync::Same);
    }

    #[test]
    fn password_change_requires_current_password() {
        let mut device = UnlockedAccount::create("old-password", NOW).unwrap();
        let before = device.account().clone();
        assert_eq!(
            device.change_password("wrong", "new-password").err(),
            Some(CoreError::WrongPassword)
        );
        assert_eq!(device.account(), &before);

        device.change_password("old-password", "new-password").unwrap();
        let changed = device.account().clone();
        assert_eq!(changed.rev, before.rev + 1);
        assert_ne!(changed.kdf.salt, before.kdf.salt);
        assert_eq!(changed.vaults, before.vaults);
        assert!(changed.unlock("new-password").is_ok());
        // смена на уже открытом устройстве не трогает ключи в памяти
        let (id, _) = device.vaults().next().unwrap();
        assert!(device.vault_key(id).is_ok());
    }

    #[test]
    fn newer_server_copy_replaces_stale_device_copy() {
        let created = UnlockedAccount::create("old-password", NOW).unwrap();
        let saved = created.account().clone();
        let server = saved.change_password("old-password", "new-password").unwrap();
        assert!(server.is_newer_than(&saved));
        assert!(!saved.is_newer_than(&server));
        assert!(!saved.is_newer_than(&saved));
        // новый пароль не открывает копию устройства, но открывает более новую копию с сервера
        assert_eq!(saved.unlock("new-password").err(), Some(CoreError::WrongPassword));
        assert!(server.unlock("new-password").is_ok());

        let mut foreign = UnlockedAccount::create("new-password", NOW).unwrap().account().clone();
        foreign.rev = saved.rev + 10;
        assert!(!foreign.is_newer_than(&saved));
    }

    #[test]
    fn old_backup_on_server_does_not_roll_back_password_or_vaults() {
        let mut device = UnlockedAccount::create("old-password", NOW).unwrap();
        let backup = device.account().clone();
        device.change_password("old-password", "new-password").unwrap();
        let added = device.add_vault(NOW + 1).unwrap();
        let current = device.account().clone();

        assert_eq!(device.refresh(&backup).unwrap(), AccountSync::Publish);
        assert_eq!(device.account(), &current);
        // после публикации на сервере актуальный пароль и оба хранилища
        let restored = device.account().unlock("new-password").unwrap();
        assert!(restored.vault_key(&added).is_ok());
        assert_eq!(
            device.account().unlock("old-password").err(),
            Some(CoreError::WrongPassword)
        );
    }

    #[test]
    fn vaults_from_both_sides_are_kept_and_personal_stays_first() {
        let created = UnlockedAccount::create("pw-1234567890", NOW).unwrap();
        let (personal, _) = created.vaults().next().unwrap();
        let personal = personal.to_owned();
        let mut a = created.account().unlock("pw-1234567890").unwrap();
        let mut b = created.account().unlock("pw-1234567890").unwrap();
        let from_a = a.add_vault(NOW + 2).unwrap();
        // часы устройства b отстают: id его хранилища меньше id личного
        let from_b = b.add_vault(NOW - 1_000_000).unwrap();
        let server = b.account().clone();

        assert_eq!(a.refresh(&server).unwrap(), AccountSync::Publish);
        let ids: Vec<&str> = a.vaults().map(|(id, _)| id).collect();
        assert_eq!(ids, [personal.as_str(), from_b.as_str(), from_a.as_str()]);
        assert_eq!(b.refresh(a.account()).unwrap(), AccountSync::Updated);
        assert_eq!(a.account(), b.account());
        assert!(b.vault_key(&from_a).is_ok());
    }

    #[test]
    fn concurrent_password_changes_converge() {
        let created = UnlockedAccount::create("pw-1234567890", NOW).unwrap();
        let mut a = created.account().unlock("pw-1234567890").unwrap();
        let mut b = created.account().unlock("pw-1234567890").unwrap();
        a.change_password("pw-1234567890", "password-a").unwrap();
        b.change_password("pw-1234567890", "password-b").unwrap();
        let (from_a, from_b) = (a.account().clone(), b.account().clone());
        a.refresh(&from_b).unwrap();
        b.refresh(&from_a).unwrap();
        assert_eq!(a.account(), b.account());
        let works = |pw| a.account().unlock(pw).is_ok();
        assert!(works("password-a") != works("password-b"));
    }

    #[test]
    fn key_id_is_checked_on_unlock() {
        let mut account = UnlockedAccount::create("pw-1234567890", NOW).unwrap().account().clone();
        let other = UnlockedAccount::create("pw-1234567890", NOW).unwrap().account().clone();
        account.key_id = other.key_id;
        assert_eq!(account.unlock("pw-1234567890").err(), Some(CoreError::InvalidAccount));
    }

    #[test]
    fn device_unlock_survives_password_change() {
        let mut unlocked = UnlockedAccount::create("old-password", NOW).unwrap();
        let (secret, blob) = unlocked.enroll_device().unwrap();
        unlocked.change_password("old-password", "new-password").unwrap();
        let account = unlocked.account().clone();
        let fast = account.unlock_with_device(secret.as_ref(), &blob).unwrap();
        let (id, _) = unlocked.vaults().next().unwrap();
        assert_eq!(fast.vault_key(id).unwrap().key, unlocked.vault_key(id).unwrap().key);
        assert_eq!(
            account.unlock_with_device(&[0u8; 32], &blob).err(),
            Some(CoreError::DeviceKey)
        );
    }

    #[test]
    fn foreign_account_is_a_separate_state() {
        let mut mine = UnlockedAccount::create("pw-1234567890", NOW).unwrap();
        let before = mine.account().clone();
        let foreign = UnlockedAccount::create("pw-1234567890", NOW).unwrap();
        assert_eq!(mine.refresh(foreign.account()).unwrap(), AccountSync::Foreign);
        assert_eq!(mine.account(), &before);
        // ключ устройства своей учетной записи не открывает чужую
        let (secret, blob) = mine.enroll_device().unwrap();
        assert_eq!(
            foreign.account().unlock_with_device(secret.as_ref(), &blob).err(),
            Some(CoreError::DeviceKey)
        );
    }

    #[test]
    fn tampered_wraps_on_server() {
        let mut device = UnlockedAccount::create("pw-1234567890", NOW).unwrap();
        let before = device.account().clone();
        let stranger = UnlockedAccount::create("pw-1234567890", NOW).unwrap().account().vaults[0].clone();

        // обертка известного хранилища подменена: остается своя, исправленная копия публикуется
        let mut server = before.clone();
        server.vaults[0].key = stranger.key.clone();
        assert_eq!(device.refresh(&server).unwrap(), AccountSync::Publish);
        assert_eq!(device.account(), &before);

        // незнакомое хранилище с чужой оберткой: ошибка, локальная копия не меняется
        let mut server = before.clone();
        server.vaults.push(stranger);
        assert_eq!(device.refresh(&server).err(), Some(CoreError::Decrypt));
        assert_eq!(device.account(), &before);
    }
}
