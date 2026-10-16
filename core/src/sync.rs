//! Движок синхронизации одного хранилища без сетевого кода (sans-IO).
//!
//! Платформа передает движку события сети (подключение, загруженные и полученные элементы,
//! результаты публикаций) и действия пользователя, а получает команды для сервера и события
//! для интерфейса. Команды и события - интерфейс бэкенда: для PEP их исполняет адаптер на
//! платформе, для компонента появится второй адаптер, логика здесь останется прежней.
//!
//! Локальная версия записи сливается с версией сервера. Если результат отличается от версии
//! сервера, движок публикует его: так устройство, чье изменение перезаписала чужая публикация,
//! возвращает его, и все устройства сходятся к одной версии.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::hlc::{Clock, Hlc};
use crate::lang::{self, tr};
use crate::record::{Record, validate_tag};
use crate::{CoreError, KEY_LEN, Key, decrypt_item, derive_cache_key, encrypt_item, open_sealed, seal_random};

/// Метка, опережающая часы устройства больше чем на сутки, означает неверные часы
/// на этом или на другом устройстве.
pub const CLOCK_AHEAD_LIMIT_MS: u64 = 24 * 60 * 60 * 1000;
/// Запас на станзу публикации вокруг шифротекста: item, entry и publish-options.
const STANZA_OVERHEAD: usize = 1024;
const SNAPSHOT_FORMAT: u32 = 1;
/// Лимит записей нового узла хранилища: столько разрешает Prosody без настройки (pep_max_items = 256).
/// Узел, который уже есть на сервере, остается со своим лимитом.
pub const DEFAULT_MAX_ITEMS: u32 = 256;
const DOMAIN_CACHE: &[u8] = b"inkvault:cache";

pub struct VaultKey {
    pub id: String,
    pub key_version: u32,
    pub key: Key,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Лимит записей, с которым создается узел хранилища.
    pub max_items: u32,
    pub max_stanza_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_items: DEFAULT_MAX_ITEMS,
            max_stanza_bytes: 256 * 1024,
        }
    }
}

/// Элемент узла хранилища в том виде, в каком его передает сервер.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteItem {
    pub id: String,
    pub key_version: u32,
    /// Шифротекст записи в base64.
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Command {
    /// Прочитать настройки узла запросом владельца и передать его max_items в `config_fetched`.
    FetchConfig { request: u32, node: String },
    /// Загрузить все элементы узла и передать их в `items_fetched`.
    FetchAll { node: String },
    /// Опубликовать элемент с publish-options (whitelist, persist_items, max_items) и передать итог в `publish_result`.
    Publish {
        request: u32,
        node: String,
        max_items: u32,
        item: RemoteItem,
    },
    /// Привести настройки узла к ожидаемым и передать итог в `configure_result`.
    ConfigureNode { request: u32, node: String, max_items: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningKind {
    /// Элемент не расшифровался или поврежден.
    Unreadable,
    /// Формат записи новее клиента: запись показывается, но не изменяется.
    UnsupportedRecord,
    /// Станза больше лимита сервера, запись не отправлена.
    TooLarge,
    /// Запись была на сервере и пропала, движок публикует ее снова.
    MissingOnServer,
    /// Сервер отклонил публикацию или настройку узла.
    PublishRejected,
    /// Метка опережает часы устройства больше чем на сутки.
    ClockAhead,
}

/// Причина предупреждения с параметрами: по коду клиент обрабатывает предупреждение, не разбирая текст.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum WarningReason {
    /// error - код ошибки ядра (`CoreError::code`).
    Unreadable {
        error: String,
    },
    UnsupportedRecord {
        version: u32,
    },
    TooLarge {
        bytes: u32,
        max_bytes: u32,
    },
    MissingOnServer,
    /// Узел с таким лимитом сервер не создает: max_items больше pep_max_items.
    NodeLimitRejected {
        max_items: u32,
        server_error: String,
    },
    /// server_error - условие ошибки XMPP и текст сервера.
    PublishRejected {
        server_error: String,
    },
    /// Сервер не принял лимит узла, заданный пользователем.
    MaxItemsRejected {
        max_items: u32,
    },
    ConfigUnreadable,
    ConfigRejected,
    /// Записей больше лимита узла, изменения не отправляются.
    OverLimit {
        items: u32,
        max_items: u32,
    },
    EncryptFailed {
        error: String,
    },
    /// hlc - метка записи.
    ClockAhead {
        hlc: String,
    },
}

impl WarningReason {
    pub fn kind(&self) -> WarningKind {
        match self {
            Self::Unreadable { .. } => WarningKind::Unreadable,
            Self::UnsupportedRecord { .. } => WarningKind::UnsupportedRecord,
            Self::TooLarge { .. } => WarningKind::TooLarge,
            Self::MissingOnServer => WarningKind::MissingOnServer,
            Self::ClockAhead { .. } => WarningKind::ClockAhead,
            Self::NodeLimitRejected { .. }
            | Self::PublishRejected { .. }
            | Self::MaxItemsRejected { .. }
            | Self::ConfigUnreadable
            | Self::ConfigRejected
            | Self::OverLimit { .. }
            | Self::EncryptFailed { .. } => WarningKind::PublishRejected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    ItemChanged {
        item_id: String,
    },
    /// Загрузка узла после подключения обработана.
    Synced,
    /// detail - текст на языке процесса (`lang::set`).
    Warning {
        kind: WarningKind,
        item_id: Option<String>,
        detail: String,
        reason: WarningReason,
    },
}

impl Event {
    fn warning(item_id: Option<String>, reason: WarningReason, detail: String) -> Self {
        Self::Warning {
            kind: reason.kind(),
            item_id,
            detail,
            reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    Ok,
    /// Параметры публикации не совпали с настройками узла (pubsub#errors precondition-not-met).
    PreconditionFailed,
    Rejected(String),
}

impl PublishOutcome {
    /// Итог по ошибке XMPP "условие" или "условие: текст сервера": None - успех,
    /// "precondition-not-met" - расхождение настроек узла.
    pub fn from_error(error: Option<&str>) -> Self {
        match error {
            None => Self::Ok,
            Some(e) if e.split(": ").next() == Some("precondition-not-met") => Self::PreconditionFailed,
            Some(other) => Self::Rejected(other.to_owned()),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    /// Id записи, созданной вызовом `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    /// Итог вызова `import`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<ImportStats>,
    pub commands: Vec<Command>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportStats {
    pub added: u32,
    pub updated: u32,
    pub unchanged: u32,
    /// Записи, которые не прочитались или доступны только для чтения.
    pub skipped: u32,
}

impl Output {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("команды и события сериализуются в JSON")
    }
}

impl RemoteItem {
    pub fn from_json(json: &str) -> Result<Self, CoreError> {
        serde_json::from_str(json).map_err(|e| CoreError::InvalidRecord(e.to_string()))
    }

    pub fn list_from_json(json: &str) -> Result<Vec<Self>, CoreError> {
        serde_json::from_str(json).map_err(|e| CoreError::InvalidRecord(e.to_string()))
    }
}

/// Поля новой записи из JSON-объекта {"имя поля": "значение"}.
pub fn tags_from_json(json: &str) -> Result<BTreeMap<String, bool>, CoreError> {
    serde_json::from_str(json).map_err(|e| CoreError::InvalidRecord(e.to_string()))
}

pub fn fields_from_json(json: &str) -> Result<BTreeMap<String, String>, CoreError> {
    serde_json::from_str(json).map_err(|e| CoreError::InvalidRecord(e.to_string()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Item {
    /// Локальная версия. None, если запись есть только на сервере и не читается.
    local: Option<Record>,
    /// Последняя известная версия на сервере.
    server: Option<Record>,
    /// Формат записи на сервере новее клиента: запись не изменяется и не публикуется.
    read_only: bool,
}

impl Item {
    fn pending(&self) -> bool {
        !self.read_only && self.local.is_some() && self.local != self.server
    }
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    v: u32,
    vault_id: String,
    clock: Hlc,
    items: BTreeMap<String, Item>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_max_items: Option<u32>,
}

#[derive(Clone, Copy)]
struct Configuring {
    request: u32,
    max_items: u32,
    /// Лимит меняет пользователь, а не движок после отказа сервера в публикации.
    requested: bool,
}

pub struct SyncEngine {
    vault: VaultKey,
    node: String,
    limits: Limits,
    clock: Clock,
    items: BTreeMap<String, Item>,
    connected: bool,
    /// Узел загружен в текущей сессии. До этого публиковать нельзя: можно перезаписать
    /// на сервере изменения, которых устройство еще не видело.
    fetched: bool,
    next_request: u32,
    publishing: BTreeMap<u32, (String, Record)>,
    /// Последний известный лимит узла на сервере. Сохраняется в снимке: без сети место в узле
    /// проверяется по нему, а пропавший узел создается заново с тем же лимитом.
    node_max_items: Option<u32>,
    /// Узел есть на сервере. None - настройки в этой сессии еще не прочитаны.
    node_exists: Option<bool>,
    /// Запрос настроек узла; true - после ответа узел нужно перенастроить (publish-options не совпали).
    fetching_config: Option<(u32, bool)>,
    configuring: Option<Configuring>,
    /// Элементы, публикацию которых сервер отклонил в этой сессии. Повтор - после переподключения.
    rejected: BTreeSet<String>,
    over_limit_reported: bool,
    out: Output,
}

impl SyncEngine {
    pub fn new(vault: VaultKey, node: &str, device: u64, limits: Limits) -> Self {
        Self::with_state(vault, node, limits, Clock::new(device), BTreeMap::new(), None)
    }

    fn with_state(
        vault: VaultKey,
        node: &str,
        limits: Limits,
        clock: Clock,
        items: BTreeMap<String, Item>,
        node_max_items: Option<u32>,
    ) -> Self {
        Self {
            vault,
            node: node.to_owned(),
            limits,
            clock,
            items,
            connected: false,
            fetched: false,
            next_request: 0,
            publishing: BTreeMap::new(),
            node_max_items,
            node_exists: None,
            fetching_config: None,
            configuring: None,
            rejected: BTreeSet::new(),
            over_limit_reported: false,
            out: Output::default(),
        }
    }

    /// Восстанавливает движок из снимка. Снимок зашифрован ключом, выведенным из vault key,
    /// поэтому открывается только после разблокировки хранилища.
    pub fn restore(vault: VaultKey, node: &str, limits: Limits, data: &[u8]) -> Result<Self, CoreError> {
        let cache_key = derive_cache_key(vault.key.as_ref())?;
        let plain = open_sealed(cache_key.as_ref(), data, DOMAIN_CACHE, &[vault.id.as_bytes()])?;
        let snapshot: Snapshot = serde_json::from_slice(&plain).map_err(|e| CoreError::InvalidRecord(e.to_string()))?;
        if snapshot.v != SNAPSHOT_FORMAT || snapshot.vault_id != vault.id {
            return Err(CoreError::InvalidFormat);
        }
        Ok(Self::with_state(
            vault,
            node,
            limits,
            Clock::restore(snapshot.clock),
            snapshot.items,
            snapshot.node_max_items,
        ))
    }

    /// Снимок локального кэша: записи, известные версии сервера, часы и id устройства в них.
    /// Сохраняется после каждого изменения, чтобы офлайн-правки и рост меток пережили перезапуск.
    pub fn snapshot(&self) -> Result<Vec<u8>, CoreError> {
        let snapshot = Snapshot {
            v: SNAPSHOT_FORMAT,
            vault_id: self.vault.id.clone(),
            clock: self.clock.last(),
            items: self.items.clone(),
            node_max_items: self.node_max_items,
        };
        let json = zeroize::Zeroizing::new(serde_json::to_vec(&snapshot).expect("снимок сериализуется в JSON"));
        let cache_key = derive_cache_key(self.vault.key.as_ref())?;
        seal_random(cache_key.as_ref(), DOMAIN_CACHE, &[self.vault.id.as_bytes()], &json)
    }

    pub fn record(&self, item_id: &str) -> Option<&Record> {
        self.items.get(item_id).and_then(|i| i.local.as_ref())
    }

    /// Записи для интерфейса: id, запись, есть ли неотправленные изменения. Удаленные записи
    /// тоже входят в список, интерфейс показывает их в корзине. Заглушек после очистки корзины
    /// в списке нет.
    pub fn records(&self) -> impl Iterator<Item = (&str, &Record, bool)> {
        self.items.iter().filter_map(|(id, item)| {
            item.local
                .as_ref()
                .filter(|r| !r.is_purged())
                .map(|r| (id.as_str(), r, item.pending()))
        })
    }

    /// Записи для интерфейса в JSON: [{"id", "pending", "record"}].
    pub fn records_json(&self) -> String {
        #[derive(Serialize)]
        struct View<'a> {
            id: &'a str,
            pending: bool,
            record: &'a Record,
        }
        let views: Vec<View> = self
            .records()
            .map(|(id, record, pending)| View { id, pending, record })
            .collect();
        serde_json::to_string(&views).expect("записи сериализуются в JSON")
    }

    pub fn pending(&self) -> usize {
        self.items.values().filter(|i| i.pending()).count()
    }

    pub fn clock_last(&self) -> Hlc {
        self.clock.last()
    }

    /// Лимит записей узла: прочитанный с сервера или, если узел еще не встречался, лимит для его создания.
    pub fn max_items(&self) -> u32 {
        self.node_max_items.unwrap_or(self.limits.max_items)
    }

    pub fn connected(&mut self, resumed: bool, max_stanza_bytes: Option<u32>) -> Output {
        self.connected = true;
        self.rejected.clear();
        self.over_limit_reported = false;
        if let Some(limit) = max_stanza_bytes {
            self.limits.max_stanza_bytes = limit;
        }
        // восстановленная сессия не теряла уведомлений, загружать узел заново не нужно
        if resumed && self.fetched {
            self.flush();
        } else {
            self.fetched = false;
            self.fetch_config(false);
            self.out.commands.push(Command::FetchAll {
                node: self.node.clone(),
            });
        }
        self.take()
    }

    /// Обрыв соединения. Ответы на отправленные публикации уже не придут, неотправленные
    /// изменения уйдут после следующего подключения.
    pub fn disconnected(&mut self) {
        self.connected = false;
        self.publishing.clear();
        self.fetching_config = None;
        self.configuring = None;
    }

    /// Сессия завершена без возможности восстановления: узел нужно загрузить заново.
    pub fn session_lost(&mut self) {
        self.disconnected();
        self.fetched = false;
        self.node_exists = None;
    }

    pub fn items_fetched(&mut self, items: Vec<RemoteItem>, now_ms: u64) -> Output {
        let present: BTreeSet<String> = items.iter().map(|i| i.id.clone()).collect();
        for item in items {
            self.absorb(item, now_ms);
        }
        for (id, item) in &mut self.items {
            if !present.contains(id) && item.server.is_some() && !item.read_only {
                item.server = None;
                self.out.events.push(Event::warning(
                    Some(id.clone()),
                    WarningReason::MissingOnServer,
                    tr!(
                        lang::current(),
                        "the item disappeared from the server and will be published again",
                        "запись пропала с сервера и будет опубликована снова"
                    ),
                ));
            }
        }
        self.fetched = true;
        self.out.events.push(Event::Synced);
        self.flush();
        self.take()
    }

    /// Настройки узла: его max_items или None, если узла нет или настройки не прочитались.
    pub fn config_fetched(&mut self, request: u32, max_items: Option<u32>) -> Output {
        let Some((expected, repair)) = self.fetching_config else {
            return self.take();
        };
        if expected != request {
            return self.take();
        }
        self.fetching_config = None;
        match max_items {
            Some(max_items) => {
                self.node_max_items = Some(max_items);
                self.node_exists = Some(true);
                if repair {
                    // остальные параметры узла приводятся к нужным, лимит остается тем, что на сервере
                    self.configure(max_items, false);
                } else {
                    self.flush();
                }
            }
            // лимит узла неизвестен, а перенастройка с меньшим лимитом удалила бы записи на сервере
            None if repair => self.reject_all(
                WarningReason::ConfigUnreadable,
                tr!(
                    lang::current(),
                    "could not read the vault node settings",
                    "не удалось прочитать настройки узла хранилища"
                ),
            ),
            None => {
                self.node_exists = Some(false);
                self.flush();
            }
        }
        self.take()
    }

    pub fn item_notified(&mut self, item: RemoteItem, now_ms: u64) -> Output {
        let id = item.id.clone();
        self.absorb(item, now_ms);
        self.schedule(&id);
        self.take()
    }

    pub fn publish_result(&mut self, request: u32, outcome: PublishOutcome) -> Output {
        let Some((id, sent)) = self.publishing.remove(&request) else {
            return self.take();
        };
        match outcome {
            PublishOutcome::Ok => {
                // первая публикация создает узел с лимитом движка
                self.node_exists = Some(true);
                self.node_max_items.get_or_insert(self.limits.max_items);
                if let Some(item) = self.items.get_mut(&id) {
                    item.server = Some(sent);
                }
                self.schedule(&id);
            }
            // лимит узла мог поменять другой клиент, поэтому перед перенастройкой он читается с сервера
            PublishOutcome::PreconditionFailed => {
                if self.configuring.is_none() && self.fetching_config.is_none() {
                    self.fetch_config(true);
                }
            }
            PublishOutcome::Rejected(reason) => {
                self.rejected.insert(id.clone());
                // Prosody отклоняет max_items больше pep_max_items с текстом "max_items: out of bounds"
                let warning = if reason.contains("max_items") {
                    let max_items = self.max_items();
                    let detail = tr!(
                        lang::current(),
                        "the server does not accept a vault node with {0} items, the administrator needs to raise pep_max_items in Prosody to {0} ({1})",
                        "сервер не принимает узел хранилища на {0} записей, администратору нужно поднять pep_max_items в Prosody до {0} ({1})",
                        max_items,
                        reason
                    );
                    let reason = WarningReason::NodeLimitRejected {
                        max_items,
                        server_error: reason,
                    };
                    Event::warning(Some(id), reason, detail)
                } else {
                    let detail = tr!(
                        lang::current(),
                        "the server rejected publishing the item: {}",
                        "сервер отклонил публикацию записи: {}",
                        reason
                    );
                    Event::warning(
                        Some(id),
                        WarningReason::PublishRejected { server_error: reason },
                        detail,
                    )
                };
                self.out.events.push(warning);
            }
        }
        self.take()
    }

    pub fn configure_result(&mut self, request: u32, ok: bool) -> Output {
        let Some(configuring) = self.configuring.filter(|c| c.request == request) else {
            return self.take();
        };
        self.configuring = None;
        if ok {
            self.node_max_items = Some(configuring.max_items);
            self.node_exists = Some(true);
            self.flush();
        } else if configuring.requested {
            self.out.events.push(Event::warning(
                None,
                WarningReason::MaxItemsRejected {
                    max_items: configuring.max_items,
                },
                tr!(
                    lang::current(),
                    "the server did not accept the node limit of {} items: pep_max_items on the server is lower, the administrator needs to raise it",
                    "сервер не принял лимит узла {} записей: на сервере pep_max_items меньше, администратору нужно его поднять",
                    configuring.max_items
                ),
            ));
            self.flush();
        } else {
            // без настройки узла публикации снова получат отказ, повтор - после переподключения
            self.reject_all(
                WarningReason::ConfigRejected,
                tr!(
                    lang::current(),
                    "the server did not allow changing the vault node settings",
                    "сервер не дал изменить настройки узла хранилища"
                ),
            );
        }
        self.take()
    }

    /// Новый лимит записей узла. Узел перенастраивается сразу, поэтому нужна связь с сервером.
    /// Лимит меньше числа записей не принимается: при уменьшении Prosody удаляет из узла самые старые записи.
    pub fn set_max_items(&mut self, max_items: u32) -> Result<Output, CoreError> {
        let count = self.items.len().max(1);
        if (max_items as usize) < count {
            return Err(CoreError::MaxItemsTooSmall(count as u32));
        }
        let Some(exists) = self.node_exists.filter(|_| self.connected && self.fetched) else {
            return Err(CoreError::NotConnected);
        };
        self.limits.max_items = max_items;
        if exists {
            // ответ на прежний запрос настроек перенастроил бы узел со старым лимитом
            self.fetching_config = None;
            self.configure(max_items, true);
        } else {
            self.node_max_items = Some(max_items);
            self.flush();
        }
        Ok(self.take())
    }

    /// Новая запись. Ее id возвращается в `Output::item_id`.
    pub fn create(&mut self, kind: &str, fields: BTreeMap<String, String>, now_ms: u64) -> Result<Output, CoreError> {
        if self.items.len() >= self.max_items() as usize {
            return Err(CoreError::VaultFull(self.max_items()));
        }
        let id = new_item_id(now_ms)?;
        let record = Record::new(kind, fields, &mut self.clock, now_ms);
        self.items.insert(
            id.clone(),
            Item {
                local: Some(record),
                server: None,
                read_only: false,
            },
        );
        self.out.events.push(Event::ItemChanged { item_id: id.clone() });
        self.schedule(&id);
        Ok(Output {
            item_id: Some(id),
            ..self.take()
        })
    }

    /// Зашифрованный экспорт всех записей хранилища, включая удаленные и неотправленные изменения.
    pub fn export(&self, password: &str, now_ms: u64) -> Result<String, CoreError> {
        crate::export::seal(
            &self.vault.id,
            self.records().map(|(id, record, _)| (id, record)),
            password,
            now_ms,
        )
    }

    /// Импорт файла экспорта - слияние по HLC, как при синхронизации: повторный импорт ничего
    /// не меняет, более новые правки этого хранилища не затираются. Новые и измененные записи
    /// публикуются. Файл может быть из другого хранилища: записи шифруются ключом этого.
    pub fn import(&mut self, file: &str, password: &str, now_ms: u64) -> Result<Output, CoreError> {
        let imported = crate::export::open(file, password)?;
        let new = imported
            .ids()
            .into_iter()
            .filter(|id| !self.items.contains_key(*id))
            .count();
        if self.items.len() + new > self.max_items() as usize {
            return Err(CoreError::VaultFull(self.max_items()));
        }
        let mut stats = ImportStats {
            skipped: imported.skipped,
            ..ImportStats::default()
        };
        for (id, record) in imported.records {
            let max_ts = record.max_ts();
            if max_ts.wall_ms > now_ms.saturating_add(CLOCK_AHEAD_LIMIT_MS) {
                self.out.events.push(clock_ahead(&id, max_ts));
            }
            self.clock.observe(max_ts, now_ms);
            let item = self.items.entry(id.clone()).or_default();
            if item.read_only {
                stats.skipped += 1;
                continue;
            }
            let merged = match &item.local {
                Some(local) => local.merge(&record),
                None => record,
            };
            match &item.local {
                Some(local) if *local == merged => {
                    stats.unchanged += 1;
                    continue;
                }
                Some(_) => stats.updated += 1,
                None => stats.added += 1,
            }
            item.local = Some(merged);
            self.out.events.push(Event::ItemChanged { item_id: id.clone() });
            self.schedule(&id);
        }
        Ok(Output {
            imported: Some(stats),
            ..self.take()
        })
    }

    pub fn set_field(&mut self, item_id: &str, name: &str, value: &str, now_ms: u64) -> Result<Output, CoreError> {
        self.update(item_id, |record, clock| {
            record.set(name, value, clock, now_ms);
            Ok(())
        })
    }

    /// Несколько изменений записи одной операцией: одна новая версия и одна публикация.
    /// Теги проверяются заранее, чтобы ошибка не оставила запись измененной наполовину.
    pub fn edit(
        &mut self,
        item_id: &str,
        fields: &BTreeMap<String, String>,
        tags: &BTreeMap<String, bool>,
        now_ms: u64,
    ) -> Result<Output, CoreError> {
        for tag in tags.keys() {
            validate_tag(tag)?;
        }
        self.update(item_id, |record, clock| {
            for (name, value) in fields {
                record.set(name, value, clock, now_ms);
            }
            for (tag, on) in tags {
                record.set_tag(tag, *on, clock, now_ms)?;
            }
            Ok(())
        })
    }

    pub fn set_tag(&mut self, item_id: &str, tag: &str, on: bool, now_ms: u64) -> Result<Output, CoreError> {
        self.update(item_id, |record, clock| record.set_tag(tag, on, clock, now_ms))
    }

    pub fn delete_item(&mut self, item_id: &str, now_ms: u64) -> Result<Output, CoreError> {
        self.update(item_id, |record, clock| {
            record.delete(clock, now_ms);
            Ok(())
        })
    }

    pub fn restore_item(&mut self, item_id: &str, now_ms: u64) -> Result<Output, CoreError> {
        self.update(item_id, |record, clock| {
            record.restore(clock, now_ms);
            Ok(())
        })
    }

    /// Очистка корзины: каждая удаленная запись заменяется заглушкой без содержимого и
    /// публикуется. Записи, доступные только для чтения, остаются.
    pub fn purge_trash(&mut self, now_ms: u64) -> Output {
        let ids: Vec<String> = self
            .items
            .iter()
            .filter(|(_, item)| {
                !item.read_only && item.local.as_ref().is_some_and(|r| r.is_deleted() && !r.is_purged())
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Some(record) = self.items.get_mut(&id).and_then(|i| i.local.as_mut()) {
                record.purge(&mut self.clock, now_ms);
            }
            self.out.events.push(Event::ItemChanged { item_id: id.clone() });
            self.schedule(&id);
        }
        self.take()
    }

    fn update(
        &mut self,
        item_id: &str,
        change: impl FnOnce(&mut Record, &mut Clock) -> Result<(), CoreError>,
    ) -> Result<Output, CoreError> {
        let item = self.items.get_mut(item_id).ok_or(CoreError::NotFound)?;
        if item.read_only {
            return Err(CoreError::ReadOnly);
        }
        let record = item.local.as_mut().ok_or(CoreError::ReadOnly)?;
        if record.is_purged() {
            return Err(CoreError::NotFound);
        }
        let before = record.clone();
        change(record, &mut self.clock)?;
        if *record != before {
            self.out.events.push(Event::ItemChanged {
                item_id: item_id.to_owned(),
            });
            self.schedule(item_id);
        }
        Ok(self.take())
    }

    fn absorb(&mut self, remote: RemoteItem, now_ms: u64) {
        let id = remote.id.clone();
        let item = self.items.entry(id.clone()).or_default();
        let decoded = BASE64
            .decode(remote.ciphertext.as_bytes())
            .map_err(|_| CoreError::InvalidFormat)
            .and_then(|ct| decrypt_item(self.vault.key.as_ref(), &self.vault.id, &id, remote.key_version, &ct));
        let record = decoded.and_then(|plain| Record::from_json(&plain));
        match record {
            Ok(record) => {
                let max_ts = record.max_ts();
                if max_ts.wall_ms > now_ms.saturating_add(CLOCK_AHEAD_LIMIT_MS) {
                    self.out.events.push(clock_ahead(&id, max_ts));
                }
                self.clock.observe(max_ts, now_ms);
                let merged = match &item.local {
                    Some(local) => local.merge(&record),
                    None => record.clone(),
                };
                item.server = Some(record);
                item.read_only = false;
                if item.local.as_ref() != Some(&merged) {
                    item.local = Some(merged);
                    self.out.events.push(Event::ItemChanged { item_id: id });
                }
            }
            Err(CoreError::UnsupportedRecord(v)) => {
                item.read_only = true;
                self.out.events.push(Event::warning(
                    Some(id),
                    WarningReason::UnsupportedRecord { version: v },
                    tr!(
                        lang::current(),
                        "record format {} is newer than the client",
                        "формат записи {} новее клиента",
                        v
                    ),
                ));
            }
            Err(err) => {
                // если локальная версия есть, она будет опубликована вместо поврежденной
                item.server = None;
                self.out.events.push(Event::warning(
                    Some(id),
                    WarningReason::Unreadable {
                        error: err.code().to_owned(),
                    },
                    err.to_string(),
                ));
            }
        }
    }

    fn fetch_config(&mut self, repair: bool) {
        let request = self.request();
        self.fetching_config = Some((request, repair));
        self.out.commands.push(Command::FetchConfig {
            request,
            node: self.node.clone(),
        });
    }

    fn configure(&mut self, max_items: u32, requested: bool) {
        let request = self.request();
        self.configuring = Some(Configuring {
            request,
            max_items,
            requested,
        });
        self.out.commands.push(Command::ConfigureNode {
            request,
            node: self.node.clone(),
            max_items,
        });
    }

    fn reject_all(&mut self, reason: WarningReason, detail: String) {
        self.rejected.extend(self.items.keys().cloned());
        self.out.events.push(Event::warning(None, reason, detail));
    }

    fn flush(&mut self) {
        let ids: Vec<String> = self.items.keys().cloned().collect();
        for id in ids {
            self.schedule(&id);
        }
    }

    fn schedule(&mut self, id: &str) {
        if !self.connected || !self.fetched || self.configuring.is_some() || self.rejected.contains(id) {
            return;
        }
        // в узле больше записей, чем его лимит: каждая публикация вытесняла бы с сервера самую старую запись
        if self.items.len() > self.max_items() as usize {
            if !self.over_limit_reported {
                self.over_limit_reported = true;
                let (items, max_items) = (self.items.len() as u32, self.max_items());
                self.out.events.push(Event::warning(
                    None,
                    WarningReason::OverLimit { items, max_items },
                    tr!(
                        lang::current(),
                        "the vault has {} items, but the node limit on the server is {}: changes are not sent, the node limit needs to be raised",
                        "в хранилище {} записей, а лимит узла на сервере {}: изменения не отправляются, нужно поднять лимит узла",
                        items,
                        max_items
                    ),
                ));
            }
            return;
        }
        if self.publishing.values().any(|(item_id, _)| item_id == id) {
            return;
        }
        let Some(item) = self.items.get(id).filter(|i| i.pending()) else {
            return;
        };
        let record = item.local.clone().expect("pending означает наличие локальной версии");
        let sealed = encrypt_item(
            self.vault.key.as_ref(),
            &self.vault.id,
            id,
            self.vault.key_version,
            &record.to_json(),
        );
        let ciphertext = match sealed {
            Ok(ct) => BASE64.encode(ct),
            Err(err) => {
                self.out.events.push(Event::warning(
                    Some(id.to_owned()),
                    WarningReason::EncryptFailed {
                        error: err.code().to_owned(),
                    },
                    err.to_string(),
                ));
                return;
            }
        };
        if ciphertext.len() + STANZA_OVERHEAD > self.limits.max_stanza_bytes as usize {
            self.rejected.insert(id.to_owned());
            let (bytes, max_bytes) = (ciphertext.len() as u32, self.limits.max_stanza_bytes);
            self.out.events.push(Event::warning(
                Some(id.to_owned()),
                WarningReason::TooLarge { bytes, max_bytes },
                tr!(
                    lang::current(),
                    "the item of {} bytes exceeds the server limit of {}",
                    "запись {} байт больше лимита сервера {}",
                    bytes,
                    max_bytes
                ),
            ));
            return;
        }
        let request = self.request();
        self.publishing.insert(request, (id.to_owned(), record));
        self.out.commands.push(Command::Publish {
            request,
            node: self.node.clone(),
            max_items: self.max_items(),
            item: RemoteItem {
                id: id.to_owned(),
                key_version: self.vault.key_version,
                ciphertext,
            },
        });
    }

    fn request(&mut self) -> u32 {
        self.next_request = self.next_request.wrapping_add(1);
        self.next_request
    }

    fn take(&mut self) -> Output {
        std::mem::take(&mut self.out)
    }
}

/// Идентификатор записи UUIDv7: время создания в миллисекундах и 74 случайных бита.
/// Время передается снаружи, потому что в WASM системных часов нет.
fn clock_ahead(item_id: &str, hlc: Hlc) -> Event {
    Event::warning(
        Some(item_id.to_owned()),
        WarningReason::ClockAhead { hlc: hlc.to_string() },
        tr!(
            lang::current(),
            "timestamp {} is more than a day ahead of the device clock",
            "метка {} опережает часы устройства больше чем на сутки",
            hlc
        ),
    )
}

pub fn new_item_id(now_ms: u64) -> Result<String, CoreError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b[6..]).map_err(|_| CoreError::Random)?;
    b[..6].copy_from_slice(&now_ms.to_be_bytes()[2..]);
    b[6] = 0x70 | (b[6] & 0x0f);
    b[8] = 0x80 | (b[8] & 0x3f);
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Ключ хранилища из байтов, полученных после снятия обертки.
pub fn vault_key(id: &str, key_version: u32, key: &[u8]) -> Result<VaultKey, CoreError> {
    let bytes: [u8; KEY_LEN] = key.try_into().map_err(|_| CoreError::InvalidKey)?;
    Ok(VaultKey {
        id: id.to_owned(),
        key_version,
        key: zeroize::Zeroizing::new(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(device: u64) -> SyncEngine {
        SyncEngine::new(
            vault_key("vault-1", 1, &[7u8; 32]).unwrap(),
            "urn:inkvault:vault:0",
            device,
            Limits::default(),
        )
    }

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn published(out: &Output) -> Vec<(u32, RemoteItem)> {
        out.commands
            .iter()
            .filter_map(|c| match c {
                Command::Publish { request, item, .. } => Some((*request, item.clone())),
                _ => None,
            })
            .collect()
    }

    fn record_of(e: &SyncEngine, id: &str) -> Record {
        e.records().find(|(i, _, _)| *i == id).unwrap().1.clone()
    }

    fn config_request(out: &Output) -> u32 {
        out.commands
            .iter()
            .find_map(|c| match c {
                Command::FetchConfig { request, .. } => Some(*request),
                _ => None,
            })
            .unwrap_or_else(|| panic!("нет запроса настроек узла: {out:?}"))
    }

    /// Подключение к узлу с лимитом node_max_items (None - узла нет) и пустой загрузкой.
    fn online(e: &mut SyncEngine, node_max_items: Option<u32>) -> Output {
        let out = e.connected(false, None);
        e.config_fetched(config_request(&out), node_max_items);
        e.items_fetched(vec![], 1_000)
    }

    fn warnings(out: &Output) -> Vec<WarningReason> {
        out.events
            .iter()
            .filter_map(|ev| match ev {
                Event::Warning { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn export_import_round_trip_into_another_vault() {
        let mut a = engine(1);
        let github = a
            .create("login", fields(&[("name", "github.com"), ("password", "p1")]), 1_000)
            .unwrap()
            .item_id
            .unwrap();
        a.edit(
            &github,
            &fields(&[("password", "p2")]),
            &BTreeMap::from([("работа".to_owned(), true)]),
            2_000,
        )
        .unwrap();
        let deleted = a
            .create("login", fields(&[("name", "old")]), 3_000)
            .unwrap()
            .item_id
            .unwrap();
        a.delete_item(&deleted, 4_000).unwrap();
        let file = a.export("export-password", 5_000).unwrap();
        // короткая строка вроде пароля может случайно встретиться в base64, название - нет
        assert!(!file.contains("github.com"));

        let mut b = SyncEngine::new(
            vault_key("vault-2", 1, &[9u8; 32]).unwrap(),
            "urn:inkvault:vault:0",
            2,
            Limits::default(),
        );
        b.connected(false, None);
        b.items_fetched(vec![], 6_000);
        let out = b.import(&file, "export-password", 6_000).unwrap();
        assert_eq!(
            out.imported,
            Some(ImportStats {
                added: 2,
                ..ImportStats::default()
            })
        );
        // записи публикуются под ключом второго хранилища
        assert_eq!(published(&out).len(), 2);
        assert_eq!(record_of(&b, &github), record_of(&a, &github));
        assert_eq!(record_of(&b, &github).history.len(), 1);
        assert!(record_of(&b, &deleted).is_deleted());

        let again = b.import(&file, "export-password", 7_000).unwrap();
        assert_eq!(
            again.imported,
            Some(ImportStats {
                unchanged: 2,
                ..ImportStats::default()
            })
        );
        assert!(again.events.is_empty() && again.commands.is_empty());
    }

    #[test]
    fn import_keeps_newer_local_changes() {
        let mut a = engine(1);
        let id = a
            .create("login", fields(&[("name", "a"), ("username", "old")]), 1_000)
            .unwrap()
            .item_id
            .unwrap();
        let file = a.export("pw", 2_000).unwrap();
        a.set_field(&id, "username", "new", 3_000).unwrap();
        let out = a.import(&file, "pw", 4_000).unwrap();
        assert_eq!(out.imported.unwrap().unchanged, 1);
        assert_eq!(record_of(&a, &id).get("username"), Some("new"));
    }

    #[test]
    fn export_file_errors() {
        let mut a = engine(1);
        a.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        assert_eq!(a.export("", 2_000).err(), Some(CoreError::EmptyPassword));
        let file = a.export("pw", 2_000).unwrap();
        assert_eq!(
            a.import(&file, "wrong", 3_000).err(),
            Some(CoreError::WrongExportPassword)
        );
        assert!(matches!(a.import("{}", "pw", 3_000), Err(CoreError::InvalidExport(_))));
        assert!(matches!(
            a.import("not json", "pw", 3_000),
            Err(CoreError::InvalidExport(_))
        ));

        let mut envelope: serde_json::Value = serde_json::from_str(&file).unwrap();
        // параметры KDF входят в AAD: подмена в пределах границ дает ошибку расшифровки
        envelope["kdf"]["t"] = 4.into();
        assert_eq!(
            a.import(&envelope.to_string(), "pw", 3_000).err(),
            Some(CoreError::WrongExportPassword)
        );
        // параметры вне границ отклоняются до Argon2id
        envelope["kdf"]["m"] = (4u32 * 1024 * 1024).into();
        assert_eq!(
            a.import(&envelope.to_string(), "pw", 3_000).err(),
            Some(CoreError::InvalidKdfParams)
        );
        envelope["v"] = 2.into();
        assert!(matches!(
            a.import(&envelope.to_string(), "pw", 3_000),
            Err(CoreError::InvalidExport(_))
        ));
    }

    #[test]
    fn import_respects_vault_limit() {
        let mut a = engine(1);
        for i in 0..3 {
            a.create("login", fields(&[("name", &i.to_string())]), 1_000 + i)
                .unwrap();
        }
        let file = a.export("pw", 2_000).unwrap();
        let limits = Limits {
            max_items: 2,
            ..Limits::default()
        };
        let mut b = SyncEngine::new(
            vault_key("vault-2", 1, &[9u8; 32]).unwrap(),
            "urn:inkvault:vault:0",
            2,
            limits,
        );
        assert_eq!(b.import(&file, "pw", 3_000).err(), Some(CoreError::VaultFull(2)));
        assert_eq!(b.records().count(), 0);
    }

    #[test]
    fn item_id_is_uuid_v7() {
        let id = new_item_id(0x0192_a3f4_5678).unwrap();
        assert_eq!(id.len(), 36);
        assert!(id.starts_with("0192a3f4-5678-7"));
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn nothing_is_published_before_fetch() {
        let mut e = engine(1);
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let id = out.item_id.clone().unwrap();
        assert!(out.commands.is_empty());
        let out = e.connected(false, None);
        assert_eq!(
            out.commands,
            [
                Command::FetchConfig {
                    request: 1,
                    node: "urn:inkvault:vault:0".to_owned()
                },
                Command::FetchAll {
                    node: "urn:inkvault:vault:0".to_owned()
                }
            ]
        );
        e.config_fetched(1, None);
        let out = e.items_fetched(vec![], 1_001);
        let p = published(&out);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].1.id, id);
        assert_eq!(e.pending(), 1);
        e.publish_result(p[0].0, PublishOutcome::Ok);
        assert_eq!(e.pending(), 0);
    }

    #[test]
    fn small_pep_max_items_is_reported_clearly() {
        let mut e = engine(1);
        e.connected(false, None);
        e.items_fetched(vec![], 1_000);
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let (request, _) = published(&out)[0].clone();
        let out = e.publish_result(
            request,
            PublishOutcome::from_error(Some("bad-request: max_items: out of bounds")),
        );
        assert_eq!(
            warnings(&out),
            [WarningReason::NodeLimitRejected {
                max_items: 256,
                server_error: "bad-request: max_items: out of bounds".to_owned(),
            }]
        );
        assert_eq!(e.pending(), 1);
        // условие с текстом сервера распознается так же, как без него
        assert_eq!(
            PublishOutcome::from_error(Some("precondition-not-met: Field does not match: max_items")),
            PublishOutcome::PreconditionFailed
        );
    }

    #[test]
    fn precondition_failure_reconfigures_node_with_its_own_limit() {
        let mut e = engine(1);
        online(&mut e, Some(DEFAULT_MAX_ITEMS));
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let (request, _) = published(&out)[0].clone();
        // другой клиент поднял лимит узла, пока это устройство было в сети
        let out = e.publish_result(request, PublishOutcome::from_error(Some("precondition-not-met")));
        let out = e.config_fetched(config_request(&out), Some(5_000));
        let [
            Command::ConfigureNode {
                request: configure,
                max_items: 5_000,
                ..
            },
        ] = out.commands[..]
        else {
            panic!("{out:?}")
        };
        let out = e.configure_result(configure, true);
        assert!(matches!(out.commands[..], [Command::Publish { max_items: 5_000, .. }]));
        assert_eq!(e.max_items(), 5_000);
    }

    #[test]
    fn unknown_node_config_is_not_overwritten() {
        let mut e = engine(1);
        online(&mut e, Some(DEFAULT_MAX_ITEMS));
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let (request, _) = published(&out)[0].clone();
        let out = e.publish_result(request, PublishOutcome::PreconditionFailed);
        let out = e.config_fetched(config_request(&out), None);
        assert!(out.commands.is_empty());
        assert_eq!(warnings(&out), [WarningReason::ConfigUnreadable]);
        assert_eq!(e.pending(), 1);
    }

    #[test]
    fn node_limit_comes_from_server() {
        let mut e = SyncEngine::new(
            vault_key("vault-1", 1, &[7u8; 32]).unwrap(),
            "node",
            1,
            Limits {
                max_items: 1,
                ..Limits::default()
            },
        );
        online(&mut e, Some(3));
        for i in 0..3 {
            let out = e
                .create("login", fields(&[("name", &i.to_string())]), 1_000 + i)
                .unwrap();
            assert!(matches!(out.commands[..], [Command::Publish { max_items: 3, .. }]));
        }
        assert_eq!(
            e.create("login", fields(&[("name", "x")]), 2_000).err(),
            Some(CoreError::VaultFull(3))
        );
        // без сети место в узле проверяется по лимиту из снимка
        let restored = SyncEngine::restore(
            vault_key("vault-1", 1, &[7u8; 32]).unwrap(),
            "node",
            Limits::default(),
            &e.snapshot().unwrap(),
        )
        .unwrap();
        assert_eq!(restored.max_items(), 3);
    }

    #[test]
    fn new_node_is_created_with_default_limit() {
        let mut e = engine(1);
        online(&mut e, None);
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        assert!(matches!(
            out.commands[..],
            [Command::Publish {
                max_items: DEFAULT_MAX_ITEMS,
                ..
            }]
        ));
        e.publish_result(published(&out)[0].0, PublishOutcome::Ok);
        assert_eq!(e.max_items(), DEFAULT_MAX_ITEMS);
    }

    #[test]
    fn max_items_change() {
        let mut e = engine(1);
        e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        e.create("login", fields(&[("name", "b")]), 1_001).unwrap();
        assert_eq!(e.set_max_items(10_000).err(), Some(CoreError::NotConnected));
        let out = online(&mut e, Some(DEFAULT_MAX_ITEMS));
        for (request, _) in published(&out) {
            e.publish_result(request, PublishOutcome::Ok);
        }
        assert_eq!(e.set_max_items(1).err(), Some(CoreError::MaxItemsTooSmall(2)));

        let out = e.set_max_items(10_000).unwrap();
        let [
            Command::ConfigureNode {
                request,
                max_items: 10_000,
                ..
            },
        ] = out.commands[..]
        else {
            panic!("{out:?}")
        };
        // до ответа сервера лимит прежний
        assert_eq!(e.max_items(), DEFAULT_MAX_ITEMS);
        e.configure_result(request, true);
        assert_eq!(e.max_items(), 10_000);

        let out = e.set_max_items(20_000).unwrap();
        let Command::ConfigureNode { request, .. } = out.commands[0] else {
            panic!("{out:?}")
        };
        let out = e.configure_result(request, false);
        assert_eq!(warnings(&out), [WarningReason::MaxItemsRejected { max_items: 20_000 }]);
        assert_eq!(e.max_items(), 10_000);
        assert!(e.create("login", fields(&[("name", "c")]), 2_000).is_ok());
    }

    #[test]
    fn records_over_node_limit_are_not_published() {
        let mut e = engine(1);
        for i in 0..3 {
            e.create("login", fields(&[("name", &i.to_string())]), 1_000 + i)
                .unwrap();
        }
        let out = online(&mut e, Some(2));
        assert!(published(&out).is_empty());
        assert_eq!(warnings(&out), [WarningReason::OverLimit { items: 3, max_items: 2 }]);
        assert_eq!(e.pending(), 3);
    }

    #[test]
    fn oversized_record_is_not_published() {
        let mut e = engine(1);
        e.connected(false, Some(4 * 1024));
        e.items_fetched(vec![], 1_000);
        let out = e
            .create("login", fields(&[("notes", &"x".repeat(8 * 1024))]), 1_000)
            .unwrap();
        assert!(out.commands.is_empty());
        assert!(matches!(
            out.events.last(),
            Some(Event::Warning {
                kind: WarningKind::TooLarge,
                ..
            })
        ));
    }

    #[test]
    fn edit_publishes_once_and_validates_tags_first() {
        let mut e = engine(1);
        e.connected(false, None);
        e.items_fetched(vec![], 1_000);
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let id = out.item_id.clone().unwrap();
        e.publish_result(published(&out)[0].0, PublishOutcome::Ok);
        let tags: BTreeMap<String, bool> = [("работа".to_owned(), true), ("@favorite".to_owned(), true)].into();
        let out = e
            .edit(&id, &fields(&[("name", "b"), ("username", "u")]), &tags, 2_000)
            .unwrap();
        assert_eq!(published(&out).len(), 1);
        let record = e.record(&id).unwrap();
        assert_eq!((record.get("name"), record.has_tag("работа")), (Some("b"), true));

        let bad: BTreeMap<String, bool> = [("@archive".to_owned(), true)].into();
        let before = e.record(&id).unwrap().clone();
        assert!(e.edit(&id, &fields(&[("name", "c")]), &bad, 3_000).is_err());
        assert_eq!(e.record(&id).unwrap(), &before);
    }

    #[test]
    fn vault_full_is_reported() {
        let mut e = SyncEngine::new(
            vault_key("vault-1", 1, &[7u8; 32]).unwrap(),
            "node",
            1,
            Limits {
                max_items: 1,
                ..Limits::default()
            },
        );
        e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        assert_eq!(
            e.create("login", fields(&[("name", "b")]), 1_001).err(),
            Some(CoreError::VaultFull(1))
        );
    }

    #[test]
    fn missing_on_server_is_republished() {
        let mut e = engine(1);
        e.connected(false, None);
        e.items_fetched(vec![], 1_000);
        let out = e.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let (request, item) = published(&out)[0].clone();
        e.publish_result(request, PublishOutcome::Ok);
        e.session_lost();
        e.connected(false, None);
        let out = e.items_fetched(vec![], 2_000);
        assert!(out.events.iter().any(|ev| matches!(
            ev,
            Event::Warning {
                kind: WarningKind::MissingOnServer,
                ..
            }
        )));
        assert_eq!(published(&out)[0].1.id, item.id);
    }

    #[test]
    fn snapshot_roundtrip_and_wrong_vault_key() {
        let mut e = engine(1);
        e.create("login", fields(&[("name", "a"), ("password", "p")]), 1_000)
            .unwrap();
        let data = e.snapshot().unwrap();
        let restored = SyncEngine::restore(
            vault_key("vault-1", 1, &[7u8; 32]).unwrap(),
            "node",
            Limits::default(),
            &data,
        )
        .unwrap();
        assert_eq!(restored.records().count(), 1);
        assert_eq!(restored.pending(), 1);
        assert_eq!(restored.clock_last(), e.clock_last());
        let wrong = SyncEngine::restore(
            vault_key("vault-1", 1, &[8u8; 32]).unwrap(),
            "node",
            Limits::default(),
            &data,
        );
        assert_eq!(wrong.err(), Some(CoreError::Decrypt));
        let other_vault = SyncEngine::restore(
            vault_key("vault-2", 1, &[7u8; 32]).unwrap(),
            "node",
            Limits::default(),
            &data,
        );
        assert_eq!(other_vault.err(), Some(CoreError::Decrypt));
    }

    #[test]
    fn purged_trash_does_not_come_back_from_offline_device() {
        let mut a = engine(1);
        a.connected(false, None);
        a.items_fetched(vec![], 1_000);
        let out = a.create("login", fields(&[("name", "kept")]), 1_000).unwrap();
        let kept = out.item_id.clone().unwrap();
        let (request, kept_item) = published(&out)[0].clone();
        a.publish_result(request, PublishOutcome::Ok);
        let out = a.create("login", fields(&[("name", "old")]), 1_100).unwrap();
        let old = out.item_id.clone().unwrap();
        a.publish_result(published(&out)[0].0, PublishOutcome::Ok);
        let out = a.delete_item(&old, 2_000).unwrap();
        let (request, deleted_item) = published(&out)[0].clone();
        a.publish_result(request, PublishOutcome::Ok);

        // b видел удаление, потом без связи восстановил запись уже после очистки корзины на a
        let mut b = engine(2);
        b.connected(false, None);
        b.items_fetched(vec![kept_item.clone(), deleted_item], 2_500);
        b.session_lost();
        b.restore_item(&old, 3_500).unwrap();

        let out = a.purge_trash(3_000);
        let stubs = published(&out);
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].1.id, old);
        a.publish_result(stubs[0].0, PublishOutcome::Ok);
        assert_eq!(a.records().map(|(id, _, _)| id).collect::<Vec<_>>(), [kept.as_str()]);
        assert!(a.record(&old).unwrap().is_purged());
        assert_eq!(a.restore_item(&old, 3_100).err(), Some(CoreError::NotFound));
        assert!(a.purge_trash(3_200).commands.is_empty());
        assert_eq!(a.pending(), 0);

        b.connected(false, None);
        let out = b.items_fetched(vec![kept_item, stubs[0].1.clone()], 4_000);
        assert!(published(&out).is_empty());
        assert_eq!(b.pending(), 0);
        assert_eq!(b.records().map(|(id, _, _)| id).collect::<Vec<_>>(), [kept.as_str()]);
        let file = b.export("pw", 4_100).unwrap();
        let mut c = engine(3);
        assert_eq!(c.import(&file, "pw", 4_200).unwrap().imported.unwrap().added, 1);
    }

    #[test]
    fn foreign_record_format_is_read_only() {
        let mut a = engine(1);
        a.connected(false, None);
        a.items_fetched(vec![], 1_000);
        let out = a.create("login", fields(&[("name", "a")]), 1_000).unwrap();
        let id = out.item_id.clone().unwrap();
        let mut item = published(&out)[0].1.clone();
        let record = a
            .record(&id)
            .unwrap()
            .to_json_string()
            .replacen("\"v\":1", "\"v\":3", 1);
        let ct = encrypt_item(&[7u8; 32], "vault-1", &id, 1, record.as_bytes()).unwrap();
        item.ciphertext = BASE64.encode(ct);

        let mut b = engine(2);
        b.connected(false, None);
        let out = b.items_fetched(vec![item], 2_000);
        assert!(out.commands.is_empty());
        assert!(out.events.iter().any(|ev| matches!(
            ev,
            Event::Warning {
                kind: WarningKind::UnsupportedRecord,
                ..
            }
        )));
        assert_eq!(b.set_field(&id, "name", "x", 2_001).err(), Some(CoreError::ReadOnly));
    }
}
