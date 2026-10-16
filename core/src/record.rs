//! Запись хранилища: поля и теги с метками HLC, признак удаления и история паролей.
//!
//! Каждое поле и каждый тег - регистр "побеждает последняя запись" по метке HLC, поэтому
//! теги, добавленные на разных устройствах одновременно, сохраняются все. Слияние коммутативно,
//! ассоциативно и идемпотентно, поэтому устройства, обменявшиеся версиями в любом порядке,
//! приходят к одной записи. История паролей - множество всех вытесненных версий пароля
//! (значение и метка), поэтому одновременные правки пароля не теряются. Одно значение может
//! встретиться в истории несколько раз, повторы скрывает интерфейс.
//!
//! JSON записи канонический: поля упорядочены, история отсортирована. Одинаковые записи
//! дают одинаковые байты на всех платформах.
//!
//! Очистка корзины заменяет запись заглушкой без содержимого (формат `PURGED_FORMAT`).
//! Заглушка побеждает при слиянии любую версию записи: устройство, которое было офлайн,
//! получает ее с сервера и не возвращает запись.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::hlc::{Clock, Hlc};

pub const RECORD_FORMAT: u32 = 1;
/// Заглушка записи, удаленной из корзины навсегда: поля, теги и история пустые, в `deleted`
/// метка очистки. Структура та же, что у формата 1, поэтому клиент, знающий только формат 1,
/// разбирает заглушку как запись нового формата и не публикует поверх нее свою версию.
pub const PURGED_FORMAT: u32 = 2;
pub const HISTORY_LIMIT: usize = 32;
pub const PASSWORD: &str = "password";
/// Служебные теги начинаются с '@' и не пересекаются с пользовательскими.
pub const FAVORITE_TAG: &str = "@favorite";
pub const TAG_MAX_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub value: String,
    pub ts: Hlc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flag {
    pub value: bool,
    pub ts: Hlc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub value: String,
    /// Метка, с которой значение было установлено. Она уникальна и служит ключом записи истории.
    pub set_at: Hlc,
}

// Новые ключи верхнего уровня добавляются только с повышением RECORD_FORMAT: старый клиент
// отклонит такую запись, а не потеряет незнакомые данные при повторной публикации
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub fields: BTreeMap<String, Field>,
    /// Снятый тег остается со значением false: иначе устройство, не видевшее снятия, вернуло бы его.
    #[serde(default)]
    pub tags: BTreeMap<String, Flag>,
    pub deleted: Flag,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

impl Record {
    pub fn new<I, K, V>(kind: &str, fields: I, clock: &mut Clock, now_ms: u64) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let ts = clock.tick(now_ms);
        Self {
            v: RECORD_FORMAT,
            kind: kind.to_owned(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), Field { value: v.into(), ts }))
                .collect(),
            tags: BTreeMap::new(),
            deleted: Flag { value: false, ts },
            history: Vec::new(),
        }
    }

    /// Новая запись из JSON-объекта {"имя поля": "значение"}: в таком виде поля передают JS и Kotlin.
    pub fn new_from_json(kind: &str, fields_json: &str, clock: &mut Clock, now_ms: u64) -> Result<Self, CoreError> {
        let fields: BTreeMap<String, String> =
            serde_json::from_str(fields_json).map_err(|e| CoreError::InvalidRecord(e.to_string()))?;
        Ok(Self::new(kind, fields, clock, now_ms))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|f| f.value.as_str())
    }

    /// Пустая строка очищает поле: так очистка тоже сливается по метке, как обычная правка.
    /// Отсутствующее поле уже пустое: форма клиента с новым полем не меняет старые записи.
    pub fn set(&mut self, name: &str, value: &str, clock: &mut Clock, now_ms: u64) {
        if self.is_purged() || self.get(name).unwrap_or_default() == value {
            return;
        }
        let field = Field {
            value: value.to_owned(),
            ts: clock.tick(now_ms),
        };
        if let Some(old) = self.fields.insert(name.to_owned(), field)
            && name == PASSWORD
        {
            self.history.push(HistoryEntry {
                value: old.value,
                set_at: old.ts,
            });
            self.history = normalize_history(std::mem::take(&mut self.history), self.fields.get(PASSWORD));
        }
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.get(tag).is_some_and(|t| t.value)
    }

    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.tags.iter().filter(|(_, t)| t.value).map(|(name, _)| name.as_str())
    }

    /// Иерархия тегов задается через '/', например "работа/серверы".
    pub fn set_tag(&mut self, tag: &str, on: bool, clock: &mut Clock, now_ms: u64) -> Result<(), CoreError> {
        validate_tag(tag)?;
        if !self.is_purged() && self.has_tag(tag) != on {
            self.tags.insert(
                tag.to_owned(),
                Flag {
                    value: on,
                    ts: clock.tick(now_ms),
                },
            );
        }
        Ok(())
    }

    pub fn delete(&mut self, clock: &mut Clock, now_ms: u64) {
        if !self.deleted.value {
            self.deleted = Flag {
                value: true,
                ts: clock.tick(now_ms),
            };
        }
    }

    pub fn restore(&mut self, clock: &mut Clock, now_ms: u64) {
        if self.deleted.value && !self.is_purged() {
            self.deleted = Flag {
                value: false,
                ts: clock.tick(now_ms),
            };
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted.value
    }

    pub fn is_purged(&self) -> bool {
        self.v == PURGED_FORMAT
    }

    /// Окончательное удаление: содержимое стирается, восстановить запись нельзя.
    pub fn purge(&mut self, clock: &mut Clock, now_ms: u64) {
        if !self.is_purged() {
            *self = Self::stub(&self.kind, clock.tick(now_ms));
        }
    }

    fn stub(kind: &str, ts: Hlc) -> Self {
        Self {
            v: PURGED_FORMAT,
            kind: kind.to_owned(),
            fields: BTreeMap::new(),
            tags: BTreeMap::new(),
            deleted: Flag { value: true, ts },
            history: Vec::new(),
        }
    }

    /// Наибольшая метка записи. Ее передают в `Clock::observe` после получения записи с сервера.
    pub fn max_ts(&self) -> Hlc {
        self.fields
            .values()
            .map(|f| f.ts)
            .chain(self.tags.values().map(|t| t.ts))
            .chain(self.history.iter().map(|h| h.set_at))
            .fold(self.deleted.ts, Hlc::max)
    }

    pub fn merge(&self, other: &Record) -> Record {
        // заглушка побеждает любую версию, даже правку или восстановление после очистки корзины
        match (self.is_purged(), other.is_purged()) {
            (true, true) if (&other.deleted.ts, &other.kind) > (&self.deleted.ts, &self.kind) => return other.clone(),
            (true, _) => return self.clone(),
            (false, true) => return other.clone(),
            (false, false) => {}
        }
        let mut history: Vec<HistoryEntry> = self.history.iter().chain(&other.history).cloned().collect();
        let mut fields = self.fields.clone();
        for (name, theirs) in &other.fields {
            let Some(ours) = fields.get(name) else {
                fields.insert(name.clone(), theirs.clone());
                continue;
            };
            let (winner, loser) = if newer(theirs, ours) {
                (theirs, ours)
            } else {
                (ours, theirs)
            };
            // в историю идет каждая вытесненная версия, даже с тем же значением: иначе состав
            // истории зависел бы от порядка слияний
            if name == PASSWORD && winner != loser {
                history.push(HistoryEntry {
                    value: loser.value.clone(),
                    set_at: loser.ts,
                });
            }
            let winner = winner.clone();
            fields.insert(name.clone(), winner);
        }
        let mut tags = self.tags.clone();
        for (name, theirs) in &other.tags {
            let merged = tags.get(name).map_or(theirs, |ours| later(ours, theirs)).clone();
            tags.insert(name.clone(), merged);
        }
        let deleted = later(&self.deleted, &other.deleted).clone();
        let history = normalize_history(history, fields.get(PASSWORD));
        Record {
            v: RECORD_FORMAT,
            kind: self.kind.clone().min(other.kind.clone()),
            fields,
            tags,
            deleted,
            history,
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        self.to_json_string().into_bytes()
    }

    pub fn to_json_string(&self) -> String {
        // сериализация структуры из строк, меток и BTreeMap не может завершиться ошибкой
        serde_json::to_string(self).expect("запись сериализуется в JSON")
    }

    pub fn from_json(data: &[u8]) -> Result<Record, CoreError> {
        let mut record: Record = serde_json::from_slice(data).map_err(|e| CoreError::InvalidRecord(e.to_string()))?;
        match record.v {
            RECORD_FORMAT => {
                record.history = normalize_history(std::mem::take(&mut record.history), record.fields.get(PASSWORD));
                Ok(record)
            }
            // содержимое заглушки отбрасывается, даже если его записал клиент с ошибкой
            PURGED_FORMAT => Ok(Self::stub(&record.kind, record.deleted.ts)),
            v => Err(CoreError::UnsupportedRecord(v)),
        }
    }
}

// Метки уникальны, сравнение значений нужно только для детерминизма при ошибке в данных
fn newer(a: &Field, b: &Field) -> bool {
    (a.ts, &a.value) > (b.ts, &b.value)
}

fn later<'a>(a: &'a Flag, b: &'a Flag) -> &'a Flag {
    if (b.ts, b.value) > (a.ts, a.value) { b } else { a }
}

/// Проверка тега, который ставит пользователь. Теги из полученных записей не проверяются:
/// незнакомые служебные теги более новых клиентов должны сохраняться.
pub fn validate_tag(tag: &str) -> Result<(), CoreError> {
    let valid = if tag.starts_with('@') {
        tag == FAVORITE_TAG
    } else {
        tag.len() <= TAG_MAX_LEN && tag.split('/').all(|part| !part.is_empty() && part.trim() == part)
    };
    if valid {
        Ok(())
    } else {
        Err(CoreError::InvalidTag(tag.to_owned()))
    }
}

// Сначала новые, без повторов и без текущего пароля, не длиннее HISTORY_LIMIT
fn normalize_history(mut history: Vec<HistoryEntry>, current: Option<&Field>) -> Vec<HistoryEntry> {
    history.sort_by(|a, b| b.set_at.cmp(&a.set_at).then_with(|| b.value.cmp(&a.value)));
    history.dedup();
    if let Some(current) = current {
        history.retain(|h| !(h.set_at == current.ts && h.value == current.value));
    }
    history.truncate(HISTORY_LIMIT);
    history
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(node: u64) -> Clock {
        Clock::new(node)
    }

    fn login(clock: &mut Clock, now: u64) -> Record {
        Record::new(
            "login",
            [("name", "github.com"), ("username", "alice"), ("password", "p1")],
            clock,
            now,
        )
    }

    #[test]
    fn set_same_value_does_not_change_record() {
        let mut a = device(1);
        let mut r = login(&mut a, 1_000);
        let before = r.clone();
        r.set("name", "github.com", &mut a, 2_000);
        r.set("totp", "", &mut a, 2_000);
        assert_eq!(r, before);
    }

    #[test]
    fn password_change_goes_to_history() {
        let mut a = device(1);
        let mut r = login(&mut a, 1_000);
        r.set(PASSWORD, "p2", &mut a, 2_000);
        r.set("name", "GitHub", &mut a, 3_000);
        assert_eq!(r.get(PASSWORD), Some("p2"));
        assert_eq!(r.history.len(), 1);
        assert_eq!(r.history[0].value, "p1");
    }

    #[test]
    fn concurrent_edits_of_different_fields_both_survive() {
        let (mut a, mut b) = (device(1), device(2));
        let base = login(&mut a, 1_000);
        let (mut ra, mut rb) = (base.clone(), base);
        ra.set("username", "alice2", &mut a, 2_000);
        rb.set("notes", "2fa on", &mut b, 2_000);
        let m = ra.merge(&rb);
        assert_eq!((m.get("username"), m.get("notes")), (Some("alice2"), Some("2fa on")));
        assert_eq!(m, rb.merge(&ra));
    }

    #[test]
    fn concurrent_password_edits_keep_loser_in_history() {
        let (mut a, mut b) = (device(1), device(2));
        let base = login(&mut a, 1_000);
        let (mut ra, mut rb) = (base.clone(), base);
        ra.set(PASSWORD, "from-a", &mut a, 2_000);
        rb.set(PASSWORD, "from-b", &mut b, 2_500);
        let m = ra.merge(&rb);
        assert_eq!(m.get(PASSWORD), Some("from-b"));
        let history: Vec<&str> = m.history.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(history, ["from-a", "p1"]);
    }

    #[test]
    fn delete_wins_over_older_edit_and_restore_wins_later() {
        let (mut a, mut b) = (device(1), device(2));
        let base = login(&mut a, 1_000);
        let (mut ra, mut rb) = (base.clone(), base);
        rb.set("notes", "edited offline", &mut b, 2_000);
        ra.delete(&mut a, 3_000);
        let mut m = ra.merge(&rb);
        assert!(m.is_deleted());
        assert_eq!(m.get("notes"), Some("edited offline"));
        b.observe(m.max_ts(), 3_001);
        m.restore(&mut b, 3_001);
        assert!(!m.merge(&ra).is_deleted());
    }

    #[test]
    fn purge_wins_over_any_version_and_drops_content() {
        let (mut a, mut b) = (device(1), device(2));
        let mut base = login(&mut a, 1_000);
        base.set(PASSWORD, "p2", &mut a, 1_500);
        base.delete(&mut a, 2_000);
        let (mut ra, mut rb) = (base.clone(), base);
        ra.purge(&mut a, 3_000);
        // правка и восстановление на устройстве, которое не видело очистки, позже нее
        rb.restore(&mut b, 4_000);
        rb.set("notes", "after purge", &mut b, 4_100);
        let m = ra.merge(&rb);
        assert_eq!(m, rb.merge(&ra));
        assert!(m.is_purged() && m.is_deleted());
        assert!(m.fields.is_empty() && m.tags.is_empty() && m.history.is_empty());
        assert_eq!(m, ra);

        let mut later = rb.clone();
        later.purge(&mut b, 5_000);
        assert_eq!(ra.merge(&later), later);
        assert_eq!(later.merge(&ra), later);
    }

    #[test]
    fn purged_json_round_trip_and_content_is_dropped() {
        let mut a = device(1);
        let mut r = login(&mut a, 1_000);
        r.delete(&mut a, 2_000);
        r.purge(&mut a, 3_000);
        let json = r.to_json();
        assert!(String::from_utf8(json.clone()).unwrap().starts_with("{\"v\":2,"));
        assert_eq!(Record::from_json(&json).unwrap(), r);

        let with_content = login(&mut a, 4_000).to_json_string().replacen("\"v\":1", "\"v\":2", 1);
        let stub = Record::from_json(with_content.as_bytes()).unwrap();
        assert!(stub.is_purged() && stub.is_deleted() && stub.fields.is_empty());
    }

    #[test]
    fn unknown_field_names_are_preserved() {
        let (mut a, mut b) = (device(1), device(2));
        let base = login(&mut a, 1_000);
        let mut newer_client = base.clone();
        newer_client.set("x-totp", "otpauth://totp/alice", &mut b, 2_000);
        let mut old_client = base;
        old_client.set("username", "alice2", &mut a, 2_000);
        let m = old_client.merge(&newer_client);
        assert_eq!(m.get("x-totp"), Some("otpauth://totp/alice"));
    }

    #[test]
    fn json_is_canonical_and_validated() {
        let mut a = device(0xa1);
        let mut r = login(&mut a, 1_000);
        r.set(PASSWORD, "p2", &mut a, 2_000);
        let json = r.to_json();
        assert_eq!(Record::from_json(&json).unwrap(), r);
        assert_eq!(Record::from_json(&json).unwrap().to_json(), json);

        let newer = String::from_utf8(json.clone())
            .unwrap()
            .replacen("\"v\":1", "\"v\":3", 1);
        assert_eq!(
            Record::from_json(newer.as_bytes()),
            Err(CoreError::UnsupportedRecord(3))
        );
        let extra = String::from_utf8(json)
            .unwrap()
            .replacen("\"v\":1", "\"v\":1,\"tags\":[]", 1);
        assert!(matches!(
            Record::from_json(extra.as_bytes()),
            Err(CoreError::InvalidRecord(_))
        ));
    }

    #[test]
    fn concurrent_tag_changes_merge_per_tag() {
        let (mut a, mut b) = (device(1), device(2));
        let mut base = login(&mut a, 1_000);
        base.set_tag("работа/серверы", true, &mut a, 1_500).unwrap();
        let (mut ra, mut rb) = (base.clone(), base);
        ra.set_tag(FAVORITE_TAG, true, &mut a, 2_000).unwrap();
        rb.set_tag("работа/серверы", false, &mut b, 2_000).unwrap();
        rb.set_tag("личное", true, &mut b, 2_100).unwrap();
        let m = ra.merge(&rb);
        assert_eq!(m.tags().collect::<Vec<_>>(), ["@favorite", "личное"]);
        assert_eq!(m, rb.merge(&ra));
    }

    #[test]
    fn tag_validation() {
        for tag in ["работа", "работа/серверы", FAVORITE_TAG] {
            assert_eq!(validate_tag(tag), Ok(()), "{tag}");
        }
        for tag in ["", "/работа", "работа/", "работа//серверы", " работа", "@archive", "@"]
        {
            assert_eq!(validate_tag(tag), Err(CoreError::InvalidTag(tag.to_owned())), "{tag}");
        }
    }

    #[test]
    fn history_is_bounded() {
        let mut a = device(1);
        let mut r = login(&mut a, 1_000);
        for i in 0..(HISTORY_LIMIT + 10) {
            r.set(PASSWORD, &format!("p{}", i + 2), &mut a, 2_000 + i as u64);
        }
        assert_eq!(r.history.len(), HISTORY_LIMIT);
        assert!(r.history.windows(2).all(|w| w[0].set_at > w[1].set_at));
    }
}
