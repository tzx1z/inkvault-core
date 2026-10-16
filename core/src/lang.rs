//! Язык сообщений ядра: тексты ошибок и предупреждений синхронизации. Язык один на процесс,
//! по умолчанию английский, клиент выбирает его по языку своего интерфейса.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

static CURRENT: AtomicU8 = AtomicU8::new(Lang::En as u8);

impl Lang {
    /// Язык по тегу BCP 47 ("ru", "ru-RU") или локали POSIX ("ru_RU.UTF-8"). Неизвестный язык - английский.
    pub fn from_tag(tag: &str) -> Self {
        let primary = tag.split(['-', '_', '.', '@']).next().unwrap_or_default();
        if primary.eq_ignore_ascii_case("ru") {
            Self::Ru
        } else {
            Self::En
        }
    }
}

pub fn set(lang: Lang) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn current() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        x if x == Lang::Ru as u8 => Lang::Ru,
        _ => Lang::En,
    }
}

/// Текст на одном из языков: `tr!(lang, "english {}", "русский {}", arg)`.
macro_rules! tr {
    ($lang:expr, $en:literal, $ru:literal $(, $arg:expr)* $(,)?) => {
        match $lang {
            $crate::lang::Lang::En => format!($en $(, $arg)*),
            $crate::lang::Lang::Ru => format!($ru $(, $arg)*),
        }
    };
}

pub(crate) use tr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        for tag in ["ru", "RU", "ru-RU", "ru_RU.UTF-8", "ru@euro"] {
            assert_eq!(Lang::from_tag(tag), Lang::Ru, "{tag}");
        }
        for tag in ["", "en", "en-US", "C", "POSIX", "uk-UA", "rue"] {
            assert_eq!(Lang::from_tag(tag), Lang::En, "{tag}");
        }
    }
}
