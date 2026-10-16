//! Гибридные логические часы (HLC): метка из физического времени, логического счетчика и узла.
//!
//! Метки сравниваются как (время, счетчик, узел). Порядок полный и одинаковый на всех
//! устройствах, а изменение, сделанное после получения чужой метки, всегда получает метку больше.
//! Ядро не читает системные часы: в WASM их нет, поэтому время передает платформа.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
    pub node: u64,
}

// Шестнадцатеричные поля фиксированной ширины: строки сортируются так же, как метки
impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}-{:08x}-{:016x}", self.wall_ms, self.counter, self.node)
    }
}

impl FromStr for Hlc {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('-');
        let (Some(wall), Some(counter), Some(node), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CoreError::InvalidHlc);
        };
        if wall.len() != 16 || counter.len() != 8 || node.len() != 16 {
            return Err(CoreError::InvalidHlc);
        }
        Ok(Self {
            wall_ms: u64::from_str_radix(wall, 16).map_err(|_| CoreError::InvalidHlc)?,
            counter: u32::from_str_radix(counter, 16).map_err(|_| CoreError::InvalidHlc)?,
            node: parse_node(node)?,
        })
    }
}

impl Serialize for Hlc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Идентификатор устройства в метках. Создается один раз и хранится вместе с состоянием часов.
pub fn generate_node_id() -> Result<u64, CoreError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| CoreError::Random)?;
    Ok(u64::from_be_bytes(bytes))
}

pub fn format_node(node: u64) -> String {
    format!("{node:016x}")
}

pub fn parse_node(s: &str) -> Result<u64, CoreError> {
    if s.len() != 16 {
        return Err(CoreError::InvalidHlc);
    }
    u64::from_str_radix(s, 16).map_err(|_| CoreError::InvalidHlc)
}

/// Часы одного устройства. Последнюю метку нужно сохранять между запусками и передавать
/// в `restore`, иначе после перевода системных часов назад метки перестанут расти.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clock {
    node: u64,
    wall_ms: u64,
    counter: u32,
}

impl Clock {
    pub fn new(node: u64) -> Self {
        Self {
            node,
            wall_ms: 0,
            counter: 0,
        }
    }

    pub fn restore(last: Hlc) -> Self {
        Self {
            node: last.node,
            wall_ms: last.wall_ms,
            counter: last.counter,
        }
    }

    pub fn last(&self) -> Hlc {
        Hlc {
            wall_ms: self.wall_ms,
            counter: self.counter,
            node: self.node,
        }
    }

    /// Метка для локального изменения.
    pub fn tick(&mut self, now_ms: u64) -> Hlc {
        if now_ms > self.wall_ms {
            self.wall_ms = now_ms;
            self.counter = 0;
        } else {
            self.bump();
        }
        self.last()
    }

    /// Учитывает метку, полученную с другого устройства: следующая локальная метка будет больше нее.
    pub fn observe(&mut self, remote: Hlc, now_ms: u64) {
        let wall = self.wall_ms.max(remote.wall_ms).max(now_ms);
        let counter = match (wall == self.wall_ms, wall == remote.wall_ms) {
            (true, true) => self.counter.max(remote.counter),
            (true, false) => self.counter,
            (false, true) => remote.counter,
            (false, false) => {
                self.wall_ms = wall;
                self.counter = 0;
                return;
            }
        };
        self.wall_ms = wall;
        self.counter = counter;
        self.bump();
    }

    fn bump(&mut self) {
        if self.counter == u32::MAX {
            self.wall_ms += 1;
            self.counter = 0;
        } else {
            self.counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_grow_when_wall_clock_goes_back() {
        let mut clock = Clock::new(1);
        let a = clock.tick(1_000);
        let b = clock.tick(500);
        let c = clock.tick(1_000);
        assert!(a < b && b < c);
        assert_eq!((b.wall_ms, b.counter), (1_000, 1));
    }

    #[test]
    fn observe_orders_after_remote() {
        let mut remote = Clock::new(2);
        let theirs = remote.tick(10_000);
        let mut local = Clock::new(1);
        local.tick(5_000);
        local.observe(theirs, 5_001);
        assert!(local.tick(5_002) > theirs);
    }

    #[test]
    fn observe_with_newer_physical_time_resets_counter() {
        let mut clock = Clock::new(1);
        clock.tick(1_000);
        clock.observe(
            Hlc {
                wall_ms: 1_000,
                counter: 7,
                node: 2,
            },
            2_000,
        );
        assert_eq!(
            clock.last(),
            Hlc {
                wall_ms: 2_000,
                counter: 0,
                node: 1
            }
        );
    }

    #[test]
    fn counter_overflow_moves_wall() {
        let mut clock = Clock::restore(Hlc {
            wall_ms: 10,
            counter: u32::MAX,
            node: 1,
        });
        assert_eq!(
            clock.tick(10),
            Hlc {
                wall_ms: 11,
                counter: 0,
                node: 1
            }
        );
    }

    #[test]
    fn string_form_roundtrip_and_order() {
        let a = Hlc {
            wall_ms: 0x19a1b2c3d4e,
            counter: 1,
            node: 0xa1b2,
        };
        let b = Hlc {
            wall_ms: 0x19a1b2c3d4e,
            counter: 2,
            node: 0x01,
        };
        assert_eq!(a.to_string(), "0000019a1b2c3d4e-00000001-000000000000a1b2");
        assert_eq!(a.to_string().parse::<Hlc>().unwrap(), a);
        assert_eq!(a < b, a.to_string() < b.to_string());
    }

    #[test]
    fn invalid_strings_rejected() {
        for s in [
            "",
            "1-2-3",
            "0000019a1b2c3d4e-00000001",
            "0000019a1b2c3d4e-0000000g-000000000000a1b2",
            "a-b-c-d",
        ] {
            assert_eq!(s.parse::<Hlc>(), Err(CoreError::InvalidHlc), "{s}");
        }
    }
}
