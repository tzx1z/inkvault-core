//! Генератор паролей. Символы выбираются равномерно из выбранных классов, а пароль без
//! символа какого-либо класса генерируется заново: подстановка обязательных символов
//! в фиксированные позиции давала бы смещение в распределении.

use zeroize::Zeroizing;

use crate::CoreError;

pub const MIN_LENGTH: u32 = 8;
pub const MAX_LENGTH: u32 = 128;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
// без кавычек, обратной косой черты и пробела: их плохо принимают формы и командная строка
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "Il1O0o|";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: u32,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

fn classes(options: &PasswordOptions) -> Vec<Vec<u8>> {
    [
        (options.lower, LOWER),
        (options.upper, UPPER),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, chars)| {
        chars
            .bytes()
            .filter(|c| !(options.avoid_ambiguous && AMBIGUOUS.as_bytes().contains(c)))
            .collect()
    })
    .collect()
}

fn validate(options: &PasswordOptions) -> Result<Vec<Vec<u8>>, CoreError> {
    let classes = classes(options);
    if classes.is_empty()
        || !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length)
        || (options.length as usize) < classes.len()
    {
        return Err(CoreError::InvalidPasswordOptions);
    }
    Ok(classes)
}

/// Энтропия пароля с такими параметрами в битах: длина * log2(размер алфавита).
pub fn entropy_bits(options: &PasswordOptions) -> Result<f64, CoreError> {
    let alphabet: usize = validate(options)?.iter().map(Vec::len).sum();
    Ok(options.length as f64 * (alphabet as f64).log2())
}

pub fn generate(options: &PasswordOptions) -> Result<Zeroizing<String>, CoreError> {
    let classes = validate(options)?;
    let alphabet: Vec<u8> = classes.concat();
    // отбрасывание байтов выше наибольшего кратного размеру алфавита убирает смещение по модулю
    let limit = 256 - 256 % alphabet.len();
    let mut out = Zeroizing::new(Vec::with_capacity(options.length as usize));
    let mut random = Zeroizing::new([0u8; 64]);
    loop {
        out.clear();
        while out.len() < options.length as usize {
            getrandom::fill(random.as_mut()).map_err(|_| CoreError::Random)?;
            for &b in random.iter() {
                if (b as usize) < limit && out.len() < options.length as usize {
                    out.push(alphabet[b as usize % alphabet.len()]);
                }
            }
        }
        if classes.iter().all(|class| out.iter().any(|c| class.contains(c))) {
            let text = String::from_utf8(out.to_vec()).expect("алфавит генератора - ASCII");
            return Ok(Zeroizing::new(text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_classes() {
        let options = PasswordOptions::default();
        for _ in 0..200 {
            let p = generate(&options).unwrap();
            assert_eq!(p.len(), 20);
            assert!(p.bytes().any(|c| c.is_ascii_lowercase()));
            assert!(p.bytes().any(|c| c.is_ascii_uppercase()));
            assert!(p.bytes().any(|c| c.is_ascii_digit()));
            assert!(p.bytes().any(|c| SYMBOLS.as_bytes().contains(&c)));
        }
    }

    #[test]
    fn every_character_of_alphabet_appears() {
        let options = PasswordOptions {
            length: 128,
            avoid_ambiguous: true,
            ..PasswordOptions::default()
        };
        let alphabet: Vec<u8> = classes(&options).concat();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..100 {
            seen.extend(generate(&options).unwrap().bytes());
        }
        assert_eq!(seen.len(), alphabet.len());
        assert!(!seen.iter().any(|c| AMBIGUOUS.as_bytes().contains(c)));
    }

    #[test]
    fn options_are_validated_and_entropy_is_computed() {
        let none = PasswordOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert_eq!(generate(&none).err(), Some(CoreError::InvalidPasswordOptions));
        let short = PasswordOptions {
            length: 4,
            ..PasswordOptions::default()
        };
        assert_eq!(generate(&short).err(), Some(CoreError::InvalidPasswordOptions));
        let digits = PasswordOptions {
            length: 10,
            lower: false,
            upper: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert!((entropy_bits(&digits).unwrap() - 10.0 * 10f64.log2()).abs() < 1e-9);
    }
}
