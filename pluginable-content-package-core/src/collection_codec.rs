use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::Hash,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectionLimits {
    pub max_elements: u32,
    pub max_element_bytes: u32,
    pub max_total_bytes: usize,
}
impl Default for CollectionLimits {
    fn default() -> Self {
        Self {
            max_elements: 1_000_000,
            max_element_bytes: 64 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListAppendMode {
    All,
    NewIndices,
    Unique,
}

pub fn append_encoded_list(
    destination: &[u8],
    source: &[u8],
    mode: ListAppendMode,
    limits: CollectionLimits,
) -> Result<Vec<u8>, CollectionError> {
    let destination = decode_blobs(destination, limits)?;
    let source = decode_blobs(source, limits)?;
    let mut merged: Vec<Vec<u8>> = destination.iter().map(|item| item.to_vec()).collect();
    match mode {
        ListAppendMode::All => merged.extend(source.into_iter().map(<[u8]>::to_vec)),
        ListAppendMode::NewIndices => {
            merged.extend(source.into_iter().skip(merged.len()).map(<[u8]>::to_vec))
        }
        ListAppendMode::Unique => {
            for item in source {
                if !merged.iter().any(|existing| existing == item) {
                    merged.push(item.to_vec());
                }
            }
        }
    }
    encode_blobs(&merged, limits)
}

pub fn encode_list<T>(
    items: &[T],
    mut encode: impl FnMut(&T) -> Vec<u8>,
    limits: CollectionLimits,
) -> Result<Vec<u8>, CollectionError> {
    let count = u32::try_from(items.len()).map_err(|_| CollectionError::TooManyElements)?;
    check_count(count, limits)?;
    let encoded: Vec<_> = items.iter().map(&mut encode).collect();
    encode_blobs(&encoded, limits)
}
pub fn decode_list<T>(
    bytes: &[u8],
    mut decode: impl FnMut(&[u8]) -> Result<T, String>,
    limits: CollectionLimits,
) -> Result<Vec<T>, CollectionError> {
    decode_blobs(bytes, limits)?
        .into_iter()
        .map(|bytes| decode(bytes).map_err(CollectionError::Element))
        .collect()
}

pub fn encode_set<T: Eq + Hash>(
    items: &HashSet<T>,
    mut encode: impl FnMut(&T) -> Vec<u8>,
    limits: CollectionLimits,
) -> Result<Vec<u8>, CollectionError> {
    let mut encoded: Vec<_> = items.iter().map(&mut encode).collect();
    encoded.sort();
    if encoded.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CollectionError::DuplicateEncodedKey);
    }
    encode_blobs(&encoded, limits)
}
pub fn decode_set<T: Eq + Hash>(
    bytes: &[u8],
    mut decode: impl FnMut(&[u8]) -> Result<T, String>,
    limits: CollectionLimits,
) -> Result<HashSet<T>, CollectionError> {
    let mut result = HashSet::new();
    for bytes in decode_blobs(bytes, limits)? {
        let value = decode(bytes).map_err(CollectionError::Element)?;
        if !result.insert(value) {
            return Err(CollectionError::DuplicateValue);
        }
    }
    Ok(result)
}

pub fn encode_map<K: Eq + Hash, V>(
    items: &HashMap<K, V>,
    mut encode_key: impl FnMut(&K) -> Vec<u8>,
    mut encode_value: impl FnMut(&V) -> Vec<u8>,
    limits: CollectionLimits,
) -> Result<Vec<u8>, CollectionError> {
    let count = u32::try_from(items.len()).map_err(|_| CollectionError::TooManyElements)?;
    check_count(count, limits)?;
    let mut entries: Vec<_> = items
        .iter()
        .map(|(key, value)| (encode_key(key), encode_value(value)))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CollectionError::DuplicateEncodedKey);
    }
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_le_bytes());
    for (key, value) in entries {
        push_blob(&mut output, &key, limits)?;
        push_blob(&mut output, &value, limits)?;
    }
    check_total(output.len(), limits)?;
    Ok(output)
}
pub fn decode_map<K: Eq + Hash, V>(
    bytes: &[u8],
    mut decode_key: impl FnMut(&[u8]) -> Result<K, String>,
    mut decode_value: impl FnMut(&[u8]) -> Result<V, String>,
    limits: CollectionLimits,
) -> Result<HashMap<K, V>, CollectionError> {
    check_total(bytes.len(), limits)?;
    let (count, mut position) = read_count(bytes, limits)?;
    let mut result = HashMap::new();
    for _ in 0..count {
        let key = take_blob(bytes, &mut position, limits)?;
        let value = take_blob(bytes, &mut position, limits)?;
        let key = decode_key(key).map_err(CollectionError::Element)?;
        let value = decode_value(value).map_err(CollectionError::Element)?;
        if result.insert(key, value).is_some() {
            return Err(CollectionError::DuplicateValue);
        }
    }
    if position != bytes.len() {
        return Err(CollectionError::TrailingBytes(bytes.len() - position));
    }
    Ok(result)
}

fn encode_blobs(blobs: &[Vec<u8>], limits: CollectionLimits) -> Result<Vec<u8>, CollectionError> {
    let count = u32::try_from(blobs.len()).map_err(|_| CollectionError::TooManyElements)?;
    check_count(count, limits)?;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_le_bytes());
    for blob in blobs {
        push_blob(&mut output, blob, limits)?;
    }
    check_total(output.len(), limits)?;
    Ok(output)
}
fn decode_blobs(bytes: &[u8], limits: CollectionLimits) -> Result<Vec<&[u8]>, CollectionError> {
    check_total(bytes.len(), limits)?;
    let (count, mut position) = read_count(bytes, limits)?;
    let mut output = Vec::with_capacity(count as usize);
    for _ in 0..count {
        output.push(take_blob(bytes, &mut position, limits)?);
    }
    if position != bytes.len() {
        return Err(CollectionError::TrailingBytes(bytes.len() - position));
    }
    Ok(output)
}
fn read_count(bytes: &[u8], limits: CollectionLimits) -> Result<(u32, usize), CollectionError> {
    if bytes.len() < 4 {
        return Err(CollectionError::UnexpectedEnd);
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
    check_count(count, limits)?;
    Ok((count, 4))
}
fn push_blob(
    output: &mut Vec<u8>,
    bytes: &[u8],
    limits: CollectionLimits,
) -> Result<(), CollectionError> {
    let size = u32::try_from(bytes.len()).map_err(|_| CollectionError::ElementTooLarge)?;
    if size > limits.max_element_bytes {
        return Err(CollectionError::ElementTooLarge);
    }
    output.extend_from_slice(&size.to_le_bytes());
    output.extend_from_slice(bytes);
    check_total(output.len(), limits)
}
fn take_blob<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    limits: CollectionLimits,
) -> Result<&'a [u8], CollectionError> {
    let size_end = position
        .checked_add(4)
        .ok_or(CollectionError::UnexpectedEnd)?;
    if size_end > bytes.len() {
        return Err(CollectionError::UnexpectedEnd);
    }
    let size = u32::from_le_bytes(bytes[*position..size_end].try_into().expect("four bytes"));
    if size > limits.max_element_bytes {
        return Err(CollectionError::ElementTooLarge);
    }
    let end = size_end
        .checked_add(size as usize)
        .ok_or(CollectionError::UnexpectedEnd)?;
    let value = bytes
        .get(size_end..end)
        .ok_or(CollectionError::UnexpectedEnd)?;
    *position = end;
    Ok(value)
}
fn check_count(count: u32, limits: CollectionLimits) -> Result<(), CollectionError> {
    if count > limits.max_elements {
        Err(CollectionError::TooManyElements)
    } else {
        Ok(())
    }
}
fn check_total(size: usize, limits: CollectionLimits) -> Result<(), CollectionError> {
    if size > limits.max_total_bytes {
        Err(CollectionError::TotalTooLarge)
    } else {
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CollectionError {
    TooManyElements,
    ElementTooLarge,
    TotalTooLarge,
    UnexpectedEnd,
    TrailingBytes(usize),
    DuplicateValue,
    DuplicateEncodedKey,
    Element(String),
}
impl fmt::Display for CollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyElements => write!(f, "Collection exceeds its element limit."),
            Self::ElementTooLarge => write!(f, "Collection element exceeds its byte limit."),
            Self::TotalTooLarge => write!(f, "Collection exceeds its total byte limit."),
            Self::UnexpectedEnd => write!(f, "Collection payload ended unexpectedly."),
            Self::TrailingBytes(count) => {
                write!(f, "Collection payload has {count} trailing bytes.")
            }
            Self::DuplicateValue => write!(f, "Set or map contains a duplicate decoded key."),
            Self::DuplicateEncodedKey => {
                write!(f, "Set or map contains a duplicate canonical encoded key.")
            }
            Self::Element(error) => write!(f, "Collection element is invalid: {error}"),
        }
    }
}
impl std::error::Error for CollectionError {}
