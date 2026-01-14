use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn from_hex(hex: &String) -> Vec<u8> {
    hex::decode(hex.strip_prefix("0x").unwrap()).unwrap()
}

fn to_hex(bytes: &Vec<u8>) -> String {
    let hex = hex::encode(bytes);
    format!("0x{}", hex)
}

/// Hex serialization function.
///
/// Can be used in `#[serde(serialize_with = "")]` attributes for any `AsRef<[u8]>` type.
pub fn serialize_bytes_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&to_hex(&bytes.to_vec()))
}

/// Serialization function for encoding `Vec<[u8; 32]>` objects as hex strings with a leading `0x`.
///
/// Can be used in `#[serde(serialize_with = "serialize_bytes32_array_as_hex")]`
/// for any `Vec<[u8; 32]>` field.
pub fn serialize_bytes32_array_as_hex<S>(
    bytes_array: &[[u8; 32]],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    bytes_array
        .iter()
        .map(|bytes| to_hex(&bytes.to_vec()))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

/// Hex deserialization function.
///
/// Can be used in `#[serde(deserialize_with = "deserialize_bytes_hex")]`
/// for any `Vec<u8>` type.
pub fn deserialize_bytes_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let b = String::deserialize(deserializer)?;
    Ok(from_hex(&b))
}

/// Hex deserialization function.
///
/// Can be used in `#[serde(deserialize_with = "deserialize_bytes_hex32")]`
/// for any `[u8; 32]` type.
pub fn deserialize_bytes_hex32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let b = String::deserialize(deserializer)?;
    from_hex(&b)
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid length"))
}

/// Deserialization function for `Vec<[u8; 32]>` objects that are encoded as hex strings with a leading `0x`.
///
/// Can be used in `#[serde(deserialize_with = "deserialize_bytes32_array_as_hex")]`
/// for any `Vec<[u8; 32]>` field.
pub fn deserialize_bytes32_array_as_hex<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes32_array = Vec::<String>::deserialize(deserializer)?;
    bytes32_array
        .into_iter()
        .map(|b| {
            from_hex(&b)
                .try_into()
                .map_err(|_| serde::de::Error::custom("Invalid length"))
        })
        .collect()
}
