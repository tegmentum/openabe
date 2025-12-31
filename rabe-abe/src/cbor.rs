//! ABE-CBOR v1 Serialization
//!
//! This module implements ABE-CBOR v1 serialization format for cross-platform
//! compatibility between native and WASM implementations.

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::schemes::waters::{
    Ciphertext, CiphertextComponent, Mpk, Msk, SecretKey,
    RawCiphertext, RawMpk, RawMsk, RawSecretKey,
};
use crate::schemes::waters_cca::{CcaCiphertext, CcaFullCiphertext};
use ciborium::value::Value;
use rabe_bls12381::{Fr, G1, G2, Gt};

// ============================================================================
// Constants (from ABE-CBOR Registry)
// ============================================================================

/// ABE-CBOR tag (private-use range)
pub const ABE_CBOR_TAG: u64 = 60001;

/// ABE-CBOR version
pub const ABE_CBOR_VERSION: u64 = 1;

/// ABE item kinds
pub mod kind {
    pub const MSK: u64 = 1;
    pub const MPK: u64 = 2;
    pub const SK: u64 = 3;
    pub const CT: u64 = 4;
    pub const RK: u64 = 5;      // Re-encryption key
    pub const RE_CT: u64 = 6;   // Re-encrypted ciphertext
}

/// Scheme identifiers
pub mod scheme {
    pub const CPABE_WATERS: &str = "cpabe-waters";
    pub const CPABE_WATERS_CCA: &str = "cpabe-waters-cca";
    pub const CPABE_WATERS_PRE: &str = "cpabe-waters-pre";
    pub const DABE_PRE: &str = "dabe-pre";
}

/// Curve identifiers
pub mod curve {
    pub const BLS12_381: &str = "bls12-381";
}

/// Group element encoding IDs
pub mod ge_encoding {
    pub const IETF_COMPRESSED: u64 = 0;
}

/// Endianness
pub mod endianness {
    pub const BIG: u64 = 0;
}

/// Policy encoding
pub mod policy_encoding {
    pub const BOOL_AST: u64 = 0;
}

/// Token kinds for Boolean AST
pub mod token_kind {
    pub const ATTR: u64 = 0;
    pub const AND: u64 = 1;
    pub const OR: u64 = 2;
    pub const THRESH: u64 = 3;
}

// ============================================================================
// Helper functions for building CBOR maps
// ============================================================================

type CborMap = Vec<(Value, Value)>;

fn map_insert(map: &mut CborMap, key: u64, value: Value) {
    map.push((Value::Integer(key.into()), value));
}

fn map_get<'a>(map: &'a [(Value, Value)], key: u64) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_integer().map(|i| i128::from(i) == key as i128).unwrap_or(false))
        .map(|(_, v)| v)
}

// ============================================================================
// Suite Descriptor
// ============================================================================

/// Suite descriptor for ABE-CBOR
#[derive(Clone, Debug)]
pub struct Suite {
    pub scheme_id: String,
    pub curve_id: String,
    pub security_level: u64,
    pub ge_encoding: u64,
    pub endianness: u64,
    pub subgroup_check: bool,
}

impl Default for Suite {
    fn default() -> Self {
        Suite {
            scheme_id: scheme::CPABE_WATERS.to_string(),
            curve_id: curve::BLS12_381.to_string(),
            security_level: 128,
            ge_encoding: ge_encoding::IETF_COMPRESSED,
            endianness: endianness::BIG,
            subgroup_check: true,
        }
    }
}

impl Suite {
    /// Create suite for CCA-secure Waters scheme
    pub fn waters_cca() -> Self {
        Suite {
            scheme_id: scheme::CPABE_WATERS_CCA.to_string(),
            ..Default::default()
        }
    }

    /// Encode suite to CBOR value
    fn to_cbor(&self) -> Value {
        let mut map: CborMap = Vec::with_capacity(3);
        map_insert(&mut map, 0, Value::Text(self.scheme_id.clone()));

        // Curve info
        let mut curve_map: CborMap = Vec::with_capacity(2);
        map_insert(&mut curve_map, 0, Value::Text(self.curve_id.clone()));
        map_insert(&mut curve_map, 1, Value::Integer(self.security_level.into()));
        map_insert(&mut map, 1, Value::Map(curve_map));

        // GE encoding
        let mut ge_map: CborMap = Vec::with_capacity(3);
        map_insert(&mut ge_map, 0, Value::Integer(self.ge_encoding.into()));
        map_insert(&mut ge_map, 1, Value::Integer(self.endianness.into()));
        map_insert(&mut ge_map, 2, Value::Bool(self.subgroup_check));
        map_insert(&mut map, 2, Value::Map(ge_map));

        Value::Map(map)
    }

    /// Decode suite from CBOR value
    fn from_cbor(value: &Value) -> Result<Self, AbeError> {
        let map = value.as_map()
            .ok_or_else(|| AbeError::DecryptError("Suite must be a map".to_string()))?;

        let mut suite = Suite::default();

        if let Some(v) = map_get(map, 0) {
            suite.scheme_id = v.as_text()
                .ok_or_else(|| AbeError::DecryptError("scheme_id must be text".to_string()))?
                .to_string();
        }

        if let Some(curve_val) = map_get(map, 1) {
            if let Some(curve_map) = curve_val.as_map() {
                if let Some(v) = map_get(curve_map, 0) {
                    suite.curve_id = v.as_text()
                        .ok_or_else(|| AbeError::DecryptError("curve_id must be text".to_string()))?
                        .to_string();
                }
                if let Some(v) = map_get(curve_map, 1) {
                    suite.security_level = v.as_integer()
                        .and_then(|i| u64::try_from(i128::from(i)).ok())
                        .unwrap_or(128);
                }
            }
        }

        if let Some(ge_val) = map_get(map, 2) {
            if let Some(ge_map) = ge_val.as_map() {
                if let Some(v) = map_get(ge_map, 0) {
                    suite.ge_encoding = v.as_integer()
                        .and_then(|i| u64::try_from(i128::from(i)).ok())
                        .unwrap_or(0);
                }
                if let Some(v) = map_get(ge_map, 1) {
                    suite.endianness = v.as_integer()
                        .and_then(|i| u64::try_from(i128::from(i)).ok())
                        .unwrap_or(0);
                }
                if let Some(v) = map_get(ge_map, 2) {
                    suite.subgroup_check = v.as_bool().unwrap_or(true);
                }
            }
        }

        Ok(suite)
    }
}

// ============================================================================
// Policy Encoding
// ============================================================================

/// Encode policy to Boolean AST (RPN) format
fn policy_to_rpn(policy: &PolicyNode, attr_list: &mut Vec<String>) -> Vec<Value> {
    let mut tokens = Vec::new();

    match policy {
        PolicyNode::Attr(name) => {
            let idx = if let Some(pos) = attr_list.iter().position(|a| a == name) {
                pos
            } else {
                attr_list.push(name.clone());
                attr_list.len() - 1
            };

            let mut token: CborMap = Vec::new();
            map_insert(&mut token, 0, Value::Integer(token_kind::ATTR.into()));
            let mut attr_ref: CborMap = Vec::new();
            map_insert(&mut attr_ref, 0, Value::Integer((idx as u64).into()));
            map_insert(&mut token, 1, Value::Map(attr_ref));
            tokens.push(Value::Map(token));
        }
        PolicyNode::And(children) => {
            for child in children {
                tokens.extend(policy_to_rpn(child, attr_list));
            }
            for _ in 1..children.len() {
                let mut token: CborMap = Vec::new();
                map_insert(&mut token, 0, Value::Integer(token_kind::AND.into()));
                tokens.push(Value::Map(token));
            }
        }
        PolicyNode::Or(children) => {
            for child in children {
                tokens.extend(policy_to_rpn(child, attr_list));
            }
            for _ in 1..children.len() {
                let mut token: CborMap = Vec::new();
                map_insert(&mut token, 0, Value::Integer(token_kind::OR.into()));
                tokens.push(Value::Map(token));
            }
        }
        PolicyNode::Threshold(k, children) => {
            for child in children {
                tokens.extend(policy_to_rpn(child, attr_list));
            }
            let mut token: CborMap = Vec::new();
            map_insert(&mut token, 0, Value::Integer(token_kind::THRESH.into()));
            let mut thresh: CborMap = Vec::new();
            map_insert(&mut thresh, 0, Value::Integer((*k as u64).into()));
            map_insert(&mut thresh, 1, Value::Integer((children.len() as u64).into()));
            map_insert(&mut token, 1, Value::Map(thresh));
            tokens.push(Value::Map(token));
        }
    }

    tokens
}

/// Decode Boolean AST (RPN) to policy
fn rpn_to_policy(tokens: &[Value], attr_list: &[String]) -> Result<PolicyNode, AbeError> {
    let mut stack: Vec<PolicyNode> = Vec::new();

    for token_val in tokens {
        let token = token_val.as_map()
            .ok_or_else(|| AbeError::InvalidPolicy("Token must be map".to_string()))?;

        let kind = map_get(token, 0)
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i128::from(i)).ok())
            .ok_or_else(|| AbeError::InvalidPolicy("Token kind must be uint".to_string()))?;

        match kind {
            token_kind::ATTR => {
                let payload = map_get(token, 1)
                    .ok_or_else(|| AbeError::InvalidPolicy("ATTR missing payload".to_string()))?;
                let attr_ref = payload.as_map()
                    .ok_or_else(|| AbeError::InvalidPolicy("AttrRef must be map".to_string()))?;
                let idx = map_get(attr_ref, 0)
                    .and_then(|v| v.as_integer())
                    .and_then(|i| usize::try_from(i128::from(i)).ok())
                    .ok_or_else(|| AbeError::InvalidPolicy("Invalid attr index".to_string()))?;
                let attr_name = attr_list.get(idx)
                    .ok_or_else(|| AbeError::InvalidPolicy("Attr index out of bounds".to_string()))?;
                stack.push(PolicyNode::Attr(attr_name.clone()));
            }
            token_kind::AND => {
                let right = stack.pop()
                    .ok_or_else(|| AbeError::InvalidPolicy("AND: stack underflow".to_string()))?;
                let left = stack.pop()
                    .ok_or_else(|| AbeError::InvalidPolicy("AND: stack underflow".to_string()))?;
                stack.push(PolicyNode::And(vec![left, right]));
            }
            token_kind::OR => {
                let right = stack.pop()
                    .ok_or_else(|| AbeError::InvalidPolicy("OR: stack underflow".to_string()))?;
                let left = stack.pop()
                    .ok_or_else(|| AbeError::InvalidPolicy("OR: stack underflow".to_string()))?;
                stack.push(PolicyNode::Or(vec![left, right]));
            }
            token_kind::THRESH => {
                let payload = map_get(token, 1)
                    .ok_or_else(|| AbeError::InvalidPolicy("THRESH missing payload".to_string()))?;
                let thresh_map = payload.as_map()
                    .ok_or_else(|| AbeError::InvalidPolicy("Thresh payload must be map".to_string()))?;
                let k = map_get(thresh_map, 0)
                    .and_then(|v| v.as_integer())
                    .and_then(|i| usize::try_from(i128::from(i)).ok())
                    .ok_or_else(|| AbeError::InvalidPolicy("Invalid threshold k".to_string()))?;
                let n = map_get(thresh_map, 1)
                    .and_then(|v| v.as_integer())
                    .and_then(|i| usize::try_from(i128::from(i)).ok())
                    .ok_or_else(|| AbeError::InvalidPolicy("Invalid threshold n".to_string()))?;
                let mut children = Vec::with_capacity(n);
                for _ in 0..n {
                    children.push(stack.pop()
                        .ok_or_else(|| AbeError::InvalidPolicy("THRESH: stack underflow".to_string()))?);
                }
                children.reverse();
                stack.push(PolicyNode::Threshold(k, children));
            }
            _ => return Err(AbeError::InvalidPolicy(format!("Unknown token kind: {}", kind))),
        }
    }

    stack.pop()
        .ok_or_else(|| AbeError::InvalidPolicy("Empty policy stack".to_string()))
}

// ============================================================================
// Encode/Decode Helpers
// ============================================================================

fn encode_group_elems(elems: &[Vec<u8>]) -> Value {
    let mut arr = Vec::with_capacity(elems.len());
    for e in elems {
        arr.push(Value::Bytes(e.clone()));
    }
    Value::Array(arr)
}

fn decode_group_elems(value: &Value) -> Result<Vec<Vec<u8>>, AbeError> {
    let arr = value.as_array()
        .ok_or_else(|| AbeError::DecryptError("GroupElems must be array".to_string()))?;
    let mut result = Vec::with_capacity(arr.len());
    for v in arr {
        let bytes = v.as_bytes()
            .ok_or_else(|| AbeError::DecryptError("GroupElem must be bytes".to_string()))?;
        result.push(bytes.to_vec());
    }
    Ok(result)
}

fn encode_attr_set(attrs: &[String]) -> Value {
    let mut sorted_attrs: Vec<_> = attrs.to_vec();
    sorted_attrs.sort();

    let mut attr_array = Vec::with_capacity(sorted_attrs.len());
    for a in &sorted_attrs {
        let mut attr_map: CborMap = Vec::with_capacity(2);
        map_insert(&mut attr_map, 0, Value::Integer(0.into())); // type = STRING
        map_insert(&mut attr_map, 1, Value::Text(a.clone()));
        attr_array.push(Value::Map(attr_map));
    }

    let mut map: CborMap = Vec::with_capacity(1);
    map_insert(&mut map, 0, Value::Array(attr_array));
    Value::Map(map)
}

fn decode_attr_set(value: &Value) -> Result<Vec<String>, AbeError> {
    let map = value.as_map()
        .ok_or_else(|| AbeError::DecryptError("AttrSet must be map".to_string()))?;
    let attrs_val = map_get(map, 0)
        .ok_or_else(|| AbeError::DecryptError("AttrSet missing attrs array".to_string()))?;
    let attrs_arr = attrs_val.as_array()
        .ok_or_else(|| AbeError::DecryptError("Attrs must be array".to_string()))?;

    attrs_arr.iter()
        .map(|attr_val| {
            let attr_map = attr_val.as_map()
                .ok_or_else(|| AbeError::DecryptError("Attr must be map".to_string()))?;
            map_get(attr_map, 1)
                .and_then(|v| v.as_text())
                .map(|s| s.to_string())
                .ok_or_else(|| AbeError::DecryptError("Attr value must be text".to_string()))
        })
        .collect()
}

// ============================================================================
// MPK Encoding/Decoding
// ============================================================================

/// Encode MPK to CBOR bytes
pub fn encode_mpk(mpk: &Mpk) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    // Collect group elements: g1, g2, g1a, g2alpha, egg_alpha, k
    // Pre-allocate with known size: 6 elements
    let mut elems = Vec::with_capacity(6);
    elems.push(mpk.g1.into_bytes());
    elems.push(mpk.g2.into_bytes());
    elems.push(mpk.g1a.into_bytes());
    elems.push(mpk.g2alpha.into_bytes());
    elems.push(mpk.egg_alpha.into_bytes());
    elems.push(mpk.k.clone());

    let mut body: CborMap = Vec::with_capacity(1);
    map_insert(&mut body, 0, encode_group_elems(&elems));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::MPK.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate output buffer: ~1KB for typical MPK
    let mut output = Vec::with_capacity(1024);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode MPK from CBOR bytes
pub fn decode_mpk(data: &[u8]) -> Result<Mpk, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("MPK must be map".to_string()))?;

    let kind = map_get(map, 0)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i128::from(i)).ok())
        .ok_or_else(|| AbeError::DecryptError("Kind must be uint".to_string()))?;

    if kind != kind::MPK {
        return Err(AbeError::DecryptError(format!("Expected MPK (kind=2), got kind={}", kind)));
    }

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let elems_val = map_get(body, 0)
        .ok_or_else(|| AbeError::DecryptError("Missing group elems".to_string()))?;
    let elems = decode_group_elems(elems_val)?;

    if elems.len() < 6 {
        return Err(AbeError::DecryptError("MPK requires 6 group elements".to_string()));
    }

    let g1 = G1::from_slice_checked(&elems[0], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid G1".to_string()))?;
    let g2 = G2::from_slice_checked(&elems[1], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid G2".to_string()))?;
    let g1a = G1::from_slice_checked(&elems[2], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid G1a".to_string()))?;
    let g2alpha = G2::from_slice_checked(&elems[3], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid G2alpha".to_string()))?;
    let egg_alpha = Gt::from_slice_checked(&elems[4], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid egg_alpha".to_string()))?;
    let k = elems[5].clone();

    Ok(RawMpk { g1, g2, g1a, g2alpha, egg_alpha, k }.into())
}

// ============================================================================
// MSK Encoding/Decoding
// ============================================================================

/// Encode MSK to CBOR bytes
pub fn encode_msk(msk: &Msk) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    // Pre-allocate for 2 elements
    let mut elems = Vec::with_capacity(2);
    elems.push(msk.alpha.into_bytes());
    elems.push(msk.g2a.into_bytes());

    let mut body: CborMap = Vec::with_capacity(1);
    map_insert(&mut body, 0, encode_group_elems(&elems));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::MSK.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate output buffer: ~256 bytes for typical MSK
    let mut output = Vec::with_capacity(256);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode MSK from CBOR bytes
pub fn decode_msk(data: &[u8]) -> Result<Msk, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("MSK must be map".to_string()))?;

    let kind = map_get(map, 0)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i128::from(i)).ok())
        .ok_or_else(|| AbeError::DecryptError("Kind must be uint".to_string()))?;

    if kind != kind::MSK {
        return Err(AbeError::DecryptError(format!("Expected MSK (kind=1), got kind={}", kind)));
    }

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let elems_val = map_get(body, 0)
        .ok_or_else(|| AbeError::DecryptError("Missing group elems".to_string()))?;
    let elems = decode_group_elems(elems_val)?;

    if elems.len() < 2 {
        return Err(AbeError::DecryptError("MSK requires 2 elements".to_string()));
    }

    let alpha = Fr::from_slice(&elems[0])
        .ok_or_else(|| AbeError::DecryptError("Invalid alpha".to_string()))?;
    let g2a = G2::from_slice_checked(&elems[1], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid g2a".to_string()))?;

    Ok(RawMsk { alpha, g2a }.into())
}

// ============================================================================
// SecretKey Encoding/Decoding
// ============================================================================

/// Encode SecretKey to CBOR bytes
pub fn encode_sk(sk: &SecretKey) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    let mut sorted_attrs: Vec<_> = sk.attributes.clone();
    sorted_attrs.sort();

    // Pre-allocate: 2 fixed elements + 1 per attribute
    let mut elems = Vec::with_capacity(2 + sorted_attrs.len());
    elems.push(sk.k.into_bytes());
    elems.push(sk.l.into_bytes());

    for attr in &sorted_attrs {
        if let Some(kx) = sk.kx.get(attr) {
            elems.push(kx.into_bytes());
        }
    }

    let mut body: CborMap = Vec::with_capacity(2);
    map_insert(&mut body, 0, encode_group_elems(&elems));
    map_insert(&mut body, 1, encode_attr_set(&sorted_attrs));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::SK.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate: ~256 bytes base + ~100 bytes per attribute
    let mut output = Vec::with_capacity(256 + sorted_attrs.len() * 100);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode SecretKey from CBOR bytes
pub fn decode_sk(data: &[u8]) -> Result<SecretKey, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("SK must be map".to_string()))?;

    let kind = map_get(map, 0)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i128::from(i)).ok())
        .ok_or_else(|| AbeError::DecryptError("Kind must be uint".to_string()))?;

    if kind != kind::SK {
        return Err(AbeError::DecryptError(format!("Expected SK (kind=3), got kind={}", kind)));
    }

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let elems_val = map_get(body, 0)
        .ok_or_else(|| AbeError::DecryptError("Missing group elems".to_string()))?;
    let elems = decode_group_elems(elems_val)?;

    let attrs_val = map_get(body, 1)
        .ok_or_else(|| AbeError::DecryptError("Missing attr set".to_string()))?;
    let attributes = decode_attr_set(attrs_val)?;

    if elems.len() < 2 + attributes.len() {
        return Err(AbeError::DecryptError("SK: not enough group elements".to_string()));
    }

    let k = G2::from_slice_checked(&elems[0], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid K".to_string()))?;
    let l = G2::from_slice_checked(&elems[1], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid L".to_string()))?;

    let mut kx = std::collections::HashMap::new();
    for (i, attr) in attributes.iter().enumerate() {
        let kx_elem = G1::from_slice_checked(&elems[2 + i], false)
            .ok_or_else(|| AbeError::DecryptError("Invalid key component".into()))?;
        kx.insert(attr.clone(), kx_elem);
    }

    Ok(RawSecretKey { k, l, kx, attributes }.into())
}

// ============================================================================
// Ciphertext Encoding/Decoding
// ============================================================================

/// Encode Ciphertext to CBOR bytes
pub fn encode_ct(ct: &Ciphertext) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    let policy = crate::schemes::waters::parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    let mut attr_list = Vec::new();
    let rpn_tokens = policy_to_rpn(&policy, &mut attr_list);

    let mut sorted_attrs: Vec<_> = attr_list.clone();
    sorted_attrs.sort();

    // Pre-allocate: 2 fixed elements + 2 per attribute (c and d)
    let mut elems = Vec::with_capacity(2 + sorted_attrs.len() * 2);
    elems.push(ct.c.into_bytes());
    elems.push(ct.c_prime.into_bytes());

    for attr in &sorted_attrs {
        if let Some(comp) = ct.components.get(attr) {
            elems.push(comp.c.into_bytes());
            elems.push(comp.d.into_bytes());
        }
    }

    let mut policy_map: CborMap = Vec::with_capacity(2);
    map_insert(&mut policy_map, 0, Value::Integer(policy_encoding::BOOL_AST.into()));
    map_insert(&mut policy_map, 1, Value::Array(rpn_tokens));

    let mut body: CborMap = Vec::with_capacity(3);
    map_insert(&mut body, 0, encode_group_elems(&elems));
    map_insert(&mut body, 1, Value::Map(policy_map));
    map_insert(&mut body, 2, encode_attr_set(&sorted_attrs));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate: ~1KB base + ~200 bytes per attribute (G1 + G2)
    let mut output = Vec::with_capacity(1024 + sorted_attrs.len() * 200);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode Ciphertext from CBOR bytes
pub fn decode_ct(data: &[u8]) -> Result<Ciphertext, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("CT must be map".to_string()))?;

    let kind = map_get(map, 0)
        .and_then(|v| v.as_integer())
        .and_then(|i| u64::try_from(i128::from(i)).ok())
        .ok_or_else(|| AbeError::DecryptError("Kind must be uint".to_string()))?;

    if kind != kind::CT {
        return Err(AbeError::DecryptError(format!("Expected CT (kind=4), got kind={}", kind)));
    }

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let elems_val = map_get(body, 0)
        .ok_or_else(|| AbeError::DecryptError("Missing group elems".to_string()))?;
    let elems = decode_group_elems(elems_val)?;

    let policy_val = map_get(body, 1)
        .ok_or_else(|| AbeError::DecryptError("Missing policy".to_string()))?;
    let policy_map = policy_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Policy must be map".to_string()))?;

    let attrs_val = map_get(body, 2)
        .ok_or_else(|| AbeError::DecryptError("Missing attr list".to_string()))?;
    let attr_list = decode_attr_set(attrs_val)?;

    let tokens_val = map_get(policy_map, 1)
        .ok_or_else(|| AbeError::DecryptError("Missing policy tokens".to_string()))?;
    let tokens = tokens_val.as_array()
        .ok_or_else(|| AbeError::DecryptError("Tokens must be array".to_string()))?;

    let policy = rpn_to_policy(tokens, &attr_list)?;
    let policy_str = policy.to_canonical_string();

    if elems.len() < 2 {
        return Err(AbeError::DecryptError("CT: not enough elements".to_string()));
    }

    let c = Gt::from_slice_checked(&elems[0], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid C".to_string()))?;
    let c_prime = G1::from_slice_checked(&elems[1], false)
        .ok_or_else(|| AbeError::DecryptError("Invalid C'".to_string()))?;

    let mut components = std::collections::HashMap::new();
    for (i, attr) in attr_list.iter().enumerate() {
        let c_i = G1::from_slice_checked(&elems[2 + i * 2], false)
            .ok_or_else(|| AbeError::DecryptError("Invalid ciphertext component".into()))?;
        let d_i = G2::from_slice_checked(&elems[2 + i * 2 + 1], false)
            .ok_or_else(|| AbeError::DecryptError("Invalid ciphertext component".into()))?;
        components.insert(attr.clone(), CiphertextComponent { c: c_i, d: d_i });
    }

    Ok(RawCiphertext {
        policy: policy_str,
        c,
        c_prime,
        components,
    }.into())
}

// ============================================================================
// CCA Ciphertext Encoding/Decoding
// ============================================================================

/// Encode CCA Ciphertext to CBOR bytes
pub fn encode_cca_ct(ct: &CcaCiphertext) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::waters_cca();

    let cpa_cbor = encode_ct(&ct.cpa_ct)?;

    let mut body: CborMap = Vec::with_capacity(3);
    map_insert(&mut body, 0, Value::Bytes(cpa_cbor.clone()));
    map_insert(&mut body, 1, Value::Bytes(ct.encrypted_m.clone()));
    map_insert(&mut body, 2, Value::Bytes(ct.uid.to_vec()));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate based on CPA size + overhead
    let mut output = Vec::with_capacity(cpa_cbor.len() + 256);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode CCA Ciphertext from CBOR bytes
pub fn decode_cca_ct(data: &[u8]) -> Result<CcaCiphertext, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("CCA CT must be map".to_string()))?;

    let suite_val = map_get(map, 1)
        .ok_or_else(|| AbeError::DecryptError("Missing suite".to_string()))?;
    let suite = Suite::from_cbor(suite_val)?;

    if suite.scheme_id != scheme::CPABE_WATERS_CCA {
        return Err(AbeError::DecryptError(format!(
            "Expected scheme {}, got {}",
            scheme::CPABE_WATERS_CCA,
            suite.scheme_id
        )));
    }

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let cpa_bytes = map_get(body, 0)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| AbeError::DecryptError("Missing CPA ciphertext".to_string()))?;
    let cpa_ct = decode_ct(cpa_bytes)?;

    let encrypted_m = map_get(body, 1)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| AbeError::DecryptError("Missing encrypted_m".to_string()))?;

    let uid_bytes = map_get(body, 2)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| AbeError::DecryptError("Missing uid".to_string()))?;

    let mut uid = [0u8; 16];
    if uid_bytes.len() >= 16 {
        uid.copy_from_slice(&uid_bytes[..16]);
    } else {
        uid[..uid_bytes.len()].copy_from_slice(uid_bytes);
    }

    Ok(CcaCiphertext { cpa_ct, encrypted_m, uid })
}

/// Encode CCA Full Ciphertext (with payload) to CBOR bytes
pub fn encode_cca_full_ct(ct: &CcaFullCiphertext) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::waters_cca();

    let cca_cbor = encode_cca_ct(&ct.cca_ct)?;

    let mut body: CborMap = Vec::with_capacity(2);
    map_insert(&mut body, 0, Value::Bytes(cca_cbor.clone()));
    map_insert(&mut body, 1, Value::Bytes(ct.sym_ct.clone()));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate based on CCA size + payload
    let mut output = Vec::with_capacity(cca_cbor.len() + ct.sym_ct.len() + 256);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode CCA Full Ciphertext from CBOR bytes
pub fn decode_cca_full_ct(data: &[u8]) -> Result<CcaFullCiphertext, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("CCA Full CT must be map".to_string()))?;

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let cca_bytes = map_get(body, 0)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| AbeError::DecryptError("Missing CCA ciphertext".to_string()))?;
    let cca_ct = decode_cca_ct(cca_bytes)?;

    let sym_ct = map_get(body, 1)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| AbeError::DecryptError("Missing sym_ct".to_string()))?;

    Ok(CcaFullCiphertext { cca_ct, sym_ct })
}

// ============================================================================
// FullCiphertext (Waters CPA) Encoding/Decoding
// ============================================================================

use crate::schemes::waters::FullCiphertext;

/// Encode Full Ciphertext (with payload) to CBOR bytes
pub fn encode_full_ct(ct: &FullCiphertext) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    // Convert raw ciphertext to typed wrapper for encoding
    let abe_ct: Ciphertext = ct.abe_ct.clone().into();
    let ct_cbor = encode_ct(&abe_ct)?;

    let mut body: CborMap = Vec::with_capacity(2);
    map_insert(&mut body, 0, Value::Bytes(ct_cbor.clone()));
    map_insert(&mut body, 1, Value::Bytes(ct.sym_ct.clone()));

    let mut item: CborMap = Vec::with_capacity(4);
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    // Pre-allocate based on CT size + payload
    let mut output = Vec::with_capacity(ct_cbor.len() + ct.sym_ct.len() + 256);
    ciborium::into_writer(&tagged, &mut output)
        .map_err(|e| AbeError::EncryptError(format!("CBOR encode error: {}", e)))?;

    Ok(output)
}

/// Decode Full Ciphertext from CBOR bytes
pub fn decode_full_ct(data: &[u8]) -> Result<FullCiphertext, AbeError> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| AbeError::DecryptError(format!("CBOR decode error: {}", e)))?;

    let inner = match &value {
        Value::Tag(tag, inner) if *tag == ABE_CBOR_TAG => inner.as_ref(),
        _ => &value,
    };

    let map = inner.as_map()
        .ok_or_else(|| AbeError::DecryptError("Full CT must be map".to_string()))?;

    let body_val = map_get(map, 5)
        .ok_or_else(|| AbeError::DecryptError("Missing body".to_string()))?;
    let body = body_val.as_map()
        .ok_or_else(|| AbeError::DecryptError("Body must be map".to_string()))?;

    let ct_bytes = map_get(body, 0)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| AbeError::DecryptError("Missing ABE ciphertext".to_string()))?;
    let abe_ct = decode_ct(ct_bytes)?;

    let sym_ct = map_get(body, 1)
        .and_then(|v| v.as_bytes())
        .map(|b| b.to_vec())
        .ok_or_else(|| AbeError::DecryptError("Missing sym_ct".to_string()))?;

    use crate::schemes::waters::RawFullCiphertext;
    Ok(RawFullCiphertext { abe_ct: abe_ct.into_inner(), sym_ct }.into())
}

// ============================================================================
// GPSW (KP-ABE) Encoding/Decoding - Using JSON for simplicity
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::gpsw;

/// Encode GPSW MPK to CBOR bytes (wraps JSON)
#[cfg(feature = "serde")]
pub fn encode_gpsw_mpk(mpk: &gpsw::Mpk) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(mpk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode GPSW MPK from CBOR bytes
#[cfg(feature = "serde")]
pub fn decode_gpsw_mpk(data: &[u8]) -> Result<gpsw::Mpk, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode GPSW MSK to CBOR bytes
#[cfg(feature = "serde")]
pub fn encode_gpsw_msk(msk: &gpsw::Msk) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(msk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode GPSW MSK from CBOR bytes
#[cfg(feature = "serde")]
pub fn decode_gpsw_msk(data: &[u8]) -> Result<gpsw::Msk, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode GPSW SecretKey to CBOR bytes
#[cfg(feature = "serde")]
pub fn encode_gpsw_sk(sk: &gpsw::SecretKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(sk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode GPSW SecretKey from CBOR bytes
#[cfg(feature = "serde")]
pub fn decode_gpsw_sk(data: &[u8]) -> Result<gpsw::SecretKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode GPSW FullCiphertext to CBOR bytes
#[cfg(feature = "serde")]
pub fn encode_gpsw_full_ct(ct: &gpsw::FullCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode GPSW FullCiphertext from CBOR bytes
#[cfg(feature = "serde")]
pub fn decode_gpsw_full_ct(data: &[u8]) -> Result<gpsw::FullCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// Waters PRE (Proxy Re-Encryption) Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::waters_pre;

/// Encode Waters PRE ReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_waters_rk(rk: &waters_pre::ReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters PRE ReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_waters_rk(data: &[u8]) -> Result<waters_pre::ReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters PRE ReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_waters_re_ct(ct: &waters_pre::ReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters PRE ReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_waters_re_ct(data: &[u8]) -> Result<waters_pre::ReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters PRE FullReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_waters_full_re_ct(ct: &waters_pre::FullReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters PRE FullReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_waters_full_re_ct(data: &[u8]) -> Result<waters_pre::FullReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// DABE PRE (Proxy Re-Encryption) Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::dabe_pre;

/// Encode DABE PRE DabeReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_rk(rk: &dabe_pre::DabeReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE PRE DabeReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_rk(data: &[u8]) -> Result<dabe_pre::DabeReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE PRE DabeReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_re_ct(ct: &dabe_pre::DabeReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE PRE DabeReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_re_ct(data: &[u8]) -> Result<dabe_pre::DabeReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE PRE FullDabeReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_full_re_ct(ct: &dabe_pre::FullDabeReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE PRE FullDabeReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_full_re_ct(data: &[u8]) -> Result<dabe_pre::FullDabeReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// Waters U2U PRE (User-to-User Proxy Re-Encryption) Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::waters_u2u_pre;

/// Encode Waters U2U PRE DelegationKeyPair to bytes
#[cfg(feature = "serde")]
pub fn encode_delegation_keypair(kp: &waters_u2u_pre::DelegationKeyPair) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(kp)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters U2U PRE DelegationKeyPair from bytes
#[cfg(feature = "serde")]
pub fn decode_delegation_keypair(data: &[u8]) -> Result<waters_u2u_pre::DelegationKeyPair, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters U2U PRE TargetPublicKey to bytes
#[cfg(feature = "serde")]
pub fn encode_target_pk(pk: &waters_u2u_pre::TargetPublicKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(pk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters U2U PRE TargetPublicKey from bytes
#[cfg(feature = "serde")]
pub fn decode_target_pk(data: &[u8]) -> Result<waters_u2u_pre::TargetPublicKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters U2U PRE TargetSecret to bytes
#[cfg(feature = "serde")]
pub fn encode_target_secret(secret: &waters_u2u_pre::TargetSecret) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(secret)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters U2U PRE TargetSecret from bytes
#[cfg(feature = "serde")]
pub fn decode_target_secret(data: &[u8]) -> Result<waters_u2u_pre::TargetSecret, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters U2U PRE U2UReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_waters_u2u_rk(rk: &waters_u2u_pre::U2UReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters U2U PRE U2UReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_waters_u2u_rk(data: &[u8]) -> Result<waters_u2u_pre::U2UReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters U2U PRE U2UReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_waters_u2u_re_ct(ct: &waters_u2u_pre::U2UReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters U2U PRE U2UReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_waters_u2u_re_ct(data: &[u8]) -> Result<waters_u2u_pre::U2UReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Waters U2U PRE FullU2UReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_waters_u2u_full_re_ct(ct: &waters_u2u_pre::FullU2UReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Waters U2U PRE FullU2UReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_waters_u2u_full_re_ct(data: &[u8]) -> Result<waters_u2u_pre::FullU2UReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// DABE U2U PRE (User-to-User Proxy Re-Encryption) Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::dabe_u2u_pre;

/// Encode DABE U2U PRE DabeU2UReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_u2u_rk(rk: &dabe_u2u_pre::DabeU2UReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE U2U PRE DabeU2UReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_u2u_rk(data: &[u8]) -> Result<dabe_u2u_pre::DabeU2UReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE U2U PRE DabeU2UReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_u2u_re_ct(ct: &dabe_u2u_pre::DabeU2UReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE U2U PRE DabeU2UReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_u2u_re_ct(data: &[u8]) -> Result<dabe_u2u_pre::DabeU2UReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE U2U PRE FullDabeU2UReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_u2u_full_re_ct(ct: &dabe_u2u_pre::FullDabeU2UReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE U2U PRE FullDabeU2UReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_u2u_full_re_ct(data: &[u8]) -> Result<dabe_u2u_pre::FullDabeU2UReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// AC17 PRE (Proxy Re-Encryption) Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::ac17_pre;

/// Encode AC17 PRE ReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_rk(rk: &ac17_pre::ReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 PRE ReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_rk(data: &[u8]) -> Result<ac17_pre::ReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 PRE ReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_re_ct(ct: &ac17_pre::ReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 PRE ReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_re_ct(data: &[u8]) -> Result<ac17_pre::ReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 PRE FullReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_full_re_ct(ct: &ac17_pre::FullReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 PRE FullReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_full_re_ct(data: &[u8]) -> Result<ac17_pre::FullReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// AC17 U2U PRE (User-to-User Proxy Re-Encryption) Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::ac17_u2u_pre;

/// Encode AC17 U2U PRE U2UReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_u2u_rk(rk: &ac17_u2u_pre::U2UReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 U2U PRE U2UReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_u2u_rk(data: &[u8]) -> Result<ac17_u2u_pre::U2UReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 U2U PRE U2UReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_u2u_re_ct(ct: &ac17_u2u_pre::U2UReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 U2U PRE U2UReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_u2u_re_ct(data: &[u8]) -> Result<ac17_u2u_pre::U2UReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 U2U PRE FullU2UReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_u2u_full_re_ct(ct: &ac17_u2u_pre::FullU2UReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 U2U PRE FullU2UReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_u2u_full_re_ct(data: &[u8]) -> Result<ac17_u2u_pre::FullU2UReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// Conditional PRE Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::conditional_pre;

/// Encode Conditional PRE ConditionalReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_conditional_rk(rk: &conditional_pre::ConditionalReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Conditional PRE ConditionalReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_conditional_rk(data: &[u8]) -> Result<conditional_pre::ConditionalReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Conditional PRE ConditionalReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_conditional_re_ct(ct: &conditional_pre::ConditionalReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Conditional PRE ConditionalReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_conditional_re_ct(data: &[u8]) -> Result<conditional_pre::ConditionalReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Conditional PRE FullConditionalReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_conditional_full_re_ct(ct: &conditional_pre::FullConditionalReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Conditional PRE FullConditionalReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_conditional_full_re_ct(data: &[u8]) -> Result<conditional_pre::FullConditionalReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Conditional PRE PolicyConditionalReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_policy_conditional_rk(rk: &conditional_pre::PolicyConditionalReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Conditional PRE PolicyConditionalReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_policy_conditional_rk(data: &[u8]) -> Result<conditional_pre::PolicyConditionalReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode TimeCondition to bytes
#[cfg(feature = "serde")]
pub fn encode_time_condition(cond: &conditional_pre::TimeCondition) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(cond)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode TimeCondition from bytes
#[cfg(feature = "serde")]
pub fn decode_time_condition(data: &[u8]) -> Result<conditional_pre::TimeCondition, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// Multi-hop PRE Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::multihop_pre;

/// Encode Multi-hop PRE MultiHopReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_multihop_rk(rk: &multihop_pre::MultiHopReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Multi-hop PRE MultiHopReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_multihop_rk(data: &[u8]) -> Result<multihop_pre::MultiHopReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Multi-hop PRE MultiHopReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_multihop_re_ct(ct: &multihop_pre::MultiHopReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Multi-hop PRE MultiHopReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_multihop_re_ct(data: &[u8]) -> Result<multihop_pre::MultiHopReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode Multi-hop PRE FullMultiHopReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_multihop_full_re_ct(ct: &multihop_pre::FullMultiHopReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode Multi-hop PRE FullMultiHopReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_multihop_full_re_ct(data: &[u8]) -> Result<multihop_pre::FullMultiHopReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode HopInfo to bytes
#[cfg(feature = "serde")]
pub fn encode_hop_info(hop: &multihop_pre::HopInfo) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(hop)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode HopInfo from bytes
#[cfg(feature = "serde")]
pub fn decode_hop_info(data: &[u8]) -> Result<multihop_pre::HopInfo, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// AC17 Conditional PRE Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::ac17_conditional_pre;

/// Encode AC17 Conditional PRE Ac17ConditionalReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_conditional_rk(rk: &ac17_conditional_pre::Ac17ConditionalReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 Conditional PRE Ac17ConditionalReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_conditional_rk(data: &[u8]) -> Result<ac17_conditional_pre::Ac17ConditionalReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 Conditional PRE Ac17ConditionalReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_conditional_re_ct(ct: &ac17_conditional_pre::Ac17ConditionalReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 Conditional PRE Ac17ConditionalReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_conditional_re_ct(data: &[u8]) -> Result<ac17_conditional_pre::Ac17ConditionalReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 Conditional PRE FullAc17ConditionalReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_conditional_full_re_ct(ct: &ac17_conditional_pre::FullAc17ConditionalReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 Conditional PRE FullAc17ConditionalReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_conditional_full_re_ct(data: &[u8]) -> Result<ac17_conditional_pre::FullAc17ConditionalReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 TimeCondition to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_time_condition(cond: &ac17_conditional_pre::TimeCondition) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(cond)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 TimeCondition from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_time_condition(data: &[u8]) -> Result<ac17_conditional_pre::TimeCondition, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// AC17 Multi-hop PRE Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::ac17_multihop_pre;

/// Encode AC17 Multi-hop PRE Ac17MultiHopReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_multihop_rk(rk: &ac17_multihop_pre::Ac17MultiHopReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 Multi-hop PRE Ac17MultiHopReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_multihop_rk(data: &[u8]) -> Result<ac17_multihop_pre::Ac17MultiHopReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 Multi-hop PRE Ac17MultiHopReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_multihop_re_ct(ct: &ac17_multihop_pre::Ac17MultiHopReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 Multi-hop PRE Ac17MultiHopReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_multihop_re_ct(data: &[u8]) -> Result<ac17_multihop_pre::Ac17MultiHopReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 Multi-hop PRE FullAc17MultiHopReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_multihop_full_re_ct(ct: &ac17_multihop_pre::FullAc17MultiHopReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 Multi-hop PRE FullAc17MultiHopReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_multihop_full_re_ct(data: &[u8]) -> Result<ac17_multihop_pre::FullAc17MultiHopReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode AC17 HopInfo to bytes
#[cfg(feature = "serde")]
pub fn encode_ac17_hop_info(hop: &ac17_multihop_pre::Ac17HopInfo) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(hop)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode AC17 HopInfo from bytes
#[cfg(feature = "serde")]
pub fn decode_ac17_hop_info(data: &[u8]) -> Result<ac17_multihop_pre::Ac17HopInfo, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// DABE Conditional PRE Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::dabe_conditional_pre;

/// Encode DABE Conditional PRE DabeConditionalReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_conditional_rk(rk: &dabe_conditional_pre::DabeConditionalReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE Conditional PRE DabeConditionalReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_conditional_rk(data: &[u8]) -> Result<dabe_conditional_pre::DabeConditionalReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE Conditional PRE DabeConditionalReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_conditional_re_ct(ct: &dabe_conditional_pre::DabeConditionalReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE Conditional PRE DabeConditionalReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_conditional_re_ct(data: &[u8]) -> Result<dabe_conditional_pre::DabeConditionalReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE Conditional PRE FullDabeConditionalReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_conditional_full_re_ct(ct: &dabe_conditional_pre::FullDabeConditionalReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE Conditional PRE FullDabeConditionalReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_conditional_full_re_ct(data: &[u8]) -> Result<dabe_conditional_pre::FullDabeConditionalReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE TimeCondition to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_time_condition(cond: &dabe_conditional_pre::TimeCondition) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(cond)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE TimeCondition from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_time_condition(data: &[u8]) -> Result<dabe_conditional_pre::TimeCondition, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode TrustedTimestamp to bytes
#[cfg(feature = "serde")]
pub fn encode_trusted_timestamp(ts: &dabe_conditional_pre::TrustedTimestamp) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ts)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode TrustedTimestamp from bytes
#[cfg(feature = "serde")]
pub fn decode_trusted_timestamp(data: &[u8]) -> Result<dabe_conditional_pre::TrustedTimestamp, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// DABE Multi-hop PRE Encoding/Decoding
// Only available when serde feature is enabled
// ============================================================================

#[cfg(feature = "serde")]
use crate::schemes::dabe_multihop_pre;

/// Encode DABE Multi-hop PRE DabeMultiHopReEncryptionKey to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_multihop_rk(rk: &dabe_multihop_pre::DabeMultiHopReEncryptionKey) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(rk)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE Multi-hop PRE DabeMultiHopReEncryptionKey from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_multihop_rk(data: &[u8]) -> Result<dabe_multihop_pre::DabeMultiHopReEncryptionKey, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE Multi-hop PRE DabeMultiHopReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_multihop_re_ct(ct: &dabe_multihop_pre::DabeMultiHopReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE Multi-hop PRE DabeMultiHopReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_multihop_re_ct(data: &[u8]) -> Result<dabe_multihop_pre::DabeMultiHopReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE Multi-hop PRE FullDabeMultiHopReEncryptedCiphertext to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_multihop_full_re_ct(ct: &dabe_multihop_pre::FullDabeMultiHopReEncryptedCiphertext) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(ct)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE Multi-hop PRE FullDabeMultiHopReEncryptedCiphertext from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_multihop_full_re_ct(data: &[u8]) -> Result<dabe_multihop_pre::FullDabeMultiHopReEncryptedCiphertext, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

/// Encode DABE HopInfo to bytes
#[cfg(feature = "serde")]
pub fn encode_dabe_hop_info(hop: &dabe_multihop_pre::DabeHopInfo) -> Result<Vec<u8>, AbeError> {
    serde_json::to_vec(hop)
        .map_err(|e| AbeError::EncryptError(format!("JSON encode error: {}", e)))
}

/// Decode DABE HopInfo from bytes
#[cfg(feature = "serde")]
pub fn decode_dabe_hop_info(data: &[u8]) -> Result<dabe_multihop_pre::DabeHopInfo, AbeError> {
    serde_json::from_slice(data)
        .map_err(|e| AbeError::DecryptError(format!("JSON decode error: {}", e)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::waters;
    use rand::thread_rng;

    #[test]
    fn test_mpk_roundtrip() {
        let mut rng = thread_rng();
        let (mpk, _msk) = waters::setup(&mut rng);

        let encoded = encode_mpk(&mpk).unwrap();
        let decoded = decode_mpk(&encoded).unwrap();

        assert_eq!(mpk.g1.into_bytes(), decoded.g1.into_bytes());
        assert_eq!(mpk.g1a.into_bytes(), decoded.g1a.into_bytes());
        assert_eq!(mpk.g2.into_bytes(), decoded.g2.into_bytes());
        assert_eq!(mpk.g2alpha.into_bytes(), decoded.g2alpha.into_bytes());
        assert_eq!(mpk.egg_alpha.into_bytes(), decoded.egg_alpha.into_bytes());
        assert_eq!(mpk.k, decoded.k);
    }

    #[test]
    fn test_msk_roundtrip() {
        let mut rng = thread_rng();
        let (_mpk, msk) = waters::setup(&mut rng);

        let encoded = encode_msk(&msk).unwrap();
        let decoded = decode_msk(&encoded).unwrap();

        assert_eq!(msk.alpha.into_bytes(), decoded.alpha.into_bytes());
    }

    #[test]
    fn test_sk_roundtrip() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);
        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let encoded = encode_sk(&sk).unwrap();
        let decoded = decode_sk(&encoded).unwrap();

        assert_eq!(sk.k.into_bytes(), decoded.k.into_bytes());
        assert_eq!(sk.l.into_bytes(), decoded.l.into_bytes());

        for attr in &sk.attributes {
            let orig = sk.kx.get(attr).unwrap();
            let dec = decoded.kx.get(attr).unwrap();
            assert_eq!(orig.into_bytes(), dec.into_bytes());
        }
    }

    #[test]
    fn test_ct_roundtrip() {
        let mut rng = thread_rng();
        let (mpk, _msk) = waters::setup(&mut rng);

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("dept:eng".to_string()),
        ]);

        let plaintext = b"Hello, CBOR!";
        let ct = waters::encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        let abe_ct: Ciphertext = ct.abe_ct.clone().into();
        let encoded = encode_ct(&abe_ct).unwrap();
        let decoded = decode_ct(&encoded).unwrap();

        assert_eq!(ct.abe_ct.c.into_bytes(), decoded.c.into_bytes());
        assert_eq!(ct.abe_ct.c_prime.into_bytes(), decoded.c_prime.into_bytes());

        for (attr, comp) in &ct.abe_ct.components {
            let dec_comp = decoded.components.get(attr).unwrap();
            assert_eq!(comp.c.into_bytes(), dec_comp.c.into_bytes());
            assert_eq!(comp.d.into_bytes(), dec_comp.d.into_bytes());
        }
    }

    #[test]
    fn test_cca_ct_roundtrip() {
        use crate::schemes::waters_cca;

        let mut rng = thread_rng();
        let (mpk, _msk) = waters::setup(&mut rng);

        let policy = PolicyNode::Attr("admin".to_string());
        let (ct, _key) = waters_cca::encrypt_kem(&mut rng, &mpk, &policy).unwrap();

        let encoded = encode_cca_ct(&ct).unwrap();
        let decoded = decode_cca_ct(&encoded).unwrap();

        assert_eq!(ct.encrypted_m, decoded.encrypted_m);
        assert_eq!(ct.uid, decoded.uid);
        assert_eq!(ct.cpa_ct.c.into_bytes(), decoded.cpa_ct.c.into_bytes());
    }

    #[test]
    fn test_full_encrypt_decrypt_with_cbor() {
        use crate::schemes::waters_cca;

        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Secret message via CBOR!";
        let ct = waters_cca::encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Encode to CBOR
        let mpk_cbor = encode_mpk(&mpk).unwrap();
        let sk_cbor = encode_sk(&sk).unwrap();
        let ct_cbor = encode_cca_full_ct(&ct).unwrap();

        // Decode from CBOR
        let mpk2 = decode_mpk(&mpk_cbor).unwrap();
        let sk2 = decode_sk(&sk_cbor).unwrap();
        let ct2 = decode_cca_full_ct(&ct_cbor).unwrap();

        // Decrypt
        let decrypted = waters_cca::decrypt(&mpk2, &sk2, &ct2).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_policy_rpn_roundtrip() {
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);

        let mut attr_list = Vec::new();
        let tokens = policy_to_rpn(&policy, &mut attr_list);
        let decoded = rpn_to_policy(&tokens, &attr_list).unwrap();

        assert_eq!(policy.to_canonical_string(), decoded.to_canonical_string());
    }

    #[test]
    fn test_waters_pre_rk_roundtrip() {
        use crate::schemes::waters_pre;

        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let rk = waters_pre::generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();

        let encoded = encode_waters_rk(&rk).unwrap();
        let decoded = decode_waters_rk(&encoded).unwrap();

        assert_eq!(rk.rk_k.into_bytes(), decoded.rk_k.into_bytes());
        assert_eq!(rk.rk_l.into_bytes(), decoded.rk_l.into_bytes());
        assert_eq!(rk.g2_delta.into_bytes(), decoded.g2_delta.into_bytes());
        assert_eq!(rk.source_attributes, decoded.source_attributes);
    }

    #[test]
    fn test_waters_pre_full_roundtrip() {
        use crate::schemes::waters_pre;

        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = waters::encrypt(&mut rng, &mpk, &policy, b"secret").unwrap();

        let rk = waters_pre::generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();
        let re_ct = waters_pre::re_encrypt_full(&mpk, &ct, &rk).unwrap();

        // Test FullReEncryptedCiphertext roundtrip
        let encoded = encode_waters_full_re_ct(&re_ct).unwrap();
        let decoded = decode_waters_full_re_ct(&encoded).unwrap();

        // Verify decryption works with decoded
        let decrypted = waters_pre::decrypt_reencrypted(&mpk, &decoded).unwrap();
        assert_eq!(decrypted, b"secret");
    }

    #[test]
    fn test_dabe_pre_rk_roundtrip() {
        use crate::schemes::dabe;
        use crate::schemes::dabe_pre;

        let mut rng = thread_rng();
        let gp = dabe::global_setup(&mut rng);
        let (apk, ask) = dabe::authority_setup(&mut rng, &gp, "auth");

        let uk = dabe::authority_keygen(&mut rng, &gp, &ask, "user", &["attr".to_string()]).unwrap();
        let usk = dabe::aggregate_user_keys(vec![uk]).unwrap();

        let rk = dabe_pre::generate_rekey(&mut rng, &gp, &usk).unwrap();

        let encoded = encode_dabe_rk(&rk).unwrap();
        let decoded = decode_dabe_rk(&encoded).unwrap();

        // Verify authority components
        assert!(decoded.authority_components.contains_key("auth"));
        let orig_comp = rk.authority_components.get("auth").unwrap();
        let dec_comp = decoded.authority_components.get("auth").unwrap();
        assert_eq!(orig_comp.rk_k.into_bytes(), dec_comp.rk_k.into_bytes());
    }

    #[test]
    fn test_dabe_pre_full_roundtrip() {
        use crate::schemes::dabe;
        use crate::schemes::dabe_pre;
        use std::collections::HashMap;

        let mut rng = thread_rng();
        let gp = dabe::global_setup(&mut rng);
        let (apk, ask) = dabe::authority_setup(&mut rng, &gp, "auth");

        let uk = dabe::authority_keygen(&mut rng, &gp, &ask, "user", &["attr".to_string()]).unwrap();
        let usk = dabe::aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth".to_string(), apk);

        let policy = PolicyNode::Attr("auth:attr".to_string());
        let ct = dabe::encrypt(&mut rng, &gp, &pks, &policy, b"dabe secret").unwrap();

        let rk = dabe_pre::generate_rekey(&mut rng, &gp, &usk).unwrap();
        let re_ct = dabe_pre::re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Test serialization roundtrip
        let encoded = encode_dabe_full_re_ct(&re_ct).unwrap();
        let decoded = decode_dabe_full_re_ct(&encoded).unwrap();

        // Verify decryption works with decoded
        let decrypted = dabe_pre::decrypt_reencrypted(&gp, &decoded).unwrap();
        assert_eq!(decrypted, b"dabe secret");
    }

    #[test]
    fn test_waters_u2u_delegation_keypair_roundtrip() {
        use crate::schemes::waters_u2u_pre;

        let mut rng = thread_rng();
        let (mpk, _msk) = waters::setup(&mut rng);
        let kp = waters_u2u_pre::generate_delegation_keypair(&mut rng, &mpk);

        let encoded = encode_delegation_keypair(&kp).unwrap();
        let decoded = decode_delegation_keypair(&encoded).unwrap();

        assert_eq!(kp.pk.into_bytes(), decoded.pk.into_bytes());
        assert_eq!(kp.sk.into_bytes(), decoded.sk.into_bytes());
    }

    #[test]
    fn test_waters_u2u_rk_roundtrip() {
        use crate::schemes::waters_u2u_pre::{self, TargetPublicKey};

        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let bob_keys = waters_u2u_pre::generate_delegation_keypair(&mut rng, &mpk);
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = waters_u2u_pre::generate_u2u_rekey(&mut rng, &mpk, &sk, &target_pk, &attrs).unwrap();

        let encoded = encode_waters_u2u_rk(&rk).unwrap();
        let decoded = decode_waters_u2u_rk(&encoded).unwrap();

        assert_eq!(rk.rk_k.into_bytes(), decoded.rk_k.into_bytes());
        assert_eq!(rk.rk_l.into_bytes(), decoded.rk_l.into_bytes());
        assert_eq!(rk.u.into_bytes(), decoded.u.into_bytes());
        assert_eq!(rk.w.into_bytes(), decoded.w.into_bytes());
        assert_eq!(rk.source_attributes, decoded.source_attributes);
    }

    #[test]
    fn test_waters_u2u_full_roundtrip() {
        use crate::schemes::waters_u2u_pre::{self, TargetPublicKey, TargetSecret};

        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let bob_keys = waters_u2u_pre::generate_delegation_keypair(&mut rng, &mpk);
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = waters::encrypt(&mut rng, &mpk, &policy, b"u2u secret").unwrap();

        let rk = waters_u2u_pre::generate_u2u_rekey(&mut rng, &mpk, &sk, &target_pk, &attrs).unwrap();
        let re_ct = waters_u2u_pre::u2u_re_encrypt_full(&mpk, &ct, &rk).unwrap();

        // Test serialization roundtrip
        let encoded = encode_waters_u2u_full_re_ct(&re_ct).unwrap();
        let decoded = decode_waters_u2u_full_re_ct(&encoded).unwrap();

        // Verify decryption works with decoded
        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = waters_u2u_pre::u2u_decrypt_reencrypted(&decoded, &target_secret).unwrap();
        assert_eq!(decrypted, b"u2u secret");
    }

    #[test]
    fn test_dabe_u2u_rk_roundtrip() {
        use crate::schemes::dabe;
        use crate::schemes::dabe_u2u_pre;
        use crate::schemes::waters_u2u_pre::TargetPublicKey;

        let mut rng = thread_rng();
        let gp = dabe::global_setup(&mut rng);
        let (_apk, ask) = dabe::authority_setup(&mut rng, &gp, "auth");

        let uk = dabe::authority_keygen(&mut rng, &gp, &ask, "user", &["attr".to_string()]).unwrap();
        let usk = dabe::aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = dabe_u2u_pre::generate_delegation_keypair(&mut rng, &gp);
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);

        let rk = dabe_u2u_pre::generate_u2u_rekey(&mut rng, &gp, &usk, &target_pk).unwrap();

        let encoded = encode_dabe_u2u_rk(&rk).unwrap();
        let decoded = decode_dabe_u2u_rk(&encoded).unwrap();

        // Verify authority components
        assert!(decoded.authority_components.contains_key("auth"));
        let orig_comp = rk.authority_components.get("auth").unwrap();
        let dec_comp = decoded.authority_components.get("auth").unwrap();
        assert_eq!(orig_comp.rk_k.into_bytes(), dec_comp.rk_k.into_bytes());
        assert_eq!(rk.u.into_bytes(), decoded.u.into_bytes());
        assert_eq!(rk.w.into_bytes(), decoded.w.into_bytes());
    }

    #[test]
    fn test_dabe_u2u_full_roundtrip() {
        use crate::schemes::dabe;
        use crate::schemes::dabe_u2u_pre;
        use crate::schemes::waters_u2u_pre::{TargetPublicKey, TargetSecret};
        use std::collections::HashMap;

        let mut rng = thread_rng();
        let gp = dabe::global_setup(&mut rng);
        let (apk, ask) = dabe::authority_setup(&mut rng, &gp, "auth");

        let uk = dabe::authority_keygen(&mut rng, &gp, &ask, "user", &["attr".to_string()]).unwrap();
        let usk = dabe::aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = dabe_u2u_pre::generate_delegation_keypair(&mut rng, &gp);
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);

        let mut pks = HashMap::new();
        pks.insert("auth".to_string(), apk);

        let policy = PolicyNode::Attr("auth:attr".to_string());
        let ct = dabe::encrypt(&mut rng, &gp, &pks, &policy, b"dabe u2u secret").unwrap();

        let rk = dabe_u2u_pre::generate_u2u_rekey(&mut rng, &gp, &usk, &target_pk).unwrap();
        let re_ct = dabe_u2u_pre::u2u_re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Test serialization roundtrip
        let encoded = encode_dabe_u2u_full_re_ct(&re_ct).unwrap();
        let decoded = decode_dabe_u2u_full_re_ct(&encoded).unwrap();

        // Verify decryption works with decoded
        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = dabe_u2u_pre::u2u_decrypt_reencrypted(&gp, &decoded, &target_secret).unwrap();
        assert_eq!(decrypted, b"dabe u2u secret");
    }
}
