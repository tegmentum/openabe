//! ABE-CBOR v1 Serialization
//!
//! This module implements ABE-CBOR v1 serialization format for cross-platform
//! compatibility between native and WASM implementations.

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::schemes::waters::{Ciphertext, CiphertextComponent, Mpk, Msk, SecretKey};
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
}

/// Scheme identifiers
pub mod scheme {
    pub const CPABE_WATERS: &str = "cpabe-waters";
    pub const CPABE_WATERS_CCA: &str = "cpabe-waters-cca";
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
        let mut map: CborMap = Vec::new();
        map_insert(&mut map, 0, Value::Text(self.scheme_id.clone()));

        // Curve info
        let mut curve_map: CborMap = Vec::new();
        map_insert(&mut curve_map, 0, Value::Text(self.curve_id.clone()));
        map_insert(&mut curve_map, 1, Value::Integer(self.security_level.into()));
        map_insert(&mut map, 1, Value::Map(curve_map));

        // GE encoding
        let mut ge_map: CborMap = Vec::new();
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
    Value::Array(elems.iter().map(|e| Value::Bytes(e.clone())).collect())
}

fn decode_group_elems(value: &Value) -> Result<Vec<Vec<u8>>, AbeError> {
    let arr = value.as_array()
        .ok_or_else(|| AbeError::DecryptError("GroupElems must be array".to_string()))?;
    arr.iter()
        .map(|v| {
            v.as_bytes()
                .map(|b| b.to_vec())
                .ok_or_else(|| AbeError::DecryptError("GroupElem must be bytes".to_string()))
        })
        .collect()
}

fn encode_attr_set(attrs: &[String]) -> Value {
    let mut sorted_attrs: Vec<_> = attrs.to_vec();
    sorted_attrs.sort();

    let attr_array: Vec<Value> = sorted_attrs.iter().map(|a| {
        let mut attr_map: CborMap = Vec::new();
        map_insert(&mut attr_map, 0, Value::Integer(0.into())); // type = STRING
        map_insert(&mut attr_map, 1, Value::Text(a.clone()));
        Value::Map(attr_map)
    }).collect();

    let mut map: CborMap = Vec::new();
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
    let elems = vec![
        mpk.g1.into_bytes(),
        mpk.g2.into_bytes(),
        mpk.g1a.into_bytes(),
        mpk.g2alpha.into_bytes(),
        mpk.egg_alpha.into_bytes(),
        mpk.k.clone(),
    ];

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, encode_group_elems(&elems));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::MPK.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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

    let g1 = G1::from_slice(&elems[0])
        .ok_or_else(|| AbeError::DecryptError("Invalid G1".to_string()))?;
    let g2 = G2::from_slice(&elems[1])
        .ok_or_else(|| AbeError::DecryptError("Invalid G2".to_string()))?;
    let g1a = G1::from_slice(&elems[2])
        .ok_or_else(|| AbeError::DecryptError("Invalid G1a".to_string()))?;
    let g2alpha = G2::from_slice(&elems[3])
        .ok_or_else(|| AbeError::DecryptError("Invalid G2alpha".to_string()))?;
    let egg_alpha = Gt::from_slice(&elems[4])
        .ok_or_else(|| AbeError::DecryptError("Invalid egg_alpha".to_string()))?;
    let k = elems[5].clone();

    Ok(Mpk { g1, g2, g1a, g2alpha, egg_alpha, k })
}

// ============================================================================
// MSK Encoding/Decoding
// ============================================================================

/// Encode MSK to CBOR bytes
pub fn encode_msk(msk: &Msk) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    let elems = vec![
        msk.alpha.into_bytes(),
        msk.g2a.into_bytes(),
    ];

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, encode_group_elems(&elems));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::MSK.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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
    let g2a = G2::from_slice(&elems[1])
        .ok_or_else(|| AbeError::DecryptError("Invalid g2a".to_string()))?;

    Ok(Msk { alpha, g2a })
}

// ============================================================================
// SecretKey Encoding/Decoding
// ============================================================================

/// Encode SecretKey to CBOR bytes
pub fn encode_sk(sk: &SecretKey) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::default();

    let mut elems = vec![
        sk.k.into_bytes(),
        sk.l.into_bytes(),
    ];

    let mut sorted_attrs: Vec<_> = sk.attributes.clone();
    sorted_attrs.sort();

    for attr in &sorted_attrs {
        if let Some(kx) = sk.kx.get(attr) {
            elems.push(kx.into_bytes());
        }
    }

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, encode_group_elems(&elems));
    map_insert(&mut body, 1, encode_attr_set(&sorted_attrs));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::SK.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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

    let k = G2::from_slice(&elems[0])
        .ok_or_else(|| AbeError::DecryptError("Invalid K".to_string()))?;
    let l = G2::from_slice(&elems[1])
        .ok_or_else(|| AbeError::DecryptError("Invalid L".to_string()))?;

    let mut kx = std::collections::HashMap::new();
    for (i, attr) in attributes.iter().enumerate() {
        let kx_elem = G1::from_slice(&elems[2 + i])
            .ok_or_else(|| AbeError::DecryptError(format!("Invalid Kx for {}", attr)))?;
        kx.insert(attr.clone(), kx_elem);
    }

    Ok(SecretKey { k, l, kx, attributes })
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

    let mut elems = vec![
        ct.c.into_bytes(),
        ct.c_prime.into_bytes(),
    ];

    let mut sorted_attrs: Vec<_> = attr_list.clone();
    sorted_attrs.sort();

    for attr in &sorted_attrs {
        if let Some(comp) = ct.components.get(attr) {
            elems.push(comp.c.into_bytes());
            elems.push(comp.d.into_bytes());
        }
    }

    let mut policy_map: CborMap = Vec::new();
    map_insert(&mut policy_map, 0, Value::Integer(policy_encoding::BOOL_AST.into()));
    map_insert(&mut policy_map, 1, Value::Array(rpn_tokens));

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, encode_group_elems(&elems));
    map_insert(&mut body, 1, Value::Map(policy_map));
    map_insert(&mut body, 2, encode_attr_set(&sorted_attrs));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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

    let c = Gt::from_slice(&elems[0])
        .ok_or_else(|| AbeError::DecryptError("Invalid C".to_string()))?;
    let c_prime = G1::from_slice(&elems[1])
        .ok_or_else(|| AbeError::DecryptError("Invalid C'".to_string()))?;

    let mut components = std::collections::HashMap::new();
    for (i, attr) in attr_list.iter().enumerate() {
        let c_i = G1::from_slice(&elems[2 + i * 2])
            .ok_or_else(|| AbeError::DecryptError(format!("Invalid C_i for {}", attr)))?;
        let d_i = G2::from_slice(&elems[2 + i * 2 + 1])
            .ok_or_else(|| AbeError::DecryptError(format!("Invalid D_i for {}", attr)))?;
        components.insert(attr.clone(), CiphertextComponent { c: c_i, d: d_i });
    }

    Ok(Ciphertext {
        policy: policy_str,
        c,
        c_prime,
        components,
    })
}

// ============================================================================
// CCA Ciphertext Encoding/Decoding
// ============================================================================

/// Encode CCA Ciphertext to CBOR bytes
pub fn encode_cca_ct(ct: &CcaCiphertext) -> Result<Vec<u8>, AbeError> {
    let suite = Suite::waters_cca();

    let cpa_cbor = encode_ct(&ct.cpa_ct)?;

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, Value::Bytes(cpa_cbor));
    map_insert(&mut body, 1, Value::Bytes(ct.encrypted_m.clone()));
    map_insert(&mut body, 2, Value::Bytes(ct.uid.to_vec()));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, Value::Bytes(cca_cbor));
    map_insert(&mut body, 1, Value::Bytes(ct.sym_ct.clone()));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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

    let ct_cbor = encode_ct(&ct.abe_ct)?;

    let mut body: CborMap = Vec::new();
    map_insert(&mut body, 0, Value::Bytes(ct_cbor));
    map_insert(&mut body, 1, Value::Bytes(ct.sym_ct.clone()));

    let mut item: CborMap = Vec::new();
    map_insert(&mut item, 0, Value::Integer(kind::CT.into()));
    map_insert(&mut item, 1, suite.to_cbor());
    map_insert(&mut item, 2, Value::Integer(ABE_CBOR_VERSION.into()));
    map_insert(&mut item, 5, Value::Map(body));

    let tagged = Value::Tag(ABE_CBOR_TAG, Box::new(Value::Map(item)));

    let mut output = Vec::new();
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

    Ok(FullCiphertext { abe_ct, sym_ct })
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

        let encoded = encode_ct(&ct.abe_ct).unwrap();
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
}
