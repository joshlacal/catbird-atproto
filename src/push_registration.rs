//! Byte-exact push binding transcript shared by the canonical service and gateway.
//! Wire types are generated; this is the handwritten encoding specified by the lexicon.
use crate::blue_catbird::chat::PushRegistrationBody;

pub const DOMAIN: &str = "CATBIRD-CHAT-PUSH-BINDING\0";
pub const AUTHORITY: &str = "did:web:chat.catbird.blue";
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, thiserror::Error)]
#[error("invalid canonical push binding")]
pub struct InvalidPushBinding;

fn text(out: &mut Vec<u8>, value: &str) -> Result<(), InvalidPushBinding> {
    let len = u32::try_from(value.len()).map_err(|_| InvalidPushBinding)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn uuid_bytes(value: &str) -> Result<[u8; 16], InvalidPushBinding> {
    if value.len() != 36 {
        return Err(InvalidPushBinding);
    }
    let mut out = [0; 16];
    let mut nibble = 0;
    for (i, byte) in value.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if byte != b'-' {
                return Err(InvalidPushBinding);
            }
            continue;
        }
        let hex = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(InvalidPushBinding),
        };
        out[nibble / 2] = (out[nibble / 2] << 4) | hex;
        nibble += 1;
    }
    Ok(out)
}
/// Does not authenticate the key or establish freshness. Callers must bind the
/// principal, current enrolled key/generation, exact token hash and monotonic CAS.
pub fn transcript(body: &PushRegistrationBody) -> Result<Vec<u8>, InvalidPushBinding> {
    let actor = body.actor_did.as_str();
    let signed_at = body.signed_at.as_str();
    let app: &str = body.app_id.as_ref();
    let key: &str = body.key_id.as_ref();
    if body.protocol_version.as_str() != "2"
        || body.signature_domain.as_str() != DOMAIN
        || body.authority_did.as_str() != AUTHORITY
        || !(1..=MAX_SAFE_INTEGER).contains(&body.auth_generation)
        || !(1..=MAX_SAFE_INTEGER).contains(&body.token_generation)
        || !matches!(body.provider.as_str(), "apns" | "fcm")
        || app.is_empty()
        || app.len() > 128
        || !app.is_ascii()
        || app
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || key.len() != 43
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || !(12..=261).contains(&actor.len())
        || actor.contains(['#', '?'])
        || body.token_sha256.len() != 32
        || body.extra_data.as_ref().is_some_and(|x| !x.is_empty())
        || signed_at.len() != 24
        || !signed_at.ends_with('Z')
        || signed_at.as_bytes()[10] != b'T'
        || signed_at.as_bytes()[19] != b'.'
    {
        return Err(InvalidPushBinding);
    }
    let mut out = DOMAIN.as_bytes().to_vec();
    text(&mut out, body.protocol_version.as_str())?;
    text(&mut out, body.authority_did.as_ref())?;
    text(&mut out, actor)?;
    out.extend_from_slice(&uuid_bytes(body.actor_device_id.as_ref())?);
    text(&mut out, key)?;
    out.extend_from_slice(&(body.auth_generation as u64).to_be_bytes());
    out.extend_from_slice(&uuid_bytes(body.registration_id.as_ref())?);
    text(&mut out, body.provider.as_str())?;
    text(&mut out, app)?;
    out.extend_from_slice(&(body.token_generation as u64).to_be_bytes());
    out.extend_from_slice(&body.token_sha256);
    out.push(u8::from(body.enabled));
    text(&mut out, signed_at)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_cross_platform_golden_transcript_and_domain_fences() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/push-registration.json")).unwrap();
        let mut body: PushRegistrationBody =
            serde_json::from_value(fixture["body"].clone()).unwrap();
        let actual = transcript(&body)
            .unwrap()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>();
        assert_eq!(actual, fixture["transcriptHex"].as_str().unwrap());
        body.protocol_version = crate::blue_catbird::chat::PushRegistrationBodyProtocolVersion::Other("1".into());
        assert!(transcript(&body).is_err());
        body.protocol_version = crate::blue_catbird::chat::PushRegistrationBodyProtocolVersion::_2;
        body.signature_domain = "CATBIRD-CHAT-CREATE\0".into();
        assert!(transcript(&body).is_err());
    }
    #[test]
    fn uuid_encoding_rejects_noncanonical_spellings() {
        assert_eq!(
            uuid_bytes("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            [0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255]
        );
        for invalid in [
            "00112233445566778899aabbccddeeff",
            "00112233-4455-6677-8899-AABBCCDDEEFF",
            "00112233_4455-6677-8899-aabbccddeeff",
        ] {
            assert!(uuid_bytes(invalid).is_err());
        }
    }
}
