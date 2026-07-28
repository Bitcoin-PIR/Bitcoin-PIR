//! Shared PIR wire opcode registry for service authorization.

/// Fetch the live signed service policy after strict channel verification.
pub const REQ_SERVICE_POLICY_V1: u8 = 0x0d;
/// Response-direction label for [`REQ_SERVICE_POLICY_V1`].
pub const RESP_SERVICE_POLICY_V1: u8 = 0x0d;

/// Present one provider-local capability for one bounded logical operation.
pub const REQ_AUTH_BEGIN_V1: u8 = 0x0e;
/// Response-direction label for [`REQ_AUTH_BEGIN_V1`].
pub const RESP_AUTH_RESULT_V1: u8 = 0x0e;

/// Request a server-fresh, secure-channel-bound free proof-of-work challenge.
pub const REQ_POW_CHALLENGE_V1: u8 = 0x0f;
/// Response-direction label for [`REQ_POW_CHALLENGE_V1`].
pub const RESP_POW_CHALLENGE_V1: u8 = 0x0f;

/// Attach the complementary HarmonyPIR V2 half after the primary half has
/// consumed the authorization capability.
pub const REQ_HARMONY_ATTACH_V1: u8 = 0x10;
/// Response-direction label for [`REQ_HARMONY_ATTACH_V1`].
pub const RESP_HARMONY_ATTACH_V1: u8 = 0x10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_opcode_assignments_are_stable() {
        assert_eq!(REQ_SERVICE_POLICY_V1, 0x0d);
        assert_eq!(RESP_SERVICE_POLICY_V1, 0x0d);
        assert_eq!(REQ_AUTH_BEGIN_V1, 0x0e);
        assert_eq!(RESP_AUTH_RESULT_V1, 0x0e);
        assert_eq!(REQ_POW_CHALLENGE_V1, 0x0f);
        assert_eq!(RESP_POW_CHALLENGE_V1, 0x0f);
        assert_eq!(REQ_HARMONY_ATTACH_V1, 0x10);
        assert_eq!(RESP_HARMONY_ATTACH_V1, 0x10);
    }
}
