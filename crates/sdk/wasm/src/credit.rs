//! Credits in the browser (docs/CREDITS.md): a JavaScript credit provider
//! behind the SDK's `CreditProvider`, and the JavaScript shapes of a credit
//! status and a receipt. The wallet itself, Cashu ecash presented as
//! `REQ_CREDIT_PRESENT` kind 1, is `web/src/cashu-wallet.ts`.

use wasm_bindgen::prelude::*;

/// [`CreditProvider`] over a JavaScript function `(credits: number) =>
/// { kind: number, payload: Uint8Array, credits?: number } | null`: the
/// browser's wallet (`web/src/cashu-wallet.ts` `CashuWallet.present`), which
/// moves the proofs it hands over to "in flight" first.
///
/// `js_sys::Function` is `!Send + !Sync`; the wrapper lies about the bound,
/// which is sound on wasm32 where everything runs on the one JS thread.
#[cfg(target_arch = "wasm32")]
pub(crate) struct JsCreditProvider {
    cb: send_wrapper::SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl JsCreditProvider {
    pub(crate) fn new(cb: js_sys::Function) -> Self {
        Self {
            cb: send_wrapper::SendWrapper::new(cb),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl pir_sdk_client::credit_transport::CreditProvider for JsCreditProvider {
    fn present(
        &self,
        credits: u64,
    ) -> pir_sdk_client::PirResult<Option<pir_sdk_client::credit_transport::Presentation>> {
        use pir_sdk::PirError;
        let value = (*self.cb)
            .call1(&JsValue::NULL, &JsValue::from_f64(credits as f64))
            .map_err(|e| PirError::Protocol(format!("credit provider threw: {e:?}")))?;
        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }
        let field = |name: &str| js_sys::Reflect::get(&value, &JsValue::from_str(name)).ok();
        let kind = field("kind")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| PirError::Protocol("credit provider: missing kind".into()))?;
        let payload = field("payload")
            .filter(|v| v.is_instance_of::<js_sys::Uint8Array>())
            .map(|v| js_sys::Uint8Array::new(&v).to_vec())
            .ok_or_else(|| {
                PirError::Protocol("credit provider: payload must be a Uint8Array".into())
            })?;
        let presented = field("credits")
            .and_then(|v| v.as_f64())
            .unwrap_or(credits as f64);
        Ok(Some(pir_sdk_client::credit_transport::Presentation {
            kind: kind as u8,
            payload,
            credits: presented.max(0.0) as u64,
        }))
    }
}

/// `"not-enabled" | "not-required" | "required" | "best-effort"` for
/// `enableCredits`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn credit_status_str(
    status: pir_sdk_client::credit_transport::CreditStatus,
) -> &'static str {
    use pir_sdk_client::credit_transport::CreditStatus;
    match status {
        CreditStatus::NotEnabled => "not-enabled",
        CreditStatus::NotRequired => "not-required",
        CreditStatus::Required => "required",
        CreditStatus::BestEffort => "best-effort",
    }
}

/// `{ gasAdded, gasBalance }` for the `presentCredits` wrappers.
pub(crate) fn credit_receipt_to_js(receipt: pir_sdk_client::credits::CreditReceipt) -> JsValue {
    let object = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &object,
        &JsValue::from_str("gasAdded"),
        &JsValue::from_f64(receipt.gas_added as f64),
    );
    let _ = js_sys::Reflect::set(
        &object,
        &JsValue::from_str("gasBalance"),
        &JsValue::from_f64(receipt.gas_balance as f64),
    );
    object.into()
}
