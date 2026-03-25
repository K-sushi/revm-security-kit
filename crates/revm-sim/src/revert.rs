//! Revert classification and decoding utilities.
//!
//! Extracted from [`Simulator`] to keep the core module focused
//! on execution. These helpers are used by `convert_result` and
//! can be called standalone for post-hoc analysis.

use revm::primitives::ExecutionResult;

use crate::simulator::Simulator;
use crate::types::RevertLabel;

impl Simulator {
    /// Classify revert reason for analysis.
    pub fn classify_revert(
        result: &ExecutionResult,
        gas_limit: u64,
    ) -> RevertLabel {
        use revm::primitives::HaltReason;
        match result {
            ExecutionResult::Success { .. } => RevertLabel::Unknown,
            ExecutionResult::Revert { gas_used, .. } => {
                if *gas_used >= gas_limit {
                    RevertLabel::OutOfGas
                } else {
                    RevertLabel::RevertedNoReason
                }
            }
            ExecutionResult::Halt { reason, .. } => match reason {
                HaltReason::OutOfGas(_) => RevertLabel::OutOfGas,
                HaltReason::InvalidFEOpcode
                | HaltReason::OpcodeNotFound => RevertLabel::InvalidOpcode,
                HaltReason::OutOfFunds => {
                    RevertLabel::InsufficientLiquidity
                }
                _ => RevertLabel::Unknown,
            },
        }
    }

    /// Decode a Solidity `Error(string)` revert into a human-readable
    /// message. Falls back to hex-encoded output when the selector
    /// does not match `0x08c379a0`.
    pub(crate) fn decode_revert(
        output: &revm::primitives::Bytes,
    ) -> String {
        if output.len() >= 68
            && output[0..4] == [0x08, 0xc3, 0x79, 0xa0]
        {
            let len_start = 36;
            if len_start + 32 <= output.len() {
                let len_bytes: [u8; 8] = [
                    output[len_start + 24],
                    output[len_start + 25],
                    output[len_start + 26],
                    output[len_start + 27],
                    output[len_start + 28],
                    output[len_start + 29],
                    output[len_start + 30],
                    output[len_start + 31],
                ];
                let length = u64::from_be_bytes(len_bytes) as usize;
                let str_start = len_start + 32;
                if str_start + length <= output.len() {
                    if let Ok(reason) = String::from_utf8(
                        output[str_start..str_start + length].to_vec(),
                    ) {
                        return reason;
                    }
                }
            }
        }
        format!("0x{}", hex::encode(output))
    }
}
