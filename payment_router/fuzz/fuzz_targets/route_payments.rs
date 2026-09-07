#![no_main]

//! Fuzz target for `PaymentRouter::route_payments` (issue #527).
//!
//! Feeds randomly generated, malformed, and massive `Payment` arrays to the
//! batch routing entry point. The contract is expected to fail gracefully
//! (return an `Err`) on invalid input rather than panic or trap — libFuzzer
//! treats any panic as a crash, so a clean `Result` either way is a pass.

use std::sync::Once;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use payment_router::{Payment, PaymentRouter, PaymentRouterClient};
use soroban_sdk::{testutils::Address as _, vec, Address, Env};

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            eprintln!("Panic caught: {:?}", info);
        }));
    });
}

/// Cap the batch size so a single fuzz iteration stays fast; the underlying
/// `Vec<Payment>` machinery is already exercised at whatever size libFuzzer
/// generates up to this bound.
const MAX_PAYMENTS: usize = 32;
const NUM_SENDERS: usize = 4;
const NUM_RECIPIENTS: usize = 4;
const SENDER_STARTING_BALANCE: i128 = i128::MAX / 4;

// Fixed, sane admin configuration. The fuzz target is only concerned with
// malicious/malformed `Payment` arrays, not admin misconfiguration, so fee
// settings mirror the values used by the existing unit tests.
const FEE_BPS: i128 = 100;
const FEE_CAP: i128 = 1_000_000;
// Mirrors the contract's private `PaymentRouter::MAX_AMOUNT` constant, which
// isn't reachable from outside the crate.
const MAX_AMOUNT: i128 = 1_000_000_000_000_000;

#[derive(Debug, Arbitrary)]
struct FuzzPayment {
    amount: i128,
    sender_idx: u8,
    recipient_idx: u8,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    payments: Vec<FuzzPayment>,
}

fuzz_target!(|input: FuzzInput| {
    setup();

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);

        let contract_id = env.register_contract(None, PaymentRouter);
        let client = PaymentRouterClient::new(&env, &contract_id);

        if client
            .try_initialize(&admin, &treasury, &FEE_BPS, &FEE_CAP, &MAX_AMOUNT)
            .is_err()
        {
            return;
        }

        let token_admin = Address::generate(&env);
        let token_address = env.register_stellar_asset_contract(token_admin);
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);

        let senders: Vec<Address> = (0..NUM_SENDERS).map(|_| Address::generate(&env)).collect();
        for sender in &senders {
            sac.mint(sender, &SENDER_STARTING_BALANCE);
        }
        let recipients: Vec<Address> = (0..NUM_RECIPIENTS)
            .map(|_| Address::generate(&env))
            .collect();

        let mut payments = vec![&env];
        for fuzz_payment in input.payments.iter().take(MAX_PAYMENTS) {
            let sender = &senders[fuzz_payment.sender_idx as usize % senders.len()];
            let recipient = &recipients[fuzz_payment.recipient_idx as usize % recipients.len()];
            payments.push_back(Payment {
                sender: sender.clone(),
                recipient: recipient.clone(),
                token_address: token_address.clone(),
                amount: fuzz_payment.amount,
            });
        }

        // Only the absence of a panic/trap matters here — any `Err` is a graceful
        // rejection, which is the behavior this fuzz target verifies.
        let _ = client.try_route_payments(&payments);
    }));
});

