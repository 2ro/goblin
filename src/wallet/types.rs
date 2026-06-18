// Copyright 2023 The Grim Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use grin_keychain::ExtKeychain;
use grin_util::Mutex;
use grin_wallet_impls::{DefaultLCProvider, HTTPNodeClient};
use grin_wallet_libwallet::{
	Error, PaymentProof, SlateState, SlatepackAddress, TxLogEntry, TxLogEntryType, WalletInfo,
	WalletInst,
};
use grin_wallet_util::OnionV3Address;
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;

use crate::wallet::Wallet;

/// Mnemonic phrase word.
#[derive(Clone)]
pub struct PhraseWord {
	/// Word text.
	pub text: String,
	/// Flag to check if word is valid.
	pub valid: bool,
}

/// Mnemonic phrase setup mode.
#[derive(PartialEq, Clone)]
pub enum PhraseMode {
	/// Generate new mnemonic phrase.
	Generate,
	/// Import existing mnemonic phrase.
	Import,
}

/// Mnemonic phrase size based on entropy.
#[derive(PartialEq, Clone)]
pub enum PhraseSize {
	Words12,
	Words15,
	Words18,
	Words21,
	Words24,
}

impl PhraseSize {
	pub const VALUES: [PhraseSize; 5] = [
		PhraseSize::Words12,
		PhraseSize::Words15,
		PhraseSize::Words18,
		PhraseSize::Words21,
		PhraseSize::Words24,
	];

	/// Get entropy value.
	pub fn value(&self) -> usize {
		match *self {
			PhraseSize::Words12 => 12,
			PhraseSize::Words15 => 15,
			PhraseSize::Words18 => 18,
			PhraseSize::Words21 => 21,
			PhraseSize::Words24 => 24,
		}
	}

	/// Get entropy size for current phrase size.
	pub fn entropy_size(&self) -> usize {
		match *self {
			PhraseSize::Words12 => 16,
			PhraseSize::Words15 => 20,
			PhraseSize::Words18 => 24,
			PhraseSize::Words21 => 28,
			PhraseSize::Words24 => 32,
		}
	}

	/// Get phrase type for entropy size.
	pub fn type_for_value(count: usize) -> Option<PhraseSize> {
		if Self::is_correct_count(count) {
			match count {
				12 => Some(PhraseSize::Words12),
				15 => Some(PhraseSize::Words15),
				18 => Some(PhraseSize::Words18),
				21 => Some(PhraseSize::Words21),
				24 => Some(PhraseSize::Words24),
				_ => None,
			}
		} else {
			None
		}
	}

	/// Check if correct entropy size was provided.
	pub fn is_correct_count(count: usize) -> bool {
		count == 12 || count == 15 || count == 18 || count == 21 || count == 24
	}
}

/// Wallet connection method.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum ConnectionMethod {
	/// Integrated node.
	Integrated,
	/// External node, contains connection identifier and URL.
	External(i64, String),
}

/// Wallet instance type.
pub type WalletInstance = Arc<
	Mutex<
		Box<
			dyn WalletInst<
					'static,
					DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
					HTTPNodeClient,
					ExtKeychain,
				>,
		>,
	>,
>;

/// Wallet account data.
#[derive(Clone)]
pub struct WalletAccount {
	/// Spendable balance amount.
	pub spendable_amount: u64,
	/// Account label.
	pub label: String,
	/// Account BIP32 derivation path.
	pub path: String,
}

/// Wallet balance and transactions data.
#[derive(Clone)]
pub struct WalletData {
	/// Balance data for current account.
	pub info: WalletInfo,

	/// Transactions data.
	pub txs: Option<Vec<WalletTx>>,
	/// Number of txs to show on select from database.
	pub txs_limit: u32,
}

impl WalletData {
	/// Number of transactions per select to show at list.
	pub const TXS_LIMIT: u32 = 30;

	/// Update transaction action status.
	pub fn on_tx_action(&mut self, id: u32, action: Option<WalletTxAction>) {
		if self.txs.is_none() {
			return;
		}
		for tx in self.txs.as_mut().unwrap() {
			if id == tx.data.id {
				tx.action = action;
				tx.action_error = None;
				break;
			}
		}
	}

	/// Update transaction action error status.
	pub fn on_tx_error(&mut self, id: u32, err: Option<Error>) {
		if self.txs.is_none() {
			return;
		}
		for tx in self.txs.as_mut().unwrap() {
			if id == tx.data.id {
				tx.action_error = err;
				break;
			}
		}
	}

	/// Get transaction by identifier.
	pub fn tx_by_id(&self, id: u32) -> Option<WalletTx> {
		if self.txs.is_none() {
			return None;
		}
		for tx in self.txs.as_ref().unwrap() {
			if tx.data.id == id {
				return Some(tx.clone());
			}
		}
		None
	}
}

/// Wallet transaction action.
#[derive(Clone, PartialEq)]
pub enum WalletTxAction {
	Cancelling,
	Finalizing,
	Posting,
	Deleting,
}

/// Wallet transaction data.
#[derive(Clone)]
pub struct WalletTx {
	/// Information from database.
	pub data: TxLogEntry,
	/// State of transaction Slate.
	pub state: SlateState,
	/// Payment proof.
	pub(crate) proof: Option<PaymentProof>,

	/// Transaction amount without fees.
	pub amount: u64,
	/// Possible receiver of transaction.
	pub receiver: Option<SlatepackAddress>,
	/// Possible sender of transaction.
	pub sender: Option<SlatepackAddress>,
	/// Block height where tx was included.
	pub height: Option<u64>,
	/// Block height where tx started broadcasting.
	pub broadcasting_height: Option<u64>,

	/// Action on transaction.
	pub action: Option<WalletTxAction>,
	/// Action result error.
	pub action_error: Option<Error>,
}

impl WalletTx {
	/// Create new wallet transaction.
	pub fn new(
		tx: TxLogEntry,
		proof: Option<PaymentProof>,
		wallet: &Wallet,
		height: Option<u64>,
		broadcasting_height: Option<u64>,
		action: Option<WalletTxAction>,
		action_error: Option<Error>,
	) -> Self {
		// For a sent tx the wallet debits inputs and credits change, so
		// `debited - credited` is the amount sent PLUS the network fee. Subtract
		// the fee so `amount` is the value that actually reached the recipient
		// (matching what their wallet receives). Receives don't pay a fee.
		let fee = tx.fee.map(|f| f.fee()).unwrap_or(0);
		let amount = if tx.amount_debited > tx.amount_credited {
			(tx.amount_debited - tx.amount_credited).saturating_sub(fee)
		} else {
			tx.amount_credited - tx.amount_debited
		};
		let mut receiver: Option<SlatepackAddress> = None;
		let mut sender: Option<SlatepackAddress> = None;
		if let Some(proof) = &tx.payment_proof {
			let rec_onion_addr = OnionV3Address::from_bytes(proof.receiver_address.to_bytes());
			if let Ok(addr) = SlatepackAddress::try_from(rec_onion_addr) {
				receiver = Some(addr);
			}
			let send_onion_addr = OnionV3Address::from_bytes(proof.sender_address.to_bytes());
			if let Ok(addr) = SlatepackAddress::try_from(send_onion_addr) {
				sender = Some(addr);
			}
		}
		let mut t = Self {
			data: tx,
			state: SlateState::Unknown,
			proof,
			amount,
			receiver,
			sender,
			height,
			broadcasting_height,
			action,
			action_error,
		};
		// Update Slate state for unconfirmed.
		if !t.data.confirmed
			&& (t.data.tx_type == TxLogEntryType::TxSent
				|| t.data.tx_type == TxLogEntryType::TxReceived)
		{
			if let Some(slate_id) = t.data.tx_slate_id {
				t.state = wallet.get_slate_state(slate_id, &t.data.tx_type)
			}
		}
		t
	}

	/// Check if transactions can be finalized after receiving response.
	pub fn can_finalize(&self) -> bool {
		!self.cancelling()
			&& !self.data.confirmed
			&& (self.data.tx_type == TxLogEntryType::TxSent
				|| self.data.tx_type == TxLogEntryType::TxReceived)
			&& (self.state == SlateState::Invoice1 || self.state == SlateState::Standard1)
	}

	/// Check if transaction was finalized.
	pub fn finalized(&self) -> bool {
		(self.data.tx_type == TxLogEntryType::TxSent
			|| self.data.tx_type == TxLogEntryType::TxReceived)
			&& self.state == SlateState::Invoice3
			|| self.state == SlateState::Standard3
	}

	/// Check if transaction is cancelling.
	pub fn cancelling(&self) -> bool {
		if let Some(a) = self.action.as_ref() {
			return a == &WalletTxAction::Cancelling;
		}
		false
	}

	/// Check if transaction is posting.
	pub fn posting(&self) -> bool {
		if let Some(a) = self.action.as_ref() {
			return a == &WalletTxAction::Posting;
		}
		false
	}

	/// Check if transaction can be cancelled.
	pub fn can_cancel(&self) -> bool {
		!self.cancelling()
			&& !self.data.confirmed
			&& !self.broadcasting()
			&& self.data.tx_type != TxLogEntryType::TxReceivedCancelled
			&& self.data.tx_type != TxLogEntryType::TxSentCancelled
	}

	/// Check if transaction was canceled.
	pub fn cancelled(&self) -> bool {
		self.data.tx_type == TxLogEntryType::TxReceivedCancelled
			|| self.data.tx_type == TxLogEntryType::TxSentCancelled
	}

	/// Check if transaction is finalizing.
	pub fn finalizing(&self) -> bool {
		if let Some(a) = self.action.as_ref() {
			return a == &WalletTxAction::Finalizing;
		}
		false
	}

	/// Check if possible to repeat transaction action.
	pub fn can_repeat_action(&self, wallet: &Wallet) -> bool {
		if let Some(a) = &self.action {
			self.action_error.is_some() && a != &WalletTxAction::Cancelling
		} else {
			// Goblin's online payments go over nostr; there is no Tor resend.
			let _ = wallet;
			false
		}
	}

	/// Check if transaction is broadcasting after finalization.
	pub fn broadcasting(&self) -> bool {
		!self.data.confirmed && self.finalized()
	}

	/// Check if broadcasting of transaction was timed out.
	pub fn broadcasting_timed_out(&self, wallet: &Wallet) -> bool {
		if let Some(data) = wallet.get_data() {
			if self.broadcasting() {
				let last_height = data.info.last_confirmed_height;
				let broadcasting_height = self.broadcasting_height.unwrap_or(0);
				if broadcasting_height == 0 {
					return false;
				}
				let delay = wallet.broadcasting_delay();
				return last_height - broadcasting_height > delay;
			}
		}
		false
	}

	/// Check if transaction is deleting.
	pub fn deleting(&self) -> bool {
		if let Some(a) = self.action.as_ref() {
			return a == &WalletTxAction::Deleting;
		}
		false
	}
}

/// Result of [`crate::wallet::Wallet::manual_process_slatepack`]: either a reply
/// slatepack the user must hand back to the counterparty, or a returned slate now
/// being finalized and posted on the worker thread.
pub enum ManualSlatepackOutcome {
	/// A reply slatepack to send back (e.g. the receiver's response to a payment).
	Response(String),
	/// A returned slate is being finalized and posted to the chain.
	Finalizing,
}

/// Task for the wallet.
#[derive(Clone)]
pub enum WalletTask {
	/// Open Slatepack message parsing result and making an action.
	OpenMessage(String),
	/// Calculate fee to send amount.
	/// * amount
	/// * fee (to read at result)
	CalculateFee(u64, u64),
	/// Verify payment proof.
	/// * payment proof
	/// * result (tx id, sender mine, receiver mine)
	VerifyProof(PaymentProof, Option<Result<(u32, bool, bool), Error>>),
	/// Create request to send.
	/// * amount
	/// * receiver
	Send(u64, Option<SlatepackAddress>),
	/// Invoice creation.
	/// * amount
	Receive(u64),
	/// Transaction finalization.
	/// * tx id
	Finalize(u32),
	/// Post transaction to blockchain.
	/// * tx id
	Post(u32),
	/// Cancel transaction.
	/// * tx id
	Cancel(u32),
	/// Delete transaction.
	/// * tx id
	Delete(u32),
	/// Send amount to a nostr contact as NIP-17 DM.
	/// * amount
	/// * receiver public key (hex)
	/// * optional note (subject line)
	NostrSend(u64, String, Option<String>, Vec<String>),
	/// Re-dispatch the pending nostr message for transaction.
	/// * tx id
	NostrResend(u32),
	/// Pay an APPROVED incoming payment request (explicit user action).
	/// * request id (rumor event id hex)
	NostrPayRequest(String),
	/// Request an amount FROM a nostr contact: issue a grin Invoice1 slate and
	/// deliver it as a NIP-17 DM. The recipient sees an approve-to-pay card.
	/// * amount
	/// * receiver public key (hex)
	/// * optional note (subject line)
	/// * relay hints
	NostrRequest(u64, String, Option<String>, Vec<String>),
	/// Republish our kind-0 profile (e.g. after toggling the incoming-requests
	/// preference) so the change propagates to relays immediately.
	NostrRepublishProfile,
	/// Decline an incoming payment request: mark it declined and send the
	/// requester a void control message so their side clears too.
	/// * request id (rumor event id hex)
	NostrDeclineRequest(String),
	/// Cancel a request WE sent: cancel the local invoice tx and send the payer a
	/// void control message so the pending card disappears on their side.
	/// * slate id (uuid string)
	NostrCancelOutgoing(String),
	/// Cancel a payment WE sent that the recipient never completed: cancel the
	/// local grin tx to RECLAIM the locked outputs, mark it cancelled, and send
	/// the recipient a best-effort void so a late catch-up drops the dead slate.
	/// Refuses (and notes "already completed") if the payment finalized in the
	/// race window.
	/// * slate id (uuid string)
	NostrCancelSend(String),
}
