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

use crate::AppConfig;
use crate::node::{Node, NodeConfig};
use crate::nostr::{
	HeldIdentities, HeldIdentityKeys, NostrConfig, NostrIdentity, NostrService, NostrStore,
};
use crate::wallet::seed::WalletSeed;
use crate::wallet::store::TxHeightStore;
use crate::wallet::types::{
	ConnectionMethod, ManualSlatepackOutcome, PhraseMode, WalletAccount, WalletData,
	WalletInstance, WalletTask, WalletTx, WalletTxAction,
};
use crate::wallet::{ConnectionsConfig, Mnemonic, WalletConfig};

use chrono::Utc;
use futures::channel::oneshot;
use grin_api::{ApiServer, Router};
use grin_chain::SyncStatus;
use grin_keychain::{ExtKeychain, Keychain};
use grin_util::secp::SecretKey;
use grin_util::types::ZeroingString;
use grin_util::{Mutex, ToHex};
use grin_wallet_api::Owner;
use grin_wallet_controller::command::parse_slatepack;
use grin_wallet_controller::controller;
use grin_wallet_controller::controller::ForeignAPIHandlerV2;
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
use grin_wallet_libwallet::api_impl::owner::{
	cancel_tx, init_send_tx, retrieve_summary_info, retrieve_txs, verify_payment_proof,
};
use grin_wallet_libwallet::{
	Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, Slate, SlateState,
	SlatepackAddress, StatusMessage, StoredProofInfo, TxLogEntry, TxLogEntryType, WalletBackend,
	WalletInitStatus, WalletInst, WalletLCProvider, address,
};
use log::{error, info, warn};
use num_bigint::BigInt;
use parking_lot::RwLock;
use rand::Rng;
use std::fs::File;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, mpsc};
use std::thread::Thread;
use std::time::Duration;
use std::{fs, path, thread};
use uuid::Uuid;

/// A held nostr identity as the identity switcher needs to render it. Carries no
/// secret material — the nsec stays encrypted at rest as its own NIP-49 ncryptsec.
#[derive(Clone, Debug)]
pub struct HeldIdentitySummary {
	/// Public key, lowercase hex (the stable id passed to `switch_nostr_identity`).
	pub pubkey_hex: String,
	/// Public key, bech32 npub (for display/copy).
	pub npub: String,
	/// Claimed @name without the domain, if this identity has one.
	pub name: Option<String>,
	/// Full NIP-05 identifier ("user@domain") when this identity has a claimed
	/// name, for the transaction detail view.
	pub nip05: Option<String>,
	/// PRIVATE, app-only label the user set for this identity. Local metadata
	/// only, never published. Display precedence: tag, else claimed name, else
	/// truncated npub.
	pub tag: Option<String>,
	/// Convenience label from the index (claimed name's local part, or empty).
	pub label: String,
	/// Whether this is the currently active identity.
	pub active: bool,
}

impl HeldIdentitySummary {
	/// What the UI shows for this identity: the private tag if set, else the
	/// claimed name (bare, no leading @), else the truncated npub.
	pub fn display(&self) -> String {
		self.tag
			.clone()
			.filter(|s| !s.trim().is_empty())
			.or_else(|| self.name.clone())
			.unwrap_or_else(|| crate::gui::views::goblin::data::short_npub(&self.pubkey_hex))
	}
}

/// Contains wallet instance, configuration and state, handles wallet commands.
#[derive(Clone)]
pub struct Wallet {
	/// Wallet configuration.
	config: Arc<RwLock<WalletConfig>>,
	/// Wallet instance, initializing on wallet opening and clearing on wallet closing.
	instance: Arc<RwLock<Option<WalletInstance>>>,
	/// Connection of current wallet instance.
	connection: Arc<RwLock<ConnectionMethod>>,
	/// Keychain mask for API calls.
	keychain_mask: Arc<RwLock<Option<SecretKey>>>,

	/// Wallet Slatepack address to receive txs at transport.
	slatepack_address: Arc<RwLock<Option<String>>>,

	/// Wallet accounts.
	accounts: Arc<RwLock<Vec<WalletAccount>>>,
	/// Timestamp when wallet account was selected to form unique identifier for transport.
	account_time: Arc<AtomicI64>,

	/// Wallet sync thread.
	sync_thread: Arc<RwLock<Option<Thread>>>,
	/// Flag to check if wallet is syncing.
	syncing: Arc<AtomicBool>,
	/// On-demand node polling (Android battery): pause the heavy node sync at
	/// sync thread while the app is backgrounded and nothing is in flight.
	/// The relay+Nym nostr service keeps running regardless of this flag.
	node_polling_paused: Arc<AtomicBool>,
	/// Resume-signal counter closing the receipt-vs-pause race: bumped by
	/// [`Wallet::resume_node_polling`]; the sync thread only pauses when no
	/// resume arrived during the node sync it just completed.
	node_polling_resume_seq: Arc<AtomicU64>,
	/// Info loading progress in percents.
	info_sync_progress: Arc<AtomicU8>,
	/// Error on wallet loading.
	sync_error: Arc<AtomicBool>,
	/// Attempts amount to update wallet data.
	sync_attempts: Arc<AtomicU8>,

	/// Wallet data.
	data: Arc<RwLock<Option<WalletData>>>,
	/// Flag to check if wallet data was synced from node.
	from_node: Arc<AtomicBool>,
	/// Flag to check if more transactions need to be loaded.
	more_txs_loading: Arc<AtomicBool>,

	/// Flag to check if wallet reopening is needed.
	reopen: Arc<AtomicBool>,
	/// Flag to check if wallet is open.
	is_open: Arc<AtomicBool>,
	/// Flag to check if wallet is closing.
	closing: Arc<AtomicBool>,
	/// Flag to check if wallet was deleted to remove it from the list.
	deleted: Arc<AtomicBool>,

	/// Running wallet foreign API server and port.
	foreign_api_server: Arc<RwLock<Option<(ApiServer, u16)>>>,
	/// Wallet secret key for transport service.
	secret_key: Arc<RwLock<Option<SecretKey>>>,

	/// Flag to check if wallet repairing and restoring missing outputs is needed.
	repair_needed: Arc<AtomicBool>,
	/// Wallet repair progress in percents.
	repair_progress: Arc<AtomicU8>,

	/// Flag to check if wallet files are moving.
	files_moving: Arc<AtomicBool>,

	/// Flag to check if Slatepack message file is opening.
	message_opening: Arc<AtomicBool>,

	/// Amount requests to calculate fee.
	fee_calculating: Arc<AtomicU8>,
	/// Last calculated network fee as `(amount, fee)` so a screen can read the
	/// fee for the amount it is showing without owning the task-result slot.
	last_fee: Arc<RwLock<Option<(u64, u64)>>>,

	/// Flag to check if sending request is creating.
	send_creating: Arc<AtomicBool>,
	/// Flag to check if invoice is creating.
	invoice_creating: Arc<AtomicBool>,

	/// Amount requests to calculate fee.
	proof_verifying: Arc<AtomicBool>,

	/// Tasks sender.
	tasks_sender: Arc<RwLock<Option<Sender<WalletTask>>>>,
	/// Task result with optional transaction identifier.
	task_result: Arc<RwLock<Option<(Option<u32>, WalletTask)>>>,

	/// Nostr payment-messaging service, present while wallet is open.
	nostr: Arc<RwLock<Option<Arc<NostrService>>>>,
}

impl Wallet {
	/// Create new [`Wallet`] instance with provided [`WalletConfig`].
	fn new(config: WalletConfig) -> Self {
		let connection = config.connection();
		Self {
			config: Arc::new(RwLock::new(config)),
			instance: Arc::new(RwLock::new(None)),
			connection: Arc::new(RwLock::new(connection)),
			keychain_mask: Arc::new(RwLock::new(None)),
			slatepack_address: Arc::new(RwLock::new(None)),
			accounts: Arc::new(RwLock::new(vec![])),
			account_time: Arc::new(Default::default()),
			sync_thread: Arc::from(RwLock::new(None)),
			syncing: Arc::new(AtomicBool::new(false)),
			node_polling_paused: Arc::new(AtomicBool::new(false)),
			node_polling_resume_seq: Arc::new(AtomicU64::new(0)),
			info_sync_progress: Arc::from(AtomicU8::new(0)),
			sync_error: Arc::from(AtomicBool::new(false)),
			sync_attempts: Arc::new(AtomicU8::new(0)),
			data: Arc::new(RwLock::new(None)),
			from_node: Arc::new(AtomicBool::new(false)),
			more_txs_loading: Arc::new(AtomicBool::new(false)),
			reopen: Arc::new(AtomicBool::new(false)),
			is_open: Arc::from(AtomicBool::new(false)),
			closing: Arc::new(AtomicBool::new(false)),
			deleted: Arc::new(AtomicBool::new(false)),
			foreign_api_server: Arc::new(RwLock::new(None)),
			secret_key: Arc::new(RwLock::new(None)),
			repair_needed: Arc::new(AtomicBool::new(false)),
			repair_progress: Arc::new(AtomicU8::new(0)),
			files_moving: Arc::new(AtomicBool::new(false)),
			message_opening: Arc::new(AtomicBool::from(false)),
			send_creating: Arc::new(AtomicBool::new(false)),
			fee_calculating: Arc::new(AtomicU8::new(0)),
			last_fee: Arc::new(RwLock::new(None)),
			invoice_creating: Arc::new(AtomicBool::new(false)),
			proof_verifying: Arc::new(AtomicBool::new(false)),
			tasks_sender: Arc::new(RwLock::new(None)),
			task_result: Arc::new(RwLock::new(None)),
			nostr: Arc::new(RwLock::new(None)),
		}
	}

	/// Create new wallet.
	pub fn create(
		name: &String,
		password: &ZeroingString,
		mnemonic: &Mnemonic,
		conn_method: &ConnectionMethod,
	) -> Result<Wallet, Error> {
		let config = WalletConfig::create(name.clone(), conn_method);
		let w = Wallet::new(config.clone());
		{
			// Wallet directory setup.
			let mut path = PathBuf::from(config.get_data_path());
			path.push(WalletConfig::DATA_DIR_NAME);
			fs::create_dir_all(&path)
				.map_err(|_| Error::IO("Directory creation error".to_string()))?;
			// Create seed file.
			let _ = WalletSeed::init_file(
				config.seed_path().as_str(),
				ZeroingString::from(mnemonic.get_phrase()),
				password.clone(),
			)
			.map_err(|_| Error::IO("Seed file creation error".to_string()))?;
			let node_client = Self::create_node_client(&config)?;
			let mut wallet: WalletBackend<HTTPNodeClient, ExtKeychain> =
				match WalletBackend::new(path.to_str().unwrap(), node_client) {
					Err(_) => {
						return Err(Error::Lifecycle("DB creation error".to_string()).into());
					}
					Ok(d) => d,
				};
			// Save init status of this wallet, to determine whether it needs a full UTXO scan.
			let mut batch = wallet.batch_no_mask()?;
			match mnemonic.mode() {
				PhraseMode::Generate => batch.save_init_status(WalletInitStatus::InitNoScanning)?,
				PhraseMode::Import => {
					batch.save_init_status(WalletInitStatus::InitNeedsScanning)?
				}
			}
			batch.commit()?;
		}
		Ok(w)
	}

	/// Initialize [`Wallet`] from provided data path.
	pub fn init(data_path: PathBuf) -> Option<Wallet> {
		let wallet_config = WalletConfig::load(data_path);
		if let Some(config) = wallet_config {
			return Some(Wallet::new(config));
		}
		None
	}

	/// Resolve the node API URL and secret for the connection saved in `config`.
	/// Shared by [`Wallet::create_node_client`] (wallet open) and
	/// [`Wallet::reconnect_node`] (live node switch) so both always target the
	/// same node for a given config.
	fn node_url_secret(config: &WalletConfig) -> (String, Option<String>) {
		let integrated = || {
			let api_url = format!("http://{}", NodeConfig::get_api_address());
			let api_secret = NodeConfig::get_api_secret(true);
			(api_url, api_secret)
		};
		if let Some(id) = config.ext_conn_id {
			if let Some(conn) = ConnectionsConfig::ext_conn(id) {
				(conn.url, conn.secret)
			} else {
				integrated()
			}
		} else {
			integrated()
		}
	}

	/// Create [`HTTPNodeClient`] from provided config.
	fn create_node_client(config: &WalletConfig) -> Result<HTTPNodeClient, Error> {
		let (node_api_url, node_secret) = Self::node_url_secret(config);
		let client = if AppConfig::use_proxy() {
			let socks = AppConfig::use_socks_proxy();
			let url = if socks {
				AppConfig::socks_proxy_url()
			} else {
				AppConfig::http_proxy_url()
			}
			.unwrap_or("".to_string())
			.replace("http://", "")
			.replace("socks5://", "");

			// Convert URL to SocketAddr.
			let addr_res = match SocketAddr::from_str(url.as_str()) {
				Ok(ip_addr) => Some(ip_addr),
				Err(_) => {
					if let Ok(mut socket_addr_list) = url.to_socket_addrs() {
						if let Some(addr) = socket_addr_list.next() {
							Some(addr)
						} else {
							None
						}
					} else {
						None
					}
				}
			};

			match addr_res {
				None => HTTPNodeClient::new(&node_api_url, node_secret)?,
				Some(addr) => {
					let scheme = if socks { "socks5://" } else { "http://" };
					HTTPNodeClient::new_proxy(&node_api_url, node_secret, Some((addr, scheme)))?
				}
			}
		} else {
			HTTPNodeClient::new(&node_api_url, node_secret)?
		};
		Ok(client)
	}

	/// Create [`WalletInstance`] from provided [`WalletConfig`].
	fn create_wallet_instance(config: &mut WalletConfig) -> Result<WalletInstance, Error> {
		// Setup node client.
		let node_client = Self::create_node_client(config)?;

		// Create wallet instance.
		let wallet = Self::inst_wallet::<
			DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
			HTTPNodeClient,
			ExtKeychain,
		>(config, node_client)?;
		Ok(wallet)
	}

	/// Instantiate [`WalletInstance`] from provided node client and [`WalletConfig`].
	fn inst_wallet<L, C, K>(
		config: &mut WalletConfig,
		node_client: C,
	) -> Result<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>, Error>
	where
		DefaultWalletImpl<C>: WalletInst<'static, L, C, K>,
		L: WalletLCProvider<'static, C, K>,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let mut wallet = Box::new(DefaultWalletImpl::<C>::new(node_client).unwrap())
			as Box<dyn WalletInst<'static, L, C, K>>;
		let lc = wallet.lc_provider()?;
		lc.set_top_level_directory(config.get_data_path().as_str())?;
		Ok(Arc::new(Mutex::new(wallet)))
	}

	/// Open the wallet and start [`WalletData`] sync at separate thread.
	pub fn open(&self, password: ZeroingString) -> Result<(), Error> {
		if self.is_open() {
			return Err(Error::GenericError("Already opened".to_string()));
		}
		// Keep a copy of the password for nostr identity setup below; the
		// original is moved into open_wallet.
		let nostr_password = password.clone();

		// Create new wallet instance if sync thread was stopped or instance was not created.
		let has_instance = {
			let r_inst = self.instance.as_ref().read();
			r_inst.is_some()
		};
		if self.sync_thread.read().is_none() || !has_instance {
			let mut config = self.get_config();
			// Setup current connection.
			{
				let mut w_conn = self.connection.write();
				*w_conn = config.connection();
			}
			let new_instance = Self::create_wallet_instance(&mut config)?;
			let mut w_inst = self.instance.write();
			*w_inst = Some(new_instance);
		}

		// Open the wallet.
		{
			let instance = {
				let r_inst = self.instance.as_ref().read();
				r_inst.clone().unwrap()
			};
			let mut wallet_lock = instance.lock();
			let lc = wallet_lock.lc_provider()?;
			match lc.open_wallet(None, password, true, false) {
				Ok(m) => {
					{
						let mut w_mask = self.keychain_mask.write();
						*w_mask = m;
					}
					// Reset an error on opening.
					self.set_sync_error(false);
					self.reset_sync_attempts();

					// Set current account.
					let wallet_inst = lc.wallet_inst()?;
					let label = self.get_config().account.to_owned();
					wallet_inst.set_parent_key_id_by_name(label.as_str())?;
					self.account_time
						.store(Utc::now().timestamp(), Ordering::Relaxed);

					// Initialize the nostr identity + service BEFORE spawning the
					// sync thread. The sync loop starts the service on its first
					// iteration (wallet.rs, top of the loop); if the thread races
					// ahead of this, that first iteration finds no service, skips
					// it, and the service doesn't start until the NEXT cycle — a
					// full SYNC_DELAY (60s) later. That 60s gap (not the mixnet,
					// which connects a relay in ~2s) is the "stuck on Connecting…
					// for a minute" symptom. Synchronous + on this thread, so the
					// service is guaranteed present when start_sync runs.
					self.init_nostr(&nostr_password);

					// Start new synchronization thread or wake up existing one.
					let mut thread_w = self.sync_thread.write();
					if thread_w.is_none() {
						let thread = start_sync(self.clone());
						*thread_w = Some(thread);
					} else {
						thread_w.clone().unwrap().unpark();
					}
					self.is_open.store(true, Ordering::Relaxed);
				}
				Err(e) => {
					if !self.syncing() {
						let mut w_inst = self.instance.write();
						*w_inst = None;
					}
					return Err(e);
				}
			}
		}

		// Update Slatepack address and secret key.
		self.update_secret_key_addr()?;

		Ok(())
	}

	/// Initialize the nostr identity and service for this wallet.
	/// Failures are logged and disable nostr for the session only.
	/// The password is held as a [`ZeroingString`] so it is scrubbed on drop.
	fn init_nostr(&self, password: &ZeroingString) {
		{
			let r_nostr = self.nostr.read();
			if r_nostr.is_some() {
				return;
			}
		}
		let config = self.get_config();
		let wallet_dir = PathBuf::from(config.get_data_path());
		let nostr_config = NostrConfig::load(wallet_dir);
		if !nostr_config.enabled() {
			return;
		}
		let nostr_dir = config.get_nostr_path();
		// Load the existing identity or generate a fresh RANDOM one. The key
		// is deliberately independent of the wallet seed: the seed must never
		// double as identity evidence, and a rotation must not be derivable
		// from it. The nsec backup is therefore the identity backup.
		let legacy = match NostrIdentity::load(&nostr_dir) {
			Some(identity) => identity,
			None => match NostrIdentity::create_random(password) {
				Ok((identity, _)) => {
					if let Err(e) = identity.save(&nostr_dir) {
						error!("nostr: identity save failed: {e}");
						return;
					}
					identity
				}
				Err(e) => {
					error!("nostr: identity creation failed: {e}");
					return;
				}
			},
		};
		// Adopt the held-identity index (migrating a pre-feature wallet's bare
		// identity.json into it) and UNLOCK EVERY held identity now: with the wallet
		// open, all identities' keys live in memory so the wallet listens for all of
		// them at once (same trust boundary as the grin seed already in memory).
		if HeldIdentities::load_or_migrate(&nostr_dir, &legacy).is_none() {
			error!("nostr: held-identity index unreadable");
		}
		let (recv, active_hex) = match self.unlock_all_identities(&nostr_dir, password) {
			Some(v) => v,
			None => {
				error!("nostr: no identity could be unlocked; nostr disabled this session");
				return;
			}
		};
		info!(
			"nostr: {} identit(ies) unlocked; active {}",
			recv.len(),
			active_hex
		);
		let store = NostrStore::new(config.get_nostr_db_path());
		let service = NostrService::new(recv, &active_hex, nostr_config, store, nostr_dir);
		let mut w_nostr = self.nostr.write();
		*w_nostr = Some(service);
	}

	/// Unlock EVERY held identity with the wallet password, returning the decrypted
	/// set plus the active identity's pubkey hex. All held nsecs share the one
	/// wallet password. Identities that fail to unlock (corrupt file) are skipped
	/// with a warning; `None` only if not a single one could be unlocked. Used at
	/// wallet-open and when rebuilding the service after add/import/rotate.
	fn unlock_all_identities(
		&self,
		nostr_dir: &PathBuf,
		password: &str,
	) -> Option<(Vec<HeldIdentityKeys>, String)> {
		let index = HeldIdentities::load(nostr_dir)?;
		let mut recv = Vec::new();
		for entry in &index.identities {
			let Some(identity) = entry.load(nostr_dir) else {
				warn!("nostr: identity file unreadable: {}", entry.path);
				continue;
			};
			match identity.unlock(password) {
				Ok(keys) => recv.push(HeldIdentityKeys { keys, identity }),
				Err(e) => warn!("nostr: identity {} failed to unlock: {e}", entry.pubkey),
			}
		}
		if recv.is_empty() {
			return None;
		}
		// Prefer the recorded active pointer; fall back to the first that unlocked.
		let active_hex = if recv
			.iter()
			.any(|h| h.identity.pubkey_hex().as_deref() == Some(index.active.as_str()))
		{
			index.active.clone()
		} else {
			recv[0].identity.pubkey_hex().unwrap_or_default()
		};
		Some((recv, active_hex))
	}

	/// Get the nostr service when available.
	pub fn nostr_service(&self) -> Option<Arc<NostrService>> {
		let r_nostr = self.nostr.read();
		r_nostr.clone()
	}

	/// Rotate the nostr identity to a brand-new RANDOM key (no derivation
	/// chain: a future seed compromise cannot reach it, and the old key
	/// shares nothing with it), atomically moving the registered username
	/// (if any) to the new key via the name server. Blocking (network I/O):
	/// call from a worker thread. Returns the new bech32 npub.
	/// The nostr secret key (nsec, bech32) for this wallet, gated on the wallet
	/// password. Used by Advanced → "Nostr key" so the user can copy it or show
	/// it as a QR to log in to nostr apps (e.g. magick.market). Unlocking the
	/// stored identity both verifies the password and yields the keys, so a
	/// wrong password can never leak the key. The value is derived on demand and
	/// never persisted.
	pub fn get_nostr_nsec(&self, password: String) -> Result<String, String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr identity not ready".to_string())?;
		use nostr_sdk::ToBech32;
		let keys = svc
			.identity
			.read()
			.unlock(&password)
			.map_err(|_| "wrong password".to_string())?;
		keys.secret_key()
			.to_bech32()
			.map_err(|e| format!("nsec encode failed: {e}"))
	}

	pub fn rotate_nostr_identity(&self, password: String) -> Result<String, String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		// Snapshot the old identity and prove the password by unlocking it
		// (NIP-49 decryption fails on a wrong password).
		let old = svc.identity.read().clone();
		let old_keys = old
			.unlock(&password)
			.map_err(|_| "Wrong password".to_string())?;

		// Generate the replacement identity.
		let (mut new_identity, _new_keys) = NostrIdentity::create_random(&password)
			.map_err(|e| format!("key generation failed: {e}"))?;

		// Release the username first (the server also deletes its avatar);
		// abort the rotation if that fails so the user never ends up with a
		// burned key still welded to a public name. After rotation the name
		// is up for grabs — by the new key or anyone else.
		if let Some(nip05) = old.nip05.clone() {
			let name = nip05.split('@').next().unwrap_or_default().to_string();
			let server = { svc.config.read().nip05_server() };
			let rt = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.map_err(|e| e.to_string())?;
			rt.block_on(async { crate::nostr::nip05::unregister(&server, &name, &old_keys).await })
				.map_err(|e| format!("Couldn't release @{name}: {e} — rotation cancelled"))?;
		}
		new_identity.prev_npubs = {
			let mut v = old.prev_npubs.clone();
			v.push(old.npub.clone());
			v
		};

		// Persist, then swap the running service for one bound to the new key.
		let config = self.get_config();
		let nostr_dir = config.get_nostr_path();
		new_identity
			.save(&nostr_dir)
			.map_err(|e| format!("identity save failed: {e}"))?;
		svc.stop();
		for _ in 0..100 {
			if !svc.is_running() {
				break;
			}
			thread::sleep(Duration::from_millis(100));
		}
		let wallet_dir = PathBuf::from(config.get_data_path());
		let nostr_config = NostrConfig::load(wallet_dir);
		let store = NostrStore::new(config.get_nostr_db_path());
		let new_npub = new_identity.npub.clone();
		// Rebuild the service holding ALL held identities (the primary entry now
		// resolves to the new identity), with the new one active.
		let (recv, _) = self
			.unlock_all_identities(&nostr_dir, &password)
			.ok_or_else(|| "identity unlock failed".to_string())?;
		let active_hex = new_identity.pubkey_hex().unwrap_or_default();
		let new_svc = NostrService::new(recv, &active_hex, nostr_config, store, nostr_dir);
		{
			let mut w_nostr = self.nostr.write();
			*w_nostr = Some(new_svc.clone());
		}
		new_svc.start(self.clone());
		info!("nostr: identity rotated to {}", new_npub);
		Ok(new_npub)
	}

	/// Replace the nostr identity with an imported key — either a bare nsec
	/// or an exported identity-backup JSON (which restores the username and
	/// rotation history too). The current identity is overwritten; its npub
	/// is kept in `prev_npubs` for reference. Blocking-safe (no network).
	pub fn import_nostr_identity(
		&self,
		input: String,
		password: String,
		backup_password: Option<String>,
	) -> Result<String, String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		// Prove THIS wallet's password against the current identity first.
		let old = svc.identity.read().clone();
		old.unlock(&password)
			.map_err(|_| "Wrong password".to_string())?;
		let input = input.trim();
		let bpw = backup_password
			.as_deref()
			.filter(|s| !s.is_empty())
			.unwrap_or(&password);
		let (mut new_identity, new_keys) = if NostrIdentity::is_encrypted_backup(input) {
			// A GOBLIN-*.backup file: fully sealed. Open it with the password it
			// was created under (may differ on a new device), then RE-ENCRYPT
			// under this wallet's password so future unlocks use the current one.
			let (backup, keys) =
				NostrIdentity::from_encrypted_backup(input, bpw).map_err(|_| {
					"Couldn't open the backup — wrong password? If it was made on \
					 another device, enter that wallet's password in the \
					 backup-password field."
						.to_string()
				})?;
			let mut ident = NostrIdentity::from_unlocked_keys(&keys, &password, backup.source)
				.map_err(|e| format!("re-encryption failed: {e}"))?;
			ident.nip05 = backup.nip05.clone();
			ident.anonymous = backup.anonymous;
			ident.prev_npubs = backup.prev_npubs.clone();
			ident.private_tag = backup.private_tag.clone();
			(ident, keys)
		} else if input.starts_with('{') {
			// Legacy plaintext identity-backup JSON (pre-.backup-file): decrypt
			// with its password, then re-encrypt under this wallet's password.
			let backup: NostrIdentity =
				serde_json::from_str(input).map_err(|_| "Invalid identity backup".to_string())?;
			let keys = backup.unlock(bpw).map_err(|_| {
				"Couldn't decrypt the backup — if it was exported on another \
				 device, enter that wallet's password in the backup-password \
				 field"
					.to_string()
			})?;
			let mut ident = NostrIdentity::from_unlocked_keys(&keys, &password, backup.source)
				.map_err(|e| format!("re-encryption failed: {e}"))?;
			ident.nip05 = backup.nip05.clone();
			ident.anonymous = backup.anonymous;
			ident.prev_npubs = backup.prev_npubs.clone();
			ident.private_tag = backup.private_tag.clone();
			(ident, keys)
		} else {
			NostrIdentity::create_imported(input, &password)
				.map_err(|_| "Invalid nsec".to_string())?
		};
		if new_identity.npub != old.npub && !new_identity.prev_npubs.contains(&old.npub) {
			new_identity.prev_npubs.push(old.npub.clone());
		}
		let config = self.get_config();
		let nostr_dir = config.get_nostr_path();
		new_identity
			.save(&nostr_dir)
			.map_err(|e| format!("identity save failed: {e}"))?;
		svc.stop();
		for _ in 0..100 {
			if !svc.is_running() {
				break;
			}
			thread::sleep(Duration::from_millis(100));
		}
		let wallet_dir = PathBuf::from(config.get_data_path());
		let nostr_config = NostrConfig::load(wallet_dir);
		let store = NostrStore::new(config.get_nostr_db_path());
		let new_npub = new_identity.npub.clone();
		// Rebuild the service holding ALL held identities, with the imported one
		// active (the primary entry now resolves to it).
		let _ = new_keys;
		let (recv, _) = self
			.unlock_all_identities(&nostr_dir, &password)
			.ok_or_else(|| "identity unlock failed".to_string())?;
		let active_hex = new_identity.pubkey_hex().unwrap_or_default();
		let new_svc = NostrService::new(recv, &active_hex, nostr_config, store, nostr_dir);
		{
			let mut w_nostr = self.nostr.write();
			*w_nostr = Some(new_svc.clone());
		}
		new_svc.start(self.clone());
		info!("nostr: identity replaced by import: {}", new_npub);
		Ok(new_npub)
	}

	/// Build the contents of a `GOBLIN-*.backup` file: the whole nostr identity,
	/// fully sealed under the wallet password. Verifies the password first.
	pub fn create_nostr_backup(&self, password: &str) -> Result<String, String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		let identity = svc.identity.read().clone();
		let keys = identity
			.unlock(password)
			.map_err(|_| "Wrong password".to_string())?;
		identity
			.to_encrypted_backup(&keys)
			.map_err(|e| format!("backup failed: {e}"))
	}

	// ── Held nostr identities (one wallet, one balance, many front doors) ──────
	//
	// One grin seed / one balance, but the wallet can HOLD several nostr
	// identities and present a different one at will. Exactly one is ACTIVE: it
	// drives the single live gift-wrap subscription and all display, and every
	// identity redeems into the SAME shared grin balance. Only the active nsec is
	// ever decrypted into memory; the rest rest as ncryptsec on disk. Switching is
	// mechanically identical to `rotate_nostr_identity` (stop the service, rebuild
	// it on the target key, restart), plus a per-identity catch-up so payments that
	// arrived while an identity was dormant are redeemed on switch-in.

	/// The held identities for the identity switcher (no secrets). Empty if nostr
	/// is disabled/not running.
	pub fn nostr_identities(&self) -> Vec<HeldIdentitySummary> {
		let nostr_dir = self.get_config().get_nostr_path();
		let Some(index) = HeldIdentities::load(&nostr_dir) else {
			return Vec::new();
		};
		index
			.identities
			.iter()
			.filter_map(|entry| {
				let identity = entry.load(&nostr_dir)?;
				let name = identity
					.nip05
					.as_deref()
					.and_then(|n| n.split('@').next())
					.filter(|s| !s.is_empty())
					.map(|s| s.to_string());
				Some(HeldIdentitySummary {
					pubkey_hex: entry.pubkey.clone(),
					npub: identity.npub.clone(),
					name,
					nip05: identity.nip05.clone(),
					tag: identity.private_tag.clone(),
					label: entry.label.clone(),
					active: entry.pubkey == index.active,
				})
			})
			.collect()
	}

	/// The active identity's pubkey (hex), or `None` if nostr is not running.
	pub fn active_nostr_pubkey(&self) -> Option<String> {
		self.nostr_service().map(|s| s.public_key().to_hex())
	}

	/// Verify a candidate wallet password against the active nostr identity
	/// (cheap, in-memory NIP-49 unlock). Lets the identity password modal reject a
	/// wrong password up front — before spawning an add/switch worker — the way the
	/// wallet-open modal does. `false` when nostr is not running.
	pub fn verify_nostr_password(&self, password: &str) -> bool {
		self.nostr_service()
			.map(|s| s.identity.read().unlock(password).is_ok())
			.unwrap_or(false)
	}

	/// Add a nostr identity to this wallet WITHOUT switching to it: generate a
	/// fresh random nsec (`import` is `None`) or import an existing one (`import`
	/// is `Some(nsec)`). The new key is encrypted under the wallet password like
	/// every held identity, then recorded in the index. Returns the new npub. The
	/// caller may follow with `switch_nostr_identity` to make it active.
	///
	/// The wallet password is proven against the CURRENT identity first, so a
	/// wrong password can neither add a mis-encrypted key nor disturb anything.
	pub fn add_nostr_identity(
		&self,
		import: Option<String>,
		password: String,
	) -> Result<String, String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		// Prove the wallet password against the current identity before writing a
		// new key, so all held identities share the one wallet password.
		svc.identity
			.read()
			.unlock(&password)
			.map_err(|_| "Wrong password".to_string())?;
		// The import blob may be a bare nsec OR a sealed GOBLIN-*.backup file
		// (reusing the same open path as `import_nostr_identity`). Either becomes a
		// held identity re-encrypted under THIS wallet's password.
		let (identity, _keys) = match import {
			Some(blob) => {
				let blob = blob.trim();
				if NostrIdentity::is_encrypted_backup(blob) {
					// A .backup: open it (same wallet password, since a backup made
					// by this wallet is sealed under it), then re-encrypt under the
					// wallet password and restore its name/history.
					let (backup, keys) = NostrIdentity::from_encrypted_backup(blob, &password)
						.map_err(|_| {
							"Couldn't open the backup — it may have been made under a \
							 different wallet password."
								.to_string()
						})?;
					let mut ident =
						NostrIdentity::from_unlocked_keys(&keys, &password, backup.source)
							.map_err(|e| format!("re-encryption failed: {e}"))?;
					ident.nip05 = backup.nip05.clone();
					ident.anonymous = backup.anonymous;
					ident.prev_npubs = backup.prev_npubs.clone();
					ident.private_tag = backup.private_tag.clone();
					(ident, keys)
				} else {
					NostrIdentity::create_imported(blob, &password)
						.map_err(|_| "Invalid nsec".to_string())?
				}
			}
			None => NostrIdentity::create_random(&password)
				.map_err(|e| format!("key generation failed: {e}"))?,
		};
		let config = self.get_config();
		let nostr_dir = config.get_nostr_path();
		let mut index = HeldIdentities::load(&nostr_dir)
			.ok_or_else(|| "identity index unavailable".to_string())?;
		index
			.add(&nostr_dir, &identity)
			.map_err(|e| e.to_string())?;
		let new_npub = identity.npub.clone();
		info!("nostr: added held identity {new_npub}");
		// Bring the new identity ONLINE: rebuild the service holding ALL identities
		// (including the one just added) so it starts listening immediately. The
		// active identity is unchanged — adding never switches.
		let active_hex = svc.public_key().to_hex();
		let nostr_config = NostrConfig::load(PathBuf::from(config.get_data_path()));
		let store = NostrStore::new(config.get_nostr_db_path());
		let (recv, _) = self
			.unlock_all_identities(&nostr_dir, &password)
			.ok_or_else(|| "identity unlock failed".to_string())?;
		svc.stop();
		for _ in 0..100 {
			if !svc.is_running() {
				break;
			}
			thread::sleep(Duration::from_millis(100));
		}
		let new_svc = NostrService::new(recv, &active_hex, nostr_config, store, nostr_dir);
		{
			let mut w_nostr = self.nostr.write();
			*w_nostr = Some(new_svc.clone());
		}
		new_svc.start(self.clone());
		Ok(new_npub)
	}

	/// INSTANT identity switch: a purely-local change of which held identity is
	/// presented and used for sending. Every held identity is already unlocked and
	/// already listening, so there is NO password prompt, NO service teardown, and
	/// NO catch-up — payments were never missed. Just re-points the running
	/// service's active keys/identity and persists the active pointer. Returns the
	/// target npub.
	pub fn switch_nostr_identity(&self, target_hex: String) -> Result<String, String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		// Already active? Nothing to do.
		if svc.public_key().to_hex() == target_hex {
			return Ok(svc.npub());
		}
		// Re-point the active identity in memory (the target is already unlocked and
		// listening); fails only if it isn't a held identity of this wallet.
		if !svc.set_active_by_pubkey(&target_hex) {
			return Err("identity not held by this wallet".to_string());
		}
		// Persist the active pointer so the next open lands on it too. The legacy
		// identity.json is never overwritten (an older build still opens on #1).
		let nostr_dir = self.get_config().get_nostr_path();
		if let Some(mut index) = HeldIdentities::load(&nostr_dir) {
			let _ = index.set_active(&nostr_dir, &target_hex);
		}
		let new_npub = svc.npub();
		info!("nostr: switched active identity to {}", new_npub);
		Ok(new_npub)
	}

	/// Set (or clear, with an empty string) a held identity's PRIVATE tag — the
	/// local, app-only name the user gives it. Persisted in its 0600 identity
	/// file (and thus inside future sealed .backups) and updated in the running
	/// service so the switcher re-renders immediately. NEVER published to nostr.
	/// Local metadata only, so no password is required (the ncryptsec is untouched).
	pub fn rename_nostr_identity(&self, target_hex: String, tag: String) -> Result<(), String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		let nostr_dir = self.get_config().get_nostr_path();
		let index = HeldIdentities::load(&nostr_dir)
			.ok_or_else(|| "identity index unavailable".to_string())?;
		let entry = index
			.entry(&target_hex)
			.ok_or_else(|| "identity not held by this wallet".to_string())?;
		let mut identity = entry
			.load(&nostr_dir)
			.ok_or_else(|| "identity file unreadable".to_string())?;
		let tag = tag.trim().to_string();
		let tag = if tag.is_empty() { None } else { Some(tag) };
		identity.private_tag = tag.clone();
		identity
			.save_at(&entry.abs_path(&nostr_dir))
			.map_err(|e| format!("save failed: {e}"))?;
		svc.set_private_tag(&target_hex, tag);
		Ok(())
	}

	/// PERMANENTLY delete a held identity: drop it from the held-identity index,
	/// delete its on-disk encrypted file, and rebuild the running service without
	/// it (so its pubkey leaves the multi-pubkey gift-wrap subscription and its key
	/// leaves the in-memory set). The one shared grin balance and every other
	/// identity are untouched. Unrecoverable unless its nsec/.backup was saved.
	///
	/// Edge cases:
	/// - Refuses to delete the LAST identity (a wallet must keep >= 1).
	/// - Deleting the ACTIVE identity first switches active to a survivor.
	/// - Deleting the legacy primary (the `identity.json` entry, which `init_nostr`
	///   falls back to and an older build opens) PROMOTES a survivor into
	///   `identity.json` so that fallback still resolves — never leaving a hole
	///   that would spawn a fresh identity on next open.
	pub fn delete_nostr_identity(
		&self,
		target_hex: String,
		password: String,
	) -> Result<(), String> {
		let svc = self
			.nostr_service()
			.ok_or_else(|| "nostr is not running".to_string())?;
		if !self.verify_nostr_password(&password) {
			return Err("Wrong password".to_string());
		}
		let config = self.get_config();
		let nostr_dir = config.get_nostr_path();
		let mut index = HeldIdentities::load(&nostr_dir)
			.ok_or_else(|| "identity index unavailable".to_string())?;
		// (a) Never delete the only identity.
		if index.len() <= 1 {
			return Err("You must keep at least one identity".to_string());
		}
		let entry = index
			.entry(&target_hex)
			.cloned()
			.ok_or_else(|| "identity not held by this wallet".to_string())?;
		// A survivor to take over the active pointer / primary role.
		let survivor = index
			.identities
			.iter()
			.find(|e| e.pubkey != target_hex)
			.map(|e| e.pubkey.clone())
			.ok_or_else(|| "no other identity".to_string())?;

		// (c) Deleting the legacy primary: promote the survivor into identity.json
		// so init_nostr's fallback/rollback anchor still resolves. Otherwise just
		// delete the target's own file.
		if entry.path == "identity.json" {
			let survivor_entry = index
				.entry(&survivor)
				.cloned()
				.ok_or_else(|| "survivor missing".to_string())?;
			let survivor_id = survivor_entry
				.load(&nostr_dir)
				.ok_or_else(|| "survivor unreadable".to_string())?;
			// Overwrite identity.json with the survivor (its old content = the
			// deleted key is gone), and repoint the survivor entry to identity.json.
			survivor_id
				.save(&nostr_dir)
				.map_err(|e| format!("promote failed: {e}"))?;
			if survivor_entry.path != "identity.json" {
				let old_abs = survivor_entry.abs_path(&nostr_dir);
				for e in index.identities.iter_mut() {
					if e.pubkey == survivor {
						e.path = "identity.json".to_string();
					}
				}
				let _ = std::fs::remove_file(old_abs);
			}
		} else {
			let _ = std::fs::remove_file(entry.abs_path(&nostr_dir));
		}

		// Remove the target from the index (entries + order); repoint active if it
		// was the deleted one.
		index.identities.retain(|e| e.pubkey != target_hex);
		index.order.retain(|h| h != &target_hex);
		if index.active == target_hex {
			index.active = survivor.clone();
		}
		index
			.save(&nostr_dir)
			.map_err(|e| format!("index save failed: {e}"))?;

		// (b) If the deleted identity was active, the survivor becomes active.
		let active_hex = if svc.public_key().to_hex() == target_hex {
			survivor
		} else {
			svc.public_key().to_hex()
		};

		// Rebuild the service WITHOUT the deleted identity: unlock_all_identities now
		// excludes it, so it leaves both the subscription and the in-memory key set.
		let nostr_config = NostrConfig::load(PathBuf::from(config.get_data_path()));
		let store = NostrStore::new(config.get_nostr_db_path());
		let (recv, _) = self
			.unlock_all_identities(&nostr_dir, &password)
			.ok_or_else(|| "identity unlock failed".to_string())?;
		svc.stop();
		for _ in 0..100 {
			if !svc.is_running() {
				break;
			}
			thread::sleep(Duration::from_millis(100));
		}
		let new_svc = NostrService::new(recv, &active_hex, nostr_config, store, nostr_dir);
		{
			let mut w_nostr = self.nostr.write();
			*w_nostr = Some(new_svc.clone());
		}
		new_svc.start(self.clone());
		info!("nostr: deleted held identity {target_hex}");
		Ok(())
	}

	/// Get keychain mask [`SecretKey`].
	pub fn keychain_mask(&self) -> Option<SecretKey> {
		let r_key = self.keychain_mask.read();
		r_key.clone()
	}

	/// Get wallet [`SecretKey`] for transport.
	pub fn secret_key(&self) -> Option<SecretKey> {
		let r_key = self.secret_key.read();
		r_key.clone()
	}

	/// Retrieve wallet [`SecretKey`] and Slatepack address for transport.
	fn update_secret_key_addr(&self) -> Result<(), Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut w_lock = instance.lock();
		let lc = w_lock.lc_provider()?;
		let w_inst = lc.wallet_inst()?;
		let k = w_inst.keychain(self.keychain_mask().as_ref())?;
		let parent_key_id = w_inst.parent_key_id();
		let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)
			.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
		let addr = SlatepackAddress::try_from(&sec_key)?;
		let mut w_key = self.secret_key.write();
		*w_key = Some(sec_key);
		let mut w_address = self.slatepack_address.write();
		*w_address = Some(addr.to_string());
		Ok(())
	}

	/// Mint a FRESH per-sale proof/slatepack address at the next unallocated
	/// derivation index (index 0 stays the app's default address — nothing
	/// changes for normal receives). The allocation counter persists in the
	/// wallet dir and never reuses an index, so no two sales share an address;
	/// the patched receive path detects which allocated address a
	/// payment-proof slate is addressed to and signs the proof with the
	/// matching key. Returns `(index, address)`.
	pub fn mint_proof_address(&self) -> Result<(u32, String), String> {
		let index =
			crate::wallet::proof_addrs::allocate(&self.get_config().get_proof_addrs_path())?;
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst
			.clone()
			.ok_or_else(|| "wallet is not open".to_string())?;
		let mut w_lock = instance.lock();
		let lc = w_lock.lc_provider().map_err(|e| e.to_string())?;
		let w_inst = lc.wallet_inst().map_err(|e| e.to_string())?;
		let k = w_inst
			.keychain(self.keychain_mask().as_ref())
			.map_err(|e| e.to_string())?;
		let parent_key_id = w_inst.parent_key_id();
		let sec_key = address::address_from_derivation_path(&k, &parent_key_id, index)
			.map_err(|e| format!("{:?}", e))?;
		let addr = SlatepackAddress::try_from(&sec_key).map_err(|e| e.to_string())?;
		Ok((index, addr.to_string()))
	}

	/// Get unique opened wallet identifier, including current account.
	pub fn identifier(&self) -> String {
		let config = self.get_config();
		let account_ts = self.account_time.load(Ordering::Relaxed);
		format!("{}_{}_{}", config.id, config.account.to_hex(), account_ts)
	}

	/// Get Slatepack address to receive txs at transport.
	pub fn slatepack_address(&self) -> Option<String> {
		let r_address = self.slatepack_address.read();
		if r_address.is_some() {
			let addr = r_address.clone();
			return addr;
		}
		None
	}

	/// Get wallet config.
	pub fn get_config(&self) -> WalletConfig {
		self.config.read().clone()
	}

	/// Change wallet name.
	pub fn change_name(&self, name: String) {
		let mut w_config = self.config.write();
		w_config.name = name;
		w_config.save();
	}

	/// Check if Dandelion usage is needed to post transactions.
	pub fn can_use_dandelion(&self) -> bool {
		let r_config = self.config.read();
		r_config.use_dandelion.unwrap_or(true)
	}

	/// Update usage of Dandelion to post transactions.
	pub fn update_use_dandelion(&self, use_dandelion: bool) {
		let mut w_config = self.config.write();
		w_config.use_dandelion = Some(use_dandelion);
		w_config.save();
	}

	/// Update minimal amount of confirmations.
	pub fn update_min_confirmations(&self, min_confirmations: u64) {
		let mut w_config = self.config.write();
		w_config.min_confirmations = min_confirmations;
		w_config.save();
	}

	/// Get transaction broadcasting delay in blocks.
	pub fn broadcasting_delay(&self) -> u64 {
		let r_config = self.config.read();
		r_config
			.tx_broadcast_timeout
			.unwrap_or(WalletConfig::BROADCASTING_TIMEOUT_DEFAULT)
	}

	/// Update transaction broadcasting delay in blocks.
	pub fn update_broadcasting_delay(&self, delay: u64) {
		let mut w_config = self.config.write();
		w_config.tx_broadcast_timeout = Some(delay);
		w_config.save();
	}

	/// Update external connection identifier.
	pub fn update_connection(&self, conn: &ConnectionMethod) {
		let mut w_config = self.config.write();
		w_config.ext_conn_id = match conn {
			ConnectionMethod::Integrated => None,
			ConnectionMethod::External(id, _) => Some(id.clone()),
		};
		w_config.save();
	}

	/// Apply the saved connection to the RUNNING wallet session immediately.
	///
	/// A node selection persisted by [`Wallet::update_connection`] only reaches
	/// an open wallet on the next open, because the node client is baked into the
	/// wallet instance at open time. This swaps the live node client's URL and
	/// secret in place (no close/reopen, so the password is not needed again),
	/// updates the runtime connection so the UI reflects the switch at once, then
	/// wakes the sync thread to refresh the balance against the new node.
	///
	/// If the new node is unreachable the sync simply errors and the honest
	/// "can't reach node" state surfaces (with the last-known balance retained),
	/// so the user is never stranded on a silent zero.
	pub fn reconnect_node(&self) {
		// Reflect the switch in the runtime connection right away so the picker
		// and status cards stop showing the previous node.
		let conn = self.get_config().connection();
		{
			let mut w_conn = self.connection.write();
			*w_conn = conn.clone();
		}
		// Clear the stale sync error/progress so the surface shows the honest
		// "updating" state while the new node is contacted.
		self.set_sync_error(false);
		self.reset_sync_attempts();
		self.info_sync_progress.store(0, Ordering::Relaxed);

		// Swap the live node client, then kick a fresh sync. Done on a worker
		// thread: locking the instance can briefly contend with an in-flight
		// sync, and this is called from the UI thread.
		let wallet = self.clone();
		thread::spawn(move || {
			let has_instance = { wallet.instance.read().is_some() };
			if wallet.is_open() && has_instance {
				let (url, secret) = Self::node_url_secret(&wallet.get_config());
				let instance = { wallet.instance.read().clone().unwrap() };
				let mut wallet_lock = instance.lock();
				if let Ok(lc) = wallet_lock.lc_provider() {
					if let Ok(backend) = lc.wallet_inst() {
						let client = backend.w2n_client();
						client.set_node_url(&url);
						client.set_node_api_secret(secret);
					}
				}
			}
			// Resume node polling (may be paused on Android) and wake the sync
			// thread so the balance refreshes against the new node now.
			wallet.resume_node_polling();
			wallet.sync();
		});
	}

	/// Get external connection URL applied to [`WalletInstance`]
	/// after wallet opening if sync is running or get it from config.
	pub fn get_current_connection(&self) -> ConnectionMethod {
		if self.sync_thread.read().is_some() {
			let r_conn = self.connection.read();
			r_conn.clone()
		} else {
			let config = self.get_config();
			config.connection()
		}
	}

	/// Check if wallet is open.
	pub fn is_open(&self) -> bool {
		self.is_open.load(Ordering::Relaxed)
	}

	/// Check if wallet is closing.
	pub fn is_closing(&self) -> bool {
		self.closing.load(Ordering::Relaxed)
	}

	/// Close the wallet.
	pub fn close(&self) {
		let has_instance = {
			let r_inst = self.instance.read();
			r_inst.is_some()
		};
		if !self.is_open() || !has_instance {
			return;
		}
		// Stop repairing.
		if self.is_repairing() {
			self.repair_needed.store(false, Ordering::Relaxed);
		}
		// Close wallet at separate thread.
		let wallet_close = self.clone();
		let conn = wallet_close.connection.clone();
		thread::spawn(move || {
			wallet_close.closing.store(true, Ordering::Relaxed);
			// Wait common operations to finish.
			while wallet_close.message_opening()
				|| wallet_close.send_creating()
				|| wallet_close.invoice_creating()
			{
				thread::sleep(Duration::from_millis(300));
			}
			// Stop running API server.
			let api_server_exists = { wallet_close.foreign_api_server.read().is_some() };
			if api_server_exists {
				let mut w_api_server = wallet_close.foreign_api_server.write();
				w_api_server.as_mut().unwrap().0.stop();
				*w_api_server = None;
			}
			// Stop nostr service.
			{
				let mut w_nostr = wallet_close.nostr.write();
				if let Some(service) = w_nostr.take() {
					service.stop();
				}
			}
			// Close the wallet.
			let r_inst = wallet_close.instance.as_ref().read();
			let instance = r_inst.clone().unwrap();
			Self::close_wallet(&instance);
			wallet_close.closing.store(false, Ordering::Relaxed);
			wallet_close.is_open.store(false, Ordering::Relaxed);
			// Setup current connection.
			{
				let mut w_conn = conn.write();
				*w_conn = wallet_close.get_config().connection();
			}
			wallet_close.from_node.store(false, Ordering::Relaxed);
			// Start sync to exit from thread.
			wallet_close.sync();
		});
	}

	/// Close wallet for provided [`WalletInstance`].
	fn close_wallet(instance: &WalletInstance) {
		let mut wallet_lock = instance.lock();
		let lc = wallet_lock.lc_provider().unwrap();
		let _ = lc.close_wallet(None);
	}

	/// Set wallet reopen status.
	pub fn set_reopen(&self, reopen: bool) {
		self.reopen.store(reopen, Ordering::Relaxed);
	}

	/// Check if wallet reopen is needed.
	pub fn reopen_needed(&self) -> bool {
		self.reopen.load(Ordering::Relaxed)
	}

	/// Get wallet info synchronization progress.
	pub fn info_sync_progress(&self) -> u8 {
		self.info_sync_progress.load(Ordering::Relaxed)
	}

	/// Check if wallet had an error on synchronization.
	pub fn sync_error(&self) -> bool {
		self.sync_error.load(Ordering::Relaxed)
	}

	/// Set an error for wallet on synchronization.
	pub fn set_sync_error(&self, error: bool) {
		self.sync_error.store(error, Ordering::Relaxed);
	}

	/// Check if wallet was synced from node after opening.
	pub fn synced_from_node(&self) -> bool {
		self.from_node.load(Ordering::Relaxed)
	}

	/// Get current wallet synchronization attempts before setting an error.
	fn get_sync_attempts(&self) -> u8 {
		self.sync_attempts.load(Ordering::Relaxed)
	}

	/// Increment wallet synchronization attempts before setting an error.
	fn increment_sync_attempts(&self) {
		let mut attempts = self.get_sync_attempts();
		attempts += 1;
		self.sync_attempts.store(attempts, Ordering::Relaxed);
	}

	/// Reset wallet synchronization attempts.
	fn reset_sync_attempts(&self) {
		self.sync_attempts.store(0, Ordering::Relaxed);
	}

	/// Select transaction by slate id.
	fn retrieve_tx_by_id(&self, id: Option<u32>, slate_id: Option<Uuid>) -> Option<TxLogEntry> {
		let r_inst = self.instance.as_ref().read();
		let inst = r_inst.clone().unwrap();
		let mask = self.keychain_mask();
		if let Ok((_, txs)) = retrieve_txs(inst, mask.as_ref(), &None, false, id, slate_id, None) {
			if !txs.is_empty() {
				return Some(txs.get(0).unwrap().clone());
			}
		}
		None
	}

	/// Select transactions with provided limit.
	fn retrieve_txs(&self, limit: u32) -> Result<Vec<TxLogEntry>, Error> {
		let r_inst = self.instance.as_ref().read();
		let inst = r_inst.clone().unwrap();
		let mut wallet_lock = inst.lock();
		let lc = wallet_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let parent_key_id = w.parent_key_id();
		// Retrieve txs from database.
		let mut txs: Vec<TxLogEntry> = w
			.tx_log_iter()?
			.filter(|tx| tx.is_ok())
			.map(|tx| tx.unwrap())
			.filter(|tx_entry| tx_entry.parent_key_id == parent_key_id)
			// Filter transactions to not show txs without slate (usually unspent outputs).
			.filter(|tx| {
				tx.tx_slate_id.is_some() || (tx.tx_slate_id.is_none() && tx.payment_proof.is_some())
			})
			.filter(|tx_entry| {
				if tx_entry.tx_type == TxLogEntryType::TxSent
					|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
				{
					BigInt::from(tx_entry.amount_debited) - BigInt::from(tx_entry.amount_credited)
						>= BigInt::from(1)
				} else {
					BigInt::from(tx_entry.amount_credited) - BigInt::from(tx_entry.amount_debited)
						>= BigInt::from(1)
				}
			})
			.collect();
		// Sort txs by creation date (newest first); sort_by_key is stable so the
		// follow-up sort keeps this ordering within each group.
		txs.sort_by_key(|tx| -tx.creation_ts.timestamp());
		// Then float unconfirmed txs to the top.
		txs.sort_by_key(|tx| {
			tx.confirmed
				|| tx.tx_type == TxLogEntryType::TxReceivedCancelled
				|| tx.tx_type == TxLogEntryType::TxSentCancelled
				|| tx.tx_type == TxLogEntryType::TxReverted
		});
		// Apply limit.
		txs.truncate(limit as usize);
		Ok(txs)
	}

	/// Delete txs with 0 amount.
	fn clear_empty_txs(&self) -> Result<(), Error> {
		let txs: Vec<TxLogEntry> = {
			let r_inst = self.instance.as_ref().read();
			let inst = r_inst.clone().unwrap();
			let mut wallet_lock = inst.lock();
			let lc = wallet_lock.lc_provider()?;
			let w = lc.wallet_inst()?;
			let parent_key_id = w.parent_key_id();
			// Retrieve txs from database.
			w.tx_log_iter()?
				.filter(|tx| tx.is_ok())
				.map(|tx| tx.unwrap())
				.filter(|tx_entry| tx_entry.parent_key_id == parent_key_id)
				.filter(|tx_entry| {
					if tx_entry.tx_type == TxLogEntryType::TxSent
						|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
					{
						BigInt::from(tx_entry.amount_debited)
							- BigInt::from(tx_entry.amount_credited)
							== BigInt::from(0)
					} else if tx_entry.tx_type == TxLogEntryType::TxReceived
						|| tx_entry.tx_type == TxLogEntryType::TxReceivedCancelled
					{
						BigInt::from(tx_entry.amount_credited)
							- BigInt::from(tx_entry.amount_debited)
							== BigInt::from(0)
					} else {
						false
					}
				})
				.collect()
		};
		for t in &txs {
			self.delete_tx(t.id)?;
		}
		Ok(())
	}

	/// Send a task to the wallet.
	pub fn task(&self, task: WalletTask) {
		let r_tasks = self.tasks_sender.read();
		if r_tasks.is_some() {
			match task {
				WalletTask::CalculateFee(_, _) => {
					let calculating = self.fee_calculating.load(Ordering::Relaxed);
					self.fee_calculating
						.store(calculating + 1, Ordering::Relaxed);
				}
				_ => {}
			}
			let _ = r_tasks.as_ref().unwrap().send(task);
		}
	}

	/// Create account into wallet.
	pub fn create_account(&self, label: &String) -> Result<(), Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance, None);
		controller::owner_single_use(
			None,
			self.keychain_mask().as_ref(),
			Some(&mut api),
			|api, m| {
				let id = api.create_account_path(m, label)?;
				if self.get_data().is_none() {
					return Err(Error::GenericError("No wallet data".to_string()));
				}
				let current_height = self.get_data().unwrap().info.last_confirmed_height;
				if let Some(spendable_amount) = self.account_balance(current_height, api, m) {
					let mut w_data = self.accounts.write();
					w_data.push(WalletAccount {
						spendable_amount,
						label: label.clone(),
						path: id.to_bip_32_string(),
					});
					w_data.sort_by_key(|w| w.label != label.clone());
				}
				Ok(())
			},
		)
	}

	/// Set active account from provided label.
	pub fn set_active_account(&self, label: &String) -> Result<(), Error> {
		// Clear secret key for previous account.
		{
			let mut w_key = self.secret_key.write();
			*w_key = None;
		}

		// Set new active account.
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance.clone(), None);
		controller::owner_single_use(
			None,
			self.keychain_mask().as_ref(),
			Some(&mut api),
			|api, m| {
				api.set_active_account(m, label)?;
				self.account_time
					.store(Utc::now().timestamp(), Ordering::Relaxed);
				Ok(())
			},
		)?;

		// Update Slatepack address and secret key.
		self.update_secret_key_addr()?;

		// Save account label into config.
		let mut w_config = self.config.write();
		w_config.account = label.to_owned();
		w_config.save();

		// Clear wallet info.
		let mut w_data = self.data.write();
		*w_data = None;

		// Reset progress values.
		self.info_sync_progress.store(0, Ordering::Relaxed);

		// Sync wallet data.
		self.sync();
		Ok(())
	}

	/// Calculate current account balance.
	fn account_balance(
		&self,
		current_height: u64,
		o: &mut Owner<DefaultLCProvider<HTTPNodeClient, ExtKeychain>, HTTPNodeClient, ExtKeychain>,
		m: Option<&SecretKey>,
	) -> Option<u64> {
		if let Ok(outputs) = o.retrieve_outputs(m, false, false, None) {
			let mut spendable = 0;
			let min_confirmations = self.get_config().min_confirmations;
			for out_mapping in outputs.1 {
				let out = out_mapping.output;
				if out.status == grin_wallet_libwallet::OutputStatus::Unspent {
					if !out.is_coinbase
						|| out.lock_height <= current_height
						|| out.num_confirmations(current_height) >= min_confirmations
					{
						spendable += out.value;
					}
				}
			}
			return Some(spendable);
		}
		None
	}

	/// Get list of accounts for the wallet.
	pub fn accounts(&self) -> Vec<WalletAccount> {
		self.accounts.read().clone()
	}

	/// Get wallet data.
	pub fn get_data(&self) -> Option<WalletData> {
		let r_data = self.data.read();
		r_data.clone()
	}

	/// Load more transactions at list by increasing limit.
	pub fn load_more_txs(&self) {
		self.more_txs_loading.store(true, Ordering::Relaxed);
		let wallet = self.clone();
		thread::spawn(move || {
			// Wait when current sync will be finished.
			while wallet.syncing() {
				thread::sleep(Duration::from_secs(1));
			}
			// Sync wallet data with new limit.
			{
				let mut w_data = wallet.data.write();
				if w_data.is_some() {
					w_data.as_mut().unwrap().txs_limit += WalletData::TXS_LIMIT;
				}
			}
			sync_wallet_data(&wallet, false);
			wallet.more_txs_loading.store(false, Ordering::Relaxed);
		});
	}

	/// Check if more transaction are loading.
	pub fn more_txs_loading(&self) -> bool {
		self.more_txs_loading.load(Ordering::Relaxed)
	}

	/// Sync wallet data from node at sync thread or locally synchronously.
	pub fn sync(&self) {
		let thread_r = self.sync_thread.read();
		if let Some(thread) = thread_r.as_ref() {
			thread.unpark();
		}
	}

	/// Check if wallet is syncing.
	pub fn syncing(&self) -> bool {
		self.syncing.load(Ordering::Relaxed)
	}

	/// Check if the heavy node polling at sync thread is paused (on-demand
	/// node polling: Android battery optimization, never set on desktop).
	pub fn node_polling_paused(&self) -> bool {
		self.node_polling_paused.load(Ordering::SeqCst)
	}

	/// Resume node polling and wake the sync thread. Called when the app is
	/// foreground again (the user expects a live balance) and when a slatepack
	/// arrives needing node work (post/confirm). MONEY-SAFETY: bumps the
	/// resume counter first so a pause decision computed from an older sync
	/// snapshot can never override this signal (see
	/// [`maybe_pause_node_polling`]).
	pub fn resume_node_polling(&self) {
		self.node_polling_resume_seq.fetch_add(1, Ordering::SeqCst);
		if self.node_polling_paused.swap(false, Ordering::SeqCst) {
			self.sync();
		}
	}

	/// Get running Foreign API server port.
	pub fn foreign_api_port(&self) -> Option<u16> {
		let r_api = self.foreign_api_server.read();
		if r_api.is_some() {
			let api = r_api.as_ref().unwrap();
			return Some(api.1);
		}
		None
	}

	/// Check if Slatepack message is opening.
	pub fn message_opening(&self) -> bool {
		self.message_opening.load(Ordering::Relaxed)
	}

	/// Parse Slatepack message into [`Slate`].
	pub fn parse_slatepack(
		&self,
		text: &String,
	) -> Result<(Slate, Option<SlatepackAddress>), grin_wallet_controller::Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance, None);
		match parse_slatepack(
			&mut api,
			self.keychain_mask().as_ref(),
			None,
			Some(text.trim().to_string()),
		) {
			Ok(s) => Ok(s),
			Err(e) => Err(e),
		}
	}

	/// Create Slatepack message from provided slate.
	fn create_slatepack_message(
		&self,
		slate: &Slate,
		_: Option<SlatepackAddress>,
	) -> Result<String, Error> {
		let mut message = "".to_string();
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance, None);
		controller::owner_single_use(
			None,
			self.keychain_mask().as_ref(),
			Some(&mut api),
			|api, m| {
				// let recipients = match dest {
				// 	Some(a) => vec![a],
				// 	None => vec![],
				// };
				message = api.create_slatepack_message(m, &slate, Some(0), vec![])?;
				Ok(())
			},
		)?;

		// Write Slatepack message to file.
		let slatepack_dir = self.get_config().get_slate_path(slate.id, &slate.state);
		let mut output = File::create(slatepack_dir)?;
		output.write_all(message.as_bytes())?;
		output.sync_all()?;
		Ok(message)
	}

	/// Check if Slatepack file exists.
	pub fn slatepack_exists(&self, slate: &Slate) -> bool {
		let slatepack_path = self.get_config().get_slate_path(slate.id, &slate.state);
		fs::exists(slatepack_path).unwrap_or(false)
	}

	/// Read a stored Slatepack message text for the given slate id and state.
	pub fn read_slatepack_text(&self, id: Uuid, state: &SlateState) -> Option<String> {
		let path = self.get_config().get_slate_path(id, state);
		fs::read_to_string(path).ok()
	}

	/// Check if the wallet has a transaction for the given slate id.
	pub fn has_tx_for_slate(&self, slate_id: &Uuid) -> bool {
		self.retrieve_tx_by_id(None, Some(*slate_id)).is_some()
	}

	/// Manual slatepack send (the GRIM-native flow, exposed for the advanced
	/// Settings page): build a Standard1 payment of `amount` nanogrin to an
	/// optional recipient slatepack address, locking the inputs, and return the
	/// armored slatepack text to hand to the recipient out-of-band.
	pub fn manual_send_slatepack(
		&self,
		amount: u64,
		dest: Option<String>,
	) -> Result<String, Error> {
		let dest = match dest {
			Some(a) => Some(
				SlatepackAddress::try_from(a.trim())
					.map_err(|_| Error::GenericError("Invalid recipient address".to_string()))?,
			),
			None => None,
		};
		let slate = self.send(amount, dest)?;
		self.read_slatepack_text(slate.id, &slate.state)
			.ok_or_else(|| Error::GenericError("Slatepack message missing".to_string()))
	}

	/// Manual slatepack ingest mirroring [`WalletTask::OpenMessage`]'s routing:
	/// receiving a Standard1 or paying an Invoice1 is node-free, so it runs inline
	/// and returns the reply slatepack to send back; finalizing a returned slate
	/// (Standard2/Invoice2) posts to the node, so it's handed to the worker.
	pub fn manual_process_slatepack(&self, text: &String) -> Result<ManualSlatepackOutcome, Error> {
		let (slate, dest) = self
			.parse_slatepack(text)
			.map_err(|e| Error::GenericError(e.to_string()))?;
		match slate.state {
			SlateState::Standard1 => {
				let reply = self.receive(&slate, dest)?;
				let text = self
					.read_slatepack_text(reply.id, &reply.state)
					.ok_or_else(|| Error::GenericError("Reply slatepack missing".to_string()))?;
				Ok(ManualSlatepackOutcome::Response(text))
			}
			SlateState::Invoice1 => {
				let reply = self.pay(&slate)?;
				let text = self
					.read_slatepack_text(reply.id, &reply.state)
					.ok_or_else(|| Error::GenericError("Reply slatepack missing".to_string()))?;
				Ok(ManualSlatepackOutcome::Response(text))
			}
			SlateState::Standard2 | SlateState::Invoice2 => {
				// Finalize + post hits the node; let the worker handle it (GRIM's
				// OpenMessage does exactly this routing).
				self.task(WalletTask::OpenMessage(text.clone()));
				Ok(ManualSlatepackOutcome::Finalizing)
			}
			_ => Err(Error::GenericError(
				"This slatepack is already complete or isn't one Goblin can continue.".to_string(),
			)),
		}
	}

	/// Guarded nostr ingest: receive an incoming Standard1 payment and return
	/// the S2 reply slate with its slatepack text. Receiving only creates an
	/// output and signs — it never spends funds.
	pub fn nostr_receive(&self, slate: &Slate) -> Result<(Slate, String), Error> {
		let reply = self.receive(slate, None)?;
		let text = self
			.read_slatepack_text(reply.id, &reply.state)
			.ok_or_else(|| Error::GenericError("response slatepack missing".to_string()))?;
		Ok((reply, text))
	}

	/// Guarded nostr ingest: finalize and post a matching S2/I2 reply.
	/// Caller (ingest policy) has already verified the counterparty.
	///
	/// Returns `Ok(true)` when the reply was finalized + posted, `Ok(false)` when
	/// the local tx had been cancelled out-of-band (manual "Cancel payment", the
	/// generic tx-list cancel, or 24h expiry) so the reply was intentionally
	/// skipped — the caller records it as handled, NOT retried, and never
	/// re-posts a payment the sender already reclaimed.
	pub fn nostr_finalize_post(&self, slate: &Slate) -> Result<bool, Error> {
		// Serialize against a concurrent manual cancel of the same payment: hold
		// the lock across the check + finalize + post so a cancel can't reclaim
		// the outputs while we post them on-chain (and vice-versa). The guard is
		// kept alive for the whole function via `_svc`/`_lock`.
		let _svc = self.nostr_service();
		let _lock = _svc.as_ref().map(|s| s.lock_finalize());
		let tx = self
			.retrieve_tx_by_id(None, Some(slate.id))
			.ok_or_else(|| Error::GenericError("transaction not found".to_string()))?;
		if matches!(
			tx.tx_type,
			TxLogEntryType::TxSentCancelled | TxLogEntryType::TxReceivedCancelled
		) {
			return Ok(false);
		}
		// Also honour a cancel that marked the meta but whose grin cancel hasn't
		// committed yet (the cancel handler marks the meta first, under this lock).
		if let Some(svc) = &_svc {
			if svc
				.store
				.tx_meta(&slate.id.to_string())
				.map(|m| m.status == crate::nostr::NostrSendStatus::Cancelled)
				.unwrap_or(false)
			{
				return Ok(false);
			}
		}
		// A prior attempt may have finalized but then failed to post (a transient
		// node outage). Re-finalizing errors on the already-finalized tx, so when
		// the finalized (Standard3) slatepack is already on disk we parse and
		// re-post it instead of finalizing again — a post failure then recovers on
		// the next retry rather than getting permanently stuck.
		let finalized = match self.read_slatepack_text(slate.id, &SlateState::Standard3) {
			Some(text) => {
				self.parse_slatepack(&text)
					.map_err(|e| Error::GenericError(format!("reload finalized slate: {e}")))?
					.0
			}
			None => self.finalize(slate, tx.id)?,
		};
		self.post(&finalized, Some(tx.id))?;
		Ok(true)
	}

	/// Pay an APPROVED payment request (Invoice1). Only ever called from the
	/// explicit user approval task — never from the ingest pipeline.
	pub fn nostr_pay(&self, slate: &Slate) -> Result<(Slate, String), Error> {
		let reply = self.pay(slate)?;
		let text = self
			.read_slatepack_text(reply.id, &reply.state)
			.ok_or_else(|| Error::GenericError("response slatepack missing".to_string()))?;
		Ok((reply, text))
	}

	/// Get possible state from tx type.
	pub fn get_slate_state(&self, slate_id: Uuid, tx_type: &TxLogEntryType) -> SlateState {
		let mut slate = Slate::blank(1, false);
		slate.id = slate_id;
		slate.state = match tx_type {
			TxLogEntryType::TxReceived => SlateState::Invoice3,
			_ => SlateState::Standard3,
		};
		// Transaction was finalized.
		if self.slatepack_exists(&slate) {
			slate.state
		} else {
			slate.state = match tx_type {
				TxLogEntryType::TxReceived => SlateState::Standard2,
				_ => SlateState::Invoice2,
			};
			// Transaction signed to be finalized.
			if self.slatepack_exists(&slate) {
				slate.state
			} else {
				// Transaction just was created.
				slate.state = match tx_type {
					TxLogEntryType::TxReceived => SlateState::Invoice1,
					_ => SlateState::Standard1,
				};
				if self.slatepack_exists(&slate) {
					slate.state
				} else {
					SlateState::Unknown
				}
			}
		}
	}

	/// Calculate transaction fee for provided amount.
	fn calculate_fee(&self, a: u64) -> Result<u64, Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut w_lock = instance.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let config = self.get_config();
		let args = InitTxArgs {
			src_acct_name: Some(config.account.clone()),
			amount: a,
			minimum_confirmations: config.min_confirmations,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			estimate_only: Some(true),
			..Default::default()
		};
		let res = init_send_tx(w, self.keychain_mask().as_ref(), args, false);
		match res {
			Ok(slate) => Ok(slate.fee_fields.fee()),
			Err(e) => match e {
				Error::NotEnoughFunds {
					available, needed, ..
				} => Ok(needed - available),
				e => Err(e),
			},
		}
	}

	/// Check if transaction fee is calculating.
	pub fn fee_calculating(&self) -> bool {
		self.fee_calculating.load(Ordering::Relaxed) > 0
	}

	/// Last calculated network fee for `amount`, if one is cached. Returns
	/// `None` until a `CalculateFee` task for that exact amount has completed.
	pub fn calculated_fee(&self, amount: u64) -> Option<u64> {
		self.last_fee
			.read()
			.and_then(|(a, f)| if a == amount { Some(f) } else { None })
	}

	/// Initialize a transaction to send amount.
	fn send(&self, a: u64, dest: Option<SlatepackAddress>) -> Result<Slate, Error> {
		let config = self.get_config();
		let args = InitTxArgs {
			payment_proof_recipient_address: dest.clone(),
			src_acct_name: Some(config.account),
			amount: a,
			minimum_confirmations: config.min_confirmations,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance, None);
		let mut slate = None;
		let keychain_mask = self.keychain_mask();
		controller::owner_single_use(None, keychain_mask.as_ref(), Some(&mut api), |api, m| {
			let s = api.init_send_tx(m, args)?;
			// Create Slatepack message response.
			let _ = self.create_slatepack_message(&s, dest)?;
			// Lock outputs to for this transaction.
			api.tx_lock_outputs(m, &s)?;
			slate = Some(s);
			Ok(())
		})?;
		if let Some(slate) = slate {
			Ok(slate)
		} else {
			Err(Error::GenericError("slate was not created".to_string()))
		}
	}

	/// Check if request to send funds is creating.
	pub fn send_creating(&self) -> bool {
		self.send_creating.load(Ordering::Relaxed)
	}

	/// Initialize an invoice transaction to receive amount, return request for funds sender.
	fn issue_invoice(&self, amount: u64) -> Result<Slate, Error> {
		let args = IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount,
			target_slate_version: None,
		};
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let api = Owner::new(instance, None);
		let slate = api.issue_invoice_tx(self.keychain_mask().as_ref(), args)?;

		// Create Slatepack message response.
		let _ = self.create_slatepack_message(&slate, None)?;

		Ok(slate)
	}

	/// Handle message from the invoice issuer to send founds, return response for funds receiver.
	fn pay(&self, slate: &Slate) -> Result<Slate, Error> {
		let config = self.get_config();
		let args = InitTxArgs {
			src_acct_name: None,
			amount: slate.amount,
			minimum_confirmations: config.min_confirmations,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let api = Owner::new(instance, None);
		let slate = api.process_invoice_tx(self.keychain_mask().as_ref(), &slate, args)?;
		api.tx_lock_outputs(self.keychain_mask().as_ref(), &slate)?;

		// Create Slatepack message response.
		let _ = self.create_slatepack_message(&slate, None)?;

		Ok(slate)
	}

	/// Check if request to receive funds is creating.
	pub fn invoice_creating(&self) -> bool {
		self.invoice_creating.load(Ordering::Relaxed)
	}

	/// Create response to sender to receive funds.
	fn receive(&self, slate: &Slate, dest: Option<SlatepackAddress>) -> Result<Slate, Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let api = Owner::new(instance, None);
		let mut slate = slate.clone();
		controller::foreign_single_use(api.wallet_inst.clone(), self.keychain_mask(), |api| {
			slate = api.receive_tx(&slate, Some(self.get_config().account.as_str()), None)?;
			Ok(())
		})?;

		// Create Slatepack message response.
		let _ = self.create_slatepack_message(&slate, dest)?;

		Ok(slate)
	}

	/// Finalize transaction from provided message as sender or invoice issuer.
	fn finalize(&self, slate: &Slate, id: u32) -> Result<Slate, Error> {
		self.on_tx_action(id, Some(WalletTxAction::Finalizing));

		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let api = Owner::new(instance, None);
		let mut slate = slate.clone();
		controller::foreign_single_use(api.wallet_inst.clone(), self.keychain_mask(), |api| {
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		})?;

		// Save Slatepack message to file.
		let _ = self.create_slatepack_message(&slate, None)?;

		// Clear tx action.
		self.on_tx_action(id, None);

		Ok(slate)
	}

	/// Post transaction to blockchain.
	fn post(&self, slate: &Slate, id: Option<u32>) -> Result<(), Error> {
		if let Some(id) = id {
			self.on_tx_action(id, Some(WalletTxAction::Posting));
		}

		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance, None);
		controller::owner_single_use(
			None,
			self.keychain_mask().as_ref(),
			Some(&mut api),
			|api, m| {
				api.post_tx(m, &slate, self.can_use_dandelion())?;
				Ok(())
			},
		)?;

		// Clear tx action.
		if let Some(id) = id {
			self.on_tx_action(id, None);
		}
		Ok(())
	}

	/// Cancel transaction.
	fn cancel(&self, id: u32) -> Result<(), Error> {
		self.on_tx_action(id, Some(WalletTxAction::Cancelling));

		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		cancel_tx(
			instance,
			self.keychain_mask().as_ref(),
			&None,
			Some(id),
			None,
		)?;

		// Clear tx action.
		self.on_tx_action(id, None);

		Ok(())
	}

	/// Update transaction action status.
	fn on_tx_action(&self, id: u32, action: Option<WalletTxAction>) {
		let mut w_data = self.data.write();
		if let Some(data) = w_data.as_mut() {
			data.on_tx_action(id, action);
		}
	}

	/// Update transaction action error status.
	fn on_tx_error(&self, id: u32, err: Option<Error>) {
		let mut w_data = self.data.write();
		if let Some(data) = w_data.as_mut() {
			data.on_tx_error(id, err);
		}
	}

	/// Save task result to consume later.
	fn on_task_result(&self, tx: Option<TxLogEntry>, task: &WalletTask) {
		let mut w_res = self.task_result.write();
		let id = if let Some(t) = tx { Some(t.id) } else { None };
		*w_res = Some((id, task.clone()));
	}

	/// Consume result of successful task.
	pub fn consume_task_result(&self) -> Option<(Option<u32>, WalletTask)> {
		let res = {
			let r_res = self.task_result.read();
			r_res.clone()
		};
		// Clear result for task.
		let mut w_res = self.task_result.write();
		*w_res = None;
		res
	}

	/// Get possible transaction confirmation height.
	fn tx_height(&self, tx: &WalletTx) -> Result<Option<u64>, Error> {
		let mut tx_height = None;
		if tx.data.confirmed && tx.data.kernel_excess.is_some() {
			let r_inst = self.instance.as_ref().read();
			let instance = r_inst.clone().unwrap();
			let mut w_lock = instance.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			if let Ok(res) = w.w2n_client().get_kernel(
				tx.data.kernel_excess.as_ref().unwrap(),
				tx.data.kernel_lookup_min_height,
				None,
			) {
				tx_height = Some(match res {
					None => 0,
					Some((_, h, _)) => h,
				});
			}
		} else if tx.broadcasting() {
			tx_height = match self.get_data() {
				None => None,
				Some(data) => Some(data.info.last_confirmed_height),
			};
		}
		Ok(tx_height)
	}

	/// Get stored transaction Slate.
	fn get_tx_slate(&self, tx_id: u32) -> Option<Slate> {
		if let Some(tx) = self.retrieve_tx_by_id(Some(tx_id), None) {
			if let Some(slate_id) = tx.tx_slate_id {
				let slate_state = self.get_slate_state(slate_id, &tx.tx_type);
				let slatepack_path = self.get_config().get_slate_path(slate_id, &slate_state);
				let msg = fs::read_to_string(slatepack_path).unwrap_or("".to_string());
				if let Ok((slate, _)) = self.parse_slatepack(&msg) {
					return Some(slate);
				}
			}
		}
		None
	}

	/// Delete transaction from database.
	fn delete_tx(&self, id: u32) -> Result<(), Error> {
		self.on_tx_action(id, Some(WalletTxAction::Deleting));

		let slate = self.get_tx_slate(id);
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let keychain_mask = self.keychain_mask();
		let mut wallet_lock = instance.lock();
		let lc = wallet_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let parent_key = w.parent_key_id();
		let mut batch = w.batch(keychain_mask.as_ref())?;
		batch.delete_tx_log_entry(id, &parent_key)?;
		batch.commit()?;

		// Delete transaction files.
		if let Some(s) = slate {
			let slatepack_path = self.get_config().get_slate_path(s.id, &s.state);
			fs::remove_file(&slatepack_path).unwrap_or_default();
			let path = path::Path::new(&self.get_config().get_data_path())
				.join("saved_txs")
				.join(format!("{}.grintx", s.id));
			fs::remove_file(&path).unwrap_or_default();
		}
		Ok(())
	}

	/// Change wallet password.
	pub fn change_password(&self, old: String, new: String) -> Result<(), Error> {
		{
			let r_inst = self.instance.as_ref().read();
			let instance = r_inst.clone().unwrap();
			let mut wallet_lock = instance.lock();
			let lc = wallet_lock.lc_provider()?;
			lc.change_password(
				None,
				ZeroingString::from(old.clone()),
				ZeroingString::from(new.clone()),
			)?;
		}
		// The grin seed password changed; re-encrypt EVERY held nostr identity's
		// ncryptsec from old to new through the same NIP-49 path, so all front
		// doors follow the one wallet password. Best-effort and non-fatal: a
		// failure is logged (never swallowed as success), and the grin password
		// change already committed above. Takes effect for the running service on
		// the next wallet open (it reloads the active identity from disk).
		let nostr_dir = self.get_config().get_nostr_path();
		if let Some(index) = HeldIdentities::load(&nostr_dir)
			&& let Err(e) = index.reencrypt_all(&nostr_dir, &old, &new)
		{
			error!("nostr: re-encrypting held identities after password change: {e}");
		}
		Ok(())
	}

	/// Initiate wallet repair by scanning its outputs.
	pub fn repair(&self) {
		self.repair_needed.store(true, Ordering::Relaxed);
		self.sync();
	}

	/// Check if wallet is repairing.
	pub fn is_repairing(&self) -> bool {
		self.repair_needed.load(Ordering::Relaxed)
	}

	/// Get wallet repairing progress.
	pub fn repairing_progress(&self) -> u8 {
		self.repair_progress.load(Ordering::Relaxed)
	}

	/// Change wallet data path, migrating all files to new directory.
	pub fn change_data_path(&self, path: String) {
		let wallet = self.clone();
		wallet.files_moving.store(true, Ordering::Relaxed);
		// Close wallet if open.
		if self.is_open() {
			self.close();
		}
		thread::spawn(move || {
			// Wait wallet to be closed.
			while wallet.is_open() || wallet.syncing() {
				thread::sleep(Duration::from_millis(100));
			}
			// Move wallet db files.
			if let Some(old_path) = wallet.get_config().data_path {
				let mut old = PathBuf::from(old_path.as_str());
				old.push(WalletConfig::DATA_DIR_NAME);
				let mut new = PathBuf::from(path.as_str());
				new.push(WalletConfig::DATA_DIR_NAME);
				if old.exists() {
					fs::create_dir_all(&new).unwrap_or_default();
					if let Ok(_) = fs::rename(old.as_path(), new.as_path()) {
						// Save new path to config.
						let mut w_config = wallet.config.write();
						w_config.data_path = Some(path);
						w_config.save();
					}
				}
			}
			wallet.files_moving.store(false, Ordering::Relaxed);
			// Mark wallet to reopen.
			if !wallet.is_open() {
				wallet.set_reopen(true);
			}
		});
	}

	/// Deleting wallet database files.
	pub fn delete_db(&self) {
		let wallet = self.clone();
		wallet.files_moving.store(true, Ordering::Relaxed);
		// Close wallet if open.
		if self.is_open() {
			self.close();
		}
		thread::spawn(move || {
			// Wait wallet to be closed.
			while wallet.is_open() || wallet.syncing() {
				thread::sleep(Duration::from_millis(100));
			}
			// Remove wallet db files.
			let _ = fs::remove_dir_all(wallet.get_config().get_db_path());
			wallet.files_moving.store(false, Ordering::Relaxed);
			// Mark wallet to repair.
			wallet.repair();
			// Mark wallet to reopen.
			if !wallet.is_open() {
				wallet.set_reopen(true);
			}
		});
	}

	/// Check if data files are moving.
	pub fn files_moving(&self) -> bool {
		self.files_moving.load(Ordering::Relaxed)
	}

	/// Retrieve payment proof.
	pub fn get_payment_proof(
		&self,
		tx_id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<PaymentProof>, Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let key_mask = self.keychain_mask();
		let mut api = Owner::new(instance, None);
		let mut proof = None;
		controller::owner_single_use(None, key_mask.as_ref(), Some(&mut api), |api, m| {
			let result = api.retrieve_payment_proof(m, false, tx_id, slate_id);
			proof = match result {
				Ok(p) => Some(p),
				Err(e) => {
					error!("retrieve_payment_proof error: {}", e);
					None
				}
			};
			Ok(())
		})?;
		Ok(proof)
	}

	/// Retrieve a finalized send's payment proof as the `(json, kernel_excess_hex)`
	/// pair the proof-on-request delivery needs (frozen contract 4.3.2). `json` is
	/// the owner API's verbatim serialization of the proof
	/// (`{amount, excess, recipient_address, recipient_sig, sender_address,
	/// sender_sig}`); `kernel_excess_hex` is a convenience copy of the excess so
	/// the watcher can query the chain before parsing the proof. `None` when no
	/// proof exists yet (e.g. a proof-less send, or called before finalize).
	pub fn payment_proof_delivery(&self, slate_id: Uuid) -> Option<(String, String)> {
		let proof = self
			.get_payment_proof(None, Some(slate_id))
			.ok()
			.flatten()?;
		let json = serde_json::to_string(&proof).ok()?;
		let kernel_hex = proof.excess.to_hex();
		Some((json, kernel_hex))
	}

	/// Verify payment proof.
	fn verify_payment_proof(&self, proof: &PaymentProof) -> Result<(u32, bool, bool), Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let keychain_mask = self.keychain_mask();
		let verify_res = verify_payment_proof(instance.clone(), keychain_mask.as_ref(), proof);
		let res = match verify_res {
			Ok((send, rec)) => {
				// Update proof at local database for valid proof.
				if send || rec {
					let mut wallet_lock = instance.lock();
					let lc = wallet_lock.lc_provider()?;
					let w = lc.wallet_inst()?;
					// Find wallet transaction to update or create.
					let txs = w
						.tx_log_iter()?
						.filter(|tx| tx.is_ok())
						.map(|tx| tx.unwrap())
						.filter(|entry| {
							if let Some(excess) = entry.kernel_excess {
								return excess == proof.excess;
							}
							false
						})
						.collect::<Vec<TxLogEntry>>();
					if let Some(tx) = txs.get(0) {
						let mut tx = tx.clone();
						let mut batch = w.batch(keychain_mask.as_ref())?;
						let parent_key = &tx.parent_key_id;
						tx.payment_proof = Some(StoredProofInfo {
							receiver_address: proof.recipient_address.pub_key,
							receiver_signature: Some(proof.recipient_sig),
							sender_address_path: 0,
							sender_address: proof.sender_address.pub_key,
							sender_signature: Some(proof.sender_sig),
						});
						batch.save_tx_log_entry(tx.clone(), &parent_key)?;
						batch.commit()?;
						Ok((tx.id, send, rec))
					} else {
						let parent_key = w.parent_key_id();
						let mut batch = w.batch(keychain_mask.as_ref())?;
						let log_id = batch.next_tx_log_id(&parent_key)?;
						let log_type = TxLogEntryType::TxSent;
						let mut tx = TxLogEntry::new(parent_key.clone(), log_type, log_id);
						tx.amount_debited = proof.amount;
						tx.kernel_excess = Some(proof.excess);
						tx.tx_type = TxLogEntryType::TxSent;
						tx.confirmed = true;
						tx.payment_proof = Some(StoredProofInfo {
							receiver_address: proof.recipient_address.pub_key,
							receiver_signature: Some(proof.recipient_sig),
							sender_address_path: 0,
							sender_address: proof.sender_address.pub_key,
							sender_signature: Some(proof.sender_sig),
						});
						batch.save_tx_log_entry(tx.clone(), &parent_key)?;
						batch.commit()?;
						Ok((tx.id, send, rec))
					}
				} else {
					Ok((0, send, rec))
				}
			}
			Err(e) => Err(e),
		};
		// Sync wallet data on success.
		if res.is_ok() {
			sync_wallet_data(self, false);
		}
		res
	}

	/// Check if payment proof is verifying.
	pub fn payment_proof_verifying(&self) -> bool {
		self.proof_verifying.load(Ordering::Relaxed)
	}

	/// Get recovery phrase.
	pub fn get_recovery(&self, password: String) -> Result<ZeroingString, Error> {
		let r_inst = self.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut wallet_lock = instance.lock();
		let lc = wallet_lock.lc_provider()?;
		lc.get_mnemonic(None, ZeroingString::from(password))
	}

	/// Close the wallet, delete its files and mark it as deleted.
	pub fn delete_wallet(&self) {
		if self.is_open() {
			self.close();
		}
		// Mark wallet as deleted.
		let wallet_delete = self.clone();
		wallet_delete.deleted.store(true, Ordering::Relaxed);

		thread::spawn(move || {
			// Wait wallet to be closed.
			if wallet_delete.is_open() {
				thread::sleep(Duration::from_millis(100));
			}
			// Remove wallet files.
			let _ = fs::remove_dir_all(wallet_delete.get_config().get_wallet_path());
			// Mark wallet as deleted.
			wallet_delete.deleted.store(true, Ordering::Relaxed);
			// Start sync to close thread.
			wallet_delete.sync();
		});
	}

	/// Check if wallet was deleted to remove it from list.
	pub fn is_deleted(&self) -> bool {
		self.deleted.load(Ordering::Relaxed)
	}
}

/// Delay in seconds to sync [`WalletData`] (60 seconds as average block time).
const SYNC_DELAY: Duration = Duration::from_millis(60 * 1000);
/// Delay in seconds for sync thread to wait before start of new attempt.
const ATTEMPT_DELAY: Duration = Duration::from_millis(3 * 1000);
/// Number of attempts to sync [`WalletData`] before setting an error.
const SYNC_ATTEMPTS: u8 = 10;

/// Launch thread to sync wallet data from node.
fn start_sync(wallet: Wallet) -> Thread {
	// Start tasks thread.
	let (tx, rx) = mpsc::channel();
	{
		let mut w_tasks = wallet.tasks_sender.write();
		*w_tasks = Some(tx);
	}
	let wallet_thread = wallet.clone();
	thread::spawn(move || {
		loop {
			let wallet_task = wallet_thread.clone();
			if let Ok(task) = rx.recv() {
				thread::spawn(move || {
					tokio::runtime::Builder::new_current_thread()
						.enable_all()
						.build()
						.unwrap()
						.block_on(async {
							handle_task(&wallet_task, task).await;
						});
				});
			}
			if wallet_thread.is_closing() || !wallet_thread.is_open() {
				break;
			}
		}
	});

	// Reset progress values.
	wallet.info_sync_progress.store(0, Ordering::Relaxed);
	wallet.repair_progress.store(0, Ordering::Relaxed);

	// To call on sync thread stop.
	let on_thread_stop = |wallet: Wallet| {
		// Clear thread instance.
		let mut thread_w = wallet.sync_thread.write();
		*thread_w = None;

		// Clear wallet info.
		let mut w_data = wallet.data.write();
		*w_data = None;

		// Clear syncing status.
		wallet.syncing.store(false, Ordering::Relaxed);
	};

	thread::spawn(move || {
		loop {
			// Set syncing status.
			wallet.syncing.store(true, Ordering::Relaxed);

			// Close wallet on chain type change.
			if wallet.get_config().chain_type != AppConfig::chain_type() {
				wallet.close();
			}

			// Stop syncing if wallet was closed.
			if !wallet.is_open() || wallet.is_closing() {
				on_thread_stop(wallet);
				return;
			}

			// Start the nostr payment-messaging service the moment the wallet is
			// open — BEFORE (and independent of) the grin node sync. Previously
			// this lived deep in the sync body behind `!sync_error` and the node
			// checks, so the Nym/relay connection could wait up to a full
			// SYNC_DELAY (60s) — or never start while the node errored — leaving
			// the profile stuck on "Connecting…". Idempotent.
			if let Some(service) = wallet.nostr_service() {
				service.start(wallet.clone());
				// Auto-cancel/expire stale pending transactions (frees outputs
				// locked by stale sends).
				service.expire_stale(&wallet);
			}

			// Check integrated node state.
			if wallet.get_current_connection() == ConnectionMethod::Integrated {
				let not_enabled = !Node::is_running() || Node::is_stopping();
				if not_enabled {
					// Reset loading progress.
					wallet.info_sync_progress.store(0, Ordering::Relaxed);
				}
				// Set an error when integrated node is not enabled.
				wallet.set_sync_error(not_enabled);
				// Skip cycle when node sync is not finished.
				if !Node::is_running() || Node::get_sync_status() != Some(SyncStatus::NoSync) {
					thread::park_timeout(ATTEMPT_DELAY);
					continue;
				}
			}

			// Scan outputs if repair is needed or sync data if there is no error.
			if !wallet.sync_error() {
				if wallet.is_repairing() {
					repair_wallet(&wallet);
					// Stop sync if wallet was closed.
					if !wallet.is_open() || wallet.is_closing() {
						on_thread_stop(wallet);
						return;
					}
				}
				// Retrieve data from local database if current data is empty.
				if wallet.get_data().is_none() {
					sync_wallet_data(&wallet, false);
				}

				if wallet.is_open() && !wallet.is_closing() {
					// Start Foreign API listener if not running.
					let api_server_running = { wallet.foreign_api_server.read().is_some() };
					if !api_server_running {
						match start_api_server(&wallet) {
							Ok(api_server) => {
								let mut api_server_w = wallet.foreign_api_server.write();
								*api_server_w = Some(api_server);
							}
							Err(_) => {}
						}
					}
				}

				// On-demand node polling (Android battery): while the app is
				// backgrounded and no transaction is waiting on the node, skip
				// the heavy node sync. The relay+Nym nostr service started
				// above keeps running and listening for gift wraps regardless;
				// a slatepack receipt resumes polling instantly (see
				// `resume_node_polling`). Foreground always polls.
				if crate::app_foreground() {
					wallet.resume_node_polling();
				}
				if !wallet.node_polling_paused() {
					let resume_seq = wallet.node_polling_resume_seq.load(Ordering::SeqCst);
					// Sync wallet from node.
					sync_wallet_data(&wallet, true);
					// Pause polling when it's safe to (Android only).
					maybe_pause_node_polling(&wallet, resume_seq);
				}
			}

			// Stop sync if wallet was closed.
			if !wallet.is_open() || wallet.is_closing() {
				on_thread_stop(wallet);
				return;
			}

			// Setup flag to check if sync was failed.
			let failed_sync = wallet.sync_error() || wallet.get_sync_attempts() != 0;

			// Clear syncing status.
			if !failed_sync {
				wallet.syncing.store(false, Ordering::Relaxed);
			}

			// Repeat after default or attempt delay if synchronization was not successful.
			let delay = if failed_sync {
				ATTEMPT_DELAY
			} else {
				SYNC_DELAY
			};
			thread::park_timeout(delay);
		}
	})
	.thread()
	.clone()
}

/// Pause the heavy node polling after a completed node sync when it's safe
/// (Android only — desktop always polls): the app is backgrounded AND the
/// fresh sync shows nothing waiting on the node AND no resume signal
/// (slatepack receipt / foreground) arrived while that sync ran.
/// MONEY-SAFETY (non-negotiable): confirmation tracking is never dropped —
/// any unconfirmed send/receive keeps the node polled until it confirms, and
/// when in doubt (failed sync, no data, unknown txs) we keep polling.
#[allow(unused_variables)]
fn maybe_pause_node_polling(wallet: &Wallet, resume_seq_before: u64) {
	#[cfg(target_os = "android")]
	{
		// Foreground: the user expects a live balance.
		if crate::app_foreground() {
			return;
		}
		// Only pause after a clean, settled sync from the node.
		if wallet.sync_error() || wallet.get_sync_attempts() != 0 {
			return;
		}
		let Some(data) = wallet.get_data() else {
			return;
		};
		// Anything unconfirmed — a send awaiting reply/broadcast or a receive
		// awaiting confirmation — keeps the node polled until it confirms.
		// Unknown txs count as in flight (when in doubt, poll).
		let in_flight = data
			.txs
			.as_ref()
			.map(|txs| {
				txs.iter().any(|tx| {
					!tx.data.confirmed
						&& matches!(
							tx.data.tx_type,
							TxLogEntryType::TxSent | TxLogEntryType::TxReceived
						)
				})
			})
			.unwrap_or(true);
		if in_flight {
			return;
		}
		wallet.node_polling_paused.store(true, Ordering::SeqCst);
		// A slatepack receipt (or foreground) may have raced this pause while
		// the sync above ran — its transaction may not be in the data snapshot
		// we just inspected. The resume always wins.
		if wallet.node_polling_resume_seq.load(Ordering::SeqCst) != resume_seq_before {
			wallet.node_polling_paused.store(false, Ordering::SeqCst);
		}
	}
}

/// Map a wallet error to a short, user-facing reason for the failure screen so
/// "Couldn't send" actually explains itself — most often locked/unconfirmed
/// funds after a recent payment.
fn friendly_send_error(e: &Error) -> String {
	let s = format!("{e:?}");
	if s.contains("NotEnoughFunds") {
		"Not enough spendable grin — coins from a recent payment may still be confirming (about 10 min). Try again once it clears.".to_string()
	} else {
		format!("Couldn't complete the payment: {e}")
	}
}

/// Handle wallet task.
async fn handle_task(w: &Wallet, t: WalletTask) {
	match &t {
		WalletTask::OpenMessage(m) => {
			if !w.is_open() || m.is_empty() {
				return;
			}
			let w = w.clone();
			let msg = m.clone();
			w.message_opening.store(true, Ordering::Relaxed);
			if let Ok((s, dest)) = w.parse_slatepack(&msg) {
				let tx = w.retrieve_tx_by_id(None, Some(s.id));
				// Check if message already exists.
				let exists = {
					let mut exists = w.slatepack_exists(&s);
					if !exists
						&& (s.state == SlateState::Invoice2 || s.state == SlateState::Standard2)
					{
						let mut slate = s.clone();
						slate.state = if s.state == SlateState::Standard2 {
							SlateState::Standard3
						} else {
							SlateState::Invoice3
						};
						exists = w.slatepack_exists(&slate);
					}
					exists
				};
				if exists {
					w.on_task_result(tx, &t);
					w.message_opening.store(false, Ordering::Relaxed);
					return;
				}
				// Create response or finalize.
				match s.state {
					SlateState::Standard1 | SlateState::Invoice1 => {
						if s.state != SlateState::Standard1 {
							if let Ok(_) = w.pay(&s) {
								sync_wallet_data(&w, false);
								let tx = w.retrieve_tx_by_id(None, Some(s.id));
								w.on_task_result(tx, &t);
							}
						} else {
							if let Ok(_) = w.receive(&s, dest) {
								sync_wallet_data(&w, false);
								let tx = w.retrieve_tx_by_id(None, Some(s.id));
								w.on_task_result(tx, &t);
							}
						}
					}
					SlateState::Standard2 | SlateState::Invoice2 => {
						if let Some(tx) = tx {
							match w.finalize(&s, tx.id) {
								Ok(s) => match w.post(&s, Some(tx.id)) {
									Ok(_) => {
										sync_wallet_data(&w, false);
									}
									Err(e) => {
										error!("message tx post error: {:?}", e);
										w.on_tx_error(tx.id, Some(e));
									}
								},
								Err(e) => {
									error!("message tx finalize error: {:?}", e);
									w.task(WalletTask::Cancel(tx.id));
								}
							}
						}
					}
					_ => {}
				};
			}
			w.message_opening.store(false, Ordering::Relaxed);
		}
		WalletTask::CalculateFee(a, _) => {
			// Wait if there are no more fee tasks or handle next input value.
			let calculating = w.fee_calculating.load(Ordering::Relaxed);
			if calculating == 1 {
				async_std::task::sleep(Duration::from_millis(100)).await;
				let calculating = w.fee_calculating.load(Ordering::Relaxed);
				if calculating > 1 {
					w.fee_calculating.store(calculating - 1, Ordering::Relaxed);
					return;
				}
			} else {
				w.fee_calculating.store(calculating - 1, Ordering::Relaxed);
				return;
			}
			// Calculate fee for provided amount.
			if let Ok(fee) = w.calculate_fee(*a) {
				*w.last_fee.write() = Some((*a, fee));
				w.on_task_result(None, &WalletTask::CalculateFee(*a, fee))
			}
			let calculating = w.fee_calculating.load(Ordering::Relaxed);
			w.fee_calculating.store(calculating - 1, Ordering::Relaxed);
		}
		WalletTask::Send(a, r) => {
			w.send_creating.store(true, Ordering::Relaxed);
			if let Ok(s) = w.send(*a, r.clone()) {
				sync_wallet_data(&w, false);
				let tx = w.retrieve_tx_by_id(None, Some(s.id));
				if let Some(tx) = tx {
					// Slatepack send: hand the response slate back to the UI.
					// (Goblin's online payments go over nostr via NostrSend.)
					w.on_task_result(Some(tx), &t);
				}
			}
			w.send_creating.store(false, Ordering::Relaxed);
		}
		WalletTask::Receive(a) => {
			w.invoice_creating.store(true, Ordering::Relaxed);
			if let Ok(s) = w.issue_invoice(*a) {
				sync_wallet_data(&w, false);
				let tx = w.retrieve_tx_by_id(None, Some(s.id));
				if let Some(tx) = tx {
					w.on_task_result(Some(tx), &t);
				}
			}
			w.invoice_creating.store(false, Ordering::Relaxed);
		}
		WalletTask::Finalize(id) => {
			if let Some(s) = w.get_tx_slate(*id) {
				w.on_tx_error(*id, None);
				match w.finalize(&s, *id) {
					Ok(s) => match w.post(&s, Some(*id)) {
						Ok(_) => {
							sync_wallet_data(&w, false);
						}
						Err(e) => {
							error!("tx finalize post error: {:?}", e);
							w.on_tx_error(*id, Some(e));
						}
					},
					Err(e) => {
						error!("tx finalize error: {:?}", e);
						w.task(WalletTask::Cancel(*id));
					}
				}
			} else {
				error!("tx finalize: slate not found");
				w.task(WalletTask::Cancel(*id));
			}
		}
		WalletTask::Post(id) => {
			if let Some(s) = w.get_tx_slate(*id) {
				w.on_tx_error(*id, None);
				// Cleanup broadcasting tx height.
				let tx_height_store = TxHeightStore::new(w.get_config().get_extra_db_path());
				tx_height_store.delete_broadcasting_height(&id.to_string());
				let has_data = {
					let r_data = w.data.read();
					r_data.is_some()
				};
				if has_data {
					let mut w_data = w.data.write();
					for tx in w_data.as_mut().unwrap().txs.as_mut().unwrap() {
						if tx.data.id == *id {
							tx.broadcasting_height = None;
							break;
						}
					}
				}
				// Post transaction.
				match w.post(&s, Some(*id)) {
					Ok(_) => {
						sync_wallet_data(&w, false);
					}
					Err(e) => {
						error!("tx post error: {:?}", e);
						w.on_tx_error(*id, Some(e));
					}
				}
			} else {
				error!("tx post: slate not found");
				w.task(WalletTask::Cancel(*id));
			}
		}
		WalletTask::Cancel(id) => match w.cancel(*id) {
			Ok(_) => {
				sync_wallet_data(&w, false);
			}
			Err(e) => {
				error!("tx cancel error: {:?}", e);
				w.on_tx_error(*id, Some(e));
			}
		},
		WalletTask::VerifyProof(p, _) => {
			w.proof_verifying.store(true, Ordering::Relaxed);
			let res = w.verify_payment_proof(p);
			w.proof_verifying.store(false, Ordering::Relaxed);
			w.on_task_result(None, &WalletTask::VerifyProof(p.clone(), Some(res)));
		}
		WalletTask::Delete(id) => match w.delete_tx(*id) {
			Ok(_) => sync_wallet_data(&w, false),
			Err(e) => {
				error!("tx delete error: {:?}", e);
				w.on_tx_error(*id, Some(e));
			}
		},
		WalletTask::NostrSend(a, receiver, note, relay_hints, proof, order, notify) => {
			let Some(service) = w.nostr_service() else {
				error!("nostr send: service not available");
				return;
			};
			w.send_creating.store(true, Ordering::Relaxed);
			service.set_send_phase(crate::nostr::send_phase::WORKING);
			// Proof-on-request (frozen contract W2): when the payment context
			// carries a `proof=` slatepack address, re-parse it authoritatively
			// here (a second, fail-closed gate after the URI parser's shape check)
			// and thread it as the native `payment_proof_recipient_address`. Absent
			// or unparseable → `None`, a normal proof-less send. This is the ONLY
			// path that sets a proof recipient over Nostr.
			let proof_addr: Option<SlatepackAddress> = proof
				.as_deref()
				.and_then(|p| SlatepackAddress::try_from(p.trim()).ok());
			let proof_mode = proof_addr.is_some();
			match w.send(*a, proof_addr) {
				Ok(s) => {
					sync_wallet_data(&w, false);
					let now = crate::nostr::unix_time();
					// Record intent BEFORE the network dispatch so a crash
					// is recovered by the service reconcile pass. The proof context
					// (order handle + watcher npub + amount) is persisted now so a
					// crash between send and finalize loses nothing.
					service.store.save_tx_meta(&crate::nostr::TxNostrMeta {
						ver: 1,
						slate_id: s.id.to_string(),
						npub: receiver.clone(),
						direction: crate::nostr::NostrTxDirection::Sent,
						note: note.clone().and_then(|n| crate::nostr::sanitize_note(&n)),
						status: crate::nostr::NostrSendStatus::Created,
						sent_event_id: None,
						received_rumor_id: None,
						created_at: now,
						updated_at: now,
						proof_mode,
						proof_order: if proof_mode { order.clone() } else { None },
						proof_notify: if proof_mode { notify.clone() } else { None },
						proof_amount: if proof_mode { Some(*a) } else { None },
						proof_delivered: false,
						receipt_sent: false,
						recipient_pubkey: service.public_key().to_hex(),
					});
					let tx = w.retrieve_tx_by_id(None, Some(s.id));
					w.send_creating.store(false, Ordering::Relaxed);
					if let Some(text) = w.read_slatepack_text(s.id, &s.state) {
						match service
							.send_payment_dm(receiver, &text, note.as_deref(), relay_hints)
							.await
						{
							Ok(event_id) => {
								// Proof-on-request (frozen contract 4.3.1): publish the
								// plain "payment sent" receipt HERE at S1 dispatch, the
								// same moment the payment envelope was accepted by a relay
								// and the wallet UI flips to "sent", not at finalize. This
								// closes the buyer's double-send window: an offline merchant
								// leaves finalize hours away, and until this receipt lands
								// the order page still shows a scannable QR for a payment
								// already made. The encrypted PROOF stays at finalize (it
								// does not exist before then). On failure we leave
								// receipt_sent=false so the reconcile pass retries it.
								let mut receipt_sent = false;
								if crate::nostr::receipt_due_at_dispatch(
									proof_mode,
									order.as_deref(),
								) {
									let ord = order.as_deref().unwrap_or_default();
									match service.publish_receipt_sent(ord, *a).await {
										Ok(()) => receipt_sent = true,
										Err(e) => log::warn!(
											"nostr: dispatch receipt publish failed for {}: {e}",
											s.id
										),
									}
								}
								if let Some(mut meta) = service.store.tx_meta(&s.id.to_string()) {
									meta.status = crate::nostr::NostrSendStatus::AwaitingS2;
									meta.sent_event_id = Some(event_id);
									meta.receipt_sent = receipt_sent;
									meta.updated_at = crate::nostr::unix_time();
									service.store.save_tx_meta(&meta);
								}
								// Record/refresh the contact so someone you PAY shows up
								// under Suggested (sends used to create no contact — only
								// incoming payments did — so a person you paid first never
								// appeared). Create on first pay, then stamp last_paid_at.
								let mut contact =
									service.store.contact(receiver).unwrap_or_else(|| {
										crate::nostr::Contact {
											ver: 1,
											npub: receiver.clone(),
											petname: None,
											nip05: None,
											nip05_verified_at: None,
											relays: relay_hints.clone(),
											nip44_v3: false,
											hue: crate::gui::views::goblin::data::hue_of(receiver)
												as u8,
											unknown: true,
											added_at: crate::nostr::unix_time(),
											last_paid_at: None,
											blocked: false,
										}
									});
								contact.last_paid_at = Some(crate::nostr::unix_time());
								contact.unknown = false;
								service.store.save_contact(&contact);
								// Resolve the recipient's @username so activity + Suggested
								// show their name, not a bare npub.
								service.resolve_contact_identity(receiver);
								service.set_send_phase(crate::nostr::send_phase::SENT);
							}
							Err(e) => {
								error!("nostr send dispatch failed: {e}");
								service.store.update_tx_status(
									&s.id.to_string(),
									crate::nostr::NostrSendStatus::SendFailed,
								);
								if let Some(tx) = &tx {
									w.on_tx_error(
										tx.id,
										Some(Error::GenericError(format!(
											"nostr dispatch failed: {e}"
										))),
									);
								}
								service.set_send_phase(crate::nostr::send_phase::FAILED);
							}
						}
					} else {
						// No slatepack text produced — treat as failure.
						service.set_send_phase(crate::nostr::send_phase::FAILED);
					}
					w.on_task_result(tx, &t);
				}
				Err(e) => {
					error!("nostr send error: {:?}", e);
					w.send_creating.store(false, Ordering::Relaxed);
					service.fail_send(friendly_send_error(&e));
				}
			}
		}
		WalletTask::NostrRequest(a, receiver, note, relay_hints) => {
			let Some(service) = w.nostr_service() else {
				error!("nostr request: service not available");
				return;
			};
			service.set_send_phase(crate::nostr::send_phase::WORKING);
			// Respect the recipient's published opt-out (fail-open: only an
			// explicit "not accepting" blocks; unknown/unreachable still sends).
			if service.accepts_requests(receiver).await == Some(false) {
				service.set_send_phase(crate::nostr::send_phase::REQUEST_BLOCKED);
				return;
			}
			w.invoice_creating.store(true, Ordering::Relaxed);
			// Issue a grin Invoice1 (receiver-built slate, amount baked in). This
			// never spends — it only proposes a payment to the contact.
			match w.issue_invoice(*a) {
				Ok(s) => {
					sync_wallet_data(&w, false);
					let now = crate::nostr::unix_time();
					// Record intent BEFORE dispatch so a crash is recovered by the
					// service reconcile pass (RequestedByUs/AwaitingI2).
					service.store.save_tx_meta(&crate::nostr::TxNostrMeta {
						ver: 1,
						slate_id: s.id.to_string(),
						npub: receiver.clone(),
						direction: crate::nostr::NostrTxDirection::RequestedByUs,
						note: note.clone().and_then(|n| crate::nostr::sanitize_note(&n)),
						status: crate::nostr::NostrSendStatus::Created,
						sent_event_id: None,
						received_rumor_id: None,
						created_at: now,
						updated_at: now,
						// Grin's invoice flow carries no payment proofs (Fact 3), so a
						// request we issued never enters proof mode.
						proof_mode: false,
						proof_order: None,
						proof_notify: None,
						proof_amount: None,
						proof_delivered: false,
						receipt_sent: false,
						recipient_pubkey: service.public_key().to_hex(),
					});
					let tx = w.retrieve_tx_by_id(None, Some(s.id));
					w.invoice_creating.store(false, Ordering::Relaxed);
					if let Some(text) = w.read_slatepack_text(s.id, &s.state) {
						match service
							.send_payment_dm(receiver, &text, note.as_deref(), relay_hints)
							.await
						{
							Ok(event_id) => {
								if let Some(mut meta) = service.store.tx_meta(&s.id.to_string()) {
									meta.status = crate::nostr::NostrSendStatus::AwaitingI2;
									meta.sent_event_id = Some(event_id);
									meta.updated_at = crate::nostr::unix_time();
									service.store.save_tx_meta(&meta);
								}
								if let Some(mut contact) = service.store.contact(receiver) {
									contact.unknown = false;
									service.store.save_contact(&contact);
								}
								service.resolve_contact_identity(receiver);
								service.set_send_phase(crate::nostr::send_phase::SENT);
							}
							Err(e) => {
								error!("nostr request dispatch failed: {e}");
								service.store.update_tx_status(
									&s.id.to_string(),
									crate::nostr::NostrSendStatus::SendFailed,
								);
								service.set_send_phase(crate::nostr::send_phase::FAILED);
							}
						}
					} else {
						service.set_send_phase(crate::nostr::send_phase::FAILED);
					}
					w.on_task_result(tx, &t);
				}
				Err(e) => {
					error!("nostr request error: {:?}", e);
					w.invoice_creating.store(false, Ordering::Relaxed);
					service.set_send_phase(crate::nostr::send_phase::FAILED);
				}
			}
		}
		WalletTask::NostrRepublishProfile => {
			if let Some(service) = w.nostr_service() {
				service.republish_identity().await;
			}
		}
		WalletTask::NostrDeclineRequest(rumor_id) => {
			let Some(service) = w.nostr_service() else {
				return;
			};
			let Some(mut request) = service.store.request(rumor_id) else {
				error!("nostr decline: request not found");
				return;
			};
			// Mark declined locally (idempotent) so the card stays gone, then tell
			// the requester. Requests are messages; payments are final.
			request.status = crate::nostr::RequestStatus::Declined;
			service.store.save_request(&request);
			if let Err(e) = service
				.send_control_dm(&request.npub, &request.slate_id, &[])
				.await
			{
				error!("nostr decline: control dispatch failed: {e}");
			}
		}
		WalletTask::NostrCancelOutgoing(slate_id) => {
			let Some(service) = w.nostr_service() else {
				return;
			};
			let Some(meta) = service.store.tx_meta(slate_id) else {
				error!("nostr cancel: no metadata for slate {slate_id}");
				return;
			};
			if meta.direction != crate::nostr::NostrTxDirection::RequestedByUs {
				error!("nostr cancel: slate {slate_id} is not an outgoing request");
				return;
			}
			// Cancel the underlying grin invoice tx (an issued invoice locks no
			// outputs, but cancelling keeps the wallet ledger tidy).
			if let Some(tx_id) = w.get_data().and_then(|d| d.txs).and_then(|txs| {
				txs.iter()
					.find(|t| {
						t.data.tx_slate_id.map(|u| u.to_string()).as_deref()
							== Some(slate_id.as_str())
					})
					.map(|t| t.data.id)
			}) {
				if let Err(e) = w.cancel(tx_id) {
					error!("nostr cancel: wallet cancel failed: {e}");
				}
			}
			service
				.store
				.update_tx_status(slate_id, crate::nostr::NostrSendStatus::Cancelled);
			if let Err(e) = service.send_control_dm(&meta.npub, slate_id, &[]).await {
				error!("nostr cancel: control dispatch failed: {e}");
			}
			sync_wallet_data(&w, false);
		}
		WalletTask::NostrCancelSend(slate_id) => {
			let Some(service) = w.nostr_service() else {
				return;
			};
			let Some(meta) = service.store.tx_meta(slate_id) else {
				error!("nostr cancel send: no metadata for slate {slate_id}");
				return;
			};
			if meta.direction != crate::nostr::NostrTxDirection::Sent {
				error!("nostr cancel send: slate {slate_id} is not an outgoing send");
				return;
			}
			let Ok(uuid) = uuid::Uuid::parse_str(slate_id) else {
				error!("nostr cancel send: bad slate id {slate_id}");
				return;
			};
			// The critical section is serialized with `nostr_finalize_post` so a
			// concurrent S2 can't post the payment while we reclaim its outputs.
			let mut did_cancel = false;
			{
				let _lock = service.lock_finalize();
				// Re-read status UNDER the lock. If the payment already finalized in
				// the race window, refuse and report it; if it's already cancelled,
				// report success idempotently.
				match service.store.tx_meta(slate_id).map(|m| m.status) {
					Some(crate::nostr::NostrSendStatus::Finalized) => {
						service.set_cancel_notice(crate::nostr::CancelOutcome::AlreadyCompleted);
						return;
					}
					Some(crate::nostr::NostrSendStatus::Cancelled) => {
						service.set_cancel_notice(crate::nostr::CancelOutcome::Cancelled);
						return;
					}
					_ => {}
				}
				// Authoritative tx lookup (not the paginated display cache). If it's
				// missing we must NOT claim success — nothing was reclaimed.
				let Some(tx) = w.retrieve_tx_by_id(None, Some(uuid)) else {
					error!("nostr cancel send: grin tx not found for slate {slate_id}");
					service.set_cancel_notice(crate::nostr::CancelOutcome::AlreadyCompleted);
					return;
				};
				if tx.confirmed {
					service.set_cancel_notice(crate::nostr::CancelOutcome::AlreadyCompleted);
					return;
				}
				if matches!(
					tx.tx_type,
					TxLogEntryType::TxSentCancelled | TxLogEntryType::TxReceivedCancelled
				) {
					// Already cancelled at the grin layer — just reconcile the meta.
					service
						.store
						.update_tx_status(slate_id, crate::nostr::NostrSendStatus::Cancelled);
					service.set_cancel_notice(crate::nostr::CancelOutcome::Cancelled);
				} else {
					// Mark the meta cancelled FIRST so any S2 still at the decide()
					// stage is dropped, THEN cancel the grin tx to free the outputs.
					service
						.store
						.update_tx_status(slate_id, crate::nostr::NostrSendStatus::Cancelled);
					if let Err(e) = w.cancel(tx.id) {
						error!("nostr cancel send: wallet cancel failed: {e}");
					}
					service.set_cancel_notice(crate::nostr::CancelOutcome::Cancelled);
					did_cancel = true;
				}
			}
			sync_wallet_data(&w, false);
			// Best-effort void so a recipient who catches up later drops the dead
			// slate. They're likely offline (that's why the payment stalled), so a
			// failure here is expected and harmless — the local reclaim stands.
			if did_cancel {
				if let Err(e) = service.send_control_dm(&meta.npub, slate_id, &[]).await {
					info!("nostr cancel send: void dispatch failed (recipient offline?): {e}");
				}
			}
		}
		WalletTask::NostrResend(id) => {
			let Some(service) = w.nostr_service() else {
				return;
			};
			if let Some(s) = w.get_tx_slate(*id) {
				let slate_id = s.id.to_string();
				if let Some(meta) = service.store.tx_meta(&slate_id) {
					if let Some(text) = w.read_slatepack_text(s.id, &s.state) {
						match service
							.send_payment_dm(&meta.npub, &text, meta.note.as_deref(), &[])
							.await
						{
							Ok(event_id) => {
								let mut meta = meta.clone();
								meta.sent_event_id = Some(event_id);
								if meta.status == crate::nostr::NostrSendStatus::SendFailed
									|| meta.status == crate::nostr::NostrSendStatus::Created
								{
									meta.status = match meta.direction {
										crate::nostr::NostrTxDirection::RequestedByUs => {
											crate::nostr::NostrSendStatus::AwaitingI2
										}
										_ => crate::nostr::NostrSendStatus::AwaitingS2,
									};
								}
								meta.updated_at = crate::nostr::unix_time();
								service.store.save_tx_meta(&meta);
							}
							Err(e) => error!("nostr resend failed: {e}"),
						}
					}
				}
			}
		}
		WalletTask::NostrPayRequest(request_id) => {
			let Some(service) = w.nostr_service() else {
				return;
			};
			let Some(mut request) = service.store.request(request_id) else {
				error!("nostr pay: request not found");
				return;
			};
			if request.status != crate::nostr::RequestStatus::Pending {
				error!("nostr pay: request is not pending");
				return;
			}
			// Drive the approve button's busy/failed state so it doesn't stay
			// greyed forever if the pay can't go through.
			service.set_send_phase(crate::nostr::send_phase::WORKING);
			// Re-parse and re-validate the stored slatepack: it must still be
			// an Invoice1 (or a Standard1 surfaced under a strict policy).
			match w.parse_slatepack(&request.slatepack) {
				Ok((s, _)) if s.state == SlateState::Invoice1 => match w.nostr_pay(&s) {
					Ok((reply, text)) => {
						let now = crate::nostr::unix_time();
						service.store.save_tx_meta(&crate::nostr::TxNostrMeta {
							ver: 1,
							slate_id: reply.id.to_string(),
							npub: request.npub.clone(),
							direction: crate::nostr::NostrTxDirection::RequestedOfUs,
							note: request.note.clone(),
							status: crate::nostr::NostrSendStatus::ReceivedNoReply,
							sent_event_id: None,
							received_rumor_id: Some(request.rumor_id.clone()),
							created_at: now,
							updated_at: now,
							proof_mode: false,
							proof_order: None,
							proof_notify: None,
							proof_amount: None,
							proof_delivered: false,
							receipt_sent: false,
							recipient_pubkey: service.public_key().to_hex(),
						});
						match service
							.send_payment_dm(&request.npub, &text, None, &[])
							.await
						{
							Ok(event_id) => {
								if let Some(mut meta) = service.store.tx_meta(&reply.id.to_string())
								{
									meta.status =
										crate::nostr::NostrSendStatus::PaidAwaitingFinalize;
									meta.sent_event_id = Some(event_id);
									meta.updated_at = crate::nostr::unix_time();
									service.store.save_tx_meta(&meta);
								}
							}
							Err(e) => error!("nostr pay reply dispatch failed: {e}"),
						}
						request.status = crate::nostr::RequestStatus::Approved;
						service.store.save_request(&request);
						service.set_send_phase(crate::nostr::send_phase::SENT);
						sync_wallet_data(&w, false);
					}
					Err(e) => {
						error!("nostr pay failed: {:?}", e);
						service.fail_send(friendly_send_error(&e));
					}
				},
				Ok((s, _)) if s.state == SlateState::Standard1 => {
					// Incoming payment surfaced under Contacts/Ask policy:
					// receiving is safe, process like an auto-receive.
					match w.nostr_receive(&s) {
						Ok((reply, text)) => {
							let now = crate::nostr::unix_time();
							service.store.save_tx_meta(&crate::nostr::TxNostrMeta {
								ver: 1,
								slate_id: reply.id.to_string(),
								npub: request.npub.clone(),
								direction: crate::nostr::NostrTxDirection::Received,
								note: request.note.clone(),
								status: crate::nostr::NostrSendStatus::ReceivedNoReply,
								sent_event_id: None,
								received_rumor_id: Some(request.rumor_id.clone()),
								created_at: now,
								updated_at: now,
								proof_mode: false,
								proof_order: None,
								proof_notify: None,
								proof_amount: None,
								proof_delivered: false,
								receipt_sent: false,
								recipient_pubkey: service.public_key().to_hex(),
							});
							match service
								.send_payment_dm(&request.npub, &text, None, &[])
								.await
							{
								Ok(event_id) => {
									if let Some(mut meta) =
										service.store.tx_meta(&reply.id.to_string())
									{
										meta.status = crate::nostr::NostrSendStatus::RepliedS2;
										meta.sent_event_id = Some(event_id);
										meta.updated_at = crate::nostr::unix_time();
										service.store.save_tx_meta(&meta);
									}
								}
								Err(e) => error!("nostr accept reply dispatch failed: {e}"),
							}
							request.status = crate::nostr::RequestStatus::Approved;
							service.store.save_request(&request);
							service.set_send_phase(crate::nostr::send_phase::SENT);
							sync_wallet_data(&w, false);
						}
						Err(e) => {
							error!("nostr accept failed: {:?}", e);
							service.fail_send(friendly_send_error(&e));
						}
					}
				}
				_ => {
					error!("nostr pay: stored slatepack is not payable");
					service.fail_send("This request is no longer payable.".to_string());
					request.status = crate::nostr::RequestStatus::Expired;
					service.store.save_request(&request);
				}
			}
		}
	};
}

/// Refresh [`WalletData`] from local base or node.
fn sync_wallet_data(wallet: &Wallet, from_node: bool) {
	// Update info sync progress at separate thread.
	let wallet_info = wallet.clone();
	let (info_tx, info_rx) = mpsc::channel::<StatusMessage>();
	thread::spawn(move || {
		while let Ok(m) = info_rx.recv() {
			match m {
				StatusMessage::UpdatingOutputs(_) => {}
				StatusMessage::UpdatingTransactions(_) => {}
				StatusMessage::FullScanWarn(_) => {}
				StatusMessage::Scanning(_, progress) => {
					wallet_info
						.info_sync_progress
						.store(progress, Ordering::Relaxed);
				}
				StatusMessage::ScanningComplete(_) => {
					wallet_info.info_sync_progress.store(100, Ordering::Relaxed);
				}
				StatusMessage::UpdateWarning(_) => {}
			}
		}
	});

	let config = wallet.get_config();

	// Retrieve wallet info.
	let r_inst = wallet.instance.as_ref().read();
	if r_inst.is_some() {
		let instance = r_inst.clone().unwrap();
		if let Ok((_, info)) = retrieve_summary_info(
			instance.clone(),
			wallet.keychain_mask().as_ref(),
			&Some(info_tx),
			from_node,
			config.min_confirmations,
		) {
			// Do not retrieve txs if wallet was closed or its first sync.
			if !wallet.is_open()
				|| wallet.is_closing()
				|| (!from_node && info.last_confirmed_height == 0)
			{
				return;
			}

			// Setup accounts data.
			let last_height = info.last_confirmed_height;
			let spendable = if wallet.get_data().is_none() {
				None
			} else {
				Some(info.amount_currently_spendable)
			};
			update_accounts(wallet, last_height, spendable);

			if wallet.info_sync_progress() == 100 || !from_node {
				// Transactions limit setup.
				let txs_limit = {
					let r_data = wallet.data.read();
					if r_data.is_some() {
						let data = r_data.as_ref().unwrap();
						data.txs_limit
					} else {
						WalletData::TXS_LIMIT
					}
				};
				// Update wallet info.
				{
					let mut w_data = wallet.data.write();
					if w_data.is_some() {
						w_data.as_mut().unwrap().info = info;
					} else {
						*w_data = Some(WalletData {
							info,
							txs: None,
							txs_limit,
						});
					}
				}
				// Update wallet transactions.
				if update_txs(wallet, txs_limit).is_ok() {
					if !wallet.from_node.load(Ordering::Relaxed) {
						wallet.from_node.store(from_node, Ordering::Relaxed);
					}
					wallet.reset_sync_attempts();
					return;
				}
			}
		}
	}

	// Reset progress.
	wallet.info_sync_progress.store(0, Ordering::Relaxed);

	// Exit if wallet was closed or closing.
	if !wallet.is_open() || wallet.is_closing() {
		return;
	}

	// Set an error if data was not loaded after opening or increment attempts count.
	if wallet.get_data().is_none() {
		wallet.set_sync_error(true);
	} else {
		wallet.increment_sync_attempts();
	}

	// Set an error if maximum number of attempts was reached.
	if wallet.get_sync_attempts() >= SYNC_ATTEMPTS {
		wallet.reset_sync_attempts();
		wallet.set_sync_error(true);
	}
}

/// Update wallet transactions.
fn update_txs(wallet: &Wallet, mut txs_limit: u32) -> Result<(), Error> {
	let _ = wallet.clear_empty_txs();
	let txs = wallet.retrieve_txs(txs_limit)?;

	// Exit if wallet was closed.
	if !wallet.is_open() || wallet.is_closing() {
		return Err(Error::GenericError("Wallet is not open".to_string()));
	}

	// Update limit with actual length.
	let txs_size = txs.len() as u32;
	let filter_size = txs.len() as u32;

	if txs_size > filter_size && txs_limit >= filter_size {
		txs_limit = txs_limit - (txs_size - filter_size);
	}

	// Update existing tx list.
	let tx_height_store = TxHeightStore::new(wallet.get_config().get_extra_db_path());
	let data = wallet.get_data().unwrap();
	let data_txs = data.txs.unwrap_or(vec![]);
	let mut new_txs: Vec<WalletTx> = vec![];
	for tx in &txs {
		let mut height: Option<u64> = None;
		let mut broadcasting_height: Option<u64> = None;
		let mut action: Option<WalletTxAction> = None;
		let mut action_error: Option<Error> = None;
		let mut proof: Option<PaymentProof> = None;
		for t in &data_txs {
			if t.data.id == tx.id {
				action = t.action.clone();
				action_error = t.action_error.clone();
				height = t.height;
				broadcasting_height = t.broadcasting_height;
				proof = t.proof.clone();
				break;
			}
		}
		let mut new = WalletTx::new(
			tx.clone(),
			proof.clone(),
			wallet,
			height,
			broadcasting_height,
			action,
			action_error,
		);
		// Payment proof setup.
		if proof.is_none()
			&& tx.payment_proof.is_some()
			&& tx
				.payment_proof
				.as_ref()
				.unwrap()
				.receiver_signature
				.is_some()
			&& tx
				.payment_proof
				.as_ref()
				.unwrap()
				.sender_signature
				.is_some()
			&& tx.kernel_excess.is_some()
		{
			if let Ok(p) = wallet.get_payment_proof(Some(tx.id), tx.tx_slate_id) {
				proof = p.clone();
				new.proof = proof;
			}
		}
		// Initial tx heights setup.
		if let Some(slate_id) = tx.tx_slate_id {
			let id = slate_id.to_string();
			if height.is_none() && tx.confirmed {
				height = if let Some(height) = tx_height_store.read_tx_height(&id) {
					Some(height)
				} else {
					tx_height_store.delete_broadcasting_height(&id);
					let h = wallet.tx_height(&new)?;
					if let Some(h) = h {
						tx_height_store.write_tx_height(&id, h);
					}
					h
				};
				new.height = height;
			} else if broadcasting_height.is_none() && new.broadcasting() {
				let br_height = tx_height_store.read_broadcasting_height(&id);
				broadcasting_height = if br_height.is_none() || br_height.unwrap() == 0 {
					let h = data.info.last_confirmed_height;
					tx_height_store.write_broadcasting_height(&id, h);
					Some(h)
				} else {
					Some(br_height.unwrap())
				};
				new.broadcasting_height = broadcasting_height;
			}
		}
		if !new.deleting() {
			new_txs.push(new);
		}
	}
	// Update wallet txs.
	let mut w_data = wallet.data.write();
	if w_data.is_some() {
		w_data.as_mut().unwrap().txs_limit = txs_limit;
		w_data.as_mut().unwrap().txs = Some(new_txs);
	}
	Ok(())
}

/// Start Foreign API server to receive txs over transport and mining rewards.
fn start_api_server(wallet: &Wallet) -> Result<(ApiServer, u16), Error> {
	let host = "127.0.0.1";
	let port = wallet
		.get_config()
		.api_port
		.unwrap_or(rand::rng().random_range(10000..30000));
	let free_port = (port..)
		.find(|port| {
			return match TcpListener::bind((host, port.to_owned())) {
				Ok(_) => {
					let node_p2p_port = NodeConfig::get_p2p_port();
					let node_api_port = NodeConfig::get_api_ip_port().1;
					let free =
						port.to_string() != node_p2p_port && port.to_string() != node_api_port;
					if free {
						let mut config = wallet.config.write();
						config.api_port = Some(*port);
						config.save();
					}
					free
				}
				Err(_) => false,
			};
		})
		.unwrap();

	// Setup API server address.
	let api_addr = format!("{}:{}", host, free_port);

	// Start Foreign API server thread.
	let r_inst = wallet.instance.as_ref().read();
	let instance = r_inst.clone().unwrap();
	let keychain_mask = wallet.keychain_mask();
	let api_handler_v2 = ForeignAPIHandlerV2::new(
		instance,
		Arc::new(Mutex::new(keychain_mask)),
		false,
		Mutex::new(None),
	);
	let mut router = Router::new();
	router
		.add_route("/v2/foreign", Arc::new(api_handler_v2))
		.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;

	let api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>) =
		Box::leak(Box::new(oneshot::channel::<()>()));

	let mut apis = ApiServer::new();
	let socket_addr: SocketAddr = api_addr.parse().unwrap();
	let _ = apis
		.start(socket_addr, router, None, api_chan)
		.map_err(|_| Error::GenericError("API thread failed to start".to_string()))?;
	Ok((apis, free_port))
}

/// Update wallet accounts data.
fn update_accounts(wallet: &Wallet, height: u64, spendable: Option<u64>) {
	let current_account = wallet.get_config().account;
	if let Some(amount) = spendable {
		let mut accounts = wallet.accounts.read().clone();
		for a in accounts.iter_mut() {
			if a.label == current_account {
				a.spendable_amount = amount;
			}
		}
		// Save accounts data.
		let mut w_data = wallet.accounts.write();
		*w_data = accounts;
	} else {
		let r_inst = wallet.instance.as_ref().read();
		let instance = r_inst.clone().unwrap();
		let mut api = Owner::new(instance, None);
		let key_mask = wallet.keychain_mask();
		let _ = controller::owner_single_use(None, key_mask.as_ref(), Some(&mut api), |api, m| {
			let mut accounts = vec![];
			for a in api.accounts(m)? {
				api.set_active_account(m, a.label.as_str())?;
				// Calculate account balance.
				if let Some(spendable_amount) = wallet.account_balance(height, api, m) {
					accounts.push(WalletAccount {
						spendable_amount,
						label: a.label,
						path: a.path.to_bip_32_string(),
					});
				}
			}
			accounts.sort_by_key(|w| w.label != current_account);

			// Save accounts data.
			let mut w_data = wallet.accounts.write();
			*w_data = accounts;

			// Set current active account from config.
			api.set_active_account(m, current_account.as_str())?;

			Ok(())
		});
	}
}

/// Scan wallet's outputs, repairing and restoring missing outputs if required.
fn repair_wallet(wallet: &Wallet) {
	let (info_tx, info_rx) = mpsc::channel::<StatusMessage>();
	// Update scan progress at separate thread.
	let wallet_scan = wallet.clone();
	thread::spawn(move || {
		while let Ok(m) = info_rx.recv() {
			match m {
				StatusMessage::UpdatingOutputs(_) => {}
				StatusMessage::UpdatingTransactions(_) => {}
				StatusMessage::FullScanWarn(_) => {}
				StatusMessage::Scanning(_, progress) => {
					wallet_scan
						.repair_progress
						.store(progress, Ordering::Relaxed);
				}
				StatusMessage::ScanningComplete(_) => {
					wallet_scan.repair_progress.store(100, Ordering::Relaxed);
				}
				StatusMessage::UpdateWarning(_) => {}
			}
		}
	});

	let r_inst = wallet.instance.as_ref().read();
	let instance = r_inst.clone().unwrap();
	let api = Owner::new(instance, Some(info_tx));
	// Start wallet scanning.
	match api.scan(wallet.keychain_mask().as_ref(), Some(1), false) {
		Ok(()) => {
			// Set sync error if scanning was not complete and wallet is open.
			if wallet.is_open() && wallet.repair_progress.load(Ordering::Relaxed) != 100 {
				wallet.set_sync_error(true);
			} else {
				wallet.repair_needed.store(false, Ordering::Relaxed);
			}
		}
		Err(_) => {
			// Set sync error if wallet is open.
			if wallet.is_open() {
				wallet.set_sync_error(true);
			} else {
				wallet.repair_needed.store(false, Ordering::Relaxed);
			}
		}
	}

	// Reset repair progress.
	wallet.repair_progress.store(0, Ordering::Relaxed);
}
