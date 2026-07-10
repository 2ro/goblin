// Copyright 2026 The Goblin Developers
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

//! Nostr payment-messaging subsystem: contacts are nostr users, slatepacks
//! travel as NIP-17 private DMs (NIP-44 encrypted, NIP-59 gift-wrapped) over
//! relays reached through the embedded Tor client.

mod types;
pub use types::*;

pub mod config;
pub use config::{AcceptPolicy, NostrConfig};

pub mod pool;
pub mod relays;

mod store;
pub use store::NostrStore;

mod identity;
pub use identity::{
	FullBackup, IdentitySource, NostrIdentity, build_full_backup, is_full_backup, open_full_backup,
};

pub mod identities;
pub use identities::{HeldError, HeldIdentities, MAX_IDENTITIES, catchup_since};

pub mod protocol;
pub use protocol::*;

pub mod wrapv3;

pub mod ingest;
pub use ingest::*;

mod client;
pub use client::{HeldIdentityKeys, NostrProfile, NostrService, TransportStatus, send_phase};

pub mod avatar;
pub mod nip05;

pub mod authuri;
pub mod loginuri;
pub mod payuri;
pub mod session;
pub mod trusturi;
