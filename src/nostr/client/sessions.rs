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

//! Authorize-Sessions surface on NostrService: add/announce/resume/end
//! sessions, session summaries and money-prompt answering.

use super::*;

impl NostrService {
	/// Register a freshly granted session and wake the loop to subscribe its
	/// channel and publish `session-open`.
	pub fn add_session(&self, session: crate::nostr::session::Session) {
		self.sessions.write().push(session);
		self.sessions_dirty.store(true, Ordering::SeqCst);
	}

	/// True once the `session-open` announce for the session with this wallet
	/// channel pubkey (hex) was actually handed to a relay connection. The trust
	/// GUI polls this before taking the return-to-caller decision, so the app
	/// never backgrounds with the announce still pending in the service.
	pub fn session_announced(&self, wallet_channel_pk_hex: &str) -> bool {
		self.announced_ok.read().contains(wallet_channel_pk_hex)
	}

	/// True when at least one session is live (for the Trusted Sites badge/list).
	pub fn has_sessions(&self) -> bool {
		!self.sessions.read().is_empty()
	}

	/// Read-only snapshots for the Trusted Sites list, newest last.
	pub fn session_summaries(&self) -> Vec<crate::nostr::session::SessionSummary> {
		let now = unix_time() as u64;
		self.sessions
			.read()
			.iter()
			.map(|s| s.summary(now))
			.collect()
	}

	/// End (revoke) the session for `domain`: mark it ended, send the courtesy
	/// `session-end`, and drop it. Immediate and unilateral.
	pub fn end_session(&self, domain: &str) {
		let now = unix_time() as u64;
		let mut end_event = None;
		{
			let mut sessions = self.sessions.write();
			if let Some(s) = sessions.iter_mut().find(|s| s.domain == domain) {
				s.end();
				end_event = s.session_end_event(now, "revoked").ok();
			}
			sessions.retain(|s| s.domain != domain);
		}
		self.sessions_dirty.store(true, Ordering::SeqCst);
		// Best-effort courtesy notice to the site; teardown already happened.
		if let Some(ev) = end_event {
			self.publish_event_best_effort(ev);
		}
	}

	/// Resume a paused session (the user tapped "resume" in Trusted Sites).
	pub fn resume_session(&self, domain: &str) {
		let now = unix_time() as u64;
		if let Some(s) = self
			.sessions
			.write()
			.iter_mut()
			.find(|s| s.domain == domain)
		{
			s.resume(now);
		}
	}

	/// The front money-tier request awaiting the user, if any (GUI polls this to
	/// raise its per-action password prompt).
	pub fn peek_money_prompt(&self) -> Option<crate::nostr::session::PendingMoney> {
		self.money_pending.lock().first().cloned()
	}

	/// Record the user's answer to a money prompt: remove it from the display
	/// queue and hand the full request to the loop, which signs (or declines) and
	/// publishes the result on the channel.
	pub fn answer_money_prompt(&self, req_id: &str, approved: bool) {
		let answered = {
			let mut pending = self.money_pending.lock();
			let idx = pending.iter().position(|p| p.id() == req_id);
			idx.map(|i| pending.remove(i))
		};
		if let Some(p) = answered {
			self.money_answers.lock().push((p, approved));
		}
	}

	/// Take (and clear) the "signing a lot" notice, if any.
	pub fn take_session_notice(&self) -> Option<String> {
		self.session_notice.write().take()
	}
}
