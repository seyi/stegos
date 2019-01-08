//! pBFT Consensus - States and Transitions.

//
// Copyright (c) 2018 Stegos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::error::*;
use crate::message::*;
use crate::multisignature::*;
use bitvector::BitVector;
use log::*;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::time::{Duration, Instant};
use stegos_config::ConfigConsensus;
use stegos_crypto::hash::{Hash, Hashable};
use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::SecretKey as SecureSecretKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;

/// Infinity timeout.
const INFINITY_TIMEOUT: u64 = 60u64 * 60 * 24 * 365 * 100;

#[derive(Debug, PartialEq, Eq)]
enum ConsensusState {
    /// Propose state.
    Propose,
    /// Prevote state.
    Prevote,
    /// Precommit state.
    Precommit,
    /// Commit state.
    Commit,
    /// Failure state.
    Failure,
}

impl ConsensusState {
    /// Enum to string.
    fn name(&self) -> &'static str {
        match *self {
            ConsensusState::Propose => "Propose",
            ConsensusState::Prevote => "Prevote",
            ConsensusState::Precommit => "Precommit",
            ConsensusState::Commit => "Commit",
            ConsensusState::Failure => "Failure",
        }
    }
}

/// Consensus State.
pub struct Consensus<Request, Proof> {
    /// Configuration.
    cfg: ConfigConsensus,
    /// Public key of current node.
    skey: SecureSecretKey,
    /// Public key of current node.
    pkey: SecurePublicKey,
    /// Public key of leader.
    leader: SecurePublicKey,
    /// Public keys and stakes of participating nodes.
    validators: BTreeMap<SecurePublicKey, i64>,
    /// Consensus State.
    state: ConsensusState,
    /// Current round.
    round: u64,
    /// Deadline for the current state.
    deadline: Instant,
    /// Proposed request.
    request: Option<Request>,
    /// A proof need to validate request.
    proof: Option<Proof>,
    /// Collected PrevoteAccepts.
    prevote_accepts: BTreeMap<SecurePublicKey, SecureSignature>,
    /// Collected PrevoteRejects.
    prevote_rejects: BTreeMap<SecurePublicKey, SecureSignature>,
    /// Collected PrecommitAccepts.
    precommit_accepts: BTreeMap<SecurePublicKey, SecureSignature>,
    /// Collected PrecommitRejects.
    precommit_rejects: BTreeMap<SecurePublicKey, SecureSignature>,
    /// Pending messages.
    inbox: Vec<ConsensusMessage<Request, Proof>>,
    /// Outgoing messages.
    pub outbox: Vec<ConsensusMessage<Request, Proof>>,
}

impl<Request: Hashable + Clone + Debug, Proof: Hashable + Clone + Debug> Consensus<Request, Proof> {
    ///
    /// Start a new consensus protocol.
    ///
    pub fn new(
        cfg: ConfigConsensus,
        round: u64,
        skey: SecureSecretKey,
        pkey: SecurePublicKey,
        leader: SecurePublicKey,
        validators: BTreeMap<SecurePublicKey, i64>,
    ) -> Self {
        debug!("=> Propose");
        let state = ConsensusState::Propose;
        let deadline = Instant::now() + Duration::new(cfg.propose_timeout, 0);
        let prevote_accepts: BTreeMap<SecurePublicKey, SecureSignature> = BTreeMap::new();
        let prevote_rejects: BTreeMap<SecurePublicKey, SecureSignature> = BTreeMap::new();
        let precommit_accepts: BTreeMap<SecurePublicKey, SecureSignature> = BTreeMap::new();
        let precommit_rejects: BTreeMap<SecurePublicKey, SecureSignature> = BTreeMap::new();
        let request = None;
        let proof = None;
        let inbox: Vec<ConsensusMessage<Request, Proof>> = Vec::new();
        let outbox: Vec<ConsensusMessage<Request, Proof>> = Vec::new();
        Consensus {
            cfg,
            skey,
            pkey,
            leader,
            validators,
            state,
            round,
            deadline,
            request,
            proof,
            prevote_accepts,
            prevote_rejects,
            precommit_accepts,
            precommit_rejects,
            inbox,
            outbox,
        }
    }

    ///
    /// Reset current state and move to the next round.
    ///
    pub fn next_round(&mut self) {
        debug!("=> Propose");
        self.round = self.round + 1;
        self.state = ConsensusState::Propose;
        self.deadline = Instant::now() + Duration::new(self.cfg.propose_timeout, 0);
        self.prevote_accepts.clear();
        self.prevote_rejects.clear();
        self.precommit_accepts.clear();
        self.precommit_rejects.clear();
        self.request = None;
        self.proof = None;
        self.outbox.clear();
        self.process_inbox();
    }

    ///
    /// Propose a new request with a proof.
    ///
    pub fn propose(&mut self, request: Request, proof: Proof) {
        assert!(self.is_leader(), "only leader can propose");
        assert_eq!(self.state, ConsensusState::Propose, "valid state");
        let request_hash = Hash::digest(&request);
        debug!("Propose: request={}", &request_hash);
        let body = ConsensusMessageBody::Proposal { request, proof };
        let msg = ConsensusMessage::new(self.round, request_hash, &self.skey, &self.pkey, body);
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// PrevoteAccept proposal.
    ///
    pub fn prevote_accept(&mut self, request_hash: Hash) {
        debug!("PrevoteAccept: request={}", &request_hash);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        assert!(!self.prevote_accepts.contains_key(&self.pkey));
        assert!(!self.prevote_rejects.contains_key(&self.pkey));
        assert!(!self.precommit_accepts.contains_key(&self.pkey));
        assert!(!self.precommit_rejects.contains_key(&self.pkey));
        let body = ConsensusMessageBody::PrevoteAccept {};
        let msg = ConsensusMessage::new(self.round, request_hash, &self.skey, &self.pkey, body);
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// PrevoteReject proposal.
    ///
    pub fn prevote_reject(&mut self, request_hash: Hash) {
        debug!("PrevoteReject: request={}", &request_hash);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        assert!(!self.prevote_accepts.contains_key(&self.pkey));
        assert!(!self.prevote_rejects.contains_key(&self.pkey));
        assert!(!self.precommit_accepts.contains_key(&self.pkey));
        assert!(!self.precommit_rejects.contains_key(&self.pkey));
        let body = ConsensusMessageBody::PrevoteReject {};
        let msg = ConsensusMessage::new(self.round, request_hash, &self.skey, &self.pkey, body);
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// PrecommitAccept proposal.
    ///
    fn precommit_accept(&mut self, request_hash: Hash) {
        debug!("PrecommitAccept: request={}", &request_hash);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        assert!(!self.prevote_rejects.contains_key(&self.pkey));
        assert!(!self.precommit_accepts.contains_key(&self.pkey));
        assert!(!self.precommit_rejects.contains_key(&self.pkey));
        let request_hash_sig = secure_sign_hash(&request_hash, &self.skey);
        let body = ConsensusMessageBody::PrecommitAccept { request_hash_sig };
        let msg = ConsensusMessage::new(self.round, request_hash, &self.skey, &self.pkey, body);
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// PrecommitReject proposal.
    ///
    fn precommit_reject(&mut self, request_hash: Hash) {
        debug!("PrecommitReject: request={}", &request_hash);
        let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
        assert_eq!(&request_hash, &expected_request_hash);
        assert!(!self.precommit_accepts.contains_key(&self.pkey));
        assert!(!self.precommit_rejects.contains_key(&self.pkey));
        let body = ConsensusMessageBody::PrecommitReject {};
        let msg = ConsensusMessage::new(self.round, request_hash, &self.skey, &self.pkey, body);
        self.outbox.push(msg.clone());
        self.feed_message(msg).expect("message is valid");
    }

    ///
    /// Feed incoming message into the state machine.
    ///
    pub fn feed_message(
        &mut self,
        msg: ConsensusMessage<Request, Proof>,
    ) -> Result<(), ConsensusError> {
        trace!(
            "Message: state={:?}, round={:?}, msg={:?}",
            self.state.name(),
            self.round,
            &msg
        );

        // Discard all messages in Failure state.
        if self.state == ConsensusState::Failure {
            return Ok(());
        }

        // Check sender.
        if !self.validators.contains_key(&msg.pkey) {
            debug!(
                "Message from an unknown peer: state={:?}, round={:?}, msg={:?}",
                self.state.name(),
                self.round,
                &msg
            );
            return Err(ConsensusError::UnknownMessagePeer(msg.pkey));
        }

        // Validate signature and content.
        msg.validate()?;

        // Check round.
        if msg.round < self.round {
            debug!(
                "Message from the past: state={:?}, round={:?}, msg={:?}",
                self.state.name(),
                self.round,
                &msg
            );
            // Silently discard this message.
            return Ok(());
        } else if msg.round == self.round + 1 {
            debug!(
                "Message from the future: state={:?}, round={:?}, msg={:?}",
                self.state.name(),
                self.round,
                &msg
            );
            // Queue the message for future processing.
            self.inbox.push(msg);
            return Ok(());
        } else if self.round != msg.round {
            warn!(
                "Out of order message: state={:?}, round={:?}, msg={:?}",
                self.state.name(),
                self.round,
                &msg
            );
            return Err(ConsensusError::InvalidMessageRound(self.round, msg.round));
        }

        // Check request_hash.
        if self.state != ConsensusState::Propose {
            let expected_request_hash = Hash::digest(self.request.as_ref().unwrap());
            if expected_request_hash != msg.request_hash {
                error!(
                    "Message with invalid request_hash: state={:?}, round={:?}, msg={:?}",
                    self.state.name(),
                    self.round,
                    &msg
                );
                return Err(ConsensusError::InvalidRequestHash(
                    expected_request_hash,
                    msg.request_hash,
                    msg.pkey,
                ));
            }
        }

        if self.state == ConsensusState::Commit {
            debug!(
                "A late message: state={:?}, round={:?}, msg={:?}",
                self.state.name(),
                self.round,
                &msg
            );
            // Silently discard this message.
            return Ok(());
        }

        // Check valid transitions.
        match (&msg.body, &self.state) {
            // Obvious cases.
            (ConsensusMessageBody::Proposal { .. }, ConsensusState::Propose) => {}
            (ConsensusMessageBody::PrevoteAccept { .. }, ConsensusState::Prevote) => {}
            (ConsensusMessageBody::PrevoteReject { .. }, ConsensusState::Prevote) => {}
            (ConsensusMessageBody::PrecommitAccept { .. }, ConsensusState::Precommit) => {}
            (ConsensusMessageBody::PrecommitReject { .. }, ConsensusState::Precommit) => {}

            // Early pre-commits received in Prevote state.
            (ConsensusMessageBody::PrecommitAccept { .. }, ConsensusState::Prevote) => {}
            (ConsensusMessageBody::PrecommitReject { .. }, ConsensusState::Prevote) => {}

            // Late pre-votes received in Precommit state.
            (ConsensusMessageBody::PrevoteAccept { .. }, ConsensusState::Precommit) => {}
            (ConsensusMessageBody::PrevoteReject { .. }, ConsensusState::Precommit) => {}

            // Late pre-commits received in Commit state.
            (ConsensusMessageBody::PrecommitAccept { .. }, ConsensusState::Commit) => {}
            (ConsensusMessageBody::PrecommitReject { .. }, ConsensusState::Commit) => {}

            // Early Prevotes and Precommits in Propose state
            (_, ConsensusState::Propose) => {
                self.inbox.push(msg);
                return Ok(());
            }

            // Messages in Failure state.
            (_, ConsensusState::Failure) => return Ok(()),

            // Unsupported cases.
            (_, _) => {
                return Err(ConsensusError::InvalidMessage(
                    self.state.name(),
                    msg.name(),
                ));
            }
        }

        // Process received message.
        match msg.body {
            ConsensusMessageBody::Proposal { request, proof } => {
                assert_eq!(self.state, ConsensusState::Propose);

                // Check that message has been sent by leader.
                if msg.pkey != self.leader {
                    error!(
                        "Proposal from non-leader: state={:?}, round={:?}, leader={:?}, from={:?}",
                        self.state.name(),
                        self.round,
                        &self.leader,
                        &msg.pkey
                    );
                    return Err(ConsensusError::ProposalFromNonLeader(
                        msg.request_hash,
                        self.leader.clone(),
                        msg.pkey,
                    ));
                }

                // Check request hash.
                let expected_request_hash = Hash::digest(&request);
                if expected_request_hash != msg.request_hash {
                    return Err(ConsensusError::InvalidRequestHash(
                        expected_request_hash,
                        msg.request_hash,
                        msg.pkey,
                    ));
                }

                // Move to Prevote
                debug!("Propose => Prevote");
                assert!(self.prevote_accepts.is_empty());
                assert!(self.prevote_rejects.is_empty());
                assert!(self.precommit_accepts.is_empty());
                assert!(self.precommit_rejects.is_empty());
                assert!(self.request.is_none());
                assert!(self.proof.is_none());
                self.request = Some(request);
                self.proof = Some(proof);
                self.state = ConsensusState::Prevote;
                self.deadline = Instant::now() + Duration::new(self.cfg.prevote_timeout, 0);
                self.process_inbox();
            }
            ConsensusMessageBody::PrevoteAccept {} => {
                assert_ne!(self.state, ConsensusState::Propose);
                assert_ne!(self.state, ConsensusState::Failure);

                // Check previous vote.
                if self.prevote_rejects.contains_key(&msg.pkey) {
                    error!(
                        "Attempt to change vote: state={:?}, round={:?}, msg={:?}",
                        self.state.name(),
                        self.round,
                        &msg
                    );
                    return Err(ConsensusError::VoteChange(false, msg.pkey, msg.sig));
                }

                // Add vote.
                self.prevote_accepts.insert(msg.pkey, msg.sig);
            }
            ConsensusMessageBody::PrevoteReject {} => {
                assert_ne!(self.state, ConsensusState::Propose);
                assert_ne!(self.state, ConsensusState::Failure);

                // Check previous vote.
                if self.prevote_accepts.contains_key(&msg.pkey) {
                    warn!(
                        "Attempt to change vote: state={:?}, round={:?}, msg={:?}",
                        self.state.name(),
                        self.round,
                        &msg
                    );
                    return Err(ConsensusError::VoteChange(false, msg.pkey, msg.sig));
                }

                // Add vote.
                self.prevote_rejects.insert(msg.pkey, msg.sig);
            }
            ConsensusMessageBody::PrecommitAccept { request_hash_sig } => {
                assert_ne!(self.state, ConsensusState::Propose);
                assert_ne!(self.state, ConsensusState::Failure);

                // Check previous vote.
                if self.prevote_rejects.contains_key(&msg.pkey)
                    || self.precommit_rejects.contains_key(&msg.pkey)
                {
                    warn!(
                        "Attempt to change vote: state={:?}, round={:?}, msg={:?}",
                        self.state.name(),
                        self.round,
                        &msg
                    );
                    return Err(ConsensusError::VoteChange(false, msg.pkey, msg.sig));
                }

                // Add vote.
                self.precommit_accepts.insert(msg.pkey, request_hash_sig);
            }
            ConsensusMessageBody::PrecommitReject {} => {
                assert_ne!(self.state, ConsensusState::Propose);
                assert_ne!(self.state, ConsensusState::Failure);

                // Check previous vote.
                if self.precommit_accepts.contains_key(&msg.pkey) {
                    warn!(
                        "Attempt to change vote: state={:?}, round={:?}, msg={:?}",
                        self.state.name(),
                        self.round,
                        &msg
                    );
                    return Err(ConsensusError::VoteChange(false, msg.pkey, msg.sig));
                }

                // Add vote.
                self.precommit_rejects.insert(msg.pkey, msg.sig);
            }
        }

        // Check supermajority.
        if self.state == ConsensusState::Prevote {
            self.check_prevote_supermajority();
        } else if self.state == ConsensusState::Precommit {
            self.check_precommit_supermajority();
        }

        Ok(())
    }

    pub fn feed_timer(&mut self) -> Result<(), ConsensusError> {
        let now = Instant::now();
        if now < self.deadline {
            return Ok(());
        }

        match self.state {
            ConsensusState::Propose => {
                debug!("Propose => Failure: haven't received a proposal on time");
                self.state = ConsensusState::Failure;
                self.deadline = now + Duration::new(INFINITY_TIMEOUT, 0);
            }
            ConsensusState::Prevote => {
                debug!("Prevote => Precommit: failed to get enough number of pre-votes");
                self.precommit_reject(Hash::digest(self.request.as_ref().unwrap()));
                self.state = ConsensusState::Precommit;
                self.deadline = now + Duration::new(self.cfg.precommit_timeout, 0);
            }
            ConsensusState::Precommit => {
                debug!("Precommit => Failure: failed to get enough number of pre-commits");
                self.state = ConsensusState::Failure;
                self.deadline = now + Duration::new(INFINITY_TIMEOUT, 0);
            }
            ConsensusState::Commit => {}
            ConsensusState::Failure => {}
        }

        // Check supermajority.
        if self.state == ConsensusState::Prevote {
            self.check_prevote_supermajority();
        } else if self.state == ConsensusState::Precommit {
            self.check_precommit_supermajority();
        }

        Ok(())
    }

    /// Process pending messages received out-of-order.
    fn process_inbox(&mut self) {
        let inbox = std::mem::replace(&mut self.inbox, Vec::new());
        for msg in inbox {
            if let Err(e) = self.feed_message(msg) {
                warn!(
                    "Failed to process msg: state={:?}, round={:?}, error={:?}",
                    self.state.name(),
                    self.round,
                    e
                );
            }
        }
    }

    /// Returns true if current node is leader.
    pub fn is_leader(&self) -> bool {
        self.pkey == self.leader
    }

    pub fn should_propose(&self) -> bool {
        self.state == ConsensusState::Propose && self.is_leader()
    }

    pub fn should_prevote(&self) -> Option<(&Request, &Proof)> {
        if self.state == ConsensusState::Prevote
            && self.request.is_some()
            && !self.prevote_accepts.contains_key(&self.pkey)
            && !self.prevote_rejects.contains_key(&self.pkey)
        {
            Some((self.request.as_ref().unwrap(), self.proof.as_ref().unwrap()))
        } else {
            None
        }
    }

    pub fn should_commit(&self) -> bool {
        self.state == ConsensusState::Commit && self.is_leader()
    }

    pub fn commit(&mut self) -> (Request, Proof, SecureSignature, BitVector) {
        assert!(self.state == ConsensusState::Commit && self.is_leader());

        // Create multi-signature.
        let (multisig, multisigmap) =
            create_multi_signature(&self.validators, &self.precommit_accepts);
        let r = (
            self.request.take().unwrap(),
            self.proof.take().unwrap(),
            multisig,
            multisigmap,
        );
        self.next_round();
        r
    }

    ///
    /// Helper for check_prevote_supermajority() and check_precommit_supermajority().
    ///
    /// Returns Some(true) if supermajority of `accept` votes has been collected.
    /// Returns Some(false) if supermajority of `reject` votes has been collected.
    /// Returns None otherwise.
    ///
    fn check_supermajority(
        &self,
        accepts: &BTreeMap<SecurePublicKey, SecureSignature>,
        rejects: &BTreeMap<SecurePublicKey, SecureSignature>,
    ) -> Option<bool> {
        trace!("check_supermajority: state={:?}, has_accepts={:?}, has_rejects={:?}, total={:?}",
               self.state.name(), accepts.len(), rejects.len(), self.validators.len());
        if check_supermajority(accepts.len(), self.validators.len()) {
            trace!("has supermajority for accepts");
            return Some(true);
        } else if check_supermajority(rejects.len(), self.validators.len()) {
            trace!("has supermajority for rejects");
            return Some(false);
        } else {
            return None;
        }
    }

    /// Check if supermajority of Prevote has been collected.
    fn check_prevote_supermajority(&mut self) {
        assert_eq!(self.state, ConsensusState::Prevote);
        match self.check_supermajority(&self.prevote_accepts, &self.prevote_rejects) {
            // Supermajority of PrevoteAccept votes.
            Some(true) => {
                // Move to WaitPrecommit.
                self.state = ConsensusState::Precommit;
                self.deadline = Instant::now() + Duration::new(self.cfg.precommit_timeout, 0);
                if self.prevote_accepts.contains_key(&self.pkey) {
                    debug!("Prevote => Precommit: accepted");
                    self.precommit_accept(Hash::digest(&self.request));
                } else {
                    debug!(
                        "Prevote => Precommit: accepted by supermajority, byt rejected this node"
                    );
                    self.precommit_reject(Hash::digest(&self.request));
                }
            }
            // Supermajority of PrevoteReject votes.
            Some(false) => {
                // Move to WaitPrecommit.
                debug!("Prevote => Precommit: rejected");
                self.state = ConsensusState::Precommit;
                self.deadline = Instant::now() + Duration::new(self.cfg.precommit_timeout, 0);
                if self.prevote_rejects.contains_key(&self.pkey) {
                    debug!("Prevote => Precommit: reject");
                    self.precommit_reject(Hash::digest(&self.request))
                } else {
                    debug!("Prevote => Precommit: rejected by supermajority, but accepted by this node");
                    self.precommit_reject(Hash::digest(&self.request))
                }
            }
            None => (),
        }
    }

    /// Check if supermajority of Precommit has been collected.
    fn check_precommit_supermajority(&mut self) {
        assert_eq!(self.state, ConsensusState::Precommit);
        match self.check_supermajority(&self.precommit_accepts, &self.precommit_rejects) {
            // Supermajority of PrecommitAccept votes.
            Some(true) => {
                // Move to Commit.
                debug!("Precommit => Commit");
                self.deadline = Instant::now() + Duration::new(INFINITY_TIMEOUT, 0);
                self.state = ConsensusState::Commit;
            }
            // Supermajority of PrevoteReject votes.
            Some(false) => {
                // Move to Proposal.
                debug!("Precommit => Proposal");
                self.next_round();
            }
            None => (),
        }
    }
}
