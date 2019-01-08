//! pBFT Consensus - Network Messages.

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
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure::check_hash as secure_check_hash;
use stegos_crypto::pbc::secure::sign_hash as secure_sign_hash;
use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;
use stegos_crypto::pbc::secure::SecretKey as SecureSecretKey;
use stegos_crypto::pbc::secure::Signature as SecureSignature;

/// Consensus Message Payload.
#[derive(Clone, Debug)]
pub enum ConsensusMessageBody<Request, Proof> {
    Proposal { request: Request, proof: Proof },
    PrevoteReject {},
    PrevoteAccept {},
    PrecommitReject {},
    PrecommitAccept { request_hash_sig: SecureSignature },
}

impl<Request: Hashable, Proof: Hashable> Hashable for ConsensusMessageBody<Request, Proof> {
    fn hash(&self, state: &mut Hasher) {
        match self {
            ConsensusMessageBody::Proposal { request, proof } => {
                "Propose".hash(state);
                request.hash(state);
                proof.hash(state);
            }
            ConsensusMessageBody::PrevoteReject {} => {
                "PrevoteReject".hash(state);
            }
            ConsensusMessageBody::PrevoteAccept {} => {
                "PrevoteAccept".hash(state);
            }
            ConsensusMessageBody::PrecommitReject {} => {
                "PrecommitReject".hash(state);
            }
            ConsensusMessageBody::PrecommitAccept { request_hash_sig } => {
                "PrecommitAccept".hash(state);
                request_hash_sig.hash(state);
            }
        }
    }
}

/// Consensus Message.
#[derive(Clone, Debug)]
pub struct ConsensusMessage<Request, Proof> {
    /// Current round.
    pub round: u64,
    /// Hash of request.
    pub request_hash: Hash,
    /// Message Body.
    pub body: ConsensusMessageBody<Request, Proof>,
    /// Secure Public Key used to sign this message.
    pub pkey: SecurePublicKey,
    /// Secure Signature.
    pub sig: SecureSignature,
}

impl<Request, Proof> ConsensusMessage<Request, Proof> {
    pub fn name(&self) -> &'static str {
        match self.body {
            ConsensusMessageBody::Proposal { .. } => "Proposal",
            ConsensusMessageBody::PrevoteReject { .. } => "PrevoteReject",
            ConsensusMessageBody::PrevoteAccept { .. } => "PrevoteAccept",
            ConsensusMessageBody::PrecommitReject { .. } => "PrecommitReject",
            ConsensusMessageBody::PrecommitAccept { .. } => "PrecommitAccept",
        }
    }
}

impl<Request: Hashable, Proof: Hashable> ConsensusMessage<Request, Proof> {
    ///
    /// Create and sign a new consensus message.
    ///
    pub fn new(
        round: u64,
        request_hash: Hash,
        skey: &SecureSecretKey,
        pkey: &SecurePublicKey,
        body: ConsensusMessageBody<Request, Proof>,
    ) -> ConsensusMessage<Request, Proof> {
        let mut hasher = Hasher::new();
        round.hash(&mut hasher);
        request_hash.hash(&mut hasher);
        body.hash(&mut hasher);
        let hash = hasher.result();
        let sig = secure_sign_hash(&hash, skey);
        ConsensusMessage {
            round,
            request_hash,
            body,
            pkey: pkey.clone(),
            sig,
        }
    }

    ///
    /// Validate signature.
    ///
    pub fn validate(&self) -> Result<(), ConsensusError> {
        let mut hasher = Hasher::new();
        self.round.hash(&mut hasher);
        self.request_hash.hash(&mut hasher);
        self.body.hash(&mut hasher);
        let hash = hasher.result();
        if !secure_check_hash(&hash, &self.sig, &self.pkey) {
            return Err(ConsensusError::InvalidMessageSignature);
        }
        Ok(())
    }
}

/// Used by protobuf tests.
impl<Request: Hashable, Proof: Hashable> Hashable for ConsensusMessage<Request, Proof> {
    fn hash(&self, state: &mut Hasher) {
        self.round.hash(state);
        self.request_hash.hash(state);
        self.body.hash(state);
        self.pkey.hash(state);
        self.sig.hash(state);
    }
}
