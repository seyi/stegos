// Cosi-bls.rs - Consensus using COSI protocol
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

// --------------------------------------------------------------------------------
// NOTE: All messages should be signed by sender, and be accompanied by session ID, data for message,
// signature on message, and sender ID = secure Public key.

pub fn cosi_bls(block_header, block_body, list_of_transactions)
{
    // call this function from Leader node with args representing
    // the proposed block (header + body), the ordered list of transactions
    // that went into the block.

    // The prototype block header has all fields filled in except the multi-signature.
    // Compute the hash of the block header (sans multisig fields) to use as the session ID.
    // Broadcast to all witness nodes in message PREPARE
    let session_id = digest(block_header);
    broadcast_prepare_message(session_id, block_header, block_body, list_of_transactions, my_secure_public_key);

    // Wait for some period of time, to allow witnesses a chance to validate proposed block,
    // collect incoming multi-signature component signatures, summing them to a single multi-signature, while
    // also recording in a bitmap which witnesses responded. Ignore multiple responses from a witness.

    // Once duration has elapsed, or a BFT threshold of component signatures has arrived, then continue:
    // -- If we have a BFT threshold number of signatures, plant tha multi-signature into the proposed block
    // header, (this includes the signature bitmap as well as the summed BLS signature), commit the new block
    // to the blockchain, then broadcast the multisignature and bitmap in a COMMIT message for the same session ID (= block header hash). 
    // Each witness receiving the COMMIT message will plant the signature into their local copy of the block, and
    // commit the new block as the head of the blockchain, and respond with another BLS signature indicating committal.
    //
    // Wait for some duration, collecting BLS signatures on the COMMIT message. Hopefully, a BFT threshold number of
    // responses are received from witnesses. Be sure to ignore duplicates from any one witness. After that duration,
    // publish the new block as the new head of blockchain.
}

// ------------------------------------------------------------------------------------------

fn handle_prepare_message(session_id, block_header, block_body, list_of_transactons, from) {
    // this handler should be called on receipt of PREPARE message. The message contains
    // a proposed block header, block body, and ordered list of transactions which make up
    // the block.
    //
    // Check that from = current leader
    // check that session_id = hash(block_header)
    if from != current_leader { return Err(SpoofMessage); }
    if digest(block_header) != session_id { return Err(InvalidPrepareMessage); }

    // This is the only chance to verify that transaction elements, notably UTXOS, have been 
    // faithfully copied into the block body. So begin by first validating each transaction.
    for trans in transaction_list {
        validate_transaction(trans)?;
        verify_utxo_in_block_body(trans, block_body)?;
    }
    validate_block(blk_header, blk_body)?; // does the block itself look correct?
    
    // we made it, so send back our component BLS signature, who we are, to Leader
    send_prepare_response(from, session_id, pbc::secure::sign_hash(session_id), my_secure_public_key);
}

fn validate_transaction(trans: Transaction) -> Result<bool, Err> {
    // transactions need several different kinds of validation:
    //  1. Structural integrity - the internal contents of all portions of a transaction
    //     must validate against an authenticating signature. This indicates that the 
    //     transaction has not suffered mutations of any fields. 
    //     - A valid UTXO ID should be the hash of all remaining fields in the UTXO.
    //  2. Numeric integrity - the Bulletproofs must validate, indicating valid monetary
    //     entries in all UTXO's in the transaction.
    //     - The sum of all TXIN Pedersen commitments, minus the sum of all UTXO commitments,
    //     less the FEE * A (monetary curve generator A), must equal gamma_adj * G (non-monetary curve generator G).
    //     This indicates that the transaction represents a zero balance on the monetary curve.
    //  3. Referential integrity - every TXIN should match an existing, unspent UTXO somewhere either in
    //     the blockchain, or among the UTXO of the transactions offered as components of the block.
    //     There should be no duplicate TXIN references (no double spending).
}

fn verify_utxo_in_block_body(trans: Transaction, block_body) -> Result<bool, Err> {
    // this function shoud verify that the UTXO were faithfully copied over to the block body
    // of the prototype block.
}

fn validate_block(block_header, block_body) -> Result<bool, Err> {
    // validate that every block header field is correct:
    //   1. Hash of header sans mulitsig fields should equal the session ID
    //   2. header block_gamma_adj should equal the sum of all transaction gamma_adj
    //   3. sum of all TXIN Pedersen commitments, minus the sum of all UTXO Pedersen commitments,
    //      less SUM_FEE * A should equal sum_gamma_adj * G. This indicates that the block
    //      represents a zero balance condition.
    //   4. prev hash should equal the hash of the current head of blockchain
    //   5. Other structural checks... e.g., leader slot = current Cosi Leader key,
    //      Merkel hashes on block body match computed Merkel trees, epoch is current epoch, etc.
}

// ---------------------------------------------------------------------------
fun handle_commit_message(session_id, muti_signature, signature_bitmap, from) {
    // check that from == current leader
    // check that session_id == digest(block_header) of prototype in waiting
    // check that census of bitmap >= BFT threshold
    // check that multi-signature is correct
    // If so...
    //   sign response to commit message
    //   fill in block header multi-signature fields
    //   commit the prototype block to the blockchain
    //   perform any necessary database maintenance
}