use crate::account::{AccountId, AccountPublicKey, AccountSecretKey};
use crate::ledger::{self, Amount};
use anyhow::{anyhow, Result};
use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_crypto_primitives::SignatureScheme;
use ark_ed_on_bls12_377::EdwardsProjective;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, EqGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::Rng;
use simpleworks::marlin::MarlinInst;
use simpleworks::schnorr_signature::{
    schnorr::{Parameters, Schnorr},
    SchnorrSignatureVerifyGadget, SimpleSchnorrConstraintF, SimpleSchnorrMessage,
    SimpleSchnorrParameters, SimpleSchnorrParametersVar, SimpleSchnorrPublicKey,
    SimpleSchnorrPublicKeyVar, SimpleSchnorrSignature, SimpleSchnorrSignatureVar,
};

#[derive(Clone)]
pub struct SimpleSchnorrSignatureVerification {
    parameters: SimpleSchnorrParameters,
    // The public key of the signer.
    public_key: SimpleSchnorrPublicKey,
    // The signed message.
    message: SimpleSchnorrMessage,
    // The signature of the message.
    signature: SimpleSchnorrSignature,
}

impl ConstraintSynthesizer<SimpleSchnorrConstraintF> for SimpleSchnorrSignatureVerification {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<SimpleSchnorrConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First we allocate the parameters.
        let parameters = SimpleSchnorrParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            self.parameters,
        )?;

        // Then we allocate the public key.
        let public_key =
            SimpleSchnorrPublicKeyVar::new_witness(ark_relations::ns!(cs, "public_key"), || {
                Ok(&self.public_key)
            })?;

        // Then we allocate the message.
        // let message = UInt8::new_input_vec(ark_relations::ns!(cs, "message"), &self.message)?;
        let mut message = Vec::new();
        for i in 0..self.message.len() {
            message.push(UInt8::new_witness(cs.clone(), || Ok(&self.message[i])).unwrap())
        }

        // Then we allocate the signature.
        let signature =
            SimpleSchnorrSignatureVar::new_witness(ark_relations::ns!(cs, "signature"), || {
                Ok(&self.signature)
            })?;

        // Finally we verify the signature.
        let result =
            SchnorrSignatureVerifyGadget::verify(&parameters, &public_key, &message, &signature);

        result?.enforce_equal(&Boolean::Constant(true))?;

        Ok(())
    }
}

/// Transaction transferring some amount from one account to another.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// The account information of the sender.
    pub sender: AccountId,
    /// The account information of the recipient.
    pub recipient: AccountId,
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub signature: simpleworks::schnorr_signature::schnorr::Signature<EdwardsProjective>,
}

impl Transaction {
    /// Verify just the signature in the transaction.
    fn verify_signature(
        &self,
        pp: &Parameters<EdwardsProjective>,
        pub_key: &AccountPublicKey,
        rng: &mut StdRng,
    ) -> Result<bool> {
        // And sample a random universal SRS.
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, rng)
            .map_err(|_| anyhow!("Error creating universal_setup"))?;

        // The authorized message consists of
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = self.sender.to_bytes_le();
        message.extend(self.recipient.to_bytes_le());
        message.extend(self.amount.to_bytes_le());
        let schnorr_verify = Schnorr::verify(pp, pub_key, &message, &self.signature)
            .map_err(|_| anyhow!("Error Schnorr::verify"))?;

        // Now we create the circuit that will verify the signature.
        let circuit = SimpleSchnorrSignatureVerification {
            parameters: pp.clone(),
            public_key: *pub_key,
            message: message.to_vec(),
            signature: self.signature.clone(),
        };

        // Now, try to generate the verifying key and proving key with Marlin.
        let (index_pk, index_vk) =
            MarlinInst::index(&universal_srs, circuit.clone()).map_err(|_| {
                anyhow!("Error generating the verifying key and proving key with Marlin")
            })?;

        // Generate the proof.
        let proof = MarlinInst::prove(&index_pk, circuit, rng)
            .map_err(|_| anyhow!("Error generating the Marlin proof"))?;

        let marlin_verify = MarlinInst::verify(&index_vk, &[], &proof, rng)
            .map_err(|_| anyhow!("Error generating the Marlin proof"))?;

        /*

        TODO!

        let parameters = SimpleSchnorr::setup::<_>(rng).unwrap();
        let (pk, sk) = SimpleSchnorr::keygen(&parameters, rng).unwrap();
        let sig = SimpleSchnorr::sign(&parameters, &sk, message, rng).unwrap();

        */

        Ok(schnorr_verify && marlin_verify)
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    pub fn validate(
        &self,
        parameters: &ledger::Parameters,
        state: &ledger::State,
        rng: &mut StdRng,
    ) -> Result<bool> {
        // Lookup public key corresponding to sender ID
        let sender_acc_info = state
            .id_to_account_info
            .get(&self.sender)
            .ok_or_else(|| anyhow!("sender not found"))?;

        let mut result = true;
        // Check that the account_info exists in the Merkle tree.
        result &= {
            let path = state
                .account_merkle_tree
                .generate_proof(self.sender.0 as usize)
                .expect("path should exist");
            path.verify(
                &parameters.leaf_crh_params,
                &parameters.two_to_one_crh_params,
                &state.account_merkle_tree.root(),
                &sender_acc_info.to_bytes_le(),
            )
            .map_err(|_| anyhow!("Error in path verify"))?
        };
        // Verify the signature against the sender pubkey.
        result &= self
            .verify_signature(&parameters.sig_params, &sender_acc_info.public_key, rng)
            .map_err(|_| anyhow!("Error in verify signature"))?;
        // assert!(result, "signature verification failed");
        // Verify the amount is available in the sender account.
        result &= self.amount <= sender_acc_info.balance;
        // Verify that recipient account exists.
        result &= state.id_to_account_info.get(&self.recipient).is_some();
        Ok(result)
    }

    /// Create a (possibly invalid) transaction.
    pub fn create<R: Rng>(
        parameters: &ledger::Parameters,
        sender: AccountId,
        recipient: AccountId,
        amount: Amount,
        sender_sk: &AccountSecretKey,
        rng: &mut R,
    ) -> Self {
        // The authorized message consists of (SenderAccId || RecipientAccId || Amount)
        let mut message = sender.to_bytes_le();
        message.extend(recipient.to_bytes_le());
        message.extend(amount.to_bytes_le());
        let signature = Schnorr::sign(&parameters.sig_params, sender_sk, &message, rng).unwrap();
        Self {
            sender,
            recipient,
            amount,
            signature,
        }
    }
}

// Ideas to make exercises more interesting/complex:
// 1. Add fees
// 2. Add recipient confirmation requirement if tx amount is too large.
// 3. Add authority confirmation if tx amount is too large.
// 4. Create account if it doesn't exist.
// 5. Add idea for compressing state transitions with repeated senders and recipients.
