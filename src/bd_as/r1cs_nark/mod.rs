use crate::ConstraintF;
use ark_ec::AffineCurve;
use ark_ff::{Field, PrimeField, Zero, BigInteger};
use ark_poly_commit::trivial_pc::PedersenCommitment;
use ark_relations::r1cs::{
    ConstraintSynthesizer, 
    ConstraintSystem, 
    Matrix, 
    OptimizationGoal, 
    SynthesisError,
    SynthesisMode,
};
use ark_serialize::CanonicalSerialize;
use ark_sponge::{absorb, Absorbable, CryptographicSponge, FieldElementSize};
use ark_std::rand::RngCore;
use ark_std::vec;
use ark_std::vec::Vec;
use ark_std::{cfg_into_iter, cfg_iter, marker::PhantomData, UniformRand};
use blake2::{digest::VariableOutput, VarBlake2b};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

mod data_structures;
pub use data_structures::*;

type R1CSResult<T> = Result<T, SynthesisError>;

pub(crate) const PROTOCOL_NAME: &[u8] = b"R1CS-NARK-2020";
pub(crate) const CHALLENGE_SIZE: usize = 128;

pub struct R1CSNark<G, S>
where
    G: AffineCurve + Absorbable<ConstraintF<G>>,
    ConstraintF<G>: Absorbable<ConstraintF<G>>,
    S: CryptographicSponge<ConstraintF<G>>,
{
    _affine: PhantomData<G>,
    _sponge: PhantomData<S>,
}

impl<G, S> R1CSNark<G, S>
where
    G: AffineCurve + Absorbable<ConstraintF<G>>,
    ConstraintF<G>: Absorbable<ConstraintF<G>>,
    S: CryptographicSponge<ConstraintF<G>>,
{
    pub fn setup() -> PublicParameters {}

    pub fn index<C: ConstraintSynthesizer<G::ScalarField>>(
        _pp: &PublicParameters,
        r1cs_instance: C,
    ) -> R1CSResult<(IndexProverKey<G>, IndexVerifierKey<G>)> {
        let constraint_time = start_timer!(|| "Generating constraints");

        let ics = ConstraintSystem::new_ref();
        ics.set_optimization_goal(OptimizationGoal::Constraints);
        ics.set_mode(SynthesisMode::Setup);
        r1cs_instance.generate_constraints(ics.clone())?;

        end_timer!(constraint_time);

        let matrix_processing_time = start_timer!(|| "Processing matrices");
        ics.finalize();

        let matrices = ics.to_matrices().expect("should not be `None`");
        let (a, b, c) = (matrices.a, matrices.b, matrices.c);
        let (num_input_variables, num_witness_variables, num_constraints) = (
            ics.num_instance_variables(),
            ics.num_witness_variables(),
            ics.num_constraints(),
        );

        end_timer!(matrix_processing_time);

        let matrices_hash = hash_matrices(PROTOCOL_NAME, &a, &b, &c);

        let num_variables = num_input_variables + num_witness_variables;
        let index_info = IndexInfo {
            num_variables,
            num_constraints,
            num_instance_variables: num_input_variables,
            matrices_hash,
        };
        let ipk = IndexProverKey {
            index_info,
            a,
            b,
            c,
        };
        let ivk = ipk.clone();
        Ok((ipk, ivk))
    }

    pub fn prove<C: ConstraintSynthesizer<G::ScalarField>>(
        ipk: &IndexProverKey<G>,
        r1cs: C,
        sponge: Option<S>,
        mut rng: Option<&mut dyn RngCore>,
    ) -> R1CSResult<Proof<G>> {
        let init_time = start_timer!(|| "NARK::Prover");

        let constraint_time = start_timer!(|| "Generating constraints and witnesses");
        let pcs = ConstraintSystem::new_ref();
        pcs.set_optimization_goal(OptimizationGoal::Constraints);
        pcs.set_mode(ark_relations::r1cs::SynthesisMode::Prove {
            construct_matrices: false,
        });
        r1cs.generate_constraints(pcs.clone())?;
        end_timer!(constraint_time);

        pcs.finalize();
        let (input, witness, num_constraints) = {
            let pcs = pcs.borrow().unwrap();
            (
                pcs.instance_assignment.as_slice().to_vec(),
                pcs.witness_assignment.as_slice().to_vec(),
                pcs.num_constraints,
            )
        };

        let num_input_variables = input.len();
        let num_witness_variables = witness.len();
        let num_variables = num_input_variables + num_witness_variables;

        assert_eq!(ipk.index_info.num_variables, num_variables);
        assert_eq!(ipk.index_info.num_constraints, num_constraints);
        
        let full_assgn = FullAssignment {
            input,
            witness,
        };

        let mut blinded_witness = witness; // Replace with finding merkle root for (input||witness)
        
        let commit_full_assgn = CommitmentFullAssignment {
            blinded_witness,
        };
        
        let proof = Proof {
            full_assgn,
            commit_full_assgn,
        };

        end_timer!(init_time);
        Ok(proof)
    }
    
    pub fn verify(
        ivk: &IndexVerifierKey<G>,
        input: &[G::ScalarField],
        proof: &Proof<G>,
        sponge: Option<S>,
    ) -> bool {
        let init_time = start_timer!(|| "NARK::Verifier");
        if proof.first_msg.randomness.is_some() != proof.second_msg.randomness.is_some() {
            return false;
        }
        
        let mat_vec_mul_time = start_timer!(|| "Computing M * blinded_witness");
        let a_times_blinded_witness =
            matrix_vec_mul(&ivk.a, &input, &proof.second_msg.blinded_witness);
        let b_times_blinded_witness =
            matrix_vec_mul(&ivk.b, &input, &proof.second_msg.blinded_witness);
        let c_times_blinded_witness =
            matrix_vec_mul(&ivk.c, &input, &proof.second_msg.blinded_witness);
        end_timer!(mat_vec_mul_time);
        
        let mut comm_a = proof.first_msg.comm_a.into_projective();
        let mut comm_b = proof.first_msg.comm_b.into_projective();
        let mut comm_c = proof.first_msg.comm_c.into_projective();
        if let Some(first_msg_randomness) = proof.first_msg.randomness.as_ref() {
            comm_a += first_msg_randomness.comm_r_a.mul(gamma);
            comm_b += first_msg_randomness.comm_r_b.mul(gamma);
            comm_c += first_msg_randomness.comm_r_c.mul(gamma);
        }

        let commit_time = start_timer!(|| "Reconstructing c_A, c_B, c_C commitments");
        let reconstructed_comm_a = PedersenCommitment::commit(
            &ivk.ck,
            &a_times_blinded_witness,
            proof.second_msg.randomness.as_ref().map(|r| r.sigma_a),
        );
        let reconstructed_comm_b = PedersenCommitment::commit(
            &ivk.ck,
            &b_times_blinded_witness,
            proof.second_msg.randomness.as_ref().map(|r| r.sigma_b),
        );
        let reconstructed_comm_c = PedersenCommitment::commit(
            &ivk.ck,
            &c_times_blinded_witness,
            proof.second_msg.randomness.as_ref().map(|r| r.sigma_c),
        );

        let a_equal = comm_a == reconstructed_comm_a.into_projective();
        let b_equal = comm_b == reconstructed_comm_b.into_projective();
        let c_equal = comm_c == reconstructed_comm_c.into_projective();
        drop(c_times_blinded_witness);
        end_timer!(commit_time);
        
        let had_prod_time = start_timer!(|| "Computing Hadamard product and commitment to it");
        let had_prod: Vec<_> = cfg_into_iter!(a_times_blinded_witness)
            .zip(b_times_blinded_witness)
            .map(|(a, b)| a * b)
            .collect();
        let reconstructed_had_prod_comm = PedersenCommitment::commit(
            &ivk.ck,
            &had_prod,
            proof.second_msg.randomness.as_ref().map(|r| r.sigma_o),
        );
        end_timer!(had_prod_time);

        let mut had_prod_comm = proof.first_msg.comm_c.into_projective();
        if let Some(first_msg_randomness) = proof.first_msg.randomness.as_ref() {
            had_prod_comm += first_msg_randomness.comm_1.mul(gamma);
            had_prod_comm += first_msg_randomness.comm_2.mul(gamma.square());
        }
        let had_prod_equal = had_prod_comm == reconstructed_had_prod_comm.into_projective();
        add_to_trace!(|| "Verifier result", || format!("A equal: {}, B equal: {}, C equal: {}, Hadamard Product equal: {}", a_equal, b_equal, c_equal, had_prod_equal));
        end_timer!(init_time);
        a_equal & b_equal & c_equal & had_prod_equal
    }
}

pub(crate) fn hash_matrices<F: Field>(
    domain_separator: &[u8],
    a: &Matrix<F>,
    b: &Matrix<F>,
    c: &Matrix<F>,
) -> [u8; 32] {
    let mut serialized_matrices = domain_separator.to_vec();
    a.serialize(&mut serialized_matrices).unwrap();
    b.serialize(&mut serialized_matrices).unwrap();
    c.serialize(&mut serialized_matrices).unwrap();

    let mut hasher = VarBlake2b::new(32).unwrap();
    digest::Update::update(&mut hasher, &serialized_matrices);

    let mut matrices_hash = [0u8; 32];
    hasher.finalize_variable(|res| matrices_hash.copy_from_slice(res));

    matrices_hash
}

pub(crate) fn matrix_vec_mul<F: Field>(matrix: &Matrix<F>, input: &[F], witness: &[F]) -> Vec<F> {
    ark_std::cfg_iter!(matrix)
        .map(|row| inner_prod(row, input, witness))
        .collect()
}

fn inner_prod<F: Field>(row: &[(F, usize)], input: &[F], witness: &[F]) -> F {
    let mut acc = F::zero();
    for &(ref coeff, i) in row {
        let tmp = if i < input.len() {
            input[i]
        } else {
            witness[i - input.len()]
        };

        acc += &(if coeff.is_one() { tmp } else { tmp * coeff });
    }
    acc
}