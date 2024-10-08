use crate::ConstraintF;

use ark_ec::AffineCurve;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_poly_commit::trivial_pc::PedersenCommitment;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
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
    pub(crate) fn compute_challenge(
        matrices_hash: &[u8; 32],
        input: &[G::ScalarField],
        msg: &FirstRoundMessage<G>,
        mut sponge: S,
    ) -> G::ScalarField {
        sponge.absorb(&matrices_hash.as_ref());

        let input_bytes = input
            .iter()
            .flat_map(|inp| inp.into_repr().to_bytes_le())
            .collect::<Vec<_>>();

        absorb!(&mut sponge, input_bytes, msg);

        let out = sponge
            .squeeze_nonnative_field_elements_with_sizes(&[FieldElementSize::Truncated(
                CHALLENGE_SIZE,
            )])
            .pop()
            .unwrap();

        out
    }
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
        let pp = PedersenCommitment::setup(num_constraints);
        let ck = PedersenCommitment::trim(&pp, num_constraints);
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
            ck,
        };
        let ivk = ipk.clone();
        Ok((ipk, ivk))
    }

    pub fn prove<C: ConstraintSynthesizer<G::ScalarField>>(
        ipk: &IndexProverKey<G>,
        r1cs: C,
        make_zk: bool,
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
        
        let r = if make_zk {
            let randomizer_time = start_timer!(|| "Sampling randomizer r");

            let rng = rng.as_mut().unwrap();
            let mut r = Vec::with_capacity(num_witness_variables);
            for _ in 0..num_witness_variables {
                r.push(G::ScalarField::rand(rng))
            }

            end_timer!(randomizer_time);

            Some(r)
        } else {
            None
        };

        let eval_z_m_time = start_timer!(|| "Evaluating z_M");
        let z_a = matrix_vec_mul(&ipk.a, &input, &witness);
        let z_b = matrix_vec_mul(&ipk.b, &input, &witness);
        let z_c = matrix_vec_mul(&ipk.c, &input, &witness);
        end_timer!(eval_z_m_time);

        let (r_a, r_b, r_c) = if make_zk {
            let r_ref = r.as_ref().unwrap();
            let zeros = vec![G::ScalarField::zero(); num_input_variables];
            let eval_r_m_time = start_timer!(|| "Evaluating r_M");
            let r_a = matrix_vec_mul(&ipk.a, &zeros, r_ref);
            let r_b = matrix_vec_mul(&ipk.b, &zeros, r_ref);
            let r_c = matrix_vec_mul(&ipk.c, &zeros, r_ref);
            end_timer!(eval_r_m_time);

            (Some(r_a), Some(r_b), Some(r_c))
        } else {
            (None, None, None)
        };
        
        let (mut a_blinder, mut b_blinder, mut c_blinder) = (None, None, None);
        if make_zk {
            let rng = rng.as_mut().unwrap();
            a_blinder = Some(G::ScalarField::rand(rng));
            b_blinder = Some(G::ScalarField::rand(rng));
            c_blinder = Some(G::ScalarField::rand(rng));
        }

        let commit_time = start_timer!(|| "Committing to z_A, z_B, and z_C");
        let comm_a = PedersenCommitment::commit(&ipk.ck, &z_a, a_blinder);
        let comm_b = PedersenCommitment::commit(&ipk.ck, &z_b, b_blinder);
        let comm_c = PedersenCommitment::commit(&ipk.ck, &z_c, c_blinder);

        end_timer!(commit_time);

        let (mut r_a_blinder, mut r_b_blinder, mut r_c_blinder) = (None, None, None);
        let (mut blinder_1, mut blinder_2) = (None, None);
        let first_round_randomness = if make_zk {
            let rng = rng.as_mut().unwrap();
            
            r_a_blinder = Some(G::ScalarField::rand(rng));
            r_b_blinder = Some(G::ScalarField::rand(rng));
            r_c_blinder = Some(G::ScalarField::rand(rng));
            
            let commit_time = start_timer!(|| "Committing to r_A, r_B, r_C");
            let comm_r_a = PedersenCommitment::commit(&ipk.ck, r_a.as_ref().unwrap(), r_a_blinder);
            let comm_r_b = PedersenCommitment::commit(&ipk.ck, r_b.as_ref().unwrap(), r_b_blinder);
            let comm_r_c = PedersenCommitment::commit(&ipk.ck, r_c.as_ref().unwrap(), r_c_blinder);
            end_timer!(commit_time);
            
            let cross_prod_time = start_timer!(|| "Computing cross product z_a ○ r_b + z_b ○ r_a");
            let z_a_times_r_b = cfg_iter!(z_a).zip(r_b.as_ref().unwrap());
            let z_b_times_r_a = cfg_iter!(z_b).zip(r_a.as_ref().unwrap());
            let cross_product: Vec<_> = z_a_times_r_b
                .zip(z_b_times_r_a)
                .map(|((z_a, r_b), (z_b, r_a))| *z_a * r_b + *z_b * r_a)
                .collect();
            end_timer!(cross_prod_time);
            blinder_1 = Some(G::ScalarField::rand(rng));
            let commit_time = start_timer!(|| "Committing to cross product");
            let comm_1 = PedersenCommitment::commit(&ipk.ck, &cross_product, blinder_1);
            end_timer!(commit_time);
            
            let commit_time = start_timer!(|| "Committing to r_a ○ r_b");
            let r_a_r_b_product: Vec<_> = cfg_iter!(r_a.as_ref().unwrap())
                .zip(r_b.unwrap())
                .map(|(r_a, r_b)| r_b * r_a)
                .collect();
            blinder_2 = Some(G::ScalarField::rand(rng));
            let comm_2 = PedersenCommitment::commit(&ipk.ck, &r_a_r_b_product, blinder_2);
            end_timer!(commit_time);

            Some(FirstRoundMessageRandomness {
                comm_r_a,
                comm_r_b,
                comm_r_c,
                comm_1,
                comm_2,
            })
        } else {
            None
        };
        
        let first_msg = FirstRoundMessage {
            comm_a,
            comm_b,
            comm_c,
            randomness: first_round_randomness,
        };
        
        let gamma = Self::compute_challenge(
            &ipk.index_info.matrices_hash,
            &input,
            &first_msg,
            sponge.unwrap_or_else(|| S::new()),
        );

        let mut blinded_witness = witness;
        let second_round_randomness = if make_zk {
            ark_std::cfg_iter_mut!(blinded_witness)
                .zip(r.unwrap())
                .for_each(|(s, r)| *s += gamma * r);
            
            let sigma_a = a_blinder.unwrap() + gamma * r_a_blinder.unwrap();
            let sigma_b = b_blinder.unwrap() + gamma * r_b_blinder.unwrap();
            let sigma_c = c_blinder.unwrap() + gamma * r_c_blinder.unwrap();
            
            let sigma_o = c_blinder.unwrap()
                + gamma * blinder_1.unwrap()
                + gamma.square() * blinder_2.unwrap();

            Some(SecondRoundMessageRandomness {
                sigma_a,
                sigma_b,
                sigma_c,
                sigma_o,
            })
        } else {
            None
        };
        
        let second_msg = SecondRoundMessage {
            blinded_witness,
            randomness: second_round_randomness,
        };
        
        let proof = Proof {
            first_msg,
            second_msg,
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
        
        let gamma = Self::compute_challenge(
            &ivk.index_info.matrices_hash,
            &input,
            &proof.first_msg,
            sponge.unwrap_or_else(|| S::new()),
        );
        
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