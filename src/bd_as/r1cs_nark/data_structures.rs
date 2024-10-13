use ark_ec::AffineCurve;
use ark_ff::{PrimeField, Field};
use ark_poly_commit::trivial_pc::CommitterKey;
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use ark_sponge::{collect_sponge_bytes, collect_sponge_field_elements, Absorbable};
use ark_std::vec::Vec;
use ark_std::io::{Read, Write};

pub type PublicParameters = ();

#[derive(Clone, Copy)]
pub(crate) struct IndexInfo {
    pub(crate) num_constraints: usize,
    pub(crate) num_variables: usize,
    pub(crate) num_instance_variables: usize,
    pub(crate) matrices_hash: [u8; 32],
}

#[derive(Clone)]
pub struct IndexProverKey<G: AffineCurve> {
    pub(crate) index_info: IndexInfo,
    pub(crate) a: Matrix<G::ScalarField>,
    pub(crate) b: Matrix<G::ScalarField>,
    pub(crate) b: Matrix<G::ScalarField>,
}

pub type IndexVerifierKey<G> = IndexProverKey<G>;

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct FullAssignment<F: Field> {
    pub(crate) input: Vec<F>,
    pub(crate) witness: Vec<F>,
}

impl<F: Field> FullAssignment<F> {
    pub(crate) fn zero(input_len: usize, witness_len: usize) -> Self {
        Self {
            input: vec![F::zero(); input_len],
            witness: vec![F::zero(); witness_len],
        }
    }
}

impl<CF, F> Absorbable<CF> for FullAssignment<F> 
where 
    CF: PrimeField,
    F: Field + Absorbable<CF>,
{
    fn to_sponge_bytes(&self) -> Vec<u8> {
        collect_sponge_bytes!(
            CF,
            self.input,
            self.witness,
        )
    }

    fn to_sponge_field_elements(&self) -> Vec<CF> {
        collect_sponge_bytes!(
            self.input,
            self.witness,
        )
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentFullAssignment<F: Field> {
    pub(crate) blinded_assignment: Vec<F> /// Replace with type of merkle root
}

impl<F: Field> CommitmentFullAssignment<F> { /// /// Replace with zero value of type of merkle root
    pub(crate) fn zero(witness_len: usize) -> Self {
        Self {
            blinded_witness: vec![F::zero(); witness_len]
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: Field> {
    pub instance: FullAssignment<G>,
    pub witness: CommitmentFullAssignment<F>,
}