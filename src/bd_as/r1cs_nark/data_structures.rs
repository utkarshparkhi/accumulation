use ark_ec::AffineCurve;
use ark_ff::{Field, PrimeField};
use ark_poly_commit::trivial_pc::CommitterKey;
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_sponge::{collect_sponge_bytes, collect_sponge_field_elements, Absorbable};
use ark_std::io::{Read, Write};
use ark_std::vec::Vec;


pub type PublicParameters = ();

#[derive(Clone, Copy)]
pub(crate) struct IndexInfo {
    pub(crate) num_variables: usize,
    pub(crate) num_constraints: usize,
    pub(crate) num_instance_variables: usize,
    pub(crate) matrices_hash: [u8; 32],
}

#[derive(Clone)]
pub struct IndexProverKey<G: AffineCurve> {
    pub(crate) index_info: IndexInfo,
    pub(crate) a: Matrix<G::ScalarField>,
    pub(crate) b: Matrix<G::ScalarField>,
    pub(crate) c: Matrix<G::ScalarField>,
    pub(crate) ck: CommitterKey<G>,
}

pub type IndexVerifierKey<G> = IndexProverKey<G>;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct FirstRoundMessageRandomness<G: AffineCurve> {
    pub(crate) comm_r_a: G,
    pub(crate) comm_r_b: G,
    pub(crate) comm_r_c: G,
    pub(crate) comm_1: G,
    pub(crate) comm_2: G,
}

impl<CF, G> Absorbable<CF> for FirstRoundMessageRandomness<G>
where
    CF: PrimeField,
    G: AffineCurve + Absorbable<CF>,
{
    fn to_sponge_bytes(&self) -> Vec<u8> {
        collect_sponge_bytes!(
            CF,
            self.comm_r_a,
            self.comm_r_b,
            self.comm_r_c,
            self.comm_1,
            self.comm_2
        )
    }

    fn to_sponge_field_elements(&self) -> Vec<CF> {
        collect_sponge_field_elements!(
            self.comm_r_a,
            self.comm_r_b,
            self.comm_r_c,
            self.comm_1,
            self.comm_2
        )
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct FirstRoundMessage<G: AffineCurve> {
    pub(crate) comm_a: G,
    pub(crate) comm_b: G,
    pub(crate) comm_c: G,
    pub(crate) randomness: Option<FirstRoundMessageRandomness<G>>,
}

impl<G: AffineCurve> FirstRoundMessage<G> {
    pub(crate) fn zero(make_zk: bool) -> Self {
        Self {
            comm_a: G::zero(),
            comm_b: G::zero(),
            comm_c: G::zero(),
            randomness: if make_zk {
                Some(FirstRoundMessageRandomness {
                    comm_r_a: G::zero(),
                    comm_r_b: G::zero(),
                    comm_r_c: G::zero(),
                    comm_1: G::zero(),
                    comm_2: G::zero(),
                })
            } else {
                None
            },
        }
    }
}

impl<CF, G> Absorbable<CF> for FirstRoundMessage<G>
where
    CF: PrimeField,
    G: AffineCurve + Absorbable<CF>,
{
    fn to_sponge_bytes(&self) -> Vec<u8> {
        collect_sponge_bytes!(CF, self.comm_a, self.comm_b, self.comm_c, self.randomness)
    }

    fn to_sponge_field_elements(&self) -> Vec<CF> {
        collect_sponge_field_elements!(self.comm_a, self.comm_b, self.comm_c, self.randomness)
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecondRoundMessageRandomness<F: Field> {
    pub(crate) sigma_a: F,
    pub(crate) sigma_b: F,
    pub(crate) sigma_c: F,
    pub(crate) sigma_o: F,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecondRoundMessage<F: Field> {
    pub(crate) blinded_witness: Vec<F>,
    pub(crate) randomness: Option<SecondRoundMessageRandomness<F>>,
}

impl<F: Field> SecondRoundMessage<F> {
    pub(crate) fn zero(witness_len: usize, make_zk: bool) -> Self {
        Self {
            blinded_witness: vec![F::zero(); witness_len],
            randomness: if make_zk {
                Some(SecondRoundMessageRandomness {
                    sigma_a: F::zero(),
                    sigma_b: F::zero(),
                    sigma_c: F::zero(),
                    sigma_o: F::zero(),
                })
            } else {
                None
            },
        }
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<G: AffineCurve> {
    pub first_msg: FirstRoundMessage<G>,
    pub second_msg: SecondRoundMessage<G::ScalarField>,
}
