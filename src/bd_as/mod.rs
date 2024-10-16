use core::marker::PhantomData;

use ark_ec::AffineCurve;
use ark_sponge::{Absorbable, CryptographicSponge};

use crate::{error::BoxedError, AccumulationScheme, ConstraintF};

/// module for data structures used in accumulation scheme
pub mod data_structures;
/// module for a simple r1cs NARK contains proof of a function f
pub mod r1cs_nark;
///implements bounded depth accumulation scheme for a  r1cs nark
pub struct BDASForR1CSNark<G>
where
    G: AffineCurve,
{
    _affine: PhantomData<G>,
}

impl<G, T> AccumulationScheme<ConstraintF<G>, T> for BDASForR1CSNark<G>
where
    G: AffineCurve,
    T: CryptographicSponge<ConstraintF<G>>,
{
    type PublicParameters = ();
    type PredicateParams = ();
    type PredicateIndex = ();

    type ProverKey = ();
    type VerifierKey = ();
    type DeciderKey = ();

    type InputInstance = ();
    type InputWitness = ();
    type AccumulatorInstance = ();
    type AccumulatorWitness = ();
    type Proof = ();
    type Error = BoxedError;

    fn setup(
        _rng: &mut impl ark_std::rand::RngCore,
    ) -> Result<Self::PublicParameters, Self::Error> {
        Ok(())
    }

    fn index(
        _public_params: &Self::PublicParameters,
        _predicate_params: &Self::PredicateParams,
        _predicate_index: &Self::PredicateIndex,
    ) -> Result<(Self::ProverKey, Self::VerifierKey, Self::DeciderKey), Self::Error> {
        Ok(((), (), ()))
    }

    fn prove<'a>(
        prover_key: &Self::ProverKey,
        inputs: impl IntoIterator<Item = crate::InputRef<'a, ConstraintF<G>, T, Self>>,
        old_accumulators: impl IntoIterator<Item = crate::AccumulatorRef<'a, ConstraintF<G>, T, Self>>,
        make_zk: crate::MakeZK<'_>,
        sponge: Option<T>,
    ) -> Result<(crate::Accumulator<ConstraintF<G>, _, Self>, Self::Proof), Self::Error>
    where
        Self: 'a,
        _: 'a,
    {
    }
}
