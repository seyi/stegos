use criterion::{criterion_group, criterion_main, Criterion, Bencher};
use stegos_crypto::pbc::secure::{PublicKey as SecurePublicKey};
use stegos_crypto::hash::Hash;
use std::collections::BTreeMap;
use rand::{Rng, SeedableRng};
use rand_isaac::IsaacRng;

#[path = "../src/election.rs"]
#[allow(unused_imports)]
mod election;

mod election2 {

	use log::error;
	use stegos_crypto::hash::Hash;

	use rand::{Rng, SeedableRng};
	use rand_isaac::IsaacRng;
	use std::collections::BTreeMap;

	use stegos_crypto::pbc::secure::PublicKey as SecurePublicKey;

	pub type StakersGroup = BTreeMap<SecurePublicKey, i64>;

	#[derive(Debug, Eq, PartialEq)]
	pub struct ConsensusGroup {
	    pub witnesses: StakersGroup,
	    pub leader: SecurePublicKey,
	}
	/// Choose random validator, based on `random_number`.
	/// Accepts list of validators stakes consistently sorted on all participants,
	/// Returns index of the validator which stake are won.
	fn select_winner<'a, I>(stakers: I, random_number: i64) -> Option<SecurePublicKey>
	where
	    I: IntoIterator<Item = (&'a SecurePublicKey, &'a i64)>,
	    <I as IntoIterator>::IntoIter: Clone,
	{
	    let stakers = stakers.into_iter();
	    let random = random_number.checked_abs().unwrap_or(0);

	    let sum_stakes: i64 = stakers.clone().map(|(_, v)|*v).sum();
	    if sum_stakes == 0 {
	        error!("Nobody place a stack, we can't choose a leader.");
	        return None;
	    }

	    let need_stake = random % sum_stakes;

	    let mut accumulator: i64 = 0;
	    for (pk, validator_stake) in stakers {
	        assert!(
	            * validator_stake >= 0,
	            "Processing invalid validator stake < 0."
	        );
	        if accumulator + validator_stake > need_stake {
	            return Some(*pk);
	        }
	        accumulator += validator_stake;
	    }
	    unreachable!("Validator should be found in loop.")
	}

	/// Choose a random group limited by `max_count` out of active stakers list.
	/// Stakers consist of pair (stake, PublikKey).
	/// Stakers array should not be empty, and every staker should have stake more than 0.
	///
	/// Returns Group of validators, and new leader
	pub fn choose_validators(
	    mut stakers: StakersGroup,
	    random: Hash,
	    max_group_size: usize,
	) -> ConsensusGroup {
	    assert!(!stakers.is_empty());
	    assert!(max_group_size > 0);
	    let mut witnesses = BTreeMap::new();

	    let mut seed = [0u8; 32];
	    seed.copy_from_slice(random.base_vector());

	    let mut rng = IsaacRng::from_seed(seed);

	    for _ in 0..max_group_size {
	        let rand = rng.gen::<i64>();
	        let index = select_winner(stakers.iter(), rand).unwrap();

	        let winner = stakers.remove(&index);
	        witnesses.insert(index, winner.unwrap());

	        if stakers.is_empty() {
	            break;
	        }
	    }
	    let rand = rng.gen::<i64>();
	    let leader = select_winner(witnesses.iter(), rand).unwrap();
	    ConsensusGroup { witnesses, leader }
	}
}

fn generate_key(num: usize) -> SecurePublicKey {
	 let mut rng = IsaacRng::seed_from_u64(num as u64);
	 let buffer: Vec<_> = (0..65).into_iter().map(|_| rng.gen::<u8>()).collect();
	 SecurePublicKey::try_from_bytes(&buffer).unwrap()

}

fn elect_new(b: &mut Bencher, stakers_size: usize, group_size: usize) {

    let stakes: BTreeMap<_,_> = (0..stakers_size).into_iter().map(|num|(generate_key(num), 1)).collect();
    assert_eq!(stakes.len(), stakers_size);
	let hash = Hash::digest(&1u64);
	b.iter(|| {
		let grp = election2::choose_validators(stakes.clone(), hash, group_size);
		// assert_eq!(grp.witnesses.len(), group_size);
	})
}


fn elect_old(b: &mut Bencher, stakers_size: usize, group_size: usize) {

    let stakes: Vec<_> = (0..stakers_size).into_iter().map(|num|(generate_key(num), 1)).collect();
    assert_eq!(stakes.len(), stakers_size);
	let hash = Hash::digest(&1u64);
	b.iter(|| {
		let grp = election::choose_validators(stakes.clone(), hash, group_size);
		// assert_eq!(grp.witnesses.len(), group_size);
	})
}

fn criterion_benchmark(c: &mut Criterion) {
	c.bench_function("election vector, stakers = 10000", |b| elect_old(b, 10000, 200));
	c.bench_function("election btreemap, stakers = 10000", |b| elect_new(b, 10000, 200));

	c.bench_function("election vector, stakers = 100000", |b| elect_old(b, 100000, 200));
	c.bench_function("election btreemap, stakers = 100000", |b| elect_new(b, 100000, 200));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);