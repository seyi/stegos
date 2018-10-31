//! mod.rs - Single-curve ECC on Curve1174

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
//

#![allow(non_snake_case)]
#![allow(unused)]

use rand::prelude::*;

use std::fmt;
use std::mem;

use hex;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use hash::*;
use std::cmp::Ordering;
use utils::*;

mod winvec; // window vectors for point multiplication
use self::winvec::*;

mod lev32; // little-endian byte vector represetation
use self::lev32::*;

// TODO: after debugging, make private u256
pub mod u256; // internal represntation of field elements
use self::u256::*;

pub mod fields;
use self::fields::*;

// TODO: after debugging, make private fq51
pub mod fq51; // coord representation for Elliptic curve points
use self::fq51::*;

pub mod ecpt; // uncompressed points, affine & projective coords
use self::ecpt::*;

pub mod cpt; // compressed point representation
use self::cpt::*;

use lazy_static::*;

// -------------------------------------------------------
// Curve1174 General Constants
// Curve is Edwards curve:  x^2 + y^2 = 1 + d*x^2*y^2
// embedded with cofactor, h, into prime field Fq,
// with additive field Fr on curve.

pub const CURVE_D: i64 = -1174; // the d value in the curve equation
pub const CURVE_H: i64 = 4; // cofactor of curve group

lazy_static! {
    pub static ref R: U256 =
        U256::from_str("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C971").unwrap();
    pub static ref Q: U256 =
        U256::from_str("07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7").unwrap();
    pub static ref G: ECp = {
        let gen_x =
            Fq::from_str("037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA")
                .unwrap();
        let gen_y =
            Fq::from_str("06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E")
                .unwrap();
        ECp::try_from_xy(&gen_x, &gen_y).unwrap()
    };
}

pub enum CurveError {
    NotQuadraticResidue,
    PointNotOnCurve,
}

impl fmt::Debug for CurveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                CurveError::NotQuadraticResidue => "CurveError::NotQuadraticResidue",
                CurveError::PointNotOnCurve => "CurveError::PointNotOnCurve",
            }
        )
    }
}

// -------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_hex() {
        let s = "0123456789abcdefABCDEF";
        let mut v: [u8; 22] = [0; 22];
        let mut ix = 0;
        for c in s.chars() {
            match c.to_digit(16) {
                Some(d) => {
                    v[ix] = d as u8;
                    ix += 1;
                }
                None => panic!("Invalid hex digit"),
            }
        }
        assert!(
            v == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    #[should_panic]
    fn tst_badhex() {
        let s = "ghijk";
        for c in s.chars() {
            match c.to_digit(16) {
                Some(d) => println!("{}", d),
                None => panic!("Invalid hex digit"),
            }
        }
    }

    #[test]
    fn tst_str_to_elt() {
        let Fq51(ev) =
            Coord::from_str("0000000000000000000000000000000000000000000000000000000000000123")
                .unwrap();
        assert!(ev == [0x123, 0, 0, 0, 0]);
    }

    #[test]
    fn test_new_point() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let gen_x = Fq::from_str(sx).unwrap();
        let gen_y = Fq::from_str(sy).unwrap();
        let pt1 = ECp::try_from_xy(&gen_x, &gen_y).unwrap();

        let gx = Fq::from_str(&sx).unwrap();
        let gy = Fq::from_str(&sy).unwrap();
        let pt2 = ECp::try_from_xy(&gx, &gy).unwrap();

        assert_eq!(pt1, pt2);
    }

    #[test]
    fn test_add() {
        let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA";
        let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E";

        let gen_x = Coord::from_str(sx).unwrap();
        let gen_y = Coord::from_str(sy).unwrap();

        let mut sum = Coord::zero();
        gadd(&gen_x, &gen_y, &mut sum);

        let gx = Coord::from_str(&sx).unwrap();
        let gy = Coord::from_str(&sy).unwrap();
        let gz = gx + gy;

        assert_eq!(gz, sum);
    }

    #[test]
    #[should_panic]
    fn check_bad_compression() {
        let pt = ECp::compress(ECp::inf());
        let ept = ECp::decompress(pt).unwrap();
    }
}

// ------------------------------------------------------------------------------------------

pub fn curve1174_tests() {
    let smul = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF77965C4DFD307348944D45FD166C970"; // *ed-r* - 1
    let sx = "037FBB0CEA308C479343AEE7C029A190C021D96A492ECD6516123F27BCE29EDA"; // *ed-gen* x
    let sy = "06B72F82D47FB7CC6656841169840E0C4FE2DEE2AF3F976BA4CCB1BF9B46360E"; // *ed-gen* y

    let gx = Fq::from_str(&sx).unwrap();
    let gy = Fq::from_str(&sy).unwrap();
    let mx = Fr::from_str(&smul).unwrap();
    let mut pt2: ECp = ECp::inf();
    for _ in 0..100 {
        let pt1 = ECp::try_from_xy(&gx, &gy).unwrap();
        pt2 = pt1 * mx;
    }
    println!("pt2: {}", pt2);

    let pt1 = ECp::try_from_xy(&gx, &gy).unwrap();
    let pt2 = pt1 + pt1;
    println!("ptsum {}", pt2);

    let tmp = Fr::from(2);
    let tmp2 = 1 / tmp;
    // println!("1/mul: {}", 1/Fr::from(2));
    // println!("unity? {}", (1/Fr::from(2)) * 2);
    println!("mul: {}", tmp);
    println!("1/2 = {}", tmp2);
    println!("R = {}", *R);
    println!("mx: {}", tmp * tmp2);
    /* */
    let _ = StdRng::from_entropy();
    let mut r = StdRng::from_rng(thread_rng()).unwrap();
    let mut x = [0u8; 32];
    for _ in 0..10 {
        r.fill_bytes(&mut x);
        println!("{:?}", &x);
    }

    let gen_x = Fq::from_str(&sx).unwrap();
    let gen_y = Fq::from_str(&sy).unwrap();
    let pt = ECp::try_from_xy(&gen_x, &gen_y).unwrap();

    println!("The Generator Point");
    println!("gen_x: {}", gen_x);
    println!("gen_y: {}", gen_y);
    println!("gen_pt: {}", pt);

    println!("x+y: {}", gen_x + gen_y);
    /* */
    let ept = ECp::from(Hash::from_vector(b"Testing12")); // produces an odd Y
    let cpt = Pt::from(ept); // MSB should be set
    let ept2 = ECp::try_from(cpt).unwrap();
    println!("hash -> {}", ept);
    println!("hash -> {}", cpt);
    println!("hash -> {}", ept2);

    // simulate Bulletproof basis vector derivation
    /*
    let mut gen_hash = Hash::digest(&*G);
    let hgen = Pt::from(ECp::from(gen_hash));
    println!("hgen = {}", hgen);
    let mut g_bpvec = Vec::<Pt>::new();
    for ix in 0..64 {
        gen_hash = Hash::digest(&gen_hash);
        let pt = ECp::from(gen_hash);
        let cpt = Pt::from(pt);
        g_bpvec.push(cpt);
        println!("g{}: {}", ix, cpt);
    }
    let mut h_bpvec = Vec::<Pt>::new();
    for ix in 0..64 {
        gen_hash = Hash::digest(&gen_hash);
        let pt = ECp::from(gen_hash);
        let cpt = Pt::from(pt);
        h_bpvec.push(cpt);
        println!("h{}: {}", ix, cpt);
    }
    */}