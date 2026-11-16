use k256::elliptic_curve::{ops::{LinearCombinationExt, MulByGenerator}, Field};
use k256::{ProjectivePoint as P, Scalar as S};
use k256::elliptic_curve::rand_core::{RngCore, CryptoRng, Error};
use std::time::Instant;
use std::hint::black_box;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar as DS, traits::VartimeMultiscalarMul, constants::ED25519_BASEPOINT_TABLE};

struct Rng(u64);
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
    fn next_u64(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn fill_bytes(&mut self, d: &mut [u8]) { for b in d.iter_mut() { *b = self.next_u64() as u8; } }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), Error> { self.fill_bytes(d); Ok(()) }
}
impl CryptoRng for Rng {}

fn time<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) -> f64 {
    black_box(f());
    let st = Instant::now();
    for _ in 0..iters { black_box(f()); }
    let us = st.elapsed().as_secs_f64() * 1e6 / iters as f64;
    println!("{label:<58} {us:>9.1} us");
    us
}
fn mul_small(p: P, k: u64) -> P {
    let mut acc = P::IDENTITY;
    for b in (0..64 - k.leading_zeros()).rev() { acc = acc.double(); if (k >> b) & 1 == 1 { acc += p; } }
    acc
}
fn horner_full(c: &[P], node: u64) -> P { let x = S::from(node); let mut acc = P::IDENTITY; for p in c[1..].iter().rev() { acc = (acc + p) * x; } acc + c[0] }
fn horner_small(c: &[P], node: u64) -> P { let mut acc = P::IDENTITY; for p in c[1..].iter().rev() { acc = mul_small(acc + p, node); } acc + c[0] }
fn rand128(r: &mut Rng) -> S { let mut b = [0u8; 32]; r.fill_bytes(&mut b[16..]); S::from(u128::from_be_bytes(b[16..].try_into().unwrap())) }

fn main() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    let g = P::GENERATOR;
    let q = g * S::random(&mut r);
    let s = S::random(&mut r);
    println!("== secp256k1 (k256 0.13.4)");
    let var = time("variable-base mul", 2000, || q * s);
    time("generator mul (g * s, generic)", 2000, || g * s);
    time("generator mul (mul_by_generator, table)", 2000, || P::mul_by_generator(&s));
    {
        let t=7usize; let polys: Vec<S> = (0..t).map(|_| S::random(&mut r)).collect();
        let coms: Vec<P> = polys.iter().map(|a| g * a).collect();
        let sh = polys.iter().rev().fold(S::ZERO, |v, a| v * S::from(9u64) + a);
        time("share check t=7, small Horner + table generator mul", 2000, || P::mul_by_generator(&sh) == horner_small(&coms, 9));
        time("small-index Horner alone, t=7, i=9", 5000, || horner_small(&coms, 9));
    }
    time("lincomb 2 terms (aG + bQ)", 2000, || P::lincomb_ext(&[(g, s), (q, s)]));
    for (n, t) in [(9u64, 7usize), (17, 12)] {
        println!("-- n={n} t={t}");
        let m = 16usize;
        let polys: Vec<Vec<S>> = (0..m).map(|_| (0..t).map(|_| S::random(&mut r)).collect()).collect();
        let coms: Vec<Vec<P>> = polys.iter().map(|p| p.iter().map(|a| g * a).collect()).collect();
        let node = n;
        let shares: Vec<S> = polys.iter().map(|p| p.iter().rev().fold(S::ZERO, |v, a| v * S::from(node) + a)).collect();
        assert_eq!(horner_full(&coms[0], node), g * shares[0]);
        assert_eq!(horner_small(&coms[0], node), g * shares[0]);
        let a = time("share check, prototype (full-width Horner)", 500, || g * shares[0] == horner_full(&coms[0], node));
        let b = time("share check, small-scalar Horner", 2000, || g * shares[0] == horner_small(&coms[0], node));
        println!("   speedup {:.1}x", a / b);
        let c = time("16 share checks, small-scalar Horner", 200, || (0..m).all(|i| g * shares[i] == horner_small(&coms[i], node)));
        // batch: random 128-bit r_m; aggregate commitments per coefficient, then one small Horner
        let d = time("16 share checks, one RLC batch (lincomb, 128-bit r)", 100, || {
            let rs: Vec<S> = (0..m).map(|_| rand128(&mut r)).collect();
            let agg: Vec<P> = (0..t).map(|k| { let terms: Vec<(P, S)> = (0..m).map(|i| (coms[i][k], rs[i])).collect(); P::lincomb_ext(&terms[..]) }).collect();
            let sh: S = (0..m).map(|i| rs[i] * shares[i]).sum();
            g * sh == horner_small(&agg, node)
        });
        println!("   16 prototype checks {:.0} us; small {:.0} us; batch {:.0} us ({:.1}x vs prototype)", 16.0 * a, c, d, 16.0 * a / d);
        // partial verification: sigma*(D_i + rho E_i) + c X_i with cached evaluations: one 3-term lincomb
        let (di, ei, xi) = (coms[0][0], coms[1][0], coms[2][0]);
        time("verify partial, cached evals (g*s == lincomb3)", 2000, || g * s == P::lincomb_ext(&[(di, S::ONE), (ei, s), (xi, s)]));
        // batch verify t partials via RLC: one lincomb of 2t+... terms
        time("verify t partials, one RLC lincomb", 300, || {
            let mut terms: Vec<(P, S)> = Vec::new();
            for i in 0..t { let ri = rand128(&mut r); terms.push((coms[i][0], ri)); terms.push((coms[i][1], ri * s)); terms.push((coms[i][2], ri * s)); }
            g * s == P::lincomb_ext(&terms[..])
        });
    }
    // signatures
    use k256::ecdsa::{SigningKey, signature::{Signer, Verifier}, Signature};
    let sk = SigningKey::random(&mut r); let vk = *sk.verifying_key();
    let sig: Signature = sk.sign(b"post"); 
    time("k256 ECDSA verify (one board post)", 2000, || vk.verify(b"post", &sig).is_ok());
    let ssk = k256::schnorr::SigningKey::random(&mut r); let svk = *ssk.verifying_key();
    let ssig: k256::schnorr::Signature = ssk.sign(b"post");
    time("k256 BIP340 verify", 2000, || svk.verify(b"post", &ssig).is_ok());

    println!("== edwards25519 (curve25519-dalek 4.1.3)");
    let mut wide = [0u8; 64]; r.fill_bytes(&mut wide);
    let ds = DS::from_bytes_mod_order_wide(&wide);
    let dq = &ds * ED25519_BASEPOINT_TABLE;
    let dvar = time("variable-base mul", 2000, || dq * ds);
    time("basepoint mul (table)", 2000, || &ds * ED25519_BASEPOINT_TABLE);
    time("is_torsion_free", 2000, || dq.is_torsion_free());
    time("vartime double-base (aA + bB)", 2000, || EdwardsPoint::vartime_double_scalar_mul_basepoint(&ds, &dq, &ds));
    let pts: Vec<EdwardsPoint> = (0..112).map(|i| dq * DS::from(i as u64 + 3)).collect();
    let scs: Vec<DS> = (0..112).map(|i| ds * DS::from(i as u64 + 7)).collect();
    let ms = time("vartime MSM, 112 points, full scalars", 200, || EdwardsPoint::vartime_multiscalar_mul(scs.iter(), pts.iter()));
    println!("   per point {:.1} us = {:.2} variable-base muls", ms / 112.0, ms / 112.0 / dvar);
    let scs128: Vec<DS> = (0..112).map(|i| { let mut b = [0u8; 32]; b[..16].copy_from_slice(&(0x1234567890abcdefu128 * (i as u128 + 1)).to_le_bytes()); DS::from_bytes_mod_order(b) }).collect();
    time("vartime MSM, 112 points, 128-bit scalars", 200, || EdwardsPoint::vartime_multiscalar_mul(scs128.iter(), pts.iter()));
    use ed25519_dalek::{SigningKey as ESK, Signer as _, Verifier as _};
    let mut seed = [0u8; 32]; r.fill_bytes(&mut seed);
    let esk = ESK::from_bytes(&seed); let evk = esk.verifying_key(); let esig = esk.sign(b"post");
    time("ed25519-dalek verify (one board post)", 2000, || evk.verify(b"post", &esig).is_ok());
    time("ed25519-dalek verify_strict", 2000, || evk.verify_strict(b"post", &esig).is_ok());
    let _ = var;
}
