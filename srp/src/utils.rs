use digest::{Digest, Output};
use num_bigint::BigUint;

use crate::types::SrpGroup;

// u = H(PAD(A) | PAD(B))
pub fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BigUint::from_bytes_be(&u.finalize())
}

// k = H(N | PAD(g))
pub fn compute_k<D: Digest>(params: &SrpGroup) -> BigUint {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BigUint::from_bytes_be(d.finalize().as_slice())
}

// M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)
pub fn compute_m1<D: Digest>(
    params: &SrpGroup,
    identity_hash: &[u8],
    a_pub: &[u8],
    b_pub: &[u8],
    key: &[u8],
) -> Output<D> {
    let mut d_n = D::new();
    d_n.update(params.n.to_bytes_be());
    let h_n = d_n.finalize();

    let mut d_g = D::new();
    d_g.update(params.g.to_bytes_be());
    let h_g = d_g.finalize();

    let ng_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(n, g)| n ^ g).collect();

    let mut d = D::new();
    d.update(ng_xor);
    d.update(identity_hash);
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

// M2 = H(A, M1, K)
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &Output<D>, key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(m1);
    d.update(key);
    d.finalize()
}
