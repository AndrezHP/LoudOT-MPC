use ocelot::svole::{SVoleSender, SVoleReceiver, wykw};
use rand::{CryptoRng, Rng, SeedableRng};
use ocelot::svole::wykw::{LPN_EXTEND_EXTRASMALL, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_SETUP_EXTRASMALL, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL, LpnParams};
use scuttlebutt::{field::{FiniteField}, AbstractChannel};
use sha3::{digest::{Update}};
use blake2::{Blake2b, Digest};
use aes::cipher::consts::{U16, U32};
use std::marker::PhantomData;
use rand_chacha::ChaCha20Rng;

fn main() {
    println!("Hello Mr. PC?");
}

trait Lsb {
    fn lsb(self) -> bool;
}

impl Lsb for u128 {
    fn lsb(self) -> bool {
        (self & 1) == 1
    }
}

type Blake2b128 = Blake2b<U16>;
type Blake2b256 = Blake2b<U32>;
pub fn blake2_128(bytes: &[u8]) -> u128 {
    let mut hasher = Blake2b128::new();
    Update::update(&mut hasher, bytes);
    let res = hasher.finalize();
    return u128::from_le_bytes(res.into());
}
pub fn blake2_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    Update::update(&mut hasher, bytes);
    let res = hasher.finalize();
    return res.into();
}

pub struct AuthTriple {
    x_share: bool,
    y_share: bool,
    z_share: bool,
    x_mac: u128,
    y_mac: u128,
    z_mac: u128,
    // Keys on the other party's shares
    x_key: u128,
    y_key: u128,
    z_key: u128,
}

pub struct TripleSender<FE: FiniteField> {
    x0_bits: Vec<bool>,
    x0_macs: Vec<u128>,
    y0_bits: Vec<bool>,
    y0_macs: Vec<u128>,
    z0_bits: Vec<bool>,
    r0_bits: Vec<bool>,
    r0_macs: Vec<u128>,
    delta: u128,
    x1_keys: Vec<u128>,
    y1_keys: Vec<u128>,
    z1_keys: Vec<u128>,
    r1_keys: Vec<u128>,
    type_data: PhantomData<FE>
}

impl<FE: FiniteField> TripleSender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG, lpn_setup_params: LpnParams, lpn_extend_paramd: LpnParams) -> Self {
        // Get authenticated bit keys and delta
        let mut svole_receiver: wykw::Receiver<FE> =
            wykw::Receiver::init(channel, rng, lpn_setup_params, lpn_extend_paramd).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let delta = fe_to_u128(&svole_receiver.delta());

        let fraction = vs.len() / 3;
        let x1_keys = vs[0..fraction].iter().map(|v| fe_to_u128(v)).collect();
        let y1_keys = vs[fraction..fraction * 2].iter().map(|v| fe_to_u128(v)).collect();
        let r1_keys = vs[fraction * 2..fraction * 3].iter().map(|v| fe_to_u128(v)).collect();

        // Get authenticated bits and macs
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, lpn_setup_params, lpn_extend_paramd).unwrap();
        let mut uws = Vec::new();
        svole_sender.send(channel, rng, &mut uws).unwrap();
        let mut x0_bits = Vec::new();
        let mut x0_macs = Vec::new();
        let mut y0_bits = Vec::new();
        let mut y0_macs = Vec::new();
        let mut r0_bits = Vec::new();
        let mut r0_macs = Vec::new();

        let fraction = uws.len() / 3;
        // Pool of uws for x0 bit and mac generation
        let x0_pool = &uws[0..fraction];
        // Pool of uws for y0 bit and mac generation
        let y0_pool = &uws[fraction..fraction * 2];
        // Pool of uws for r0 bit and mac generation
        let r0_pool = &uws[fraction * 2..fraction * 3];

        for (u, w) in x0_pool {
            x0_bits.push(*u.bit_decomposition().get(0).unwrap());
            x0_macs.push(fe_to_u128(w));
        }
        for (u, w) in y0_pool {
            y0_bits.push(*u.bit_decomposition().get(0).unwrap());
            y0_macs.push(fe_to_u128(w));
        }
        for (u, w) in r0_pool {
            r0_bits.push(*u.bit_decomposition().get(0).unwrap());
            r0_macs.push(fe_to_u128(w));
        }
        return Self {
            x0_bits,
            x0_macs,
            y0_bits,
            y0_macs,
            z0_bits: vec![],
            r0_bits,
            r0_macs,
            delta,
            x1_keys,
            y1_keys,
            z1_keys: vec![],
            r1_keys,
            type_data: PhantomData
        }
    }
    pub fn ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) -> Vec<bool> {
        let number_of_triples = self.x0_bits.len();
        let mut h: Vec<(bool, bool)> = Vec::new();
        let mut s0_bits: Vec<bool> = Vec::new();

        for (i , x1_key) in self.x1_keys.iter().enumerate() {
            let s0: bool = rng.gen();
            s0_bits.push(s0);
            let h0 = blake2_128(&x1_key.to_le_bytes()).lsb() ^ s0;
            let h1 = blake2_128(&(x1_key ^ self.delta).to_le_bytes()).lsb() ^ s0 ^ self.y0_bits[i];
            h.push((h0, h1));
        }

        // Receive H values from the channel
        let mut h_received: Vec<(bool, bool)> = Vec::new();
        for _ in 0..number_of_triples {
            let h0 = channel.read_bool().unwrap();
            let h1 = channel.read_bool().unwrap();
            h_received.push((h0, h1));
        }

        // TODO refrain from sending one at a time
        // Send H values on the channel
        for (h0, h1) in h {
            channel.write_bool(h0).unwrap();
            channel.write_bool(h1).unwrap();
        }
        channel.flush().unwrap();

        let mut v0_bits: Vec<bool> = Vec::new();
        for (i, x0_mac) in self.x0_macs.iter().enumerate() {
            let x0: bool = self.x0_bits[i];
            let h_x0: bool = if x0 { h_received[i].1} else { h_received[i].0};
            let t1: bool = h_x0 ^ blake2_128(&x0_mac.to_le_bytes()).lsb();
            let v0: bool = s0_bits[i] ^ t1;
            v0_bits.push(v0);
        }
        return v0_bits;
    }
    pub fn la_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, v0: Vec<bool>) {
        let number_of_triples = self.x0_bits.len();
        let mut z0: Vec<bool> = Vec::new();
        for i in 0..number_of_triples {
            z0.push(v0[i] ^ (self.x0_bits[i] && self.y0_bits[i]));
        }
        let mut d0: Vec<bool> = Vec::new();
        for i in 0..number_of_triples {
            d0.push(z0[i] ^ self.r0_bits[i]);
        }

        // Sender d0 values on the channel
        for &d0_bit in &d0 {
            channel.write_bool(d0_bit).unwrap();
        }
        channel.flush().unwrap();
        // Receive d1 values from the channel
        let mut d1: Vec<bool> = Vec::new();
        for _ in 0..number_of_triples {
            d1.push(channel.read_bool().unwrap());
        }

        let mut z1_keys = Vec::new();
        for i in 0..number_of_triples {
            z1_keys.push(self.r1_keys[i] ^ (d1[i] as u128 * self.delta));
        }

        // Get U from B
        let mut us: Vec<u128> = Vec::new();
        for _ in 0..number_of_triples {
            let u = channel.read_u128().unwrap();
            us.push(u);
        }

        let mut rs: Vec<u128> = Vec::new();
        let mut ws = Vec::new();
        for i in 0..number_of_triples {
            let r: u128 = rng.gen();
            rs.push(r);
            let v0 = blake2_128(&[self.x0_macs[i].to_le_bytes(), self.r0_macs[i].to_le_bytes()].concat());
            let v1 = blake2_128(&[self.x0_macs[i].to_le_bytes(), (self.r0_macs[i] ^ self.y0_macs[i]).to_le_bytes()].concat());
            let hash0 = blake2_128(&self.x1_keys[i].to_le_bytes());
            let hash1 = blake2_128(&(self.x1_keys[i] ^ self.delta).to_le_bytes());
            if !self.x0_bits[i] {
                let w00 = hash0 ^ v0 ^ r;
                let w01 = hash1 ^ v1 ^ r;
                ws.push((w00, w01));
            } else {
                let w11 = hash1 ^ v0 ^ us[i] ^ r;
                let w10 = hash0 ^ v1 ^ us[i] ^ r;
                ws.push((w10, w11));
            }
        }

        // Send Ws
        for (w0, w1) in ws {
            channel.write_u128(w0).unwrap();
            channel.write_u128(w1).unwrap();
        }
        channel.flush().unwrap();

        // EQ box
        assert!(self.eq(channel, rng, &rs));

        // Do it all again
        let mut ts: Vec<u128> = Vec::new();
        let mut us: Vec<u128>  = Vec::new();
        for i in 0..number_of_triples {
            if !self.x0_bits[i] {
                let t0 = blake2_128(&[self.x1_keys[i].to_le_bytes(), (z1_keys[i] ^ (z0[i] as u128 * self.delta)).to_le_bytes()].concat());
                ts.push(t0);
                let u0 = t0 ^ blake2_128(&[(self.x1_keys[i] ^ self.delta).to_le_bytes(), (self.y1_keys[i] ^ z1_keys[i] ^ (self.y0_bits[i] ^ z0[i]) as u128 * self.delta).to_le_bytes()].concat());
                us.push(u0);
            } else {
                let t1 = blake2_128(&[self.x1_keys[i].to_le_bytes(), (self.y1_keys[i] ^ z1_keys[i] ^ ((self.y0_bits[i] ^ z0[i]) as u128 * self.delta)).to_le_bytes()].concat());
                ts.push(t1);
                let u1 = t1 ^ blake2_128(&[(self.x1_keys[i] ^ self.delta).to_le_bytes(), (z1_keys[i] ^ (z0[i] as u128 * self.delta)).to_le_bytes()].concat());
                us.push(u1)
            }
        }

        // Sending U values on the channel
        for &u in &us {
            channel.write_u128(u).unwrap();
        }
        channel.flush().unwrap();

        // let mut Ws: Vec<u128> = Vec::new();
        let mut r_primes = Vec::new();
        for i in 0..number_of_triples {
            let w0 = channel.read_u128().unwrap();
            let w1 = channel.read_u128().unwrap();
            let mac_hash = blake2_128(&self.x0_macs[i].to_le_bytes());
            if !self.x0_bits[i] {
                r_primes.push(w0 ^ mac_hash ^ ts[i]);
            } else {
                r_primes.push(w1 ^ mac_hash ^ ts[i]);
            }
        }

        // EQ box
        assert!(self.eq(channel, rng, &r_primes));

        self.z0_bits = z0;
        self.z1_keys = z1_keys;
    }
    // From NNOB/TinyOT
    fn eq<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, xs: &Vec<u128>) -> bool {
        let mut rs: Vec<u128> = Vec::new();
        for x in xs {
            let r: u128 = rng.gen();
            rs.push(r);
            let c = blake2_128(&[x.to_le_bytes(), r.to_le_bytes()].concat());
            channel.write_u128(c).unwrap();
        }
        channel.flush().unwrap();

        for i in 0..xs.len() {
            let y = channel.read_u128().unwrap();
            if xs[i] != y {
                return false;
            }
        }

        for i in 0..xs.len() {
            channel.write_u128(xs[i]).unwrap();
            channel.write_u128(rs[i]).unwrap();
        }
        channel.flush().unwrap();

        return true;
    }
    pub fn wrk17_a_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, b: usize) -> Vec<AuthTriple> {
        self.permute(channel, rng);
        return self.bucketing(channel, b);
    }

    fn bucketing<C: AbstractChannel>(&mut self, channel: &mut C, b: usize) -> Vec<AuthTriple> {
        let mut triples = Vec::new();
        for i in (0..self.z0_bits.len()).step_by(b) {
            let mut x_share = self.x0_bits[i];
            let mut y_share = self.y0_bits[i];
            let mut z_share = self.z0_bits[i];
            let mut x_mac = self.x0_macs[i];
            let mut y_mac = self.y0_macs[i];
            let mut z_mac = self.r0_macs[i];
            let mut x_key = self.x1_keys[i];
            let mut y_key = self.y1_keys[i];
            let mut z_key = self.z1_keys[i];
            for j in 1..b {
                let mut d = y_share ^ self.y0_bits[j];
                let d_mac = y_mac ^ self.y0_macs[j];
                channel.write_bool(d).unwrap();
                channel.write_u128(d_mac).unwrap();
                channel.flush().unwrap();

                let d_prime = channel.read_bool().unwrap();
                let d_prime_mac = channel.read_u128().unwrap();

                let d_prime_key = y_key ^ self.y1_keys[j];

                let d_delta = if d_prime { self.delta } else { 0 };
                if d_prime_mac != d_prime_key ^ d_delta {
                    panic!("Wrong MAC");
                }

                d = d ^ d_prime;

                x_share = x_share ^ self.x0_bits[j];
                x_mac = x_mac ^ self.x0_macs[j];
                x_key = x_key ^ self.x1_keys[j];

                if d {
                    z_share = z_share ^ self.z0_bits[j] ^ self.x0_bits[j];
                    z_mac = z_mac ^ self.r0_macs[j] ^ self.x0_macs[j];
                    z_key = z_key ^ self.z1_keys[j] ^ self.x1_keys[j];
                } else {
                    z_share = z_share ^ self.z0_bits[j];
                    z_mac = z_mac ^ self.r0_macs[j];
                    z_key = z_key ^ self.z1_keys[j];
                }
            }
            let triple = AuthTriple {
                x_share,
                y_share,
                z_share,
                x_mac,
                y_mac,
                z_mac,
                x_key,
                y_key,
                z_key,
            };
            triples.push(triple);
        }
        return triples;
    }

    pub fn permute<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {
        let s: u128 = rng.gen();
        let hash_s = blake2_128(&[s.to_le_bytes()].concat());
        channel.write_u128(hash_s).unwrap();
        channel.flush().unwrap();

        let t = channel.read_u128().unwrap();

        channel.write_u128(s).unwrap();
        channel.flush().unwrap();

        let seed: [u8; 32] = blake2_256(&<[u8; 32]>::try_from([s.to_le_bytes(), t.to_le_bytes()].concat()).unwrap());

        let mut cha_rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed);

        for i in (0..self.z0_bits.len()).rev() {
            let j = cha_rng.gen_range(0..(i + 1));
            self.x0_bits.swap(i, j);
            self.y0_bits.swap(i, j);
            self.z0_bits.swap(i, j);
            self.r0_bits.swap(i, j);
            self.x0_macs.swap(i, j);
            self.y0_macs.swap(i, j);
            self.r0_macs.swap(i, j);
            self.x1_keys.swap(i, j);
            self.y1_keys.swap(i, j);
            self.z1_keys.swap(i, j);
        }
    }

    pub fn hss17_ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, b: usize) {
        let number_of_triples = self.x0_bits.len();

        let mut us = Vec::new();
        let mut ds = Vec::new();

        for(i, x1_key) in self.x1_keys.iter().enumerate() {
            let u0 = blake2_128(&x1_key.to_le_bytes()).lsb();
            us.push(u0);
            let v0 = blake2_128(&(x1_key ^ self.delta).to_le_bytes()).lsb();
            let d0 = u0 ^ v0 ^ self.y0_bits[i];
            ds.push(d0);
        }

        for d in ds {
            channel.write_bool(d).unwrap();
        }
        channel.flush().unwrap();

        let mut ds_received = Vec::new();
        for _ in 0..number_of_triples {
            ds_received.push(channel.read_bool().unwrap());
        }

        let mut z0_bits = Vec::new();
        for i in 0..number_of_triples {
            let w0 = blake2_128(&self.x0_macs[i].to_le_bytes()).lsb() ^ (self.x0_bits[i] && ds_received[i]);
            let z0 = (us[i] ^ w0) ^ (self.x0_bits[i] && self.y0_bits[i]);
            z0_bits.push(z0);
        }

        for i in 0..number_of_triples {
            let c0 = z0_bits[i] ^ self.r0_bits[i];
            channel.write_bool(c0).unwrap();
        }
        channel.flush().unwrap();

        let mut c1 = Vec::new();
        for _ in 0..number_of_triples {
            c1.push(channel.read_bool().unwrap());
        }

        let mut z1_keys = Vec::new();
        for i in 0..number_of_triples {
            z1_keys.push(self.r1_keys[i] ^ (c1[i] as u128 * self.delta));
        }

        self.z0_bits = z0_bits;
        self.z1_keys = z1_keys;
    }

    pub fn hss17_a_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, b: usize) -> Vec<AuthTriple> {
        self.hss17_ha_and(channel, rng, b);
        // Cut-and-choose (c can be as low as 3)
        // Reveal z and z_mac, if check fails -> abort, repeat for c triples
        let s: u128 = rng.gen();
        let hash_s = blake2_128(&[s.to_le_bytes()].concat());
        channel.write_u128(hash_s).unwrap();
        channel.flush().unwrap();

        let t = channel.read_u128().unwrap();

        channel.write_u128(s).unwrap();

        let seed: [u8; 32] = blake2_256(&<[u8; 32]>::try_from([s.to_le_bytes(), t.to_le_bytes()].concat()).unwrap());

        let mut cha_rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed);

        let mut idx = Vec::new();
        for _ in 0..3 {
            let i = cha_rng.gen_range(0..self.z0_bits.len());
            idx.push(i);

            channel.write_bool(self.z0_bits[i]).unwrap();
            channel.write_u128(self.r0_macs[i]).unwrap();
            channel.flush().unwrap();
            // self.x0_bits.remove(i);
            // self.y0_bits.remove(i);
            // self.r0_bits.remove(i);
            // self.x0_macs.remove(i);
            // self.y0_macs.remove(i);
            // self.x1_keys.remove(i);
            // self.y1_keys.remove(i);
            // self.r1_keys.remove(i);

            let z1 = channel.read_bool().unwrap();
            let z1_mac = channel.read_u128().unwrap();

            if self.z1_keys[i] != z1_mac ^ (z1 as u128 * self.delta) {
                panic!("MAC check failed");
            };
        }

        // Check correctness
        // Choose remaining triples, assign to buckets, do pairwise sacrifice
        let mut verified_x0_bits = Vec::new();
        let mut verified_x0_macs = Vec::new();
        let mut verified_y0_bits = Vec::new();
        let mut verified_y0_macs = Vec::new();
        let mut verified_z0_bits = Vec::new();
        let mut verified_r0_macs = Vec::new();
        let mut verified_x1_keys = Vec::new();
        let mut verified_y1_keys = Vec::new();
        let mut verified_z1_keys = Vec::new();
        self.permute(channel, rng);
        for i in (0..self.z0_bits.len()).step_by(b) {
            verified_x0_bits.push(self.x0_bits[i]);
            verified_y0_bits.push(self.y0_bits[i]);
            verified_z0_bits.push(self.z0_bits[i]);
            verified_x0_macs.push(self.x0_macs[i]);
            verified_y0_macs.push(self.y0_macs[i]);
            verified_r0_macs.push(self.r0_macs[i]);
            verified_x1_keys.push(self.x1_keys[i]);
            verified_y1_keys.push(self.y1_keys[i]);
            verified_z1_keys.push(self.z1_keys[i]);
            for j in i + 1..i + b + 1 {
                if i + b + 1 >= self.z0_bits.len() {
                    break;
                }
                let d1 = self.x0_bits[i] ^ self.x0_bits[j];
                let e1 = self.y0_bits[i] ^ self.y0_bits[j];
                let d1_mac = self.x0_macs[i] ^ self.x0_macs[j];
                let e1_mac = self.y0_macs[i] ^ self.y0_macs[j];

                channel.write_bool(d1).unwrap();
                channel.write_bool(e1).unwrap();
                channel.write_u128(d1_mac).unwrap();
                channel.write_u128(e1_mac).unwrap();
                channel.flush().unwrap();

                let d2_key = self.x1_keys[i] ^ self.x1_keys[j];
                let e2_key = self.y1_keys[i] ^ self.y1_keys[j];

                let d2_received = channel.read_bool().unwrap();
                let e2_received = channel.read_bool().unwrap();
                let d2_mac_received = channel.read_u128().unwrap();
                let e2_mac_received = channel.read_u128().unwrap();

                if d2_mac_received != d2_key ^ (d2_received as u128 * self.delta) {
                    panic!("MAC check failed");
                }

                if e2_mac_received != e2_key ^ (e2_received as u128 * self.delta) {
                    panic!("MAC check failed");
                }

                let d = d1 ^ d2_received;
                let e = e1 ^ e2_received;

                let f1 = self.z0_bits[i] ^ self.z0_bits[j] ^ (d && self.y0_bits[i]) ^ (e && self.x0_bits[i]) ^ (d && e);

                let f1_mac = self.r0_macs[i] ^ self.r0_macs[j] ^ (d as u128 * self.y0_macs[i]) ^ (e as u128 * self.x0_macs[i]);

                // Send f and f_mac to the other party
                channel.write_bool(f1).unwrap();
                channel.write_u128(f1_mac).unwrap();
                channel.flush().unwrap();

                // Receive f and f_mac from the other party and check
                let f2_received = channel.read_bool().unwrap();
                let f2_mac_received = channel.read_u128().unwrap();
                let f2_key = self.z1_keys[i] ^ self.z1_keys[j] ^
                    (d as u128 * self.y1_keys[i]) ^
                    (e as u128 * self.x1_keys[i]);

                if f2_mac_received != f2_key ^ (f2_received as u128 * self.delta) {
                    panic!("MAC check failed");
                }

                let f = f1 ^ f2_received;
                if f {
                    panic!("f is not ZERO! It was: {}, i = {}", f, i);
                }
            }
        }

        self.x0_bits = verified_x0_bits;
        self.y0_bits = verified_y0_bits;
        self.z0_bits = verified_z0_bits;
        self.x0_macs = verified_x0_macs;
        self.y0_macs = verified_y0_macs;
        self.r0_macs = verified_r0_macs;
        self.x1_keys = verified_x1_keys;
        self.y1_keys = verified_y1_keys;
        self.z1_keys = verified_z1_keys;

        // Remove leakage -> similar to wrk17_a_and
        return self.bucketing(channel, b);
    }
}

pub struct TripleReceiver<FE: FiniteField> {
    x1_bits: Vec<bool>,
    x1_macs: Vec<u128>,
    y1_bits: Vec<bool>,
    y1_macs: Vec<u128>,
    z1_bits: Vec<bool>,
    r1_bits: Vec<bool>,
    r1_macs: Vec<u128>,
    delta: u128,
    x0_keys: Vec<u128>,
    y0_keys: Vec<u128>,
    z0_keys: Vec<u128>,
    r0_keys: Vec<u128>,
    type_data: PhantomData<FE>
}

impl<FE: FiniteField> TripleReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG, lpn_setup_params: LpnParams, lpn_extend_params: LpnParams) -> Self {
        // Get authenticated bits and macs
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, lpn_setup_params, lpn_extend_params).unwrap();
        let mut uws = Vec::new();
        svole_sender.send(channel, rng, &mut uws).unwrap();

        let mut x1_bits = Vec::new();
        let mut x1_macs = Vec::new();
        let mut y1_bits = Vec::new();
        let mut y1_macs = Vec::new();
        let mut r1_bits = Vec::new();
        let mut r1_macs = Vec::new();

        let fraction = uws.len() / 3;

        // Pool of uws for x1 bit and mac generation
        let x1_pool = &uws[0..fraction];

        // Pool of uws for y1 bit and mac generation
        let y1_pool = &uws[fraction..fraction * 2];

        // Pool of uws for r bit and mac generation
        let r1_pool = &uws[fraction * 2..fraction * 3];

        for (u, w) in x1_pool {
            x1_bits.push(*u.bit_decomposition().get(0).unwrap());
            x1_macs.push(fe_to_u128(w));
        }
        for (u, w) in y1_pool {
            y1_bits.push(*u.bit_decomposition().get(0).unwrap());
            y1_macs.push(fe_to_u128(w));
        }
        for (u, w) in r1_pool {
            r1_bits.push(*u.bit_decomposition().get(0).unwrap());
            r1_macs.push(fe_to_u128(w));
        }

        // Get authenticated bit keys and delta
        let mut svole_receiver: wykw::Receiver<FE> =
            wykw::Receiver::init(channel, rng, lpn_setup_params, lpn_extend_params).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let delta = fe_to_u128(&svole_receiver.delta());

        let x0_keys = vs[0..fraction].iter().map(|v| fe_to_u128(v)).collect();
        let y0_keys = vs[fraction..fraction * 2].iter().map(|v| fe_to_u128(v)).collect();
        let r0_keys = vs[fraction * 2..fraction * 3].iter().map(|v| fe_to_u128(v)).collect();

        return Self {
            x1_bits,
            x1_macs,
            y1_bits,
            y1_macs,
            z1_bits: vec![],
            r1_bits,
            r1_macs,
            delta,
            x0_keys,
            y0_keys,
            z0_keys: vec![],
            r0_keys,
            type_data: PhantomData
        }
    }
    pub fn ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) -> Vec<bool> {
        let number_of_triples = self.x1_bits.len();
        let mut h: Vec<(bool, bool)> = Vec::new();
        let mut t0_bits: Vec<bool> = Vec::new();

        for (i, x0_key) in self.x0_keys.iter().enumerate() {
            let t0: bool = rng.gen();
            t0_bits.push(t0);
            let h0 = blake2_128(&x0_key.to_le_bytes()).lsb() ^ t0;
            let h1 = blake2_128(&(x0_key ^ self.delta).to_le_bytes()).lsb() ^ t0 ^ self.y1_bits[i];
            h.push((h0, h1));
        }

        // Sender H values on the channel
        for &(h0, h1) in &h {
            channel.write_bool(h0).unwrap();
            channel.write_bool(h1).unwrap();
        }
        channel.flush().unwrap();

        // Receive H values from the channel
        let mut h_received: Vec<(bool, bool)> = Vec::new();
        for _ in 0..number_of_triples {
            let h0 = channel.read_bool().unwrap();
            let h1 = channel.read_bool().unwrap();
            h_received.push((h0, h1));
        }

        let mut v1_bits: Vec<bool> = Vec::new();
        for (i, x1_mac) in self.x1_macs.iter().enumerate() {
            let x1: bool = self.x1_bits[i];
            let h_x1: bool = if x1 { h_received[i].1 } else { h_received[i].0 };
            let s1: bool = h_x1 ^ blake2_128(&x1_mac.to_le_bytes()).lsb();
            let v1: bool = t0_bits[i] ^ s1;
            v1_bits.push(v1);
        }

        return v1_bits;
    }

    pub fn la_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, v1: Vec<bool>) {
        let number_of_triples = self.x1_bits.len();
        let mut z1: Vec<bool> = Vec::new();
        for i in 0..number_of_triples {
            z1.push(v1[i] ^ (self.x1_bits[i] && self.y1_bits[i]));
        }
        let mut d1: Vec<bool> = Vec::new();
        for i in 0..number_of_triples {
            d1.push(z1[i] ^ self.r1_bits[i]);
        }

        // Receive d0 values from the channel
        let mut d0: Vec<bool> = Vec::new();
        for _ in 0..number_of_triples {
            d0.push(channel.read_bool().unwrap());
        }
        // Sending d1 values on the channel
        for &d1_bit in &d1 {
            channel.write_bool(d1_bit).unwrap();
        }
        channel.flush().unwrap();

        let mut z0_keys = Vec::new();
        for i in 0..number_of_triples {
            z0_keys.push(self.r0_keys[i] ^ (d0[i] as u128 * self.delta));
        }

        let mut ts: Vec<u128> = Vec::new();
        let mut us: Vec<u128> = Vec::new();
        for i in 0..number_of_triples {
            if !self.x1_bits[i] {
                let t0 = blake2_128(&[self.x0_keys[i].to_le_bytes(), (z0_keys[i] ^ (z1[i] as u128 * self.delta)).to_le_bytes()].concat());
                ts.push(t0);
                let u0 = t0 ^ blake2_128(&[(self.x0_keys[i] ^ self.delta).to_le_bytes(), (self.y0_keys[i] ^ z0_keys[i] ^ (self.y1_bits[i] ^ z1[i]) as u128 * self.delta).to_le_bytes()].concat());
                us.push(u0);
            } else {
                let t1 = blake2_128(&[self.x0_keys[i].to_le_bytes(), (self.y0_keys[i] ^ z0_keys[i] ^ ((self.y1_bits[i] ^ z1[i]) as u128 * self.delta)).to_le_bytes()].concat());
                ts.push(t1);
                let u1 = t1 ^ blake2_128(&[(self.x0_keys[i] ^ self.delta).to_le_bytes(), (z0_keys[i] ^ (z1[i] as u128 * self.delta)).to_le_bytes()].concat());
                us.push(u1)
            }
        }

        // Sending U values on the channel
        for &u in &us {
            channel.write_u128(u).unwrap();
        }
        channel.flush().unwrap();

        // let mut Ws: Vec<u128> = Vec::new();
        let mut r_primes = Vec::new();
        for i in 0..number_of_triples {
            let w0 = channel.read_u128().unwrap();
            let w1 = channel.read_u128().unwrap();
            let mac_hash = blake2_128(&self.x1_macs[i].to_le_bytes());
            if !self.x1_bits[i] {
                r_primes.push(w0 ^ mac_hash ^ ts[i]);
            } else {
                r_primes.push(w1 ^ mac_hash ^ ts[i]);
            }
        }

        // EQ box
        assert!(self.eq(channel, &r_primes));

        // Do it all again but reverse roles
        // Get U from B
        let mut us: Vec<u128> = Vec::new();
        for _ in 0..number_of_triples {
            let u = channel.read_u128().unwrap();
            us.push(u);
        }

        let mut rs = Vec::new();
        let mut ws = Vec::new();
        for i in 0..number_of_triples {
            let r: u128 = rng.gen();
            rs.push(r);
            let v0 = blake2_128(&[self.x1_macs[i].to_le_bytes(), self.r1_macs[i].to_le_bytes()].concat());
            let v1 = blake2_128(&[self.x1_macs[i].to_le_bytes(), (self.r1_macs[i] ^ self.y1_macs[i]).to_le_bytes()].concat());

            let hash0 = blake2_128(&self.x0_keys[i].to_le_bytes());
            let hash1 = blake2_128(&(self.x0_keys[i] ^ self.delta).to_le_bytes());
            if !self.x1_bits[i] {
                let w00 = hash0 ^ v0 ^ r;
                let w01 = hash1 ^ v1 ^ r;
                ws.push((w00, w01));
            } else {
                let w11 = hash1 ^ v0 ^ us[i] ^ r;
                let w10 = hash0 ^ v1 ^ us[i] ^ r;
                ws.push((w10, w11));
            }
        }

        // Send Ws
        for (w0, w1) in ws {
            channel.write_u128(w0).unwrap();
            channel.write_u128(w1).unwrap();
        }
        channel.flush().unwrap();

        // EQ box
        assert!(self.eq(channel, &rs));

        self.z1_bits = z1;
        self.z0_keys = z0_keys;
    }

    // From NNOB/TinyOT
    fn eq<C: AbstractChannel>(&mut self, channel: &mut C, ys: &Vec<u128>) -> bool {
        let mut cs: Vec<u128> = Vec::new();
        for _ in 0..ys.len() {
            cs.push(channel.read_u128().unwrap());
        }

        for y in ys {
            channel.write_u128(*y).unwrap();
        }
        channel.flush().unwrap();

        for i in 0..ys.len() {
            let x = channel.read_u128().unwrap();
            let r = channel.read_u128().unwrap();
            let c_prime = blake2_128(&[x.to_le_bytes(), r.to_le_bytes()].concat());
            if c_prime != cs[i] || x != ys[i] {
                return false;
            }
        }

        return true;
    }

    pub fn wrk17_a_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, b: usize) -> Vec<AuthTriple> {
        self.permute(channel, rng);
        return self.bucketing(channel, b);
    }

    fn bucketing<C: AbstractChannel>(&mut self, channel: &mut C, b: usize) -> Vec<AuthTriple> {
        let mut triples = Vec::new();
        for i in (0..self.z1_bits.len()).step_by(b) {
            let mut x_share = self.x1_bits[i];
            let mut y_share = self.y1_bits[i];
            let mut z_share = self.z1_bits[i];
            let mut x_mac = self.x1_macs[i];
            let mut y_mac = self.y1_macs[i];
            let mut z_mac = self.r1_macs[i];
            let mut x_key = self.x0_keys[i];
            let mut y_key = self.y0_keys[i];
            let mut z_key = self.z0_keys[i];
            for j in 1..b {
                let mut d = channel.read_bool().unwrap();
                let d_mac = channel.read_u128().unwrap();
                let d_key = y_key ^ self.y0_keys[j];

                let d_delta = if d { self.delta } else { 0 };
                if d_mac != d_key ^ d_delta {
                    panic!("Wrong MAC");
                }

                let d_prime = y_share ^ self.y1_bits[j];
                let d_prime_mac = y_mac ^ self.y1_macs[j];
                channel.write_bool(d_prime).unwrap();
                channel.write_u128(d_prime_mac).unwrap();
                channel.flush().unwrap();

                d = d ^ d_prime;

                x_share = x_share ^ self.x1_bits[j];
                x_mac = x_mac ^ self.x1_macs[j];
                x_key = x_key ^ self.x0_keys[j];

                if d {
                    z_share = z_share ^ self.z1_bits[j] ^ self.x1_bits[j];
                    z_mac = z_mac ^ self.r1_macs[j] ^ self.x1_macs[j];
                    z_key = z_key ^ self.z0_keys[j] ^ self.x0_keys[j];
                } else {
                    z_share = z_share ^ self.z1_bits[j];
                    z_mac = z_mac ^ self.r1_macs[j];
                    z_key = z_key ^ self.z0_keys[j];
                }
            }
            let triple = AuthTriple {
                x_share,
                y_share,
                z_share,
                x_mac,
                y_mac,
                z_mac,
                x_key,
                y_key,
                z_key
            };
            triples.push(triple);
        }
        return triples;
    }

    fn permute<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {
        let hash_s = channel.read_u128().unwrap();
        let t: u128 = rng.gen();
        channel.write_u128(t).unwrap();
        channel.flush().unwrap();
        let s = channel.read_u128().unwrap();

        if hash_s != blake2_128(&[s.to_le_bytes()].concat()) {
            panic!("Wrong hash");
        }

        let seed: [u8; 32] = blake2_256(&<[u8; 32]>::try_from([s.to_le_bytes(), t.to_le_bytes()].concat()).unwrap());

        let mut cha_rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed);

        for i in (0..self.z1_bits.len()).rev() {
            let j = cha_rng.gen_range(0..(i + 1));
            self.x1_bits.swap(i, j);
            self.y1_bits.swap(i, j);
            self.z1_bits.swap(i, j);
            self.r1_bits.swap(i, j);
            self.x1_macs.swap(i, j);
            self.y1_macs.swap(i, j);
            self.r1_macs.swap(i, j);
            self.x0_keys.swap(i, j);
            self.y0_keys.swap(i, j);
            self.z0_keys.swap(i, j);
        }
    }

    pub fn hss17_ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, b: usize) {
        let number_of_triples = self.x1_bits.len();

        let mut us = Vec::new();
        let mut ds = Vec::new();

        let mut ds_received = Vec::new();
        for _ in 0..number_of_triples {
            ds_received.push(channel.read_bool().unwrap());
        }

        for(i, x0_key) in self.x0_keys.iter().enumerate() {
            let u1 = blake2_128(&x0_key.to_le_bytes()).lsb();
            us.push(u1);
            let v1 = blake2_128(&(x0_key ^ self.delta).to_le_bytes()).lsb();
            let d1 = u1 ^ v1 ^ self.y1_bits[i];
            ds.push(d1);
        }

        for d in ds {
            channel.write_bool(d).unwrap();
        }
        channel.flush().unwrap();

        let mut z1_bits = Vec::new();
        for i in 0..number_of_triples {
            let w1 = blake2_128(&self.x1_macs[i].to_le_bytes()).lsb() ^ (self.x1_bits[i] && ds_received[i]);
            let z1 = (us[i] ^ w1) ^ (self.x1_bits[i] && self.y1_bits[i]);
            z1_bits.push(z1);
        }

        let mut c0 = Vec::new();
        for _ in 0..number_of_triples {
            c0.push(channel.read_bool().unwrap());
        }

        for i in 0..number_of_triples {
            let c1 = z1_bits[i] ^ self.r1_bits[i];
            channel.write_bool(c1).unwrap();
        }
        channel.flush().unwrap();

        let mut z0_keys = Vec::new();
        for i in 0..number_of_triples {
            z0_keys.push(self.r0_keys[i] ^ (c0[i] as u128 * self.delta));
        }

        self.z1_bits = z1_bits;
        self.z0_keys = z0_keys;
    }

    pub fn hss17_a_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, b: usize) -> Vec<AuthTriple> {
        self.hss17_ha_and(channel, rng, b);

        let hash_s = channel.read_u128().unwrap();
        let t: u128 = rng.gen();
        channel.write_u128(t).unwrap();
        channel.flush().unwrap();
        let s = channel.read_u128().unwrap();

        if hash_s != blake2_128(&[s.to_le_bytes()].concat()) {
            panic!("Wrong hash");
        }

        let seed: [u8; 32] = blake2_256(&<[u8; 32]>::try_from([s.to_le_bytes(), t.to_le_bytes()].concat()).unwrap());

        let mut cha_rng: ChaCha20Rng = ChaCha20Rng::from_seed(seed);

        let mut idx = Vec::new();
        for _ in 0..3 {
            let i = cha_rng.gen_range(0..self.z1_bits.len());
            idx.push(i);

            let z0 = channel.read_bool().unwrap();
            let z0_mac = channel.read_u128().unwrap();

            if self.z0_keys[i] != z0_mac ^ (z0 as u128 * self.delta) {
                panic!("MAC check failed");
            };

            channel.write_bool(self.z1_bits[i]).unwrap();
            channel.write_u128(self.r1_macs[i]).unwrap();
            channel.flush().unwrap();
            // self.x1_bits.remove(i);
            // self.y1_bits.remove(i);
            // self.r1_bits.remove(i);
            // self.x1_macs.remove(i);
            // self.y1_macs.remove(i);
            // self.x0_keys.remove(i);
            // self.y0_keys.remove(i);
            // self.r0_keys.remove(i);
        }

        let mut verified_x1_bits = Vec::new();
        let mut verified_x1_macs = Vec::new();
        let mut verified_y1_bits = Vec::new();
        let mut verified_y1_macs = Vec::new();
        let mut verified_z1_bits = Vec::new();
        let mut verified_r1_macs = Vec::new();
        let mut verified_x0_keys = Vec::new();
        let mut verified_y0_keys = Vec::new();
        let mut verified_z0_keys = Vec::new();
        self.permute(channel, rng);
        for i in (0..self.z1_bits.len()).step_by(b) {
            verified_x1_bits.push(self.x1_bits[i]);
            verified_y1_bits.push(self.y1_bits[i]);
            verified_z1_bits.push(self.z1_bits[i]);
            verified_x1_macs.push(self.x1_macs[i]);
            verified_y1_macs.push(self.y1_macs[i]);
            verified_r1_macs.push(self.r1_macs[i]);
            verified_x0_keys.push(self.x0_keys[i]);
            verified_y0_keys.push(self.y0_keys[i]);
            verified_z0_keys.push(self.z0_keys[i]);
            for j in i + 1..i + b + 1 {
                if i + b + 1 >= self.z1_bits.len() {
                    break;
                }
                let d1_received = channel.read_bool().unwrap();
                let e1_received = channel.read_bool().unwrap();
                let d1_mac_received = channel.read_u128().unwrap();
                let e1_mac_received = channel.read_u128().unwrap();

                let d1_key = self.x0_keys[i] ^ self.x0_keys[j];
                let e1_key = self.y0_keys[i] ^ self.y0_keys[j];

                if d1_mac_received != d1_key ^ (d1_received as u128 * self.delta) {
                    panic!("MAC check failed for i = {} and j = {}", i, j);
                }

                if e1_mac_received != e1_key ^ (e1_received as u128 * self.delta) {
                    panic!("MAC check failed");
                }

                let d2 = self.x1_bits[i] ^ self.x1_bits[j];
                let e2 = self.y1_bits[i] ^ self.y1_bits[j];

                let d2_mac = self.x1_macs[i] ^ self.x1_macs[j];
                let e2_mac = self.y1_macs[i] ^ self.y1_macs[j];
                channel.write_bool(d2).unwrap();
                channel.write_bool(e2).unwrap();
                channel.write_u128(d2_mac).unwrap();
                channel.write_u128(e2_mac).unwrap();
                channel.flush().unwrap();

                let d = d1_received ^ d2;
                let e = e1_received ^ e2;

                let f1_received = channel.read_bool().unwrap();
                let f1_mac_received = channel.read_u128().unwrap();
                let f1_key = self.z0_keys[i] ^ self.z0_keys[j] ^
                    (d as u128 * self.y0_keys[i]) ^
                    (e as u128 * self.x0_keys[i]) ^
                    ((d && e) as u128) * self.delta;

                if f1_mac_received != f1_key ^ (f1_received as u128 * self.delta) {
                    panic!("MAC check failed");
                }

                let f2 = self.z1_bits[i] ^ self.z1_bits[j] ^ (d && self.y1_bits[i]) ^ (e && self.x1_bits[i]);
                let f2_mac = self.r1_macs[i] ^ self.r1_macs[j] ^ (d as u128 * self.y1_macs[i]) ^ (e as u128 * self.x1_macs[i]);

                channel.write_bool(f2).unwrap();
                channel.write_u128(f2_mac).unwrap();
                channel.flush().unwrap();

                let f = f1_received ^ f2;
                if f {
                    panic!("f is not ZERO! It was: {}, i = {}, j = {}", f, i, j);
                }
            }
        }

        self.x1_bits = verified_x1_bits;
        self.y1_bits = verified_y1_bits;
        self.z1_bits = verified_z1_bits;
        self.x1_macs = verified_x1_macs;
        self.y1_macs = verified_y1_macs;
        self.r1_macs = verified_r1_macs;
        self.x0_keys = verified_x0_keys;
        self.y0_keys = verified_y0_keys;
        self.z0_keys = verified_z0_keys;

        return self.bucketing(channel, b);
    }
}


    fn fe_to_u128<FE: FiniteField>(w: &FE) -> u128 {
    let mut result: u128 = 0;
    for (index, &bit) in w.bit_decomposition().iter().enumerate() {
        if bit {
            result |= 1 << index;
        }
    }
    return result;
}

#[cfg(test)]
mod tests {
    use super::{SVoleReceiver, SVoleSender, TripleReceiver, TripleSender};

    use scuttlebutt::{field::{F128b, FiniteField as FF}, AesRng, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    use ocelot::svole::wykw::{LPN_EXTEND_LARGE, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_SETUP_LARGE, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL, LpnParams, Receiver, Sender};

    fn test_wrk17_a_and<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>(setup: LpnParams, extend: LpnParams) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng, setup, extend);
            let v1: Vec<bool> = triple_receiver.ha_and(&mut channel, &mut rng);
            triple_receiver.la_and(&mut channel, &mut rng, v1);
            let auth_triples_receiver = triple_receiver.wrk17_a_and(&mut channel, &mut rng, 3);
            return (triple_receiver, auth_triples_receiver);
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng, setup, extend);
        let number_of_triples = triple_sender.x0_bits.len();
        let v0: Vec<bool> = triple_sender.ha_and(&mut channel, &mut rng);
        triple_sender.la_and(&mut channel, &mut rng, v0);
        let auth_triples_sender = triple_sender.wrk17_a_and(&mut channel, &mut rng, 3);

        let handle_return = handle.join().unwrap();
        let triple_receiver = handle_return.0;
        let auth_triples_receiver = handle_return.1;

        let number_of_auth_tiples = auth_triples_receiver.len();

        println!("# of triples: {}", number_of_triples);
        println!("# of auth triples: {}", number_of_auth_tiples);

        for i in 0..number_of_triples {
            let u_delta = u128::from(triple_sender.x0_bits[i]) * triple_receiver.delta;
            assert_eq!(triple_receiver.x0_keys[i] ^ u_delta, triple_sender.x0_macs[i]);
        }
        for i in 0..number_of_triples {
            let u_delta = u128::from(triple_receiver.x1_bits[i]) * triple_sender.delta;
            assert_eq!(triple_sender.x1_keys[i] ^ u_delta, triple_receiver.x1_macs[i]);
        }
        for i in 0..number_of_triples {
            let u_delta = u128::from(triple_receiver.y1_bits[i]) * triple_sender.delta;
            assert_eq!(triple_sender.y1_keys[i] ^ u_delta, triple_receiver.y1_macs[i]);
        }
        // v0 ^ v1 = x0y1 ^ x1y0
        // for i in 0..number_of_triples {
        //    assert_eq!(v1[i] ^ v0[i], (triple_sender.x0_bits[i] && triple_receiver.y1_bits[i]) ^ (triple_sender.y0_bits[i] && triple_receiver.x1_bits[i]));
        // }

        for i in 0..auth_triples_receiver.len() {
            let t1 = &auth_triples_sender[i];
            let t2 = &auth_triples_receiver[i];
            let x = ((t1.x_share ^ t2.x_share) && (t1.y_share ^ t2.y_share)) == (t1.z_share ^ t2.z_share);
            if !x {
                println!("Wrong triple, {}", i);
            }
            assert_eq!(t2.x_mac, t1.x_key ^ (t2.x_share as u128 * triple_sender.delta));
            assert_eq!(t2.y_mac, t1.y_key ^ (t2.y_share as u128 * triple_sender.delta));
            assert_eq!(t2.z_mac, t1.z_key ^ (t2.z_share as u128 * triple_sender.delta));
            assert_eq!(t1.x_mac, t2.x_key ^ (t1.x_share as u128 * triple_receiver.delta));
            assert_eq!(t1.y_mac, t2.y_key ^ (t1.y_share as u128 * triple_receiver.delta));
            assert_eq!(t1.z_mac, t2.z_key ^ (t1.z_share as u128 * triple_receiver.delta));
        }
    }
    fn test_ha_and<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>(setup: LpnParams, extend: LpnParams) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng, setup, extend);
            let v1 = triple_receiver.ha_and(&mut channel, &mut rng);
            return (triple_receiver, v1);
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng, setup, extend);
        let v0 = triple_sender.ha_and(&mut channel, &mut rng);

        let handle_return = handle.join().unwrap();
        let triple_receiver = handle_return.0;
        let v1 = handle_return.1;

        // v0 ^ v1 = x0y1 ^ x1y0
        for i in 0..triple_sender.z0_bits.len() {
           assert_eq!(v1[i] ^ v0[i], (triple_sender.x0_bits[i] && triple_receiver.y1_bits[i]) ^ (triple_sender.y0_bits[i] && triple_receiver.x1_bits[i]));
        }
    }


    fn my_test_now<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>(setup: LpnParams, extend: LpnParams) {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng, setup, extend);
            let auth_triples = triple_receiver.hss17_a_and(&mut channel, &mut rng, 3);
            return (triple_receiver, auth_triples);
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng, setup, extend);
        let number_of_triples = triple_sender.x0_bits.len();
        let auth_triples_sender = triple_sender.hss17_a_and(&mut channel, &mut rng, 3);

        let handle_return = handle.join().unwrap();
        let triple_receiver = handle_return.0;
        let auth_triples_receiver = handle_return.1;

        let number_of_auth_tiples = auth_triples_receiver.len();

        println!("# of triples: {}", number_of_triples);
        println!("# of auth triples: {}", number_of_auth_tiples);

        for i in 0..auth_triples_receiver.len() {
            let t1 = &auth_triples_sender[i];
            let t2 = &auth_triples_receiver[i];
            let x = ((t1.x_share ^ t2.x_share) && (t1.y_share ^ t2.y_share)) == (t1.z_share ^ t2.z_share);
            if !x {
                panic!("Wrong triple, {}", i);
            }
            assert_eq!(t2.x_mac, t1.x_key ^ (t2.x_share as u128 * triple_sender.delta));
            assert_eq!(t2.y_mac, t1.y_key ^ (t2.y_share as u128 * triple_sender.delta));
            assert_eq!(t2.z_mac, t1.z_key ^ (t2.z_share as u128 * triple_sender.delta));
            assert_eq!(t1.x_mac, t2.x_key ^ (t1.x_share as u128 * triple_receiver.delta));
            assert_eq!(t1.y_mac, t2.y_key ^ (t1.y_share as u128 * triple_receiver.delta));
            assert_eq!(t1.z_mac, t2.z_key ^ (t1.z_share as u128 * triple_receiver.delta));
        }
    }

    #[test]
    fn test_lpn_svole_gf128() {
        my_test_now::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_LARGE, LPN_EXTEND_LARGE);
        // test_wrk17_a_and::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM);
        // test_ha_and::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM);
    }
}
