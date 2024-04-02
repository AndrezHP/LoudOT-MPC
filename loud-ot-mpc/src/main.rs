use std::io::{BufReader, BufWriter};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use::ocelot::svole::{SVoleSender, SVoleReceiver, wykw};
use rand::{CryptoRng, Rng};
use ocelot::svole::wykw::{LPN_EXTEND_EXTRASMALL, LPN_EXTEND_SMALL, LPN_SETUP_EXTRASMALL, LPN_SETUP_SMALL};
use scuttlebutt::{field::{FiniteField}, AbstractChannel, Channel};
use scuttlebutt::serialization::CanonicalSerialize;
use sha3::{digest::{Update, ExtendableOutput, XofReader}};
use blake2::{Blake2b, Digest};
use aes::cipher::consts::U16;
use bincode;
use serde::{Serialize, Deserialize};

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
pub fn blake2(bytes: &[u8]) -> u128 {
    let mut hasher = Blake2b128::new();
    Update::update(&mut hasher, bytes);
    let res = hasher.finalize();
    return u128::from_le_bytes(res.into());
}

pub struct TripleSender<FE: FiniteField> {
    x0_bits: Vec<bool>,
    x0_macs: Vec<u128>,
    y0_bits: Vec<bool>,
    y0_macs: Vec<u128>,
    r0_bits: Vec<bool>,
    r0_macs: Vec<u128>,
    delta: u128,
    x1_keys: Vec<u128>,
    y1_keys: Vec<u128>,
    r1_keys: Vec<u128>,
    whatever: Vec<FE>
}

impl<FE: FiniteField> TripleSender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG) -> Self {
        // Get authenticated bit keys and delta
        let mut svole_receiver: wykw::Receiver<FE> =
            wykw::Receiver::init(channel, rng, LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let delta = fe_to_u128(&svole_receiver.delta());

        let fraction = vs.len() / 3;
        let mut x1_keys = vs[0..fraction].iter().map(|v| fe_to_u128(v)).collect();
        let mut y1_keys = vs[fraction..fraction * 2].iter().map(|v| fe_to_u128(v)).collect();
        let mut r1_keys = vs[fraction * 2..fraction * 3].iter().map(|v| fe_to_u128(v)).collect();

        // Get authenticated bits and macs
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL).unwrap();
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

        // TODO remove whatever
        let whatever: Vec<FE> = Vec::new();
        return Self {
            x0_bits,
            x0_macs,
            y0_bits,
            y0_macs,
            r0_bits,
            r0_macs,
            delta,
            x1_keys,
            y1_keys,
            r1_keys,
            whatever
        }
    }
    pub fn ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) -> Vec<bool> {
        let mut H: Vec<(bool, bool)> = Vec::new();
        let mut s0_bits: Vec<bool> = Vec::new();

        for (i , x1_key) in self.x1_keys.iter().enumerate() {
            let s0: bool = rng.gen();
            s0_bits.push(s0);
            let H0 = blake2(&x1_key.to_le_bytes()).lsb() ^ s0;
            let H1 = blake2(&(x1_key ^ self.delta).to_le_bytes()).lsb() ^ s0 ^ self.y0_bits[i];
            H.push((H0, H1));
        }

        // Receive H values from the channel
        let mut H_received: Vec<(bool, bool)> = Vec::new();
        for i in 0..self.x0_bits.len() {
            let H0 = channel.read_bool().unwrap();
            let H1 = channel.read_bool().unwrap();
            H_received.push((H0, H1));
        }

        // TODO refrain from sending one at a time
        // Send H values on the channel
        for (i, &(H0, H1)) in H.iter().enumerate() {
            channel.write_bool(H0).unwrap();
            channel.write_bool(H1).unwrap();
        }
        channel.flush().unwrap();

        let mut v0_bits: Vec<bool> = Vec::new();
        for (i, x0_mac) in self.x0_macs.iter().enumerate() {
            let x0: bool = self.x0_bits[i];
            let H_x0: bool = if x0 {H_received[i].1} else {H_received[i].0};
            let t1: bool = H_x0 ^ blake2(&x0_mac.to_le_bytes()).lsb();
            let v0: bool = s0_bits[i] ^ t1;
            v0_bits.push(v0);
        }
        return v0_bits;
    }
    pub fn la_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {
        let v0: Vec<bool> = self.ha_and(channel, rng);
        let mut z0: Vec<bool> = Vec::new();
        for i in 0..v0.len() {
            z0.push(v0[i] ^ (self.x0_bits[i] && self.y0_bits[i]));
        }
        let mut d0: Vec<bool> = Vec::new();
        for i in 0..z0.len() {
            d0.push(z0[i] ^ self.r0_bits[i]);
        }

        // Sender d0 values on the channel
        for &d0_bit in &d0 {
            channel.write_bool(d0_bit).unwrap();
        }
        channel.flush().unwrap();
        // Receive d1 values from the channel
        let mut d1: Vec<bool> = Vec::new();
        for _ in 0..d0.len() {
            d1.push(channel.read_bool().unwrap());
        }

        let mut z1_keys = Vec::new();
        for i in 0..d1.len() {
            z1_keys.push(self.r1_keys[i] ^ (d1[i] as u128 * self.delta));
        }

        // Get U from B
        let mut Us: Vec<u128> = Vec::new();
        for _ in 0..d1.len() {
            let U = channel.read_u128().unwrap();
            Us.push(U);
        }

        let mut Rs: Vec<u128> = Vec::new();
        let mut Ws = Vec::new();
        for i in 0..z0.len() {
            let R: u128 = rng.gen();
            Rs.push(R);
            let V0 = blake2(&[self.x0_macs[i].to_le_bytes(), self.r0_macs[i].to_le_bytes()].concat());
            let V1 = blake2(&[self.x0_macs[i].to_le_bytes(), (self.r0_macs[i] ^ self.y0_macs[i]).to_le_bytes()].concat());
            let hash0 = blake2(&self.x1_keys[i].to_le_bytes());
            let hash1 = blake2(&(self.x1_keys[i] ^ self.delta).to_le_bytes());
            if !self.x0_bits[i] {
                let W00 = hash0 ^ V0 ^ R;
                let W01 = hash1 ^ V1 ^ R;
                Ws.push((W00, W01));
            } else {
                let W11 = hash1 ^ V0 ^ Us[i] ^ R;
                let W10 = hash0 ^ V1 ^ Us[i] ^ R;
                Ws.push((W10, W11));
            }
        }

        // Send Ws
        for (W0, W1) in Ws {
            channel.write_u128(W0).unwrap();
            channel.write_u128(W1).unwrap();
        }
        channel.flush().unwrap();

        // EQ box
        assert!(self.eq(channel, rng, &Rs));

        // Do it all again
        let mut Ts: Vec<u128> = Vec::new();
        let mut Us: Vec<u128>  = Vec::new();
        for i in 0..self.x1_keys.len() {
            if !self.x0_bits[i] {
                let T0 = blake2(&[self.x1_keys[i].to_le_bytes(), (z1_keys[i] ^ (z0[i] as u128 * self.delta)).to_le_bytes()].concat());
                Ts.push(T0);
                let U0 = T0 ^ blake2(&[(self.x1_keys[i] ^ self.delta).to_le_bytes(), (self.y1_keys[i] ^ z1_keys[i] ^ (self.y0_bits[i] ^ z0[i]) as u128 * self.delta).to_le_bytes()].concat());
                Us.push(U0);
            } else {
                let T1 = blake2(&[self.x1_keys[i].to_le_bytes(), (self.y1_keys[i] ^ z1_keys[i] ^ ((self.y0_bits[i] ^ z0[i]) as u128 * self.delta)).to_le_bytes()].concat());
                Ts.push(T1);
                let U1 = T1 ^ blake2(&[(self.x1_keys[i] ^ self.delta).to_le_bytes(), (z1_keys[i] ^ (z0[i] as u128 * self.delta)).to_le_bytes()].concat());
                Us.push(U1)
            }
        }

        // Sending U values on the channel
        for &U in &Us {
            channel.write_u128(U).unwrap();
        }
        channel.flush().unwrap();

        // let mut Ws: Vec<u128> = Vec::new();
        let mut R_primes = Vec::new();
        for i in 0..Us.len() {
            let W0 = channel.read_u128().unwrap();
            let W1 = channel.read_u128().unwrap();
            let mac_hash = blake2(&self.x0_macs[i].to_le_bytes());
            if !self.x0_bits[i] {
                R_primes.push(W0 ^ mac_hash ^ Ts[i]);
            } else {
                R_primes.push(W1 ^ mac_hash ^ Ts[i]);
            }
        }

        // EQ box
        assert!(self.eq(channel, rng, &R_primes));
    }

    fn check_la_and() {

    }

    fn eq<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG, xs: &Vec<u128>) -> bool {
        let mut rs: Vec<u128> = Vec::new();
        for x in xs {
            let r: u128 = rng.gen();
            rs.push(r);
            let c = blake2(&[x.to_le_bytes(), r.to_le_bytes()].concat());
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

    fn a_and() {

    }
}

pub struct TripleReceiver<FE: FiniteField> {
    x1_bits: Vec<bool>,
    x1_macs: Vec<u128>,
    y1_bits: Vec<bool>,
    y1_macs: Vec<u128>,
    r1_bits: Vec<bool>,
    r1_macs: Vec<u128>,
    delta: u128,
    x0_keys: Vec<u128>,
    y0_keys: Vec<u128>,
    r0_keys: Vec<u128>,
    whatever: Vec<FE>
}

impl<FE: FiniteField> TripleReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG) -> Self {
        // Get authenticated bits and macs
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL).unwrap();
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
        let r1_pool = &uws[fraction * 2.. fraction * 3];

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
            wykw::Receiver::init(channel, rng, LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let delta = fe_to_u128(&svole_receiver.delta());

        let mut x0_keys = vs[0..fraction].iter().map(|v| fe_to_u128(v)).collect();
        let mut y0_keys = vs[fraction..fraction * 2].iter().map(|v| fe_to_u128(v)).collect();
        let mut r0_keys = vs[fraction * 2..fraction * 3].iter().map(|v| fe_to_u128(v)).collect();

        let whatever = vs.clone();
        return Self {
            x1_bits,
            x1_macs,
            y1_bits,
            y1_macs,
            r1_bits,
            r1_macs,
            delta,
            x0_keys,
            y0_keys,
            r0_keys,
            whatever
        }
    }
    pub fn ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) -> Vec<bool> {
        let mut H: Vec<(bool, bool)> = Vec::new();
        let mut t0_bits: Vec<bool> = Vec::new();

        for (i , x0_key) in self.x0_keys.iter().enumerate() {
            let t0: bool = rng.gen();
            t0_bits.push(t0);
            let H0 = blake2(&x0_key.to_le_bytes()).lsb() ^ t0;
            let H1 = blake2(&(x0_key ^ self.delta).to_le_bytes()).lsb() ^ t0 ^ self.y1_bits[i];
            H.push((H0, H1));
        }

        // Sender H values on the channel
        for &(H0, H1) in &H {
            channel.write_bool(H0).unwrap();
            channel.write_bool(H1).unwrap();
        }
        channel.flush().unwrap();

        // Receive H values from the channel
        let mut H_received: Vec<(bool, bool)> = Vec::new();
        for i in 0..self.x1_bits.len() {
            let H0 = channel.read_bool().unwrap();
            let H1 = channel.read_bool().unwrap();
            H_received.push((H0, H1));
        }

        let mut v1_bits: Vec<bool> = Vec::new();
        for (i, x1_mac) in self.x1_macs.iter().enumerate() {
            let x1: bool = self.x1_bits[i];
            let H_x1: bool = if x1 {H_received[i].1} else {H_received[i].0};
            let s1: bool = H_x1 ^ blake2(&x1_mac.to_le_bytes()).lsb();
            let v1: bool = t0_bits[i] ^ s1;
            v1_bits.push(v1);
        }

        return v1_bits;
    }

    fn la_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {
        let v1: Vec<bool> = self.ha_and(channel, rng);
        let mut z1: Vec<bool> = Vec::new();
        for i in 0..v1.len() {
            z1.push(v1[i] ^ (self.x1_bits[i] && self.y1_bits[i]));
        }
        let mut d1: Vec<bool> = Vec::new();
        for i in 0..z1.len() {
            d1.push(z1[i] ^ self.r1_bits[i]);
        }

        // Receive d0 values from the channel
        let mut d0: Vec<bool> = Vec::new();
        for _ in 0..d1.len() {
            d0.push(channel.read_bool().unwrap());
        }
        // Sending d1 values on the channel
        for &d1_bit in &d1 {
            channel.write_bool(d1_bit).unwrap();
        }
        channel.flush().unwrap();

        let mut z0_keys = Vec::new();
        for i in 0..d0.len() {
            z0_keys.push(self.r0_keys[i] ^ (d0[i] as u128 * self.delta));
        }

        let mut Ts: Vec<u128> = Vec::new();
        let mut Us: Vec<u128>  = Vec::new();
        for i in 0..self.x0_keys.len() {
            if !self.x1_bits[i] {
                let T0 = blake2(&[self.x0_keys[i].to_le_bytes(), (z0_keys[i] ^ (z1[i] as u128 * self.delta)).to_le_bytes()].concat());
                Ts.push(T0);
                let U0 = T0 ^ blake2(&[(self.x0_keys[i] ^ self.delta).to_le_bytes(), (self.y0_keys[i] ^ z0_keys[i] ^ (self.y1_bits[i] ^ z1[i]) as u128 * self.delta).to_le_bytes()].concat());
                Us.push(U0);
            } else {
                let T1 = blake2(&[self.x0_keys[i].to_le_bytes(), (self.y0_keys[i] ^ z0_keys[i] ^ ((self.y1_bits[i] ^ z1[i]) as u128 * self.delta)).to_le_bytes()].concat());
                Ts.push(T1);
                let U1 = T1 ^ blake2(&[(self.x0_keys[i] ^ self.delta).to_le_bytes(), (z0_keys[i] ^ (z1[i] as u128 * self.delta)).to_le_bytes()].concat());
                Us.push(U1)
            }
        }

        // Sending U values on the channel
         for &U in &Us {
             channel.write_u128(U).unwrap();
         }
        channel.flush().unwrap();

        // let mut Ws: Vec<u128> = Vec::new();
        let mut R_primes = Vec::new();
        for i in 0..Us.len() {
            let W0 = channel.read_u128().unwrap();
            let W1 = channel.read_u128().unwrap();
            let mac_hash = blake2(&self.x1_macs[i].to_le_bytes());
            if !self.x1_bits[i] {
                R_primes.push(W0 ^ mac_hash ^ Ts[i]);
            } else {
                R_primes.push(W1 ^ mac_hash ^ Ts[i]);
            }
        }

        // EQ box
        assert!(self.eq(channel, &R_primes));

        // Do it all again but reverse roles
        // Get U from B
        let mut Us: Vec<u128> = Vec::new();
        for _ in 0..d1.len() {
            let U = channel.read_u128().unwrap();
            Us.push(U);
        }

        let mut Rs = Vec::new();
        let mut Ws = Vec::new();
        for i in 0..z1.len() {
            let R: u128 = rng.gen();
            Rs.push(R);
            let V0 = blake2(&[self.x1_macs[i].to_le_bytes(), self.r1_macs[i].to_le_bytes()].concat());
            let V1 = blake2(&[self.x1_macs[i].to_le_bytes(), (self.r1_macs[i] ^ self.y1_macs[i]).to_le_bytes()].concat());

            let hash0 = blake2(&self.x0_keys[i].to_le_bytes());
            let hash1 = blake2(&(self.x0_keys[i] ^ self.delta).to_le_bytes());
            if !self.x1_bits[i] {
                let W00 = hash0 ^ V0 ^ R;
                let W01 = hash1 ^ V1 ^ R;
                Ws.push((W00, W01));
            } else {
                let W11 = hash1 ^ V0 ^ Us[i] ^ R;
                let W10 = hash0 ^ V1 ^ Us[i] ^ R;
                Ws.push((W10, W11));
            }
        }

        // Send Ws
        for (W0, W1) in Ws {
            channel.write_u128(W0).unwrap();
            channel.write_u128(W1).unwrap();
        }
        channel.flush().unwrap();

        // EQ box
        assert!(self.eq(channel, &Rs));
    }

    fn check_la_and() {

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
            let c_prime = blake2(&[x.to_le_bytes(), r.to_le_bytes()].concat());
            if c_prime != cs[i] || x != ys[i] {
                return false;
            }
        }

        return true;
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
    use ocelot::svole::wykw::{Receiver, Sender};

    fn test_s_vole<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng);
            let v0 = triple_receiver.ha_and(&mut channel, &mut rng);
            triple_receiver.la_and(&mut channel, &mut rng);
            return (triple_receiver, v0);
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng);
        let v1 = triple_sender.ha_and(&mut channel, &mut rng);
        triple_sender.la_and(&mut channel, &mut rng);

        let handle_return = handle.join().unwrap();
        let mut triple_receiver = handle_return.0;
        let v0 = handle_return.1;


        for i in 0..triple_sender.x0_bits.len() {
            let u_delta = u128::from(triple_sender.x0_bits[i]) * triple_receiver.delta;
            assert_eq!(triple_receiver.x0_keys[i] ^ u_delta, triple_sender.x0_macs[i]);
        }
        for i in 0..triple_receiver.x1_bits.len() {
            let u_delta = u128::from(triple_receiver.x1_bits[i]) * triple_sender.delta;
            assert_eq!(triple_sender.x1_keys[i] ^ u_delta, triple_receiver.x1_macs[i]);
        }
        for i in 0..triple_receiver.y1_bits.len() {
            let u_delta = u128::from(triple_receiver.y1_bits[i]) * triple_sender.delta;
            assert_eq!(triple_sender.y1_keys[i] ^ u_delta, triple_receiver.y1_macs[i]);
        }
        for i in 0..triple_receiver.r1_bits.len() {
            let u_delta = u128::from(triple_receiver.r1_bits[i]) * triple_sender.delta;
            assert_eq!(triple_sender.r1_keys[i] ^ u_delta, triple_receiver.r1_macs[i]);
        }
        // v0 ^ v1 = x0y1 ^ x1y0
        for i in 0..v1.len() {
            assert_eq!(v1[i] ^ v0[i], (triple_sender.x0_bits[i] && triple_receiver.y1_bits[i]) ^ (triple_sender.y0_bits[i] && triple_receiver.x1_bits[i]));
        }
    }

    #[test]
    fn test_lpn_svole_gf128() {
        test_s_vole::<F128b, Sender<F128b>, Receiver<F128b>>();
    }

    fn test_ha_and<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng);
            return triple_receiver;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng);

        let triple_receiver = handle.join().unwrap();
    }
}
