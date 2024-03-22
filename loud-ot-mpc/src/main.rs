use std::ops::Deref;
use::ocelot::svole::{SVoleSender, SVoleReceiver, wykw};
use rand::{CryptoRng, Rng};
use ocelot::svole::wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
use scuttlebutt::{field::{FiniteField}, AbstractChannel};
use scuttlebutt::serialization::CanonicalSerialize;
use sha3::{digest::{Update, ExtendableOutput, XofReader}};
use blake2::{Blake2b, Digest};
use aes::cipher::consts::U16;

fn main() {
    println!("Hello Mr. PC?");
    a_bit();
    a_and();
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
    delta: u128,
    x1_keys: Vec<u128>,
    y1_keys: Vec<u128>,
    r_keys: Vec<u128>,
    whatever: Vec<FE>
}

impl<FE: FiniteField> TripleSender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG) -> Self {
        // Get authenticated bit keys and delta
        let mut svole_receiver: wykw::Receiver<FE> =
            wykw::Receiver::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let delta = fe_to_u128(&svole_receiver.delta());

        let fraction = vs.len() / 3;
        let mut x1_keys = vs[0..fraction].iter().map(|v| fe_to_u128(v)).collect();
        let mut y1_keys = vs[fraction..fraction * 2].iter().map(|v| fe_to_u128(v)).collect();
        let mut r_keys = vs[fraction * 2..fraction * 3].iter().map(|v| fe_to_u128(v)).collect();

        // Get authenticated bits and macs
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut uws = Vec::new();
        svole_sender.send(channel, rng, &mut uws).unwrap();
        let mut x0_bits = Vec::new();
        let mut x0_macs = Vec::new();
        let mut y0_bits = Vec::new();
        let mut y0_macs = Vec::new();
        for (u, w) in &uws {
            x0_bits.push(*u.bit_decomposition().get(0).unwrap());
            x0_macs.push(fe_to_u128(w));
        }
        let whatever: Vec<FE> = Vec::new();
        return Self {
            x0_bits,
            x0_macs,
            y0_bits,
            y0_macs,
            delta,
            x1_keys,
            y1_keys,
            r_keys,
            whatever
        }
    }
    pub fn ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {
        // self.x0_bits
        let mut H: Vec<(bool, bool)> = Vec::new();
        let mut s1_bits: Vec<bool> = Vec::new();

        for (i , x1_key) in self.x1_keys.iter().enumerate() {
            let s1: bool = rng.gen();
            s1_bits.push(s1);
            let H0 = blake2(&x1_key.to_le_bytes()).lsb() ^ s1;
            let H1 = blake2(&(x1_key ^ self.delta).to_le_bytes()).lsb() ^ s1 ^ self.y0_bits[i];
            H.push((H0, H1));
        }

        // Send H values on the channel

        // Receive H values from the channel
    }
    pub fn la_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {

    }
}

pub struct TripleReceiver<FE: FiniteField> {
    x1_bits: Vec<bool>,
    x1_macs: Vec<u128>,
    y1_bits: Vec<bool>,
    y1_macs: Vec<u128>,
    r_bits: Vec<bool>,
    r_macs: Vec<u128>,
    delta: u128,
    x0_keys: Vec<u128>,
    y0_keys: Vec<u128>,
    whatever: Vec<FE>
}

impl<FE: FiniteField> TripleReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG) -> Self {
        // Get authenticated bits and macs
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut uws = Vec::new();
        svole_sender.send(channel, rng, &mut uws).unwrap();

        let mut x1_bits = Vec::new();
        let mut x1_macs = Vec::new();
        let mut y1_bits = Vec::new();
        let mut y1_macs = Vec::new();
        let mut r_bits= Vec::new();
        let mut r_macs = Vec::new();

        let fraction = uws.len() / 3;

        // Pool of uws for x1 bit and mac generation
        let x1_pool = &uws[0..fraction];

        // Pool of uws for y1 bit and mac generation
        let y1_pool = &uws[fraction..fraction * 2];

        // Pool of uws for r bit and mac generation
        let r_pool = &uws[fraction * 2.. fraction * 3];

        for (u, w) in x1_pool {
            x1_bits.push(*u.bit_decomposition().get(0).unwrap());
            x1_macs.push(fe_to_u128(w));
        }
        for (u, w) in y1_pool {
            y1_bits.push(*u.bit_decomposition().get(0).unwrap());
            y1_macs.push(fe_to_u128(w));
        }
        for (u, w) in r_pool {
            r_bits.push(*u.bit_decomposition().get(0).unwrap());
            r_macs.push(fe_to_u128(w));
        }

        // Get authenticated bit keys and delta
        let mut svole_receiver: wykw::Receiver<FE> =
            wykw::Receiver::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let delta = fe_to_u128(&svole_receiver.delta());
        let mut x0_keys: Vec<u128> = vs.iter().map(|v| fe_to_u128(v)).collect();
        let mut y0_keys = Vec::new();
        let whatever = vs.clone();
        return Self {
            x1_bits,
            x1_macs,
            y1_bits,
            y1_macs,
            r_bits,
            r_macs,
            delta,
            x0_keys,
            y0_keys,
            whatever
        }
    }
    pub fn ha_and<C: AbstractChannel, RNG: CryptoRng + Rng>(&mut self, channel: &mut C, rng: &mut RNG) {
        let mut H: Vec<(bool, bool)> = Vec::new();
        let mut t1_bits: Vec<bool> = Vec::new();

        for (i , x0_key) in self.x0_keys.iter().enumerate() {
            let s1: bool = rng.gen();
            t1_bits.push(s1);
            let H0 = blake2(&x0_key.to_le_bytes()).lsb() ^ s1;
            let H1 = blake2(&(x0_key ^ self.delta).to_le_bytes()).lsb() ^ s1 ^ self.y1_bits[i];
            H.push((H0, H1));
        }

        // Receive H values from the channel
        let mut H_received: Vec<(bool, bool)> = Vec::new();



        // Sender H values on the channel
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

fn a_bit() {
    // from COT
}

fn a_and() {

}

#[cfg(test)]
mod tests {
    use super::{SVoleReceiver, SVoleSender, TripleReceiver, TripleSender};

    use scuttlebutt::{
        field::{F128b, FiniteField as FF},
        AesRng, Channel,
    };
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
            let triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng);
            return triple_receiver;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng);

        let triple_receiver = handle.join().unwrap();
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
        for i in 0..triple_receiver.r_bits.len() {
            let u_delta = u128::from(triple_receiver.r_bits[i]) * triple_sender.delta;
            assert_eq!(triple_sender.r_keys[i] ^ u_delta, triple_receiver.r_macs[i]);
        }
        /*println!("Number of uws: {}", triple_sender.uws.len());
        for i in 0..triple_sender.uws.len() {
            let right: FE = triple_sender.uws[i].0 * triple_receiver.delta + triple_receiver.vs[i];
            assert_eq!(triple_sender.uws[i].1, right);
        }*/
    }

    #[test]
    fn test_lpn_svole_gf128() {
        test_s_vole::<F128b, Sender<F128b>, Receiver<F128b>>();
    }
}
