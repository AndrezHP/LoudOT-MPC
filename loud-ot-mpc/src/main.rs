use::ocelot::svole::{SVoleSender, SVoleReceiver, wykw};
use rand::{
    distributions::{Distribution},
    CryptoRng, Rng, SeedableRng,
};
use ocelot::svole::wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL, LpnParams};
use scuttlebutt::{field::{FiniteField}, ring::FiniteRing, AbstractChannel, Malicious, SemiHonest};

fn main() {
    println!("Hello Mr. PC?");
}

pub struct TripleSender<FE: FiniteField> {
    vs: Vec<FE>,
    delta: FE
}

impl<FE: FiniteField> TripleSender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG) -> Self {
        let mut svole_receiver: wykw::Receiver<FE> =
            wykw::Receiver::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut vs = Vec::new();
        svole_receiver.receive(channel, rng, &mut vs).unwrap();
        let mut delta = svole_receiver.delta();
        return Self {
            vs,
            delta
        }
    }
}

pub struct TripleReceiver<FE: FiniteField> {
    uws: Vec<(FE::PrimeField, FE)>
}

impl<FE: FiniteField> TripleReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(channel: &mut C, rng: &mut RNG) -> Self {
        let mut svole_sender: wykw::Sender<FE> =
            wykw::Sender::init(channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL).unwrap();
        let mut uws = Vec::new();
        svole_sender.send(channel, rng, &mut uws).unwrap();
        for uw in &uws {
            uw.0.bit_decomposition();
        }
        return Self {
            uws
        }
    }
}

fn a_bit() {
    // from COT

}

fn ha_and() {
    // only authenticates x1 and x2 from a_bit
}

fn la_and() {

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
            let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng);
            return triple_receiver;
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng);
        let mut vs = triple_sender.vs;

        let triple_receiver = handle.join().unwrap();
        let uws = triple_receiver.uws;
        println!("Number of uws: {}", uws.len());
        for i in 0..uws.len() {
            let right: FE = uws[i].0 * triple_sender.delta + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    #[test]
    fn test_lpn_svole_gf128() {
        test_s_vole::<F128b, Sender<F128b>, Receiver<F128b>>();
    }
}
