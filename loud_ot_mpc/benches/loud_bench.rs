use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::{AesRng, Channel, field::{FiniteField as FF}};
use loud_ot_mpc::main::{TripleReceiver, TripleSender};
use ocelot::svole::{SVoleReceiver, SVoleSender};
use ocelot::svole::wykw::{Receiver, Sender};
use scuttlebutt::field::F128b;

fn protocol<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng);
        let auth_triples_receiver = triple_receiver.a_and(&mut channel, &mut rng, 3);
        return (triple_receiver, auth_triples_receiver);
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng);
    let _auth_triples_sender = triple_sender.a_and(&mut channel, &mut rng, 3);

    let handle_return = handle.join().unwrap();
    let _triple_receiver = handle_return.0;
    let _auth_triples_receiver = handle_return.1;
}

fn bench_init<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng);

        return (triple_receiver);
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let _triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng);

    let _handle_return = handle.join().unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("loud_ot whole protocol", |b| b.iter(|| protocol::<F128b, Sender<F128b>, Receiver<F128b>>()));
}

fn criterion_benchmark_init(c: &mut Criterion) {
    c.bench_function("loud_ot init", |b| b.iter(|| bench_init::<F128b, Sender<F128b>, Receiver<F128b>>()));
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark_init
}
criterion_main!(benches);
