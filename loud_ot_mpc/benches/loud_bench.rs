use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::{AesRng, Channel, field::{FiniteField as FF}};
use loud_ot_mpc::main::{TripleReceiver, TripleSender};
use ocelot::svole::{SVoleReceiver, SVoleSender};
use ocelot::svole::wykw::{LPN_EXTEND_EXTRASMALL, LPN_EXTEND_LARGE, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_SETUP_EXTRASMALL, LPN_SETUP_LARGE, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL, LpnParams, Receiver, Sender};
use scuttlebutt::field::F128b;

fn wrk17_protocol<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>(setup: LpnParams, extend: LpnParams) {
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
    let v0: Vec<bool> = triple_sender.ha_and(&mut channel, &mut rng);
    triple_sender.la_and(&mut channel, &mut rng, v0);
    let _auth_triples_sender = triple_sender.wrk17_a_and(&mut channel, &mut rng, 3);

    let handle_return = handle.join().unwrap();
    let _triple_receiver = handle_return.0;
    let _auth_triples_receiver = handle_return.1;
}

fn hss17_protocol<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>(setup: LpnParams, extend: LpnParams) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng, setup, extend);
        let auth_triples_receiver = triple_receiver.hss17_a_and(&mut channel, &mut rng, 3);
        return (triple_receiver, auth_triples_receiver);
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let mut triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng, setup, extend);
    let _auth_triples_sender = triple_sender.hss17_a_and(&mut channel, &mut rng, 3);

    let handle_return = handle.join().unwrap();
    let _triple_receiver = handle_return.0;
    let _auth_triples_receiver = handle_return.1;
}

fn bench_init<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>(setup: LpnParams, extend: LpnParams) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut triple_receiver: TripleReceiver<FE> = TripleReceiver::init(&mut channel, &mut rng, setup, extend);

        return (triple_receiver);
    });
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let _triple_sender: TripleSender<FE> = TripleSender::init(&mut channel, &mut rng, setup, extend);

    let _handle_return = handle.join().unwrap();
}

fn criterion_benchmark_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("small");
    group.bench_function("wrk17 whole protocol", |b| b.iter(|| wrk17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_SMALL, LPN_EXTEND_SMALL)));
    group.bench_function("hss17 whole protocol", |b| b.iter(|| hss17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_SMALL, LPN_EXTEND_SMALL)));
    group.finish();
}

fn criterion_benchmark_medium(c: &mut Criterion) {
    let mut group = c.benchmark_group("medium");
    group.bench_function("wrk17 whole protocol", |b| b.iter(|| wrk17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM)));
    group.bench_function("hss17 whole protocol", |b| b.iter(|| hss17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM)));
    group.finish();
}

fn criterion_benchmark_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("large");
    group.bench_function("wrk17 whole protocol", |b| b.iter(|| wrk17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_LARGE, LPN_EXTEND_LARGE)));
    group.bench_function("hss17 whole protocol", |b| b.iter(|| hss17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_LARGE, LPN_EXTEND_LARGE)));
    group.finish();
}

fn criterion_benchmark_wrk17(c: &mut Criterion) {
    let mut group = c.benchmark_group("wrk17");
    for params in [(LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL), (LPN_SETUP_SMALL, LPN_EXTEND_SMALL)].iter() {
        group.bench_function("wrk17", |b| b.iter(|| wrk17_protocol::<F128b, Sender<F128b>, Receiver<F128b>>(params.0, params.1)));
    }
    group.finish();
}

fn criterion_benchmark_init_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("init_large");
    group.bench_function("init_large", |b| b.iter(|| bench_init::<F128b, Sender<F128b>, Receiver<F128b>>(LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM)));
    group.finish();
}

// Small uses 52870 triples to create:
// hss17: 5875 triples
// wrk17: 127623 triples

// Medium uses 3335075 triples to create:
// hss17: 370564 triples
// wrk17: 1111691 triples

// Large uses 3404680 triples to create:
// hss17: 378298 triples, takes ~800s
// wrk17: 1134893 triples

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark_init_large
}
criterion_main!(benches);
