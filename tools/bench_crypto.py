"""Đo nhanh hiệu năng (thời gian + kích thước) của các nguyên thủy mật mã mà
SecChat sử dụng. Chạy: python tools/bench_crypto.py"""
import time, statistics, platform
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def timeit(fn, iters):
    # warmup
    for _ in range(5):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)  # ms
    return statistics.mean(samples)

def bench_kem(alg, iters=200):
    with oqs.KeyEncapsulation(alg) as kem:
        pk = kem.generate_keypair()
        sk_len = len(kem.export_secret_key())
        ct, ss = kem.encap_secret(pk)
        rows = {}
        rows['keygen'] = timeit(lambda: oqs.KeyEncapsulation(alg).generate_keypair(), iters)
        # encaps/decaps reuse one keypair
        def enc():
            kem.encap_secret(pk)
        rows['encaps'] = timeit(enc, iters)
        def dec():
            kem.decap_secret(ct)
        rows['decaps'] = timeit(dec, iters)
        rows['pk'] = len(pk); rows['sk'] = sk_len; rows['ct'] = len(ct); rows['ss'] = len(ss)
    return rows

def bench_x25519(iters=2000):
    rows = {}
    rows['keygen'] = timeit(lambda: X25519PrivateKey.generate(), iters)
    a = X25519PrivateKey.generate(); b = X25519PrivateKey.generate(); bp = b.public_key()
    rows['derive'] = timeit(lambda: a.exchange(bp), iters)
    rows['pk'] = 32; rows['sk'] = 32; rows['ss'] = 32
    return rows

def bench_ed25519(iters=2000):
    rows = {}
    rows['keygen'] = timeit(lambda: Ed25519PrivateKey.generate(), iters)
    k = Ed25519PrivateKey.generate(); pub = k.public_key(); msg = b'x'*64
    sig = k.sign(msg)
    rows['sign'] = timeit(lambda: k.sign(msg), iters)
    rows['verify'] = timeit(lambda: pub.verify(sig, msg), iters)
    rows['pk'] = 32; rows['sk'] = 32; rows['sig'] = len(sig)
    return rows

print("# Platform:", platform.platform())
print("# liboqs:", oqs.oqs_version(), "| enabled KEMs include ML-KEM:",
      [k for k in oqs.get_enabled_kem_mechanisms() if 'ML-KEM' in k])
print()
for alg in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
    r = bench_kem(alg)
    print(f"{alg}: keygen={r['keygen']:.3f}ms encaps={r['encaps']:.3f}ms decaps={r['decaps']:.3f}ms "
          f"| pk={r['pk']} sk={r['sk']} ct={r['ct']} ss={r['ss']}")
print()
x = bench_x25519()
print(f"X25519: keygen={x['keygen']:.4f}ms derive={x['derive']:.4f}ms | pk={x['pk']} ss={x['ss']}")
e = bench_ed25519()
print(f"Ed25519: keygen={e['keygen']:.4f}ms sign={e['sign']:.4f}ms verify={e['verify']:.4f}ms | pk={e['pk']} sig={e['sig']}")
