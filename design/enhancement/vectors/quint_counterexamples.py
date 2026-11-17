"""Counterexamples for the Quint findings of the split-line model (formal/quint/splitline.qnt).

Each case builds the attack of one model trace on real secp256k1 arithmetic, under the rule
the model flagged (old) and under the rule that fixes it (new). The old rule must leak the
committee half x_f or the full key; the new rule must not. Exit status 0 means every case
behaved as recorded in tests/quint-regressions/splitline/COUNTEREXAMPLES.md.

  S1  Board fork (DECISIONS 42, Q1). Non-TEE, n = 9, f = 2, t = 7, q = 6. A corrupt set of
      b = 6 nodes signs two (or three) board orders. Each of the 3 honest nodes sees a different
      ticket for one Schnorr slot and releases its partial for it. With its own 6 shares the
      coalition completes three committee halves on one nonce pair (D, E) and solves for x_f.
      With b = 5 it completes two halves: two signatures nobody authorized, x_f stays hidden.
      Fix: slot_anchor (O32) puts the ticket on Midnight before release; all honest nodes
      release the anchored ticket only.
  S2  Cold start ECDSA reuse (DECISIONS 46(3), Q3). E restores from a checkpoint taken before
      a slot was claimed. Without the burn rule E signs a second message on the slot.
      Two ECDSA signatures with one k give k and then x. Fix: burn every slot unclaimed at the
      checkpoint.
  S3  Slot precedence (DECISIONS 44, Q4). A later request reserves the named slot of an
      earlier one; the earlier request then signs on the same slot when it is ordered.
      Same algebra as S2 for ECDSA. Fix: precedence by board order; a later request that names
      a taken slot ends VOID SLOT_TAKEN and never gets a partial.

  S4  Restart settlement (DECISIONS 53). An ECDSA request releases its committee partial, a
      whole-committee restart loses the board tail, and the old rule settles the request VOID
      because its pinned nonce n is still unused. The record returns to unspent, a new
      authorization signs nonce n + 1, and the completed first transaction confirms as well:
      two debits from one record state on an account chain. Fix: settle RELEASED, so the
      re-post must use nonce n and the ledger accepts one of the two.

  PA3 Offline-holder birth (DECISIONS 67, REVIEW-17a finding 3). The holder registered
      U = u·G. The creator picks e_c, sets X_u = U + Hq_st(e_c·U)·G, and proves delta for
      X_u - U by a Schnorr proof; both birth proofs verify. It then puts another point
      E_c' in the record for the holder. The holder derives x_u' = u + Hq_st(u·E_c') and
      x_u'·G != X_u: nobody knows the shard of the address. Old rule: a payer funds the
      address once the record is final, and the coins lock. New rule: the holder checks
      x_u·G = X_u and acknowledges with a proof of possession under X_u; a payer funds
      only an acknowledged record. With the honest E_c the holder acknowledges.

Usage: python3 quint_counterexamples.py
"""
import hashlib, secrets, sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def jadd(p, q):
    if p is None: return q
    if q is None: return p
    X1, Y1, Z1 = p; X2, Y2, Z2 = q
    Z1s, Z2s = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2s % P, X2 * Z1s % P
    S1, S2 = Y1 * Z2s * Z2 % P, Y2 * Z1s * Z1 % P
    if U1 == U2:
        if S1 != S2: return None
        Ys = Y1 * Y1 % P; S = 4 * X1 * Ys % P; Mm = 3 * X1 * X1 % P
        X3 = (Mm * Mm - 2 * S) % P
        return (X3, (Mm * (S - X3) - 8 * Ys * Ys) % P, 2 * Y1 * Z1 % P)
    Hh = (U2 - U1) % P; R = (S2 - S1) % P; H2 = Hh * Hh % P; H3 = H2 * Hh % P
    X3 = (R * R - H3 - 2 * U1 * H2) % P
    return (X3, (R * (U1 * H2 - X3) - S1 * H3) % P, Hh * Z1 * Z2 % P)


def M(k, p):
    r, q, k = None, (p[0], p[1], 1), k % N
    while k:
        if k & 1: r = jadd(r, q)
        q = jadd(q, q); k >>= 1
    if r is None: return None
    zi = pow(r[2], P - 2, P)
    return (r[0] * zi * zi % P, r[1] * zi * zi * zi % P)


def A(*ps):
    r = None
    for p in ps:
        if p is not None: r = jadd(r, (p[0], p[1], 1))
    if r is None: return None
    zi = pow(r[2], P - 2, P)
    return (r[0] * zi * zi % P, r[1] * zi * zi * zi % P)


def neg(p): return (p[0], (-p[1]) % P)
def xb(p): return p[0].to_bytes(32, 'big')
def cb(p): return bytes([2 + (p[1] & 1)]) + xb(p)
def inv(a): return pow(a % N, N - 2, N)
def th(tag, m): t = hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t + t + m).digest()
def Hn(*a): return int.from_bytes(hashlib.sha256(b''.join(a)).digest(), 'big') % N


def lift(x):
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    return (x, y if y % 2 == 0 else P - y)


def bip340_verify(Qx, m, Rx, s):
    Q = lift(Qx)
    e = int.from_bytes(th("BIP0340/challenge", Rx.to_bytes(32, 'big') + Qx.to_bytes(32, 'big') + m), 'big') % N
    R = A(M(s, G), neg(M(e, Q)))
    return R is not None and R[1] % 2 == 0 and R[0] == Rx


def lag(i, S):
    num = den = 1
    for j in S:
        if j != i: num = num * (-j) % N; den = den * (i - j) % N
    return num * inv(den) % N


def shamir(sec, k, ids):
    co = [sec] + [secrets.randbelow(N) for _ in range(k - 1)]
    return {i: sum(c * pow(i, e, N) for e, c in enumerate(co)) % N for i in ids}


def solve3(rows):
    """Solve a 3x3 system over Z_N by Gauss-Jordan; rows are [a, b, c, rhs]. None if singular."""
    m = [r[:] for r in rows]
    for col in range(3):
        piv = next((r for r in range(col, 3) if m[r][col] % N), None)
        if piv is None: return None
        m[col], m[piv] = m[piv], m[col]
        iv = inv(m[col][col]); m[col] = [v * iv % N for v in m[col]]
        for r in range(3):
            if r != col and m[r][col]:
                f = m[r][col]; m[r] = [(a - f * b) % N for a, b in zip(m[r], m[col])]
    return [m[r][3] for r in range(3)]


# ---------------------------------------------------------------- S1 board fork
def s1_fork(b, rule):
    """n = 9, t = 7. Corrupt nodes 1..b. Honest nodes see tickets per their board fork.
    rule 'old': each honest node releases for the ticket its board fork orders.
    rule 'new': slot_anchor puts one ticket on Midnight; honest nodes release only that ticket.
    Returns (signatures completed, x_f recovered)."""
    n, t = 9, 7
    ids = list(range(1, n + 1)); corrupt = ids[:b]; honest = ids[b:]
    xf, xu = secrets.randbelow(N), secrets.randbelow(N)
    X = A(M(xf, G), M(xu, G))
    Q = X if X[1] % 2 == 0 else neg(X); g = 1 if X[1] % 2 == 0 else -1
    dl, el = secrets.randbelow(N), secrets.randbelow(N)
    Dl, El = M(dl, G), M(el, G)
    xs, ds, es = shamir(xf, t, ids), shamir(dl, t, ids), shamir(el, t, ids)
    # The coalition writes one ticket per fork; at most n - b honest nodes, t - b needed per ticket.
    need = t - b
    nforks = len(honest) // need
    tickets = []
    for j in range(nforks):
        ku = secrets.randbelow(N); RA = M(ku, G)
        m = secrets.token_bytes(32); pm = hashlib.sha256(xb(Q) + m).digest()
        rf = Hn(b"SL1/bindF", b"slot1", cb(RA), pm)
        R = A(RA, Dl, M(rf, El)); sig = 1 if R[1] % 2 == 0 else -1
        c = int.from_bytes(th("BIP0340/challenge", xb(R) + xb(Q) + m), 'big') % N
        tickets.append(dict(ku=ku, m=m, rf=rf, R=R, sig=sig, ct=g * c % N, c=c))
    if rule == 'new':
        anchored = 0                                    # Midnight anchors ticket 0 for the slot
        view = {h: anchored for h in honest}
    else:
        view = {h: j for j in range(nforks) for h in honest[j * need:(j + 1) * need]}
    # each honest node releases one partial, for the ticket its view selects
    partial = {}
    for h, j in view.items():
        tk = tickets[j]
        partial[(h, j)] = (tk['sig'] * (ds[h] + tk['rf'] * es[h]) + tk['ct'] * xs[h]) % N
    # coalition completes every ticket with t partials (own shares + honest partials)
    done = []
    for j, tk in enumerate(tickets):
        hs = [h for (h, jj) in partial if jj == j]
        if b + len(hs) < t: continue
        T = corrupt + hs[:t - b]
        own = {i: (tk['sig'] * (ds[i] + tk['rf'] * es[i]) + tk['ct'] * xs[i]) % N for i in corrupt}
        sf = sum(lag(i, T) * (own[i] if i in own else partial[(i, j)]) for i in T) % N
        s = (tk['sig'] * tk['ku'] + tk['ct'] * xu + sf) % N
        assert bip340_verify(Q[0], tk['m'], tk['R'][0], s), "committee half does not verify"
        done.append((tk, sf))
    rec = None
    if len(done) >= 3:   # sf_j = sig_j*d + sig_j*rf_j*e + ct_j*x_f, unknowns (d, e, x_f)
        rows = [[tk['sig'] % N, tk['sig'] * tk['rf'] % N, tk['ct'], sf] for tk, sf in done[:3]]
        sol = solve3(rows)
        rec = sol is not None and sol[2] == xf
    return len(done), bool(rec)


# ---------------------------------------------------------------- S2 / S3 ECDSA slot reuse
def ecdsa_slot_reuse(two_messages):
    """One ECDSA slot (k fixed by the slot presignature). Returns True when the key leaks."""
    x = secrets.randbelow(N); X = M(x, G)
    k = secrets.randbelow(N); R = M(k, G); r = R[0] % N
    sigs = []
    for _ in range(2 if two_messages else 1):
        h = secrets.randbelow(N)
        # additive split between the actor half and the committee half (§3.6)
        w, mu = inv(k), inv(k) * x % N
        wu, muu = secrets.randbelow(N), secrets.randbelow(N)
        s = ((h * wu + r * muu) + (h * (w - wu) + r * (mu - muu))) % N
        si = inv(s); assert A(M(h * si, G), M(r * si, X))[0] % N == r
        sigs.append((h, s))
    if len(sigs) < 2: return False
    (h1, s1), (h2, s2) = sigs
    kk = (h1 - h2) * inv(s1 - s2) % N
    xx = (s1 * kk - h1) * inv(r) % N
    return xx == x


def cold_start(rule):
    """Slot 11 claimed by request r1 after the checkpoint; E restores the checkpoint and
    signs a new request on slot 11 under 'old'. Under 'new' every ECDSA slot unclaimed at the
    checkpoint is burned, so r2 gets a fresh slot and one message per slot holds."""
    claimed_at_cp = set()
    claimed_live = {11: 'r1'}
    unclaimed_after_restore = {11, 12} - claimed_at_cp
    burned = unclaimed_after_restore if rule == 'new' else set()
    slot_r2 = min(s for s in (11, 12, 13) if s not in claimed_at_cp and s not in burned)
    return ecdsa_slot_reuse(two_messages=claimed_live.get(slot_r2) is not None)


def precedence(rule):
    """r1 (board order 1) names slot 11; r2 (board order 2) names slot 11 too and is
    processed first. 'old': first reservation wins, then r1 also signs on 11 when its
    request arrives (literal §5.4 reading). 'new': board order decides; r2 ends VOID SLOT_TAKEN."""
    order = {'r1': 1, 'r2': 2}
    signed_on_11 = []
    for req in ('r2', 'r1'):                 # arrival order differs from board order
        if rule == 'new' and order[req] > min(order.values()):
            continue                          # VOID SLOT_TAKEN, no partial
        signed_on_11.append(req)
    return ecdsa_slot_reuse(two_messages=len(signed_on_11) > 1)


def ecdsa_sign_split(x, h):
    """One ECDSA slot: actor half plus committee half (§3.6). Returns (r, s)."""
    k = secrets.randbelow(N - 1) + 1; r = M(k, G)[0] % N
    w, mu = inv(k), inv(k) * x % N
    wu, muu = secrets.randbelow(N), secrets.randbelow(N)
    s_actor = (h * wu + r * muu) % N
    s_committee = (h * (w - wu) + r * (mu - muu)) % N      # the released partial
    return r, (s_actor + s_committee) % N


def ecdsa_verify(X, h, r, s):
    si = inv(s); R = A(M(h * si, G), M(r * si, X))
    return R is not None and R[0] % N == r


def restart_settlement(rule):
    """Account ledger with nonces. Returns the number of debits applied from one record state."""
    x = secrets.randbelow(N); X = M(x, G)
    ledger = {'nonce': 0, 'debits': 0}
    def apply(tx):
        n, h, (r, s) = tx
        if n == ledger['nonce'] and ecdsa_verify(X, h, r, s):
            ledger['nonce'] += 1; ledger['debits'] += 1
    pinned = 0
    h1 = Hn(b"tx", b"nonce0", b"to=D1")
    tx1 = (pinned, h1, ecdsa_sign_split(x, h1))       # partial released before the restart
    # whole-committee restart: the board tail with the RELEASE votes is lost; pinned nonce unused
    outcome = 'VOID' if rule == 'old' else 'RELEASED'
    # the next authorization: VOID frees the record (wallet takes the next nonce after tx1 is
    # broadcast); RELEASED pins nonce 0
    n2 = pinned + 1 if outcome == 'VOID' else pinned
    h2 = Hn(b"tx", str(n2).encode(), b"to=D2")
    tx2 = (n2, h2, ecdsa_sign_split(x, h2))
    for tx in (tx1, tx2):                              # tx1 confirms first, then tx2
        apply(tx)
    return ledger['debits']


def schnorr_pok(x, X, ctx):
    k = secrets.randbelow(N); R = M(k, G)
    c = Hn(b"pop", cb(R), cb(X), ctx)
    return R, (k + c * x) % N


def schnorr_pok_ok(X, ctx, proof):
    R, s = proof
    return M(s, G) == A(R, M(Hn(b"pop", cb(R), cb(X), ctx), X))


def offline_birth(rule, honest_creator):
    """Returns (birth proofs verify, holder derives x_u, payer funded, coins locked)."""
    u = secrets.randbelow(N); U = M(u, G)
    pop_U = schnorr_pok(u, U, b"SL1/pop-rk")
    e_c = secrets.randbelow(N); E_c = M(e_c, G)
    delta = Hn(b"SL1/st", cb(M(e_c, U)))
    X_u = A(U, M(delta, G))
    ctx = b"birth" + cb(X_u)
    delta_proof = schnorr_pok(delta, A(X_u, neg(U)), ctx)
    birth_ok = schnorr_pok_ok(U, b"SL1/pop-rk", pop_U) and schnorr_pok_ok(A(X_u, neg(U)), ctx, delta_proof)
    E_rec = E_c if honest_creator else M(secrets.randbelow(N), G)   # the point the record carries
    x_u = (u + Hn(b"SL1/st", cb(M(u, E_rec)))) % N                  # the holder's derivation
    derives = M(x_u, G) == X_u
    # the holder acknowledges only with a valid proof of possession under X_u
    acked = derives and schnorr_pok_ok(X_u, b"SL1/pop" + cb(X_u), schnorr_pok(x_u, X_u, b"SL1/pop" + cb(X_u)))
    funded = birth_ok and (acked if rule == 'new' else True)
    return birth_ok, derives, funded, funded and not derives


def main():
    ok = True
    print("S1 board fork, n=9 t=7 non-TEE, no slot_anchor vs slot_anchor")
    for b in (2, 5, 6):
        for rule in ('old', 'new'):
            sigs, leak = s1_fork(b, rule)
            exp_sigs = {('old', 5): 2, ('old', 6): 3}.get((rule, b), 1)
            exp_leak = rule == 'old' and b == 6
            good = (sigs, leak) == (exp_sigs, exp_leak)
            ok &= good
            print(f"  b={b} rule={rule:<3} completed committee halves on one slot: {sigs}, x_f recovered: {leak}"
                  f"  {'as expected' if good else 'UNEXPECTED'}")
    for name, fn in (("S2 cold start ECDSA slot", cold_start), ("S3 slot precedence ECDSA", precedence)):
        for rule in ('old', 'new'):
            leak = fn(rule)
            good = leak == (rule == 'old')
            ok &= good
            print(f"  {name} rule={rule:<3} key recovered: {leak}  {'as expected' if good else 'UNEXPECTED'}")
    for rule in ('old', 'new'):
        d = restart_settlement(rule)
        good = d == (2 if rule == 'old' else 1)
        ok &= good
        print(f"  S4 restart settlement rule={rule:<3} debits from one record state: {d}  {'as expected' if good else 'UNEXPECTED'}")
    for honest in (False, True):
        for rule in ('old', 'new'):
            birth_ok, derives, funded, locked = offline_birth(rule, honest)
            exp = (True, honest, honest or rule == 'old', rule == 'old' and not honest)
            good = (birth_ok, derives, funded, locked) == exp
            ok &= good
            print(f"  PA3 offline birth creator={'honest' if honest else 'bad E_c'} rule={rule:<3} birth proofs verify: {birth_ok},"
                  f" holder derives: {derives}, funded: {funded}, coins locked: {locked}  {'as expected' if good else 'UNEXPECTED'}")
    print("all counterexamples as recorded" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
