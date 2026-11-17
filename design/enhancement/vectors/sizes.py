# Envelope byte budget and signing-set limits per frame (DESIGN.md §4.6, §11.1).
# Header fixed fields 150 B, AEAD tag 16 B. A capsule holds the host fields (transaction, prevouts,
# destination record), one nonce point R_0 or R_l per half, one 32-byte salt seed, the initiator term
# point T_0 = lambda_0*X_0 + tw*G, the initiator id and the signing set. HOST is the measured size of the
# host fields of the prototype fixture variants with their length prefixes (P2TR for Schnorr, P2WPKH for
# ECDSA; impl/tests/split_envelope.rs and the split_sizes binary use the same variants).
# TEE mode adds the TEE header fields: intent 24, public key 33, leaf_root 32, r_ic 32, one salt per variant.
# Run: python3 -I vectors/sizes.py
FRAME=16384; GMAX=2; KMAX=8
LAY=24*2+16      # DECISIONS 57: layout block, 24 u16 region lengths and the AEAD tag
CAP=97+32+32*KMAX # DECISIONS 57: actor capsule with k_lay and ck_v padded to K_max
HOST={(False,1):221,(False,2):306,(True,1):173,(True,2):246}   # (ECDSA, L): host field bytes
def nb(K): return sum(min(v,GMAX) for v in range(1,K+1))      # bodies (Schnorr)
def outer(n,t): return t*33+n*32+33+196
def cap(v,L,ecdsa=False):   # one capsule without actors and tag: host, nonces, salt, T_0, initiator, set
    nonces=L if ecdsa else min(v,GMAX)*L
    return HOST[(ecdsa,L)]+33*nonces+32+33+2+4
def tee_header(K): return 24+33+32+32+32*K
def base(n,t,K,L,ecdsa=False):
    B=K if ecdsa else nb(K); H=B*L; tk=36 if ecdsa else 149
    hdr=150+64+16   # fixed fields, ic and r_tkc, tag
    caps=sum(cap(v,L,ecdsa)+16 for v in range(1,K+1))
    return 96+outer(n,t)+LAY+hdr+H*tk+B*(32*L+32+16)+caps, B, H
def per_actor(K,L,tee,ecdsa=False):
    B=K if ecdsa else nb(K); H=B*L
    tbl=33+(2 if ecdsa else 0)   # H(tau_a) 32, position 1, ECDSA session party index 2
    if ecdsa: caps=K*35; teeb=33      # per capsule: signing-set id 2, weighted leaf point 33; no pool pairs
    else: caps=K*39+2*H; teeb=33+4*H   # per capsule: pool id 4, signing-set id 2, weighted leaf point 33
    return CAP+tbl+caps+(teeb if tee else 0)
def emb(K,L,ecdsa=False):
    B=K if ecdsa else nb(K)
    return B*(33+32*L+16)+16
for n,t in ((9,7),(17,12)):
    for K,L,e in ((8,2,False),(8,1,False),(5,2,False),(3,2,True),(1,1,True),(1,1,False)):
        b,B,H=base(n,t,K,L,e)
        row=[f"n={n} K={K} L={L} {'ECDSA' if e else 'Schnorr'} bodies={B} halves={H} base={b}"]
        for tee in (False,True):
            free=FRAME-b-B*33-(tee_header(K) if tee else 0)
            pa=per_actor(K,L,tee,e)
            row.append(f"{'TEE' if tee else 'non'}: per actor {pa}, max others {free//pa} (|S|<={free//pa+1})")
            pe=pa-CAP+emb(K,L,e)
            row.append(f"embedded per actor {pe}, max {free//pe}")
        print(' | '.join(row))
    for K,L in ((8,2),(8,1)):
        B=nb(K); print(f" contrib frame used n={n} K={K} L={L}: {96+outer(n,t)+LAY+166+49+B*(33+32*L+16)}  emb bytes {emb(K,L)}")
print("slot bytes", [ (n,t*2*(t*33+n*32)) for n,t in ((9,7),(17,12))])
