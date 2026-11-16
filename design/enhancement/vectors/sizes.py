# Envelope byte budget and signing-set limits per frame (DESIGN.md §4.6, §11.1). Estimates:
# header fixed fields 150 B, capsule 465 B (transaction, prevouts, destination record, per half R_0 or R_l,
# one 32-byte salt seed, the initiator term point T_0 = lambda_0*X_0 + tw*G), AEAD tag 16 B. Run: python3 -I vectors/sizes.py
FRAME=16384; GMAX=2; KMAX=8
LAY=24*2+16      # DECISIONS 57: layout block, 24 u16 region lengths and the AEAD tag
CAP=97+32+32*KMAX # DECISIONS 57: actor capsule with k_lay and ck_v padded to K_max
def nb(K): return sum(min(v,GMAX) for v in range(1,K+1))      # bodies (Schnorr)
def outer(n,t): return t*33+n*32+33+196
def base(n,t,K,L,ecdsa=False):
    B=K if ecdsa else nb(K); H=B*L; tk=36 if ecdsa else 149
    hdr=150+64+16   # fixed fields, ic and r_tkc, tag
    return 96+outer(n,t)+LAY+hdr+H*tk+B*(32*L+32+16)+K*(465+16), B, H
def per_actor(K,L,tee,ecdsa=False):
    B=K if ecdsa else nb(K); H=B*L
    cap=CAP; tbl=33+(2 if ecdsa else 0)   # H(tau_a) 32, position 1, ECDSA session party index 2
    if ecdsa: caps=K*33; teeb=33      # weighted leaf point per capsule; no pool pairs
    else: caps=K*39+2*H; teeb=33+4*H   # per capsule: pool id 4, charter slot 2, weighted leaf point 33
    return cap+tbl+caps+(teeb if tee else 0)
def emb(K,L,ecdsa=False):
    B=K if ecdsa else nb(K)
    return B*(33+32*L+16)+16
for n,t in ((9,7),(17,12)):
    for K,L,e in ((8,2,False),(8,1,False),(5,2,False),(3,2,True),(1,1,True),(1,1,False)):
        b,B,H=base(n,t,K,L,e)
        free=FRAME-b-B*33
        row=[f"n={n} K={K} L={L} {'ECDSA' if e else 'Schnorr'} bodies={B} halves={H} base={b}"]
        for tee in (False,True):
            pa=per_actor(K,L,tee,e)
            row.append(f"{'TEE' if tee else 'non'}: per actor {pa}, max others {free//pa} (|S|<={free//pa+1})")
            pe=pa-CAP+emb(K,L,e)
            row.append(f"embedded per actor {pe}, max {free//pe}")
        print(' | '.join(row))
    for K,L in ((8,2),(8,1)):
        B=nb(K); print(f" contrib frame used n={n} K={K} L={L}: {96+outer(n,t)+LAY+166+49+B*(33+32*L+16)}  emb bytes {emb(K,L)}")
print("slot bytes", [ (n,t*2*(t*33+n*32)) for n,t in ((9,7),(17,12))])
