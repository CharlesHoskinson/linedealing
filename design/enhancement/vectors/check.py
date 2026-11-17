import hashlib, secrets
# secp256k1
P=2**256-2**32-977; N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G=(Gx,Gy)
def add(a,b):
    if a is None: return b
    if b is None: return a
    if a[0]==b[0] and (a[1]+b[1])%P==0: return None
    if a==b: l=3*a[0]*a[0]*pow(2*a[1],P-2,P)%P
    else: l=(b[1]-a[1])*pow(b[0]-a[0],P-2,P)%P
    x=(l*l-a[0]-b[0])%P; return (x,(l*(a[0]-x)-a[1])%P)
def mul(k,p):
    r=None; k%=N
    while k:
        if k&1: r=add(r,p)
        p=add(p,p); k>>=1
    return r
def neg(p): return (p[0],(-p[1])%P)
def th(tag,m): t=hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t+t+m).digest()
def xb(p): return p[0].to_bytes(32,'big')
def lift(x):
    y=pow((x**3+7)%P,(P+1)//4,P); return (x,y if y%2==0 else P-y)
def bip340_verify(Qx,m,Rx,s):
    Q=lift(Qx); e=int.from_bytes(th("BIP0340/challenge",Rx.to_bytes(32,'big')+Qx.to_bytes(32,'big')+m),'big')%N
    R=add(mul(s,G),neg(mul(e,Q)))
    return R is not None and R[1]%2==0 and R[0]==Rx
H=lambda *a: int.from_bytes(hashlib.sha256(b''.join(a)).digest(),'big')%N
cases=set(); ok=0
for it in range(60):
    xu=secrets.randbelow(N); xf=secrets.randbelow(N); tw=secrets.randbelow(N)
    X=add(add(mul(xu,G),mul(xf,G)),mul(tw,G))
    gP=1 if X[1]%2==0 else -1; Pk=X if gP==1 else neg(X)
    root=secrets.token_bytes(32) if it%2 else b''
    ttap=int.from_bytes(th("TapTweak",xb(Pk)+root),'big')%N
    Q=add(Pk,mul(ttap,G)); gQ=1 if Q[1]%2==0 else -1
    g=gP*gQ
    m=secrets.token_bytes(32)
    ku=secrets.randbelow(N); d=secrets.randbelow(N); e=secrets.randbelow(N)
    Ru=mul(ku,G); D=mul(d,G); E=mul(e,G)
    pm=hashlib.sha256(xb(Q)+m).digest()
    rho=H(xb(Ru),pm)
    R=add(add(Ru,D),mul(rho,E)); sig=1 if R[1]%2==0 else -1
    c=int.from_bytes(th("BIP0340/challenge",xb(R)+xb(Q)+m),'big')%N
    su=(sig*ku + c*(g*(xu+tw) + gQ*ttap))%N
    ct=(g*c)%N
    sf=(sig*(d+rho*e) + ct*xf)%N
    s=(su+sf)%N
    cases.add((gP,gQ,sig)); ok+=bip340_verify(Q[0],m,R[0],s)
    # check committee partial verification eq
    assert mul(sf,G)==add(mul(sig,add(D,mul(rho,E))), mul(ct,mul(xf,G)))
print("bip340 ok",ok,"/60 cases",sorted(cases))
# ECDSA additive split
ok=0
for it in range(20):
    x=secrets.randbelow(N); X=mul(x,G); k=secrets.randbelow(N); R=mul(k,G); r=R[0]%N
    ki=pow(k,N-2,N); w=ki; mu=ki*x%N
    wu=secrets.randbelow(N); muu=secrets.randbelow(N); wf=(w-wu)%N; muf=(mu-muu)%N
    h=secrets.randbelow(N)
    su=(h*wu+r*muu)%N; sf=(h*wf+r*muf)%N; s=(su+sf)%N
    Wu=mul(wu,R); Mu=mul(muu,R)
    assert mul(su,R)==add(mul(h,Wu),mul(r,Mu))
    assert add(mul(wf,R),Wu)==G and add(mul(muf,R),Mu)==X
    si=pow(s,N-2,N); RR=add(mul(h*si,G),mul(r*si,X)); ok+= RR[0]%N==r
print("ecdsa ok",ok,"/20")
# ECDSA slot setup check: R=ku*Rf, a=ku^-1, w=a*phi, mu = a*(x_U'*phi+psi)
xU=secrets.randbelow(N); xf=secrets.randbelow(N); X=mul((xU+xf)%N,G)
kf=secrets.randbelow(N); Rf=mul(kf,G); phi=pow(kf,N-2,N); psi=phi*xf%N
ku=secrets.randbelow(N); R=mul(ku,Rf); a=pow(ku,N-2,N)
k=ku*kf%N; assert mul(a*phi%N,R)==mul(phi,Rf)
assert (a*phi)%N==pow(k,N-2,N) and (a*(xU*phi+psi))%N==pow(k,N-2,N)*(xU+xf)%N
print("slot algebra ok")

# ---------------------------------------------------------------------------
# Multi-shard split-line dealing (DESIGN.md §2.4, §3.6, §4.2, §4.4).
# Key x = x_f + tw + sum of top-level shards. Access structure: AND (additive),
# k-of-m group (Shamir, Lagrange weight of the chosen subset), OR (escrow copy).
# Jacobian arithmetic for speed; same curve and helpers as above.
def jadd(p,q):
    if p is None: return q
    if q is None: return p
    X1,Y1,Z1=p; X2,Y2,Z2=q
    Z1s=Z1*Z1%P; Z2s=Z2*Z2%P
    U1=X1*Z2s%P; U2=X2*Z1s%P; S1=Y1*Z2s*Z2%P; S2=Y2*Z1s*Z1%P
    if U1==U2:
        if S1!=S2: return None
        if Y1==0: return None
        A=4*X1*Y1*Y1%P; B=3*X1*X1%P; X3=(B*B-2*A)%P
        return (X3,(B*(A-X3)-8*pow(Y1,4,P))%P,2*Y1*Z1%P)
    H_=(U2-U1)%P; R_=(S2-S1)%P; H2=H_*H_%P; H3=H2*H_%P
    X3=(R_*R_-H3-2*U1*H2)%P
    return (X3,(R_*(U1*H2-X3)-S1*H3)%P,H_*Z1*Z2%P)
def jmul(k,p):
    k%=N; r=None; q=(p[0],p[1],1)
    while k:
        if k&1: r=jadd(r,q)
        q=jadd(q,q); k>>=1
    return r
def aff(p):
    if p is None: return None
    zi=pow(p[2],P-2,P); return (p[0]*zi*zi%P,p[1]*zi*zi*zi%P)
def M(k,p): return aff(jmul(k,p))
def A(*ps):
    r=None
    for p in ps:
        if p is not None: r=jadd(r,(p[0],p[1],1))
    return aff(r)
def cb(p): return bytes([2+(p[1]&1)])+xb(p)
def lag(i,S,n=N):
    num=den=1
    for j in S:
        if j!=i: num=num*(-j)%n; den=den*(i-j)%n
    return num*pow(den,n-2,n)%n
def shamir(sec,k,ids,n=N):
    co=[sec]+[secrets.randbelow(n) for _ in range(k-1)]
    return {i:sum(c*pow(i,e,n) for e,c in enumerate(co))%n for i in ids},co

# Access structures. A shard is ('one', holder) or ('grp', k, members) and may
# carry an OR escrow ('esc', k, members). A signing set picks, per shard, the
# primary holder, or a k-subset of the group, or a k-subset of the escrow group.
# Each leaf contribution gets weight = Lagrange coefficient of its subset (1 for one holder).
def birth(shards):
    """Returns shard secrets, per-holder shares, shard points."""
    st=[]
    for sh in shards:
        if sh[0]=='one':
            x=secrets.randbelow(N); rec={'x':x,'X':M(x,G),'kind':'one','holder':sh[1]}
        else:
            # group shard by DKG among members: each member deals deg k-1; x = sum of constants
            k,mem=sh[1],sh[2]; shares={i:0 for i in mem}; x=0
            for dealer in mem:
                s,co=shamir(secrets.randbelow(N),k,mem); x=(x+co[0])%N
                for i in mem: shares[i]=(shares[i]+s[i])%N
            rec={'x':x,'X':M(x,G),'kind':'grp','k':k,'shares':shares}
            if sh[0]=='nest':   # member sh[3] is itself a k2-of-m2 gate: its share is dealt on
                mid,k2,mem2=sh[3]; rec['sub']=(mid,shamir(shares[mid],k2,mem2)[0])
            # every member share matches Feldman: sum of lambda over any k-subset reconstructs x
            T=mem[:k]; assert sum(lag(i,T)*shares[i] for i in T)%N==x
        if len(sh)>3 and sh[3][0]=='esc' or (sh[0]=='one' and len(sh)>2):
            esc=sh[-1]; _,k,mem=esc; s,_=shamir(rec['x'],k,mem)
            rec['esc']={'k':k,'shares':s}
        st.append(rec)
    return st
def leaves(st,choice):
    """choice per shard: None = primary holder / first k members; ('grp',T) or ('esc',T)."""
    out=[]  # (label, weight, secret share, public point of share)
    for idx,(rec,ch) in enumerate(zip(st,choice)):
        if rec['kind']=='one' and ch is None:
            out.append((f"{idx}",1,rec['x']))
        else:
            src=rec['shares'] if (ch[0] in ('grp','nest')) else rec['esc']['shares']
            T=ch[1]
            for i in T:
                if ch[0]=='nest' and i==rec['sub'][0]:   # weight = product along the path
                    for jj in ch[2]: out.append((f"{idx}.n{i}.{jj}",lag(i,T)*lag(jj,ch[2])%N,rec['sub'][1][jj]))
                else: out.append((f"{idx}.{ch[0]}{i}",lag(i,T),src[i]))
    return out

def H_bind(label,Bser,pm): return int.from_bytes(hashlib.sha256(b"SL1/bind"+label.encode()+Bser+pm).digest(),'big')%N

def bip340_multi(st,choice,root,tally,key=None,twice=False):
    xf,tw=key if key else (secrets.randbelow(N),secrets.randbelow(N))
    X=A(M(xf,G),M(tw,G),*[r['X'] for r in st])
    gP=1 if X[1]%2==0 else -1; Pk=X if gP==1 else neg(X)
    ttap=int.from_bytes(th("TapTweak",xb(Pk)+root),'big')%N
    Q=A(Pk,M(ttap,G)); gQ=1 if Q[1]%2==0 else -1; g=gP*gQ
    m=secrets.token_bytes(32); pm=hashlib.sha256(xb(Q)+m+secrets.token_bytes(32)).digest()
    L=leaves(st,choice)
    assert len({lb for lb,_,_ in L})==len(L)   # leaf ids are distinct, so two members of one group get distinct rho_a (§4.2)
    # initiator = first leaf: fresh single nonce R_0; others: pool pair (d_a, e_a)
    k0=secrets.randbelow(N); R0=M(k0,G)
    pairs=[(secrets.randbelow(N),secrets.randbelow(N)) for _ in L[1:]]
    PD=[(M(d,G),M(e,G)) for d,e in pairs]
    dl,el=secrets.randbelow(N),secrets.randbelow(N); Dl,El=M(dl,G),M(el,G)
    # actors bind over the full commitment list CL; the committee binds over (slot, R_A, pm) only
    # the list starts with the initiator's leaf id, so it names the whole signing set (DECISIONS 72)
    Bser=L[0][0].encode()+cb(R0)+b''.join(lb.encode()+cb(D)+cb(E) for (lb,_,_),(D,E) in zip(L[1:],PD))+b"slot7"+cb(Dl)+cb(El)
    rho=[H_bind(lb,Bser,pm) for (lb,_,_) in L[1:]]
    RA=A(R0,*[A(D,M(r,E)) for (D,E),r in zip(PD,rho)])
    rf=H_bind("F",b"slot7"+cb(RA),pm)
    R=A(RA,Dl,M(rf,El))
    sig=1 if R[1]%2==0 else -1
    c=int.from_bytes(th("BIP0340/challenge",xb(R)+xb(Q)+m),'big')%N; ct=g*c%N
    # contributions
    lb0,w0,x0=L[0]
    s=[(sig*k0+ct*(w0*x0+tw)+c*gQ*ttap)%N]
    assert M(s[0],G)==A(M(sig,R0),M(ct,A(M(w0,M(x0,G)),M(tw,G))),M(c*gQ*ttap,G))
    for (lb,w,xs),(d,e),r,(D,E) in zip(L[1:],pairs,rho,PD):
        sa=(sig*(d+r*e)+ct*w*xs+(twice and (ct*tw+c*gQ*ttap)))%N; s.append(sa)
        if not twice: assert M(sa,G)==A(M(sig,A(D,M(r,E))),M(ct*w%N,M(xs,G)))   # per-actor public check
    # committee: Shamir t=7 of n=9 partials, combine any t
    ids=list(range(1,10)); xs_,_=shamir(xf,7,ids); ds,_=shamir(dl,7,ids); es,_=shamir(el,7,ids)
    T=sorted(secrets.SystemRandom().sample(ids,7))
    part={i:(sig*(ds[i]+rf*es[i])+ct*xs_[i])%N for i in T}
    i0=T[0]; assert M(part[i0],G)==A(M(sig,A(M(ds[i0],G),M(rf,M(es[i0],G)))),M(ct,M(xs_[i0],G)))
    sf=sum(lag(i,T)*part[i] for i in T)%N
    stot=(sum(s)+sf)%N
    tally.add((gP,gQ,sig))
    return bip340_verify(Q[0],m,R[0],stot)

STRUCTS={
 # AND of m outside actors, m = 1..5
 **{f"AND m={m}":([('one',f"a{j}") for j in range(m)],[None]*m) for m in range(1,6)},
}
G23=('grp',2,[1,2,3])
for T in ([1,2],[1,3],[2,3]):
    STRUCTS[f"2of3 group T={T}"]=([G23],[('grp',T)])
    STRUCTS[f"user AND 2of3 T={T}"]=([('one','user'),G23],[None,('grp',T)])
ESC=('esc',3,[1,2,3,4,5])
STRUCTS["P2 user OR G: user"]=([('one','user',ESC)],[None])
for T in ([1,2,3],[2,4,5],[1,3,5]):
    STRUCTS[f"P2 user OR G: G T={T}"]=([('one','user',ESC)],[('esc',T)])
NEST=('nest',2,[1,2,3],(3,2,[1,2,3]))   # 2-of-3 whose member 3 is a 2-of-3 subgroup
for T,T2 in (([1,3],[1,2]),([2,3],[2,3]),([1,2],None)):
    STRUCTS[f"user AND nested 2of3(o1,o2,2of3 sub) T={T} sub={T2}"]=([('one','user'),NEST],[None,('nest',T,T2)])
STRUCTS["user AND issuer2of3 AND (cust OR G3of5): G"]=([('one','user'),G23,('one','cust',ESC)],[None,('grp',[1,3]),('esc',[2,3,5])])
allok=True
for name,(shards,choice) in STRUCTS.items():
    tally=set(); ok=n=0
    while len(tally)<8 or n<8:
        st=birth(shards); root=secrets.token_bytes(32) if n%2 else b''
        ok+=bip340_multi(st,choice,root,tally); n+=1
    allok&= ok==n
    print(f"bip340 multi [{name}] ok {ok}/{n} parity cases {len(tally)}/8")
assert allok

# One key signed under several signing sets (the reissue path of §5.9): same birth, same x_f, tw.
for name,shards,choices in [("2of3",[G23],[[('grp',[1,2])],[('grp',[2,3])],[('grp',[1,3])]]),
        ("P2 user OR G",[('one','user',ESC)],[[None],[('esc',[1,2,3])],[('esc',[3,4,5])]])]:
    st=birth(shards); key=(secrets.randbelow(N),secrets.randbelow(N)); tally=set()
    res=[bip340_multi(st,ch,b'',tally,key) for ch in choices]; assert all(res)
    print(f"bip340 multi one key, subsets {len(choices)} [{name}] ok",res)
# Tweak term placed twice (by the initiator and by a second actor): the signature fails.
st=birth([('one','a'),('one','b')]); tally=set()
assert not any(bip340_multi(st,[None,None],b'',tally,twice=True) for _ in range(4))
print("bip340 multi negative: tweak term placed twice fails 4/4")
# Negative case: a coalition outside the access structure does not reach the key.
st=birth([G23]); xf=secrets.randbelow(N); tw=secrets.randbelow(N)
X=A(M(xf,G),M(tw,G),st[0]['X']); one=st[0]['shares'][1]
assert A(M(xf,G),M(tw,G),M(one,G))!=X and A(M(xf,G),M(tw,G),M(lag(1,[1,2])*one%N,G))!=X
print("bip340 multi negative: one member of 2of3 does not reach X (weighted or not)")

# ECDSA multi-shard slot session (§3.6): committee F_presig (Shamir t of n, Feldman in base R_f),
# nonce chain R_l = k_m...k_1 R_f, actor-actor MtA for additive shares of a = prod k_p^-1 and of
# a*x_A, actor-node MtA, corrections, the public check, group reshare, escrow, signing.
def split(v): u=secrets.randbelow(N); return u,(v-u)%N      # ideal MtA output
def ev(com,i): return A(*[M(pow(i,e,N),C) for e,C in enumerate(com)])
def ecdsa_multi(shards,choice,mtacount):
    n,t=9,7; ids=list(range(1,n+1))
    st=birth(shards); xf=secrets.randbelow(N); tw=secrets.randbelow(N)
    x=(xf+tw+sum(r['x'] for r in st))%N; X=M(x,G); Xf=M(xf,G)
    # session parties and additive shard parts x'_p (tw folded into the initiator, party 0)
    parties=[]
    for idx,rec in enumerate(st):
        if rec['kind']=='one': parties.append(((idx,None),rec['x']))
        else:
            mem=sorted(rec['shares']); T0=mem[:rec['k']]
            for i in mem: parties.append(((idx,i),lag(i,T0)*rec['shares'][i]%N if i in T0 else 0))
    xp=[v for _,v in parties]; xp[0]=(xp[0]+tw)%N; m=len(parties)
    assert (sum(xp)+xf)%N==x
    # F_presig for the committee
    kf=secrets.randbelow(N); Rf=M(kf,G); phi=pow(kf,N-2,N); psi=phi*xf%N
    ph,phc=shamir(phi,t,ids); ps,psc=shamir(psi,t,ids)
    Phi=[M(c,Rf) for c in phc]; Psi=[M(c,Rf) for c in psc]
    assert Phi[0]==G and Psi[0]==Xf
    # nonce chain
    ks=[secrets.randbelow(N) for _ in range(m)]; Rl=Rf
    for k in ks: Rl=M(k,Rl)
    inv=[pow(k,N-2,N) for k in ks]; a=1
    for v in inv: a=a*v%N
    # additive shares of a = prod a_p: sequential MtA
    al=[0]*m; al[0]=inv[0]; cnt=0
    for j in range(1,m):
        new=[0]*m
        for b in range(j):
            u,v=split(al[b]*inv[j]%N); new[b]=(new[b]+u)%N; new[j]=(new[j]+v)%N; cnt+=1
        al=new
    assert sum(al)%N==a
    # additive shares of a*x_A
    be=[al[b]*xp[b]%N for b in range(m)]
    for b in range(m):
        for c in range(m):
            if b!=c:
                u,v=split(al[b]*xp[c]%N); be[b]=(be[b]+u)%N; be[c]=(be[c]+v)%N; cnt+=1
    xA=(sum(xp))%N; assert sum(be)%N==a*xA%N
    # actor-node MtA, corrections
    wf={i:0 for i in ids}; muf={i:0 for i in ids}; Cw=[]; Cm=[]; wpart=[]; mpart=[]
    for p in range(m):
        Pw,cw=shamir(secrets.randbelow(N),t,ids); Pm,cm=shamir(secrets.randbelow(N),t,ids)
        wpart.append(cw[0]); mpart.append(cm[0])
        Cw.append([M(c,Rl) for c in cw]); Cm.append([M(c,Rl) for c in cm])
        for i in ids:
            c1,d1=split(al[p]*ph[i]%N); c2,d2=split(be[p]*ph[i]%N); c3,d3=split(al[p]*ps[i]%N)
            wf[i]=(wf[i]+d1+c1-Pw[i])%N; muf[i]=(muf[i]+d2+c2+d3+c3-Pm[i])%N
    mtacount.append((m,cnt,3*m*n))
    # public check per node: Phi' = sum_p x'_p * Phi (each actor publishes x'_p*Phi_k with a DLEQ)
    Phip=[A(*[M(xp[p],C) for p in range(m)]) for C in Phi]
    for i in ids:
        assert M(wf[i],Rl)==A(ev(Phi,i),*[neg(ev(Cw[p],i)) for p in range(m)])
        assert M(muf[i],Rl)==A(ev(Phip,i),ev(Psi,i),*[neg(ev(Cm[p],i)) for p in range(m)])
    assert (sum(wpart)+lag_comb(wf,ids[:t]))%N==pow(ks_prod(ks,kf),N-2,N)
    assert (sum(mpart)+lag_comb(muf,ids[:t]))%N==pow(ks_prod(ks,kf),N-2,N)*x%N
    # group halves: additive member halves reshared to Shamir k-of-m inside the group;
    # escrow: the primary's per-slot halves Shamir-shared to the escrow group
    halves={}
    for p,((idx,i),_) in enumerate(parties): halves.setdefault(idx,[]).append((i,wpart[p],mpart[p]))
    slot={}
    for idx,rec in enumerate(st):
        if rec['kind']=='one':
            _,w,mu=halves[idx][0]; slot[idx]={'w':w,'mu':mu}
            if 'esc' in rec:
                k=rec['esc']['k']; mem=sorted(rec['esc']['shares'])
                ws,wc=shamir(w,k,mem); ms,mc=shamir(mu,k,mem)
                slot[idx]['esc']=(ws,ms,[M(c,Rl) for c in wc],[M(c,Rl) for c in mc])
        else:
            k=rec['k']; mem=sorted(rec['shares']); ws={i:0 for i in mem}; ms={i:0 for i in mem}
            Wc=[None]*k; Mc=[None]*k
            for _,w,mu in halves[idx]:
                s1,c1=shamir(w,k,mem); s2,c2=shamir(mu,k,mem)
                for i in mem: ws[i]=(ws[i]+s1[i])%N; ms[i]=(ms[i]+s2[i])%N
                Wc=[A(Wc[e],M(c1[e],Rl)) for e in range(k)]; Mc=[A(Mc[e],M(c2[e],Rl)) for e in range(k)]
            slot[idx]={'grp':(ws,ms,Wc,Mc)}
    # sign one message with the chosen signing set
    r=Rl[0]%N; h=secrets.randbelow(N); s=0
    for idx,(rec,ch) in enumerate(zip(st,choice)):
        if rec['kind']=='one' and ch is None:
            sa=(h*slot[idx]['w']+r*slot[idx]['mu'])%N
            assert M(sa,Rl)==A(M(h,M(slot[idx]['w'],Rl)),M(r,M(slot[idx]['mu'],Rl))); s+=sa
        else:
            ws,ms,Wc,Mc=slot[idx]['grp'] if ch[0]=='grp' else slot[idx]['esc']
            for i in ch[1]:
                lam=lag(i,ch[1]); sa=lam*(h*ws[i]+r*ms[i])%N
                assert M(sa,Rl)==M(lam,A(M(h,ev(Wc,i)),M(r,ev(Mc,i)))); s+=sa
    T=sorted(secrets.SystemRandom().sample(ids,t))
    s=(s+sum(lag(i,T)*(h*wf[i]+r*muf[i]) for i in T))%N
    si=pow(s,N-2,N); RR=A(M(h*si%N,G),M(r*si%N,X))
    return RR[0]%N==r
def lag_comb(sh,T): return sum(lag(i,T)*sh[i] for i in T)%N
def ks_prod(ks,kf):
    v=kf
    for k in ks: v=v*k%N
    return v
ECASES=[(f"AND m={m}",[('one',f"a{j}") for j in range(m)],[None]*m) for m in range(1,6)]
ECASES+=[(f"user AND 2of3 T={T}",[('one','user'),G23],[None,('grp',T)]) for T in ([1,2],[1,3],[2,3])]
ECASES+=[(f"2of3 only T={T} (tw with a group member)",[G23],[('grp',T)]) for T in ([1,2],[2,3])]
ECASES+=[("P2 user OR G: user",[('one','user',ESC)],[None]),("P2 user OR G: G T=[2,4,5]",[('one','user',ESC)],[('esc',[2,4,5])])]
mc=[]
for name,sh,ch in ECASES:
    v=ecdsa_multi(sh,ch,mc); assert v
    print(f"ecdsa multi [{name}] ok", v)
print("MtA per slot (session parties, actor-actor, actor-node):",sorted(set(mc)))

# ---------------------------------------------------------------------------
# Speed decisions 26-28 (DESIGN.md §4.1, §4.6, §5.10).
GMAX=2
def halves(K,Lin): return [(v,g,j) for v in range(1,K+1) for g in range(1,min(v,GMAX)+1) for j in range(Lin)]
assert len(halves(8,2))==30 and len(halves(8,1))==15 and len(halves(1,1))==1 and len(halves(3,2))==10
print("halves: K=8,L=2 ->",len(halves(8,2)),"; committee slots",min(8,GMAX)*2)

# (a) One committee slot per (generation, input), shared by the candidate tickets of all variants.
# Every half has its own k_0 and its own pool pair; the committee signs one ticket per slot.
def slot_sharing(K,Lin,nact):
    ids=list(range(1,10)); t=7
    xf,tw=secrets.randbelow(N),secrets.randbelow(N); xa=[secrets.randbelow(N) for _ in range(nact+1)]
    X=A(M(xf,G),M(tw,G),*[M(x,G) for x in xa])
    gP=1 if X[1]%2==0 else -1; Pk=X if gP==1 else neg(X)
    ttap=int.from_bytes(th("TapTweak",xb(Pk)),'big')%N
    Q=A(Pk,M(ttap,G)); gQ=1 if Q[1]%2==0 else -1; g_=gP*gQ
    xfs,_=shamir(xf,t,ids)
    slots={}
    for g in range(1,min(K,GMAX)+1):
        for j in range(Lin):
            dl,el=secrets.randbelow(N),secrets.randbelow(N)
            slots[(g,j)]=(shamir(dl,t,ids)[0],shamir(el,t,ids)[0],M(dl,G),M(el,G))
    msg={(v,j):secrets.token_bytes(32) for v in range(1,K+1) for j in range(Lin)}
    used=set(); H={}
    for (v,g,j) in halves(K,Lin):
        m=msg[(v,j)]; pm=hashlib.sha256(xb(Q)+m+secrets.token_bytes(32)).digest()
        _,_,Dl,El=slots[(g,j)]
        k0=secrets.randbelow(N); R0=M(k0,G)
        prs=[(secrets.randbelow(N),secrets.randbelow(N)) for _ in range(nact)]
        PD=[(M(d_,G),M(e_,G)) for d_,e_ in prs]
        for nonce in [k0]+[d_ for d_,_ in prs]: assert nonce not in used; used.add(nonce)   # no nonce serves two halves
        slab=f"slot{g}.{j}".encode()
        # the initiator (the user, leaf "u") comes first in the list (DECISIONS 72)
        Bser=b"u"+cb(R0)+b''.join(f"a{i}".encode()+cb(D)+cb(E) for i,(D,E) in enumerate(PD))+slab+cb(Dl)+cb(El)
        rho=[H_bind(f"a{i}",Bser,pm) for i in range(nact)]
        RA=A(R0,*[A(D,M(r,E)) for (D,E),r in zip(PD,rho)])
        rf=H_bind("F",slab+cb(RA),pm); R=A(RA,Dl,M(rf,El)); sig=1 if R[1]%2==0 else -1
        c=int.from_bytes(th("BIP0340/challenge",xb(R)+xb(Q)+m),'big')%N; ct=g_*c%N
        s0=(sig*k0+ct*(xa[0]+tw)+c*gQ*ttap)%N
        sa=[(sig*(d_+r*e_)+ct*x)%N for (d_,e_),r,x in zip(prs,rho,xa[1:])]
        H[(v,g,j)]=dict(tk=(slab,RA,pm,ct,R[0]),s=(s0+sum(sa))%N,m=m)
    # candidates on one slot differ in R_A, rho, R and c
    for (g,j) in slots:
        cand=[H[h]['tk'] for h in H if h[1]==g and h[2]==j]
        assert len({tk[4] for tk in cand})==len(cand) and len({tk[1] for tk in cand})==len(cand)
    # generation 1 selects j_1, generation 2 a higher variant; one partial per slot and node
    j1=secrets.randbelow(K-1)+1 if K>1 else 1; sel=[(j1,1)]
    if K>1: sel.append((j1+1+secrets.randbelow(K-j1),2))
    ok=True; signed={}
    for (v,g) in sel:
        for j in range(Lin):
            slab,RA,pm,ct,xR=H[(v,g,j)]['tk']; ds,es,Dl,El=slots[(g,j)]
            rf=H_bind("F",slab+cb(RA),pm); R=A(RA,Dl,M(rf,El)); sig=1 if R[1]%2==0 else -1
            assert R[0]==xR                                  # release precondition: ticket x(R) = recomputed
            assert (g,j) not in signed; signed[(g,j)]=v      # the slot signs one ticket
            T=sorted(secrets.SystemRandom().sample(ids,t))
            sf=sum(lag(i,T)*((sig*(ds[i]+rf*es[i])+ct*xfs[i])%N) for i in T)%N
            ok&=bip340_verify(Q[0],H[(v,g,j)]['m'],xR,(H[(v,g,j)]['s']+sf)%N)
    # a ticket with a wrong x(R) is refused
    slab,RA,pm,ct,xR=H[(sel[0][0],1,0)]['tk']; _,_,Dl,El=slots[(1,0)]
    assert A(RA,Dl,M(H_bind("F",slab+cb(RA),pm),El))[0]!=(xR+1)%P
    return ok
for K,Lin,na in ((3,1,0),(3,2,1),(4,1,2),(1,1,1)):
    v=slot_sharing(K,Lin,na); assert v
    print(f"slot sharing [K={K} L={Lin} other actors={na}] one partial per (generation, input) slot, signatures ok",v)

# (b) One polynomial per envelope: threshold PRF keys Z = kappa_0 * H_c(dd || label).
def hc(b):                      # hash to curve by try-and-increment (vector use only)
    ctr=0
    while True:
        x=int.from_bytes(hashlib.sha256(b"SL1/hc"+b+ctr.to_bytes(4,'big')).digest(),'big')%P
        y2=(pow(x,3,P)+7)%P; y=pow(y2,(P+1)//4,P)
        if y*y%P==y2: return (x,y if y%2==0 else P-y)
        ctr+=1
def eval_small(com,i):          # Horner with the node index as a small integer (§5.10 rule 1)
    acc=None
    for C in reversed(com[1:]): acc=M(i,A(acc,C)) if acc is not None else M(i,C)
    return A(acc,com[0])
# Chaum-Pedersen transcript (DESIGN.md §4.6): the challenge hashes the whole statement
# (G, C_i = Eval(C, i), H_p, Y_i) and both commitments, under the context dd || label || i.
def dleq_ch(ctx,Ci,Hp,Yi,A1,A2):
    return int.from_bytes(hashlib.sha256(b"SL1/dleq"+ctx+cb(G)+cb(Ci)+cb(Hp)+cb(Yi)+cb(A1)+cb(A2)).digest(),'big')%N
def dleq_prove(k,Hp,ctx):
    r=secrets.randbelow(N); A1,A2=M(r,G),M(r,Hp)
    ch=dleq_ch(ctx,M(k,G),Hp,M(k,Hp),A1,A2)
    return A1,A2,(r+ch*k)%N
def dleq_verify(Ci,Hp,Yi,pf,ctx):
    A1,A2,z=pf; ch=dleq_ch(ctx,Ci,Hp,Yi,A1,A2)
    return M(z,G)==A(A1,M(ch,Ci)) and M(z,Hp)==A(A2,M(ch,Yi))
ids=list(range(1,10)); t=7
k0=secrets.randbelow(N); sh,co=shamir(k0,t,ids)
com=[M(c_,G) for c_ in co]
for i in (1,5,9): assert eval_small(com,i)==ev(com,i)==M(sh[i],G)     # small-index Horner = power form = share*G
dd=hashlib.sha256(b"pub*|commitments|ciphertexts|E"+secrets.token_bytes(16)).digest()
Zs={}
for lab in (b"hdr",b"var|1|1",b"var|2|1",b"var|2|2"):
    Hp=hc(dd+lab); Y={i:M(sh[i],Hp) for i in ids}
    T=sorted(secrets.SystemRandom().sample(ids,t)); T2=sorted(secrets.SystemRandom().sample(ids,t))
    Z=A(*[M(lag(i,T),Y[i]) for i in T]); assert Z==M(k0,Hp)==A(*[M(lag(i,T2),Y[i]) for i in T2])
    i=T[0]; ctx=dd+lab+bytes([i]); pf=dleq_prove(sh[i],Hp,ctx)
    assert dleq_verify(ev(com,i),Hp,Y[i],pf,ctx)                       # Chaum-Pedersen against the outer commitments
    bad=M((sh[i]+1)%N,Hp)
    assert not dleq_verify(ev(com,i),Hp,bad,pf,ctx)
    assert A(M(lag(i,T),bad),*[M(lag(q_,T),Y[q_]) for q_ in T[1:]])!=Z        # a bad partial changes the key
    assert A(*[M(lag(q_,T[:-1]),Y[q_]) for q_ in T[:-1]])!=Z            # t-1 partials do not give Z
    Zs[lab]=Z
assert len({cb(Z) for Z in Zs.values()})==len(Zs)                        # labels separate keys
assert M(k0,hc(hashlib.sha256(b"other dealing").digest()+b"hdr"))!=Zs[b"hdr"]   # dd confines a partial to one dealing
print("threshold PRF: t partials combine to kappa_0*H_c(dd|label), DLEQ ok, bad partial caught, labels and dd separate keys")
# Forged partial against a challenge that omits Y_i: a shareholder picks r != u, sets
# A1 = r*G, A2 = u*H, c = H(ctx, A1, A2), z = r + c*k, Y = (k + (r-u)/c)*H. Both equations hold
# and Y != k*H. With Y_i in the challenge the forgery fails, because c depends on Y.
k_=sh[1]; Hp=hc(dd+b"hdr"); ctx=dd+b"hdr"+bytes([1])
r_,u_=secrets.randbelow(N),secrets.randbelow(N); A1,A2=M(r_,G),M(u_,Hp)
c_old=int.from_bytes(hashlib.sha256(ctx+cb(A1)+cb(A2)).digest(),'big')%N
z_=(r_+c_old*k_)%N; Yf=M((k_+(r_-u_)*pow(c_old,N-2,N))%N,Hp)
assert Yf!=M(k_,Hp)
assert M(z_,G)==A(A1,M(c_old,ev(com,1))) and M(z_,Hp)==A(A2,M(c_old,Yf))   # old transcript accepts the forgery
assert not dleq_verify(ev(com,1),Hp,Yf,(A1,A2,z_),ctx)                       # full-statement transcript rejects it
print("DLEQ transcript: a forged partial passes a challenge without Y_i and fails the full-statement challenge")
# variant key -> contribution secret y, public key P = y*G; an actor seals a scalar to P
Zv=Zs[b"var|2|1"]; y=int.from_bytes(hashlib.sha256(cb(Zv)+b"ctb").digest(),'big')%N; Pv=M(y,G)
s_a=secrets.randbelow(N); e_=secrets.randbelow(N); Ea=M(e_,G)
pad=lambda pt: int.from_bytes(hashlib.sha256(cb(pt)+cb(Ea)+dd+b"position|v=2|g=1").digest(),'big')%N   # context dd, not hd (§4.6)
ct_=(s_a+pad(M(e_,Pv)))%N
assert (ct_-pad(M(y,Ea)))%N==s_a                                         # committee opens with y*E_a
yb=secrets.randbelow(N); Pbad=M(yb,G); assert M(y,G)!=Pbad               # substituted key fails y*G = P at release
assert (((s_a+pad(M(e_,Pbad)))%N)-pad(M(y,Ea)))%N!=s_a
print("sealed contribution: opens under y_{v,g}; a substituted P_{v,g} is caught by y*G = P")

# (c) Batch check of a dealer's slot dealings: one equation with 128-bit coefficients, per-item fallback.
node=4; polys=[shamir(secrets.randbelow(N),t,ids) for _ in range(8)]      # 2*B_slot polynomials, B_slot = 4
shares=[s_[node] for s_,_ in polys]; coms=[[M(c_,G) for c_ in co_] for _,co_ in polys]
evs=[eval_small(c_,node) for c_ in coms]
def batch(shs):
    r=[secrets.randbits(128) for _ in shs]
    return M(sum(a*b for a,b in zip(r,shs))%N,G)==A(*[M(a,E_) for a,E_ in zip(r,evs)])
assert batch(shares)
badsh=list(shares); badsh[5]=(badsh[5]+1)%N
assert not batch(badsh)
assert [i for i,(s_,E_) in enumerate(zip(badsh,evs)) if M(s_,G)!=E_]==[5]   # fallback names the bad dealing
print("slot batch: one 128-bit RLC equation ok, a bad share fails it, fallback names dealing 5")

# (d) ECDSA slot bound to one leaf set (DESIGN.md §3.6 step 7, §4.4). A 2-of-3 group {1,2,3}
# holds Shamir shares of its per-slot half (w_g, mu_g). If one slot served every subset, a
# corrupt committee with member 1 runs {1,2} on h1 and {1,3} on h2; members 2 and 3 each
# answer once, yet the two group evaluations give (w_g, mu_g) and, with the committee half, x.
kk=secrets.randbelow(N); xk=secrets.randbelow(N); Rk=M(kk,G); rk=Rk[0]%N
kinv=pow(kk,N-2,N); wg,mug=secrets.randbelow(N),secrets.randbelow(N)
wfk,mufk=(kinv-wg)%N,(kinv*xk-mug)%N                         # committee half, known to the adversary
gid=[1,2,3]; wsh,_=shamir(wg,2,gid); msh,_=shamir(mug,2,gid)
def grp_eval(h,T): return sum(lag(i,T)*(h*wsh[i]+rk*msh[i]) for i in T)%N
h1,h2=secrets.randbelow(N),secrets.randbelow(N)
u1,u2=grp_eval(h1,[1,2]),grp_eval(h2,[1,3])
w_rec=(u1-u2)*pow((h1-h2)%N,N-2,N)%N; mu_rec=(u1-h1*w_rec)*pow(rk,N-2,N)%N
assert (w_rec,mu_rec)==(wg,mug)
assert (mufk+mu_rec)*pow((wfk+w_rec)%N,N-2,N)%N==xk               # the address key
# The rule: slot l is bound at birth to one leaf set T_l; a member answers only for T_l, once.
def member_answers(i,T_req,T_slot,used): return i in T_req and sorted(T_req)==sorted(T_slot) and i not in used
used=set(); T_slot=[1,2]
assert member_answers(2,[1,2],T_slot,used); used.add(2)
assert not member_answers(3,[1,3],T_slot,used)                    # C refuses: slot is bound to {1,2}
assert not member_answers(2,[1,2],T_slot,used)                    # B refuses a second message
# The same holds across the branches of user OR G: the user's half (w_u, mu_u) on a slot that G
# also holds in escrow. The user answers h1, three guardians answer h2: the half line is revealed.
wu,muu=wg,mug; gs=[1,2,3,4,5]; ews,_=shamir(wu,3,gs); ems,_=shamir(muu,3,gs)
v1=(h1*wu+rk*muu)%N; v2=sum(lag(i,[2,4,5])*(h2*ews[i]+rk*ems[i]) for i in [2,4,5])%N
assert ((v1-v2)*pow((h1-h2)%N,N-2,N)%N)==wu                       # so a G-reserved slot is never the user's
print("ecdsa slot binding: two subsets on one slot reveal the group half and x; a slot bound to one leaf set refuses the second subset")

# (e) The initiator's leaf id in the commitment list (DESIGN.md §4.2 item 3, DECISIONS 72,
# finding E1). A 2-of-3 group {1,2,3}: member 1 has weight 2 beside member 2 and 3/2 beside
# member 3. Without the initiator's leaf id the two requests have one list, so member 1 has one
# rho_a, one R and one c under two weights, and two answers on the pair give x_1.
x1=secrets.randbelow(N); d1,e1=secrets.randbelow(N),secrets.randbelow(N); D1,E1=M(d1,G),M(e1,G)
R0e=M(secrets.randbelow(N),G); Dle,Ele=M(secrets.randbelow(N),G),M(secrets.randbelow(N),G)
pme=secrets.token_bytes(32); cte=secrets.randbelow(N)   # one pm, hence one c for one list
def cl(init): return init+cb(R0e)+b"0.grp1"+cb(D1)+cb(E1)+b"slot7"+cb(Dle)+cb(Ele)
w12,w13=lag(1,[1,2]),lag(1,[1,3]); assert w12==2 and w13*2%N==3
r_old=H_bind("0.grp1",cl(b""),pme)                      # old list: the same bytes for both initiators
a12=(d1+r_old*e1+cte*w12*x1)%N; a13=(d1+r_old*e1+cte*w13*x1)%N
assert (a12-a13)*pow(cte*(w12-w13)%N,N-2,N)%N==x1       # two answers under two weights give the leaf secret
r2,r3=H_bind("0.grp1",cl(b"0.grp2"),pme),H_bind("0.grp1",cl(b"0.grp3"),pme)
assert r2!=r3                                           # new list: one rho_a per signing set
print("initiator leaf in CL: without it one rho_a serves two weights and two answers give x_1; with it the two sets have two rho_a")
