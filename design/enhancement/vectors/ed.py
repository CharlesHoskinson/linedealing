import hashlib, secrets
p=2**255-19; L=2**252+27742317777372353535851937790883648493; d=-121665*pow(121666,p-2,p)%p
def add(P,Q):
    x1,y1=P;x2,y2=Q; t=d*x1*x2*y1*y2%p
    return ((x1*y2+x2*y1)*pow(1+t,p-2,p)%p,(y1*y2+x1*x2)*pow(1-t,p-2,p)%p)
def mul(k,P):
    R=(0,1)
    while k:
        if k&1: R=add(R,P)
        P=add(P,P); k>>=1
    return R
By=4*pow(5,p-2,p)%p
def xrec(y):
    xx=(y*y-1)*pow(d*y*y+1,p-2,p)%p; x=pow(xx,(p+3)//8,p)
    if (x*x-xx)%p: x=x*pow(2,(p-1)//4,p)%p
    return x if x%2==0 else p-x
B=(xrec(By),By)
def enc(P): return (P[1]|((P[0]&1)<<255)).to_bytes(32,'little')
H=lambda b:int.from_bytes(hashlib.sha512(b).digest(),'little')%L
ok=0
for i in range(10):
    xu,xf,tw=(secrets.randbelow(L) for _ in range(3)); A=mul((xu+xf+tw)%L,B)
    ku,dd,e=(secrets.randbelow(L) for _ in range(3)); M=secrets.token_bytes(40)
    Ru=mul(ku,B); D=mul(dd,B); E=mul(e,B)
    rho=H(enc(Ru)+hashlib.sha256(enc(A)+M).digest())
    R=add(add(Ru,D),mul(rho,E)); c=H(enc(R)+enc(A)+M)
    s=((ku+c*(xu+tw))+(dd+rho*e+c*xf))%L
    ok+= mul(s,B)==add(R,mul(c,A))
print("ed25519 ok",ok,"/10")

# Multi-shard (DESIGN.md §2.4, §4.3): x = x_f + tw + sum of shards; AND, 2-of-3 group (Lagrange
# weight of the chosen subset), OR escrow to a 3-of-5 group. Initiator: fresh R_0 and the
# tweak term c*tw; every other leaf: pool pair (d_a, e_a) with rho_a over all commitments.
def lag(i,S):
    num=den=1
    for j in S:
        if j!=i: num=num*(-j)%L; den=den*(i-j)%L
    return num*pow(den,L-2,L)%L
def shamir(sec,k,ids):
    co=[sec]+[secrets.randbelow(L) for _ in range(k-1)]
    return {i:sum(c*pow(i,e,L) for e,c in enumerate(co))%L for i in ids}
def leafset(kind,T=None):
    """returns (key part sum, list of (label, weight, share))"""
    if kind[0]=='and':
        xs=[secrets.randbelow(L) for _ in range(kind[1])]
        return sum(xs)%L,[(f"a{j}",1,x) for j,x in enumerate(xs)]
    if kind[0]=='grp':   # group shard by DKG among members 1..3
        mem=[1,2,3]; sh={i:0 for i in mem}; xg=0
        for _ in mem:
            c0=secrets.randbelow(L); xg=(xg+c0)%L; d=shamir(c0,2,mem)
            for i in mem: sh[i]=(sh[i]+d[i])%L
        return xg,[(f"g{i}",lag(i,T),sh[i]) for i in T]
    if kind[0]=='esc':   # user OR G(3 of 5): T None = user, else G subset
        xu=secrets.randbelow(L); e=shamir(xu,3,[1,2,3,4,5])
        return xu,([("u",1,xu)] if T is None else [(f"G{i}",lag(i,T),e[i]) for i in T])
Hb=lambda lb,b,pm:H(b"SL1/bind"+lb.encode()+b+pm)
cases=[(f"AND m={m}",('and',m),None) for m in range(1,6)]
cases+=[(f"2of3 T={T}",('grp',),T) for T in ([1,2],[1,3],[2,3])]
cases+=[("P2 user",('esc',),None),("P2 G T=[1,4,5]",('esc',),[1,4,5])]
for name,kind,T in cases:
    xs,lv=leafset(kind,T); xf,tw=secrets.randbelow(L),secrets.randbelow(L)
    Apt=mul((xs+xf+tw)%L,B); M_=secrets.token_bytes(40); pm=hashlib.sha256(enc(Apt)+M_).digest()
    k0=secrets.randbelow(L); R0=mul(k0,B)
    pr=[(secrets.randbelow(L),secrets.randbelow(L)) for _ in lv[1:]]; PD=[(mul(da,B),mul(ea,B)) for da,ea in pr]
    dl,el=secrets.randbelow(L),secrets.randbelow(L); Dl,El=mul(dl,B),mul(el,B)
    b=lv[0][0].encode()+enc(R0)+b''.join(l[0].encode()+enc(Dp)+enc(Ep) for l,(Dp,Ep) in zip(lv[1:],PD))+b"slot"+enc(Dl)+enc(El)
    assert len({l[0] for l in lv})==len(lv)   # distinct leaf ids, distinct rho_a; the initiator's leaf id is first in the list (DESIGN.md §4.2, DECISIONS 72)
    rho=[Hb(l[0],b,pm) for l in lv[1:]]
    RA=R0
    for (Dp,Ep),r in zip(PD,rho): RA=add(RA,add(Dp,mul(r,Ep)))
    rf=Hb("F",b"slot"+enc(RA),pm)          # committee binds over (slot, R_A, pm)
    R=add(RA,add(Dl,mul(rf,El))); c=H(enc(R)+enc(Apt)+M_)
    s=(k0+c*(lv[0][1]*lv[0][2]+tw))%L
    for (lb,w,x),(da,ea),r in zip(lv[1:],pr,rho): s+=da+r*ea+c*w*x
    s=(s+dl+rf*el+c*xf)%L
    v=mul(s,B)==add(R,mul(c,Apt)); assert v
    print(f"ed25519 multi [{name}] ok",v)

# Speed decision 27 (DESIGN.md §4.1): one committee slot per (generation, input), shared by the
# candidate tickets of all variants. Every half (v, g) has its own k_0 and pool pair; the
# committee signs one ticket per slot. G_max = 2.
GMAX=2
def ed_slot_sharing(K,nact):
    xf,tw=secrets.randbelow(L),secrets.randbelow(L); xa=[secrets.randbelow(L) for _ in range(nact+1)]
    Apt=mul((xf+tw+sum(xa))%L,B); ids=list(range(1,10)); xfs=shamir(xf,7,ids)
    slots={}
    for g in range(1,min(K,GMAX)+1):
        dl,el=secrets.randbelow(L),secrets.randbelow(L); slots[g]=(shamir(dl,7,ids),shamir(el,7,ids),mul(dl,B),mul(el,B))
    msgs={v:secrets.token_bytes(40) for v in range(1,K+1)}; Hh={}; used=set()
    for v in range(1,K+1):
        for g in range(1,min(v,GMAX)+1):
            _,_,Dl,El=slots[g]; pm=hashlib.sha256(enc(Apt)+msgs[v]+secrets.token_bytes(32)).digest()
            k0=secrets.randbelow(L); R0=mul(k0,B)
            pr=[(secrets.randbelow(L),secrets.randbelow(L)) for _ in range(nact)]; PD=[(mul(a,B),mul(b_,B)) for a,b_ in pr]
            for x in [k0]+[a for a,_ in pr]: assert x not in used; used.add(x)
            sl=b"slot%d"%g
            b=lv[0][0].encode()+enc(R0)+b''.join(b"a%d"%i+enc(Dp)+enc(Ep) for i,(Dp,Ep) in enumerate(PD))+sl+enc(Dl)+enc(El)
            rho=[Hb("a%d"%i,b,pm) for i in range(nact)]
            RA=R0
            for (Dp,Ep),r in zip(PD,rho): RA=add(RA,add(Dp,mul(r,Ep)))
            rf=Hb("F",sl+enc(RA),pm); R=add(RA,add(Dl,mul(rf,El))); c=H(enc(R)+enc(Apt)+msgs[v])
            s=(k0+c*(xa[0]+tw))%L
            for (a,b_),r,x in zip(pr,rho,xa[1:]): s+=a+r*b_+c*x
            Hh[(v,g)]=(sl,RA,pm,c,enc(R),s%L)
    j1=secrets.randbelow(K-1)+1 if K>1 else 1; sel=[(j1,1)]+([(j1+1+secrets.randbelow(K-j1),2)] if K>1 else [])
    ok=True
    for v,g in sel:
        sl,RA,pm,c,Renc,s=Hh[(v,g)]; ds,es,Dl,El=slots[g]
        rf=Hb("F",sl+enc(RA),pm); R=add(RA,add(Dl,mul(rf,El))); assert enc(R)==Renc      # ticket R = recomputed
        T=sorted(secrets.SystemRandom().sample(ids,7))
        sf=sum(lag(i,T)*(ds[i]+rf*es[i]+c*xfs[i]) for i in T)%L
        ok&= mul((s+sf)%L,B)==add(R,mul(c,Apt))
    assert len({h[4] for h in Hh.values()})==len(Hh)
    return ok
for K,na in ((3,0),(3,1),(1,2)):
    v=ed_slot_sharing(K,na); assert v
    print(f"ed25519 slot sharing [K={K} other actors={na}] one partial per generation slot ok",v)
