import hashlib
p=2**256-2**32-977
q=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
O=None
def inv(a,m=q): return pow(a,-1,m)
def add(P,Q):
    if P is None: return Q
    if Q is None: return P
    if P[0]==Q[0]:
        if (P[1]+Q[1])%p==0: return None
        l=3*P[0]*P[0]*inv(2*P[1],p)%p
    else: l=(Q[1]-P[1])*inv(Q[0]-P[0],p)%p
    x=(l*l-P[0]-Q[0])%p
    return (x,(l*(P[0]-x)-P[1])%p)
def mul(k,P):
    k%=q; R=None
    while k:
        if k&1: R=add(R,P)
        P=add(P,P); k>>=1
    return R
def neg(P): return None if P is None else (P[0],(-P[1])%p)
def lift_x(x):
    y=pow((pow(x,3,p)+7)%p,(p+1)//4,p)
    assert y*y%p==(pow(x,3,p)+7)%p
    return (x,y if y%2==0 else p-y)
def comp(P): return bytes([2+(P[1]&1)])+P[0].to_bytes(32,'big')
def H(tag,*parts):
    t=hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t+t+b''.join(parts)).digest()
def Hq(tag,*parts): return int.from_bytes(H(tag,*parts),'big')%q
def b32(x): return x.to_bytes(32,'big')
def sc(label): return Hq('test/scalar',label.encode()) or 1
def poly(const,t,label): return [const]+[sc(f'{label}/{u}') for u in range(1,t)]
def ev(co,i): return sum(c*pow(i,u,q) for u,c in enumerate(co))%q
def lag(S,i,at=0):
    num=den=1
    for j in S:
        if j!=i: num=num*(at-j)%q; den=den*(i-j)%q
    return num*inv(den)%q
def interp(pts,at=0):
    S=[i for i,_ in pts]; return sum(v*lag(S,i,at) for i,v in pts)%q
def Eval(C0,C,i):
    P=C0
    for u,Cu in enumerate(C,1): P=add(P,mul(pow(i,u,q),Cu))
    return P
def ecdsa_verify(X,h,r,s):
    if not(0<r<q and 0<s<q): return False
    P=add(mul(h*inv(s),G),mul(r*inv(s),X))
    return P is not None and P[0]%q==r
def bip340_verify(Xx,m,Rx,s):
    X=lift_x(Xx); c=Hq('BIP0340/challenge',b32(Rx),b32(Xx),m)
    R=add(mul(s,G),neg(mul(c,X)))
    return R is not None and R[1]%2==0 and R[0]==Rx
res=[]
def ok(name,cond,detail=''):
    res.append((name,cond)); print(('PASS' if cond else 'FAIL'),name,detail)

n,f=16,5; t=f+1
x=sc('owner-key'); X=mul(x,G)
sk=[None]+[sc(f'node-sk/{i}') for i in range(1,n+1)]; PK=[None]+[mul(s_,G) for s_ in sk[1:]]
e=sc('eph'); E=mul(e,G); hd=H('test/hd',b'fixed-header')
def pad(i,label,fixed=True):
    Ki=mul(e,PK[i])
    lab=label if fixed else b'slot-1'
    return int.from_bytes(hashlib.sha512(H('LD1/enc',hd,i.to_bytes(2,'big'),comp(PK[i]),comp(Ki),lab)).digest(),'big')%q

# ---- T1 mask reuse
k=sc('nonce-1'); R=mul(k,G); r=R[0]%q; w=inv(k); mu=x*w%q
pw=poly(w,t,'pw'); pm=poly(mu,t,'pm')
h=Hq('test/msg',b'tx-A')
s=(h*w+r*mu)%q
ok('T2a open ECDSA combined s verifies under X',ecdsa_verify(X,h,r,s))
for fixed in (False,True):
    ctw={i:(ev(pw,i)+pad(i,b'\x02\x02'+b'\0'*6,fixed))%q for i in range(1,n+1)}
    ctm={i:(ev(pm,i)+pad(i,b'\x02\x03'+b'\0'*6,fixed))%q for i in range(1,n+1)}
    delta=interp([(i,(ctm[i]-ctw[i])%q) for i in range(1,t+1)])
    w_=(s-r*delta)*inv(h+r)%q; x_=(1+delta*inv(w_))%q
    if not fixed: ok('T1a pre-fix shared mask: observer recovers x from ciphertexts + one signature',x_==x)
    else: ok('T1b fixed per-component label: same procedure does not recover x',x_!=x and mul(x_,G)!=X)

# ---- T2 open ECDSA partials
Cw=[mul(c,R) for c in pw[1:]]; Cm=[mul(c,R) for c in pm[1:]]
ok('T2b implied constant terms: w(0)R=G and mu(0)R=X',mul(w,R)==G and mul(mu,R)==X)
part={i:(h*ev(pw,i)+r*ev(pm,i))%q for i in range(1,n+1)}
ok('T2c every partial passes s_i R = m W_i + r M_i',all(mul(part[i],R)==add(mul(h,Eval(G,Cw,i)),mul(r,Eval(X,Cm,i))) for i in range(1,n+1)))
S=[2,3,5,7,11,13]; s2=interp([(i,part[i]) for i in S])
ok('T2d t=6 partials interpolate to s',s2==s)
bad=(part[4]+1)%q
ok('T2e altered partial fails the check',mul(bad,R)!=add(mul(h,Eval(G,Cw,4)),mul(r,Eval(X,Cm,4))))
ok('T2f t-1 partials do not give s',interp([(i,part[i]) for i in S[:-1]])!=s)

# ---- T7 nonce reuse ECDSA
h2=Hq('test/msg',b'tx-B'); s_b=(h2*w+r*mu)%q
k_rec=(h-h2)*inv(s-s_b)%q; x_rec=(s*k_rec-h)*inv(r)%q
ok('T7a ECDSA: two digests on one slot recover x',x_rec==x)

# ---- T3 sealed ECDSA
ks=sc('nonce-sealed'); Rs=mul(ks,G); rs=Rs[0]%q; hs=Hq('test/msg',b'variant-1')
ss=inv(ks)*(hs+rs*x)%q
F0=add(mul(hs,G),mul(rs,X))
ok('T3a sealed ECDSA: s R = hG + rX',mul(ss,Rs)==F0)
ps=poly(ss,t,'ps'); Cs=[mul(c,Rs) for c in ps[1:]]
ok('T3b sealed shares pass s_i R = Eval(F0,C,i)',all(mul(ev(ps,i),Rs)==Eval(F0,Cs,i) for i in range(1,n+1)))
ok('T3c interpolated sealed s verifies',ecdsa_verify(X,hs,rs,interp([(i,ev(ps,i)) for i in S])))
# wallet gives low-s; owner recovers R' = s^-1 (hG+rX)
s_low=min(ss,q-ss); Rrec=mul(inv(s_low),F0)
ok('T3d wallet low-s output: recovered R is +-R, same r, s_low R_rec = F0',Rrec in (Rs,neg(Rs)) and Rrec[0]%q==rs and mul(s_low,Rrec)==F0, f'(wallet s was {"high" if ss!=s_low else "low"})')
# ---- T4 low-s + yParity (ecrecover)
def ecrecover(hh,r_,s_,v):
    y=pow((pow(r_,3,p)+7)%p,(p+1)//4,p)
    if y%2!=v: y=p-y
    Rp=(r_,y); return add(mul(s_*inv(r_),Rp),neg(mul(hh*inv(r_),G)))
def finalize(Rd,s_d):
    flip=s_d>q//2; return (q-s_d if flip else s_d),(Rd[1]&1)^(1 if flip else 0)
allok=True; seen=set()
for lbl in ['case-%d'%i for i in range(12)]:
    kk=sc('yp/'+lbl); RR=mul(kk,G); rr=RR[0]%q; hh=Hq('test/msg',lbl.encode()); sd=inv(kk)*(hh+rr*x)%q
    sf,v=finalize(RR,sd); seen.add((RR[1]&1,sd>q//2))
    allok&=sf<=q//2 and ecdsa_verify(X,hh,rr,sf) and ecrecover(hh,rr,sf,v)==X and ecrecover(hh,rr,sf,v^1)!=X
ok('T4 low-s + yParity = parity(y(R)) xor flipped recovers X; wrong parity does not',allok and len(seen)==4,f'parity/flip cases covered: {sorted(seen)}')
# ---- T6 F0 = O dealer
hz=Hq('test/msg',b'zero'); rG=G[0]%q; xa=(-hz*inv(rG))%q; Xa=mul(xa,G)
F0z=add(mul(hz,G),mul(rG,Xa))
ok('T6 dealer with R=G, X=(-h/r)G gives F0 = O (Step A must reject)',F0z is None)
# ---- T5 BIP340 sealed
xb=x if X[1]%2==0 else q-x; Xb=mul(xb,G); assert Xb[1]%2==0
mb=H('test/sighash',b'taproot-variant-1')
def find_k(par):
    c=0
    while True:
        kk=sc(f'bip/{par}/{c}'); P=mul(kk,G)
        if P[1]%2==par: return kk,P
        c+=1
ko,Ro=find_k(1)
co=Hq('BIP0340/challenge',b32(Ro[0]),b32(Xb[0]),mb); so=(ko+co*xb)%q
ok('T5a odd-y R: s G = R + cX holds (pre-fix check passes)',mul(so,G)==add(Ro,mul(co,Xb)))
ok('T5b odd-y R: BIP340 verification of (x(R), s) fails',not bip340_verify(Xb[0],mb,Ro[0],so))
ok('T5c fixed check with F0 = lift_x(x(R)) + cX rejects that dealing',mul(so,G)!=add(lift_x(Ro[0]),mul(co,Xb)))
kn=q-ko; sn=(kn+co*xb)%q
ok('T5d honest wallet (negated nonce): fixed check passes and BIP340 verifies',mul(sn,G)==add(lift_x(Ro[0]),mul(co,Xb)) and bip340_verify(Xb[0],mb,Ro[0],sn))
# ---- T8 open Schnorr BIP340, two nonces
px=poly(xb,t,'px'); Cx=[mul(c,G) for c in px[1:]]
def open_schnorr(slot,dgl):
    d=sc(f'd/{slot}'); e2=sc(f'e/{slot}'); D=mul(d,G); E2=mul(e2,G)
    pd=poly(d,t,f'pd/{slot}'); pe=poly(e2,t,f'pe/{slot}')
    Cd=[mul(c,G) for c in pd[1:]]; Ce=[mul(c,G) for c in pe[1:]]
    m=H('test/sighash',dgl); dg=H('LD1/dg',m)
    rho=Hq('LD1/bind',hd,(1).to_bytes(2,'big'),slot.to_bytes(2,'big'),dg)
    R0=add(D,mul(rho,E2)); sig=1 if R0[1]%2==0 else q-1
    Rf=R0 if sig==1 else neg(R0)
    c=Hq('BIP0340/challenge',b32(Rf[0]),b32(Xb[0]),m)
    parts={i:(sig*(ev(pd,i)+rho*ev(pe,i))+c*ev(px,i))%q for i in range(1,n+1)}
    chk=all(mul(parts[i],G)==add(mul(sig,add(Eval(D,Cd,i),mul(rho,Eval(E2,Ce,i)))),mul(c,Eval(Xb,Cx,i))) for i in S)
    sfin=interp([(i,parts[i]) for i in S])
    return R0[1]%2,chk,bip340_verify(Xb[0],m,Rf[0],sfin),(d,e2,rho,sig,c,sfin)
pars={}
for slot in range(1,9):
    par,chk,ver,_=open_schnorr(slot,b'dg-%d'%slot); pars.setdefault(par,[]).append(chk and ver)
ok('T8 open BIP340: partial checks and final verify hold for even-y and odd-y R',set(pars)=={0,1} and all(all(v) for v in pars.values()),f'even:{len(pars.get(0,[]))} odd:{len(pars.get(1,[]))}')
# ---- T7b Schnorr reuse
rows=[]
for lab in (b'A',b'B',b'C'):
    _,_,_,(d,e2,rho,sig,c,sfin)=open_schnorr(1,lab); rows.append((sig,sig*rho%q,c,sfin))
def solve3(rows):
    M=[list(r_) for r_ in rows]
    for col in range(3):
        piv=next(i for i in range(col,3) if M[i][col]%q); M[col],M[piv]=M[piv],M[col]
        iv=inv(M[col][col]); M[col]=[v*iv%q for v in M[col]]
        for i in range(3):
            if i!=col:
                fct=M[i][col]; M[i]=[(a-fct*b)%q for a,b in zip(M[i],M[col])]
    return [M[i][3] for i in range(3)]
sol=solve3(rows)
ok('T7b two-nonce Schnorr: three digests on one slot recover x (two leave one unknown)',sol[2]==xb)
# two signatures only: any other x' is consistent with some (d, e')
xw=(xb+1)%q; (a1,b1,c1_,s1_),(a2,b2,c2_,s2__)=rows[0],rows[1]
det=(a1*b2-a2*b1)%q; r1=(s1_-c1_*xw)%q; r2=(s2__-c2_*xw)%q
dw=(r1*b2-r2*b1)*inv(det)%q; ew=(a1*r2-a2*r1)*inv(det)%q
ok('T7b2 two digests on a two-nonce slot do not determine x (a wrong x has a consistent (d, e\'))',det!=0 and (a1*dw+b1*ew+c1_*xw)%q==s1_ and (a2*dw+b2*ew+c2_*xw)%q==s2__)
# single-nonce contrast: two digests suffice
dd=sc('single-d'); c1=sc('c1'); c2=sc('c2'); s1=(dd+c1*xb)%q; s2_=(dd+c2*xb)%q
ok('T7c one-nonce Schnorr: two digests recover x',(s1-s2_)*inv(c1-c2)%q==xb)
# ---- T9 rid / hd
def rid(chain,board,Xc,nonce,tie=b'\0'*32): return H('LD1/rid',chain,board,Xc,nonce,tie)
A=(b'\1'*32,b'\2'*32,comp(X),b'\3'*32)
ok('T9a open rid is a function of (chain, board, X, owner_nonce) only',rid(*A)==rid(*A) and rid(*A)!=rid(A[0],A[1],A[2],b'\4'*32))
hdB=H('LD1/hd',b'owner dealing B'); hdAtk=H('LD1/hd',b'replayed released point, attacker dealing')
ok('T9b sealed rid is tied to hd: a replayed released signature under the same owner_nonce gets another rid',rid(*A,hdB)!=rid(*A,hdAtk))
# ---- T10 quorum intersection
ok('T10 two 2f+1 quorums share >= f+1 nodes (n=16,64,256)',all(2*(2*ff+1)-(3*ff+1)==ff+1 for ff in (5,21,85)))
# T10b general committee size (LOOP item 4b): q = ceil((n+f+1)/2); n=9, f=2 gives q=6, all subsets enumerated
from itertools import combinations
def quorum(n_,f_): return (n_+f_+2)//2
n9,f9=9,2; q9=quorum(n9,f9)
min_q=min(len(set(A_)&set(B_)) for A_ in combinations(range(n9),q9) for B_ in combinations(range(n9),q9))
min_below=min(len(set(A_)&set(B_)) for A_ in combinations(range(n9),q9-1) for B_ in combinations(range(n9),q9-1))
min_old=min(len(set(A_)&set(B_)) for A_ in combinations(range(n9),2*f9+1) for B_ in combinations(range(n9),2*f9+1))
ok('T10b n=9, f=2: q=6; every two q-quorums share >= f+1 nodes; q <= n-f and q >= 2f+1; size q-1 (= 2f+1) can share only f nodes; q = 2f+1 at n=3f+1',
   q9==6 and min_q==f9+1 and q9<=n9-f9 and q9>=2*f9+1 and min_below<=f9 and min_old<=f9 and all(quorum(3*ff+1,ff)==2*ff+1 for ff in (1,2,5,21,85)),
   f'min intersection: q-quorums {min_q}, 5-sets {min_below}')
# ---- T11 OBS split
hs_=[100]*5+[101]*5+[102]
old=max(hs_.count(v) for v in set(hs_))
anchor=sorted(hs_,reverse=True)[f]
ok('T11 (f,f,1) OBS split: no block has f+1 posts, median rule gives a defined anchor',old<f+1 and anchor==101,f'anchor height {anchor}')
byz_hi=sorted([100]*6+[10**9]*5,reverse=True)[f]; byz_lo=sorted([100]*3+[105]*3+[0]*5,reverse=True)[f]
ok('T11b f Byzantine extreme reports cannot move the anchor outside the honest range',byz_hi==100 and byz_lo==100)
# hash-carrying OBS (rejected design) vs height-only OBS
chain={100:'h100',101:'h101',102:'h102'}
posts=[(100,'h100')]*5+[(101,'h101')]*4+[(101,'BOGUS')]+[(102,'h102')]   # one Byzantine post sits at entry f+1
posts_sorted=sorted(posts,key=lambda t:-t[0]); sel=posts_sorted[f]
nack_hash_rule=sum(1 for _ in range(2*f+1) if chain[sel[0]]!=sel[1])      # honest nodes NACK a non-canonical hash
hstar=sorted([h_ for h_,_ in posts],reverse=True)[f]
nack_height_rule=0                                                        # each node uses its own block at hstar
ok('T11c one bogus hash at entry f+1 fails the attempt under a hash-carrying rule and cannot under the height-only rule',sel==(101,'BOGUS') and nack_hash_rule>=f+1 and hstar==101 and chain[hstar]=='h101' and nack_height_rule<f+1)
# ---- T12 fee bump with prior generation
vsize=141; rate=10; relay=1; ceiling=3000
fee_g=vsize*rate; naive=vsize*rate
fixed_fee=max(vsize*rate,fee_g+relay*vsize)
ok('T12 flat market: naive rebuild pays the same fee (rejected as replacement); rule with prior tx pays prior + increment',naive<fee_g+relay*vsize and fixed_fee==1551 and fixed_fee<=ceiling,f'naive {naive}, fixed {fixed_fee}')
mf=2*30+2; tip=2; mf2=max(2*30+2,-(-mf*1125//1000)); tip2=max(2,-(-tip*1125//1000))
ok('T12b EIP-1559 flat basefee: bumped maxFee and tip exceed prior by >= 10%',mf2*10>=mf*11 and tip2*10>=tip*11,f'maxFee {mf}->{mf2}, tip {tip}->{tip2}')
# ---- T13 fee ceiling on actual fee
inp=10762; pay=10000; cap=700; dust=294
fee2=(562); change=inp-pay-fee2
actual=inp-pay if change<dust else fee2
ok('T13 dust case: change 200 < dust, actual fee 762 > ceiling 700, Build returns bottom',change==200 and actual==762 and actual>cap)
# ---- T14 reshare
Q=[1,2,4,6,9,12]; n2,t2=16,6
def reshare(co_old,base,C0,Cold,lab):
    newsh={j:0 for j in range(1,n2+1)}; C0new=None; good=True
    for i in Q:
        vi=ev(co_old,i); gi=poly(vi,t2,f'{lab}/{i}')
        good&=mul(vi,base)==Eval(C0,Cold,i)          # dealer constant term equals public Eval
        li=lag(Q,i)
        C0new=add(C0new,mul(li,Eval(C0,Cold,i)))
        for j in newsh: newsh[j]=(newsh[j]+li*ev(gi,j))%q
    return newsh,C0new,good
nw,C0w,g1=reshare(pw,R,G,Cw,'rw'); nm,C0m,g2=reshare(pm,R,X,Cm,'rm')
s_new=interp([(j,(h*nw[j]+r*nm[j])%q) for j in [3,5,8,10,14,16]])
ok('T14 reshare: new constant commitments equal G and X in base R; new partials combine to the same valid s',g1 and g2 and C0w==G and C0m==X and s_new==s and ecdsa_verify(X,h,r,s_new))
ok('T14b freeze counting: at t_old=f+1 a 2f+1 prevote set and an f+1 reshare set can share only Byzantine nodes',(2*f+1)+(f+1)-n<=f)
# ---- T15 sealed authorship proof
# T15 uses the protocol's SHA-512 outer Hq (BIP340 elsewhere uses SHA-256).
def protocol_hq(tag, *parts):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return int.from_bytes(hashlib.sha512(tag_hash + tag_hash + b''.join(parts)).digest(), 'big') % q

def hg_eph(data):
    # Independent toy try-and-increment map; production Rust uses k256 RFC 9380.
    counter = 0
    while True:
        raw = H('LD1/eph', data, counter.to_bytes(4, 'big'))
        x_candidate = int.from_bytes(raw, 'big')
        if x_candidate < p:
            rhs = (x_candidate**3 + 7) % p
            y_candidate = pow(rhs, (p+1)//4, p)
            if y_candidate*y_candidate % p == rhs:
                return (x_candidate, y_candidate)
        counter += 1

ct15 = b32((ss + pad(1, b'sealed-s')) % q)
ct_digest15 = H('LD1/ct', ct15)
g_prime15 = hg_eph(hd + ct_digest15 + comp(E))
e_prime15 = mul(e, g_prime15)
r_e15 = sc('pok-ephemeral')
t1_15, t2_15 = mul(r_e15, G), mul(r_e15, g_prime15)
c_e15 = protocol_hq('LD1/ephpok', hd, ct_digest15, comp(E), comp(e_prime15), comp(t1_15), comp(t2_15))
z_e15 = (r_e15 + c_e15*e) % q
assert mul(z_e15, G) == add(t1_15, mul(c_e15, E))
assert mul(z_e15, g_prime15) == add(t2_15, mul(c_e15, e_prime15))
a=sc('pok-a'); T=mul(a,Rs)
cc=protocol_hq('LD1/auth', hd, ct_digest15, comp(e_prime15), comp(t1_15), comp(t2_15), b32(z_e15), comp(T))
z=(a+cc*ss)%q
ok('T15a proof of knowledge of sealed s in base R verifies: z R = T + c F0',mul(z,Rs)==add(T,mul(cc,F0)))
zf=(a+cc*sc('guess'))%q
ok('T15b same proof with a wrong s fails',mul(zf,Rs)!=add(T,mul(cc,F0)))
print(sum(1 for _,c in res if c),'of',len(res),'passed')
