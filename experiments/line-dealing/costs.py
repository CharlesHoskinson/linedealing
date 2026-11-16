FIX=524+196  # header 524 with one output, pi 196 (E', T_1, T_2, z_e, T_a, z_a; PROOFS.md C3)
def row(name,vals,fmt='{:,}'): print('|',name,'|',' | '.join(fmt.format(v) if not isinstance(v,str) else v for v in vals),'|')
def quorum(n,f): return (n+f+2)//2  # q = ceil((n+f+1)/2), SCHEME section 2; 2f+1 when n = 3f+1
def table(Ns,F,prof,label=''):
    assert all(n>=3*f+1 for n,f in zip(Ns,F))
    Q=[quorum(n,f) for n,f in zip(Ns,F)]
    assert all(2*q-n>=f+1 and q<=n-f and q>=2*f+1 for n,f,q in zip(Ns,F,Q))
    print('\n=='+label,prof)
    T=[f+1 if prof=='std' else n-f for n,f in zip(Ns,F)]
    P=[33*(t-1)+32*n for n,t in zip(Ns,T)]
    row('f',F); row('q',Q); row('t',T); row('P',P)
    row('sealed point ECDSA 33+P',[33+p for p in P])
    row('open ECDSA slot 33+2P',[33+2*p for p in P])
    row('open Schnorr key P',P); row('open Schnorr slot 2(33+P)',[2*(33+p) for p in P])
    row('MSG sealed K=8 L=1',[FIX+8*(33+p) for p in P])
    row('MSG sealed K=1',[FIX+33+p for p in P])
    row('MSG open ECDSA G=1',[FIX+33+2*p for p in P])
    row('MSG open ECDSA G=2',[FIX+2*(33+2*p) for p in P])
    row('MSG open Schnorr G=1',[FIX+p+2*(33+p) for p in P])
    row('MSG open Schnorr G=2',[FIX+p+4*(33+p) for p in P])
    # owner mults
    oE=lambda n,t,GL: GL*(2*(t-1)+1)+n+5
    oS=lambda n,t,KL: KL*(t-1)+KL+n+5
    oSch=lambda n,t,GL: (t-1)+GL*(2*(t-1)+2)+n+5
    row('owner open ECDSA G=1',[oE(n,t,1) for n,t in zip(Ns,T)])
    row('owner open ECDSA G=2',[oE(n,t,2) for n,t in zip(Ns,T)])
    row('owner sealed K=8',[oS(n,t,8) for n,t in zip(Ns,T)])
    row('owner open Schnorr G=1',[oSch(n,t,1) for n,t in zip(Ns,T)])
    row('owner ms open ECDSA G=1 / sealed K=8 / Schnorr',[f'{oE(n,t,1)*.05:.1f} / {oS(n,t,8)*.05:.1f} / {oSch(n,t,1)*.05:.1f}' for n,t in zip(Ns,T)])
    # node step A
    aE=lambda t,GL: 2*GL*t+7
    aS=lambda t,KL: KL*(t+2)+7
    aSch=lambda t,GL: t+2*GL*t+7
    row('StepA open ECDSA G=1',[aE(t,1) for t in T]); row('StepA open ECDSA G=2',[aE(t,2) for t in T])
    row('StepA sealed K=8',[aS(t,8) for t in T]); row('StepA open Schnorr G=1',[aSch(t,1) for t in T])
    # board sigs
    so=[3*q+t for q,t in zip(Q,T)]; ss=[2*q+t for q,t in zip(Q,T)]
    row('board sig verifs open min (3q+t)',so); row('board sig verifs open max 4n',[4*n for n in Ns])
    row('board sig verifs sealed min',ss); row('sealed max 3n',[3*n for n in Ns])
    row('prevote verif mults 2q',[2*q for q in Q])
    totE=[aE(t,1)+2*s for t,s in zip(T,so)]; totEmax=[aE(t,1)+8*n for t,n in zip(T,Ns)]
    totS=[aS(t,8)+2*s for t,s in zip(T,ss)]; totSmax=[aS(t,8)+6*n for t,n in zip(T,Ns)]
    totSch=[aSch(t,1)+2*s for t,s in zip(T,so)]
    row('node total open ECDSA min..max mults',[f'{a}..{b}' for a,b in zip(totE,totEmax)])
    row('node total open ECDSA ms',[f'{a*.05:.1f}..{b*.05:.1f}' for a,b in zip(totE,totEmax)])
    row('node total sealed K=8 min..max',[f'{a}..{b}' for a,b in zip(totS,totSmax)])
    row('node total sealed ms',[f'{a*.05:.1f}..{b*.05:.1f}' for a,b in zip(totS,totSmax)])
    row('node total open Schnorr min',[f'{a} ({a*.05:.1f} ms)' for a in totSch])
    row('combiner fallback ECDSA t(2t+3)',[t*(2*t+3) for t in T])
    row('combiner fallback ms',[f'{t*(2*t+3)*.05:.0f}' for t in T])
    row('download open ECDSA G=1 (msg + n*576)',[FIX+33+2*p+n*576 for n,p in zip(Ns,P)])
    row('download sealed K=8 (msg + n*409)',[FIX+8*(33+p)+n*409 for n,p in zip(Ns,P)])
    # reshare: per dealt polynomial, t_old dealers each P(t') + 164 (E, E', T_1, T_2, z_e; PROOFS.md C5, C9)
    row('reshare bytes per polynomial, t_old dealers',[t*(p+164) for t,p in zip(T,P)])
    row('reshare open ECDSA 1 slot (2 polys)',[2*t*(p+164) for t,p in zip(T,P)])
for prof in ('std','high'): table([16,64,256],[5,21,85],prof)
# n > 3f+1 (LOOP item 4b): n = 9, f = 2, q = 6
for prof in ('std','high'): table([9],[2],prof,' n=9 f=2')
