#!/usr/bin/env bash
# Exports the ITF traces of the split-line models for the replay of item 11 on impl/.
# Output: tests/quint-regressions/splitline/ (named runs and findings) and
# tests/quint-regressions/splitline/sampled/ (sampled design traces).
# Run from anywhere; run_all.sh calls it as its last job.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
out=../../tests/quint-regressions/splitline
mkdir -p "$out/sampled"
rm -f "$out/sampled/"*.itf.json
fail=0
t() {  # file module run output-name
  rm -f "$out/$4.itf.json"
  quint test "$1" --main "$2" --match "^$3\$" --out-itf "$out/$4.itf.json" 2>&1 | grep -q ' 1 passing' \
    || { echo "FAIL $2 $3"; fail=1; }
  [ -s "$out/$4.itf.json" ] || { echo "MISSING $4"; fail=1; }
}
# the bind-level runs moved to pt_seald (honest stale-vote check off) with DECISIONS 54
rm -f "$out"/pt_design__windowBurnHolds.itf.json "$out"/pt_design__accountBurnHolds.itf.json "$out"/pt_design__accountMarkerHolds.itf.json
for r in pendingBurnHolds windowVoteHolds reshareNoAnchorHolds acctEarliestHolds acctEarliestAdmitsHolds \
         burnedIndexVoteRefusedHolds burnedIndexVoidHolds restartEndsOrderedHolds windowBindHolds; do
  t splitline_pools_test.qnt pt_design $r "pt_design__$r"; done
for r in windowBurnHolds accountBurnHolds accountMarkerHolds; do
  t splitline_pools_test.qnt pt_seald $r "pt_seald__$r"; done
t splitline_pools_test.qnt pt_acct_race acctEarliestBroken pt_acct_race__acctEarliestBroken
t splitline_pools_test.qnt pt_window_bind windowBindBroken pt_window_bind__windowBindBroken
t splitline_pools_test.qnt pt_anchor reshareCoveredHolds pt_anchor__reshareCoveredHolds
t splitline_pools_test.qnt pt_no_window_burn windowBurnBroken pt_no_window_burn__windowBurnBroken
t splitline_pools_test.qnt pt_no_pending_burn pendingBurnBroken pt_no_pending_burn__pendingBurnBroken
t splitline_pools_test.qnt pt_window windowVoteBroken pt_window__windowVoteBroken
t splitline_pools_test.qnt pt_no_account_burn accountBurnBroken pt_no_account_burn__accountBurnBroken
t splitline_pools_test.qnt pt_reshare_no_anchor reshareNoAnchorBroken pt_reshare_no_anchor__reshareNoAnchorBroken
t splitline_pools_test.qnt pt_reshare_all reshareCoveredBroken pt_reshare_all__reshareCoveredBroken
for r in g5VoidHolds g5BurnHolds; do t splitline_test.qnt gt_design $r "gt_design__$r"; done
for r in g5VoidBroken g5BurnBroken; do t splitline_test.qnt gt_m_g5 $r "gt_m_g5__$r"; done
t splitline_test.qnt pg1_design pg1OpenVoidHolds pg1_design__pg1OpenVoidHolds
t splitline_test.qnt pg1_m_open pg1OpenVoidBroken pg1_m_open__pg1OpenVoidBroken
for r in c7BoundaryHolds c7EarlyHoldStopsHolds ecRevokeFreesHolds ecExpireReissueHolds coldFinalSettlesFinalHolds \
         releasedRepostHolds p1GuardianRefusedHolds gen2AfterReleaseHolds gen2AnchorsHolds; do t splitline_test.qnt fix_scenarios $r "fix__$r"; done
t splitline_test.qnt w5_scenarios w5Broken w5_mutant__w5Broken
for r in leafSetHolds slotRootHolds; do t splitline_test.qnt rt_design $r "rt_design__$r"; done
t splitline_test.qnt rt_m_leafset leafSetBroken rt_m_leafset__leafSetBroken
t splitline_test.qnt rt_m_slot_root slotRootBroken rt_m_slot_root__slotRootBroken
for m in burn:burnBroken precedence:precedenceBroken distinct:distinctBroken bf_p2:bfP2Broken \
         inclusion:inclusionBroken no_collect:noCollectBroken cold_old:coldOldBroken hold0:hold0Broken; do
  t splitline_test.qnt "mt_m_${m%%:*}" "${m#*:}" "mt_m_${m%%:*}__${m#*:}"; done
t splitline_test.qnt wk_design witkeyReleaseHolds wk_design__witkeyReleaseHolds
t splitline_test.qnt q1_n7_b3 q1ForkBroken q1_n7_b3__q1ForkBroken
t splitline_test.qnt q1_n9_b5 q1ForkBroken q1_n9_b5__q1ForkBroken
# findings from sampled runs (the violating trace)
quint run splitline_instances.qnt --main sl_n4_b2 --init initArmedSchnorr --step stepRelease4 --max-steps 14 \
  --max-samples 400 --seed 21 --invariant C12_SchnorrSlotOneTicket --out-itf "$out/q1_fork_sl_n4_b2.itf.json" > /dev/null 2>&1
quint run splitline_instances.qnt --main m_cold_void --init initArmedEcdsa --step stepReleaseCold --max-steps 25 \
  --max-samples 200 --seed 11 --invariant C11_ReleasedNeverUnspent --out-itf "$out/s4_cold_void_m_cold_void.itf.json" > /dev/null 2>&1
quint run splitline_instances.qnt --main m_g5 --init init --step stepMostlyProgress --max-steps 25 \
  --max-samples 400 --seed 31 --invariant C13_EcdsaPrecOnlyInForce --out-itf "$out/g5_m_g5_sampled.itf.json" > /dev/null 2>&1
for f in q1_fork_sl_n4_b2 s4_cold_void_m_cold_void g5_m_g5_sampled; do
  grep -q '"status":"violation"' "$out/$f.itf.json" 2>/dev/null || { echo "NO VIOLATION $f"; fail=1; }; done
# sampled design traces (invariants hold on every state)
for su in Schnorr Ecdsa; do
  quint run splitline_instances.qnt --main sl_n4 --init initArmed$su --step stepRelease4 --max-steps 25 \
    --max-samples 10 --n-traces 5 --seed 7 --invariant AllInvariants \
    --out-itf "$out/sampled/sl_n4_armed${su}_{seq}.itf.json" > /dev/null 2>&1 || { echo "FAIL sampled $su"; fail=1; }
done
quint run splitline_pools.qnt --main pl_design --init pinit --step pstepRestart --max-steps 60 \
  --max-samples 20 --n-traces 5 --seed 7 --invariant PoolInvariants \
  --out-itf "$out/sampled/pl_design_restart_{seq}.itf.json" > /dev/null 2>&1 || { echo "FAIL sampled pools"; fail=1; }
ls "$out" "$out/sampled"
echo "export exit $fail"
exit $fail
