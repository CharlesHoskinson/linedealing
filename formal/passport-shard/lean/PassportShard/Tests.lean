import PassportShard.Spec

/-!
# Step-level pins

Each pin states the expected value from a requirement sentence of
`SHARD-SPEC.md`. Every pin is checked twice: by the kernel (`decide +kernel`)
and by the compiled evaluator (`#guard`).
-/

namespace PassportShard.Tests
open PassportShard

def c0 : Cfg := { quorum := 2, nGuard := 3, native := [], synced := [0], overlap := [] }
def cN : Cfg := { c0 with native := [0] }
def s0 : St := init c0 0
def sN : St := init cN 0

def spend : List Op := [.unlock 0 7, .approve 0 7 1, .authorize 0 7 1, .release 7 1]

def pins : List Bool := [
  -- PS-002, PS-003: configuration refusals
  cfgRefusals c0 == [],
  cfgRefusals { c0 with quorum := 0 } == [.badQuorum],
  cfgRefusals { c0 with quorum := 4 } == [.badQuorum],
  cfgRefusals { c0 with quorum := 3 } == [],
  cfgRefusals { c0 with overlap := [1] } == [.guardianOverlap],
  cfgRefusals { c0 with quorum := 0, overlap := [1] } == [.badQuorum, .guardianOverlap],
  -- PS-004: creation
  s0.readers == [0] && s0.creds == [0] && s0.prfLog == [0] && s0.sigs == [] &&
    !s0.advRoot && !s0.advXf,
  -- PS-010, PS-016, PS-018, PS-022: one honest spend
  (runOps s0 spend).sigs == [7],
  (runOps s0 spend).unlockLog == [(0, 7)],
  (runOps s0 spend).prfLog == [0, 0],
  (runOps s0 spend).authorized == [(7, 1)],
  (runOps s0 spend).usedNf == [1],
  -- PS-013, PS-017: a device that is not enrolled
  refusals s0 (.unlock 3 7) == [.notEnrolled, .noWrap],
  refusals s0 (.approve 3 7 1) == [.notEnrolled],
  -- PS-019: an assertion over another intent or another nf
  refusals (runOps s0 [.approve 0 7 1]) (.authorize 0 8 1) == [.noAssertion],
  refusals (runOps s0 [.approve 0 7 1]) (.authorize 0 7 2) == [.noAssertion],
  (runOps s0 [.approve 0 7 1, .authorize 0 8 1]).authorized == [],
  -- PS-021: one authorize for each nf
  refusals (runOps s0 [.approve 0 7 1, .authorize 0 7 1, .approve 0 8 1])
    (.authorize 0 8 1) == [.nfUsed],
  -- PS-024, PS-025: release needs the authorization and a contribution
  refusals s0 (.release 7 1) == [.notAuthorized, .noContribution],
  refusals (runOps s0 [.approve 0 7 1, .authorize 0 7 1]) (.release 7 1) == [.noContribution],
  refusals (runOps s0 [.unlock 0 7]) (.release 7 1) == [.notAuthorized],
  -- PS-043, PS-055, PS-056: a fully corrupt committee completes dealt intents only
  refusals (runOps s0 [.corruptCommittee]) (.advSign 7) == [.noContribution],
  (runOps s0 [.corruptCommittee, .advSign 7]).sigs == [],
  (runOps s0 [.unlock 0 7, .corruptCommittee, .advSign 7]).sigs == [7],
  refusals (runOps s0 [.unlock 0 7, .corruptCommittee]) (.advSign 8) == [.noContribution],
  refusals s0 (.advSign 7) == [.noCommitteeHalf, .noContribution],
  -- PS-023: the honest release of a corrupt committee
  refusals (runOps s0 (spend.take 3 ++ [.corruptCommittee])) (.release 7 1) == [.committeeCorrupt],
  -- PS-012, PS-045: a corrupt origin sees the root of a web reader
  (runOps s0 [.corruptOrigin, .unlock 0 7]).advRoot,
  (runOps s0 [.corruptOrigin, .unlock 0 7]).via == [.originLeak 0],
  !(runOps s0 [.unlock 0 7, .corruptOrigin]).advRoot,
  !(runOps sN [.corruptOrigin, .unlock 0 7]).advRoot,
  -- a root alone, with an honest committee: no authorization, no signature
  refusals (runOps s0 [.corruptOrigin, .unlock 0 7]) (.release 9 1) == [.notAuthorized],
  refusals (runOps s0 [.corruptOrigin, .unlock 0 7]) (.advAssert 0 9 1) == [.noCredential],
  refusals (runOps s0 [.corruptOrigin, .unlock 0 7]) (.advSign 9) == [.noCommitteeHalf],
  -- the whole key: root and committee half
  (runOps s0 [.corruptOrigin, .unlock 0 7, .corruptCommittee, .advSign 9]).sigs == [9],
  -- PS-006, PS-008: enroll, remove; the wrap of a removed device remains
  (runOps s0 [.enroll 0 1]).creds == [1, 0],
  (runOps s0 [.enroll 0 1]).readers == [1, 0],
  (runOps s0 [.enroll 0 1]).prfLog == [0, 0],
  (runOps s0 [.enroll 0 1, .removeDevice 0 1]).creds == [0],
  (runOps s0 [.enroll 0 1, .removeDevice 0 1]).readers == [1, 0],
  refusals (runOps s0 [.enroll 0 1, .removeDevice 0 1]) (.unlock 1 7) == [.notEnrolled],
  refusals s0 (.removeDevice 0 0) == [.selfRemoval],
  refusals s0 (.enroll 0 0) == [.alreadyEnrolled],
  (runOps s0 [.enroll 0 1, .removeDevice 0 1, .stealDevice 1 true]).advRoot,
  refusals (runOps s0 [.enroll 0 1, .removeDevice 0 1, .stealDevice 1 true, .advAssert 1 9 1])
    (.authorize 1 9 1) == [.notEnrolled],
  -- PS-048, PS-049: theft
  runOps s0 [.stealDevice 0 false] == s0,
  (runOps s0 [.stealDevice 0 true]).advRoot,
  (runOps s0 [.stealDevice 0 true]).via == [.theft 0],
  (runOps s0 [.stealDevice 0 true]).advCred == [0],
  (runOps s0 [.stealDevice 0 true]).prfLog == [0, 0],
  refusals s0 (.stealDevice 4 true) == [.unknownDevice],
  -- PS-051, PS-052: the provider of a synced passkey
  (runOps s0 [.providerTakeover 0]).advRoot,
  (runOps s0 [.providerTakeover 0]).via == [.provider 0],
  !(runOps sN [.providerTakeover 0]).advRoot,
  (runOps sN [.providerTakeover 0]).advCred == [0],
  refusals (runOps s0 [.enroll 0 1]) (.providerTakeover 1) == [.notSynced],
  -- PS-030, PS-046, PS-047: the guardian quorum
  !(runOps s0 [.publishRWrap 0, .corruptGuardian 0]).advRoot,
  (runOps s0 [.publishRWrap 0, .corruptGuardian 0, .corruptGuardian 1]).advRoot,
  (runOps s0 [.publishRWrap 0, .corruptGuardian 0, .corruptGuardian 1]).via == [.quorum],
  (runOps s0 [.corruptGuardian 0, .corruptGuardian 1, .publishRWrap 0]).advRoot,
  !(runOps s0 [.corruptGuardian 0, .corruptGuardian 1]).advRoot,
  refusals s0 (.corruptGuardian 3) == [.unknownGuardian],
  refusals (runOps s0 [.corruptGuardian 0]) (.corruptGuardian 0) == [.alreadyCorrupt],
  -- PS-032 to PS-039: recovery
  refusals s0 (.recoverSubmit 5) == [.noRecoveryWrap],
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5]).pending == some (5, false),
  refusals (runOps s0 [.publishRWrap 0, .recoverSubmit 5]) (.recoverSubmit 6) == [.recoveryPending],
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverCancel 0]).pending == none,
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverFinalise]).creds == [5],
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverFinalise]).readers == [5, 0],
  !(runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverFinalise]).rWrap,
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverFinalise]).rWrapEver,
  !(runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverFinalise]).advRoot,
  refusals s0 .recoverFinalise == [.noPending],
  refusals s0 (.recoverCancel 0) == [.noPending],
  (runOps s0 [.publishRWrap 0, .corruptOrigin, .recoverSubmit 5, .recoverFinalise]).via
    == [.recoveryLeak 5],
  -- PS-040, PS-041: recovery by a corrupt quorum
  refusals (runOps s0 [.publishRWrap 0]) (.advRecoverSubmit 5) == [.noQuorum],
  (runOps s0 [.publishRWrap 0, .corruptGuardian 0, .corruptGuardian 1, .advRecoverSubmit 5,
    .recoverFinalise]).advCred == [5],
  (runOps s0 [.publishRWrap 0, .corruptGuardian 0, .corruptGuardian 1, .advRecoverSubmit 5,
    .recoverCancel 0]).pending == none,
  -- PS-067 (D-1, OD-1): the id of a pending successor cannot be enrolled
  refusals (runOps s0 [.corruptGuardian 0, .corruptGuardian 1, .publishRWrap 0,
    .advRecoverSubmit 2]) (.enroll 0 2) == [.pendingSuccessor],
  refusals (runOps s0 [.publishRWrap 0, .recoverSubmit 5]) (.enroll 0 5) == [.pendingSuccessor],
  refusals (runOps s0 [.publishRWrap 0, .recoverSubmit 5]) (.enroll 3 5)
    == [.notEnrolled, .noWrap, .pendingSuccessor],
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5, .enroll 0 6]).creds == [6, 0],
  (runOps s0 [.publishRWrap 0, .recoverSubmit 5, .recoverCancel 0, .enroll 0 5]).creds == [5, 0],
  -- the od1 sequence: ENROLL(0, 2) is refused, and the honest device never holds id 2
  (runOps s0 [.corruptGuardian 0, .corruptGuardian 1, .publishRWrap 0, .advRecoverSubmit 2,
    .enroll 0 2]).creds == [0],
  (runOps s0 [.corruptGuardian 0, .corruptGuardian 1, .publishRWrap 0, .advRecoverSubmit 2,
    .enroll 0 2]).readers == [0],
  (runOps s0 [.corruptGuardian 0, .corruptGuardian 1, .publishRWrap 0, .advRecoverSubmit 2,
    .enroll 0 2, .recoverFinalise]).advCred == [2],
  -- PS-042, PS-044: the group E
  (runOps s0 [.corruptCommittee, .eReprovision]).committeeCorrupt == false,
  (runOps s0 [.corruptCommittee, .eReprovision]).advXf,
  (runOps s0 [.eReprovision]).epoch == 1,
  !(runOps s0 [.eReprovision]).advXf,
  (runOps s0 [.corruptE]).advXf && (runOps s0 [.corruptE]).eCorrupt,
  -- PS-057: a refused operation changes nothing
  apply s0 (.release 7 1) == s0,
  -- PS-065, PS-066: a corrupt origin sets the challenge of an approval
  refusals s0 (.originAssert 0 9 1) == [.originHonest],
  refusals (runOps sN [.corruptOrigin]) (.originAssert 0 9 1) == [.nativeCredential],
  refusals (runOps s0 [.corruptOrigin]) (.originAssert 3 9 1) == [.notEnrolled],
  (runOps s0 [.corruptOrigin, .originAssert 0 9 1]).asserts == [(0, 9, 1)],
  (runOps s0 [.corruptOrigin, .originAssert 0 9 1]).hijacked == [(0, 9, 1)],
  (runOps s0 [.corruptOrigin, .originAssert 0 9 1]).approved == [],
  (runOps s0 [.corruptOrigin, .unlock 0 7, .originAssert 0 9 1, .authorize 0 9 1,
    .release 9 1]).sigs == [9],
  refusals (runOps s0 [.corruptOrigin, .originAssert 0 9 1, .authorize 0 9 1])
    (.release 9 1) == [.noContribution],
  -- PS-053: the adversary asserts with a stolen credential
  (runOps s0 [.stealDevice 0 true, .advAssert 0 9 1, .authorize 0 9 1, .release 9 1]).sigs == [9]
]

example : pins.all id = true := by decide +kernel

#guard pins.all id

/-- The pins fail one by one when a pin is false (a guard on the harness). -/
example : (pins ++ [false]).all id = false := by decide +kernel

end PassportShard.Tests
