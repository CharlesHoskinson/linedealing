//! Verified envelope bridge to the pure committee reducer.
//!
//! This is an in-process adapter: callers supply authenticated ordering votes,
//! authorization proofs and chain observations. It does not verify those proofs
//! or implement peer persistence. Envelope proofs, node shares, header AEAD and
//! contribution tokens are checked here. Release ticket checks run in the caller's
//! cryptographic callback before a release event reaches the reducer.

use crate::split::{envelope, prf, profile, state};
use crate::{board::Committee, hash::h, Error};
use k256::{ProjectivePoint, Scalar};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub type BoardResult<T> = Result<T, BoardError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardError {
    Crypto(Error),
    Reducer(state::SplitError),
    Parameters,
    RequestKind,
    TicketMembership,
    ContributionTarget,
    ContributionToken,
}
impl From<Error> for BoardError {
    fn from(value: Error) -> Self {
        Self::Crypto(value)
    }
}
impl From<state::SplitError> for BoardError {
    fn from(value: state::SplitError) -> Self {
        Self::Reducer(value)
    }
}
impl std::fmt::Display for BoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request board adapter: {self:?}")
    }
}
impl std::error::Error for BoardError {}

/// Facts supplied by the source-policy adapter, in opened ticket order.
/// These are verifier results, not fields accepted from a network message.
#[derive(Clone, Debug)]
pub struct HeaderPolicy {
    pub charter: profile::Charter,
    pub source: profile::Source,
    pub record: state::Digest,
    pub nf: state::Digest,
    pub pin: state::Digest,
    pub outputs: Vec<state::Digest>,
    pub source_checks: profile::SourceEvidence,
    pub ticket_membership: Vec<bool>,
    pub selection_rule: state::Digest,
    /// Semantic header checks, including any TEE intent proof, performed by the caller.
    pub header_checks_verified: bool,
}
impl HeaderPolicy {
    /// Simulator fixture only: assumes stateless P1 owner policy checks passed.
    /// ECDSA callers must still supply one source-root result per ticket.
    pub fn simulator_owner(record: state::Digest, nf: state::Digest, pin: state::Digest) -> Self {
        Self {
            charter: profile::Charter {
                profile: profile::Profile::P1 {
                    exit: [0; 32],
                    owner_checks: profile::OwnerChecks::default(),
                },
                board_first: false,
            },
            source: profile::Source::Owner,
            record,
            nf,
            pin,
            outputs: vec![],
            source_checks: profile::SourceEvidence::verified(),
            ticket_membership: vec![],
            selection_rule: [0; 32],
            header_checks_verified: true,
        }
    }
}

/// Caller verification of the complete authorization statement and final inclusion.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationEvidence {
    pub statement_verified: bool,
    pub inclusion_verified: bool,
    pub midnight_height: u64,
}

/// Caller verification of the header rule at the committed anchor and chain view.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseEvidence {
    pub selection_verified: bool,
    pub midnight_height: u64,
    pub not_revoked_verified: bool,
}

/// Attribution retained alongside the reducer's terminal result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponsibleParty {
    Initiator,
    Actor(u16),
    Committee(u16),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributedFailure {
    pub eid: state::Eid,
    pub party: ResponsibleParty,
    pub reason: state::VoidReason,
}

pub struct BoardAdapter {
    board: state::SplitBoard,
    keys: Vec<ProjectivePoint>,
    committee: Committee,
    delta_c: u64,
    failures: Vec<AttributedFailure>,
    header_bindings: BTreeMap<state::Eid, state::Digest>,
    contribution_payloads: BTreeMap<state::Eid, envelope::ContributionPayload>,
}

impl BoardAdapter {
    pub fn new(
        committee: Committee,
        epoch: u32,
        delta_c: u64,
        reservation_window: u64,
        tee: bool,
        slot_anchor: bool,
        keys: Vec<ProjectivePoint>,
    ) -> BoardResult<Self> {
        if keys.len() != usize::from(committee.n) {
            return Err(BoardError::Parameters);
        }
        envelope::keylist_hash(&keys)?;
        Ok(Self {
            board: state::SplitBoard::new(
                committee,
                u64::from(epoch),
                delta_c,
                reservation_window,
                tee,
                slot_anchor,
            )?,
            keys,
            committee,
            delta_c,
            failures: vec![],
            header_bindings: BTreeMap::new(),
            contribution_payloads: BTreeMap::new(),
        })
    }

    pub fn board(&self) -> &state::SplitBoard {
        &self.board
    }
    pub fn failures(&self) -> &[AttributedFailure] {
        &self.failures
    }

    /// Return only the frames currently attached by the reducer's ordering rule.
    /// Re-read that rule after complaints rather than caching a previous selection.
    pub fn accepted_contributions(
        &self,
        eid: state::Eid,
    ) -> BoardResult<Vec<envelope::ContributionPayload>> {
        self.board
            .request(&eid)?
            .contributions
            .values()
            .map(|frame| {
                self.contribution_payloads
                    .get(frame)
                    .cloned()
                    .ok_or(BoardError::ContributionTarget)
            })
            .collect()
    }

    /// Advanced simulator boundary for witness/hold/board-first events. The caller
    /// must authenticate every event and verify all evidence flags before use.
    /// Committee rotation needs a new adapter with the new epoch's key list.
    pub fn apply(&mut self, height: u64, event: state::Event) -> BoardResult<()> {
        self.board.apply(height, event)?;
        Ok(())
    }

    fn verify_public(&self, height: u64, envelope: &envelope::Envelope) -> BoardResult<()> {
        let epoch = u32::try_from(self.board.epoch).map_err(|_| BoardError::Parameters)?;
        envelope.verify_public(
            &self.keys,
            usize::from(self.committee.n - self.committee.f),
            epoch,
            height,
        )?;
        Ok(())
    }

    pub fn post(&mut self, height: u64, envelope: &envelope::Envelope) -> BoardResult<()> {
        self.verify_public(height, envelope)?;
        self.apply(
            height,
            state::Event::Post {
                envelope: state::Envelope {
                    eid: envelope.eid(),
                    hd: envelope.hd(),
                    dd: envelope.dd(),
                    auth_ref: envelope.public().auth_ref,
                    epoch: u64::from(envelope.public().epoch),
                    exp: envelope.public().exp,
                    checks: state::PublicChecks::verified(),
                },
            },
        )
    }

    pub fn order(&mut self, height: u64, eid: state::Eid, qc_verified: bool) -> BoardResult<()> {
        self.apply(height, state::Event::Order { eid, qc_verified })
    }

    fn header_partials(
        &self,
        height: u64,
        envelope: &envelope::Envelope,
        node_keys: &[(u16, Scalar)],
    ) -> BoardResult<Vec<prf::Partial>> {
        self.verify_public(height, envelope)?;
        if node_keys.len() < envelope.threshold()
            || node_keys
                .iter()
                .map(|(n, _)| n)
                .collect::<BTreeSet<_>>()
                .len()
                != node_keys.len()
        {
            return Err(Error::Threshold.into());
        }
        node_keys
            .iter()
            .map(|(node, secret)| {
                let share = Zeroizing::new(envelope.decrypt_share(*node, *secret, &self.keys)?);
                Ok(prf::partial(
                    *share,
                    *node,
                    &envelope.dd(),
                    prf::Label::Hdr,
                )?)
            })
            .collect()
    }

    pub fn open_header(
        &mut self,
        height: u64,
        envelope: &envelope::Envelope,
        node_keys: &[(u16, Scalar)],
        policy: HeaderPolicy,
    ) -> BoardResult<envelope::OpenedHeader> {
        let request = self.board.request(&envelope.eid())?;
        if request.order_position.is_none() {
            return Err(state::SplitError::NotOrdered.into());
        }
        let partials = self.header_partials(height, envelope, node_keys)?;
        let opened = envelope.open_header(&partials)?;
        if opened.header().delta_c != self.delta_c {
            return Err(BoardError::Parameters);
        }
        let header = translate_header(envelope, opened.header(), policy)?;
        for partial in partials {
            // Retrying a header blocked by an earlier unopened request reuses the
            // already accepted partials; it does not create duplicate votes.
            if !self
                .board
                .request(&envelope.eid())?
                .header_partials
                .contains(&partial.index)
            {
                self.apply(
                    height,
                    state::Event::HeaderPartial {
                        eid: envelope.eid(),
                        node: partial.index,
                        share_verified: true,
                    },
                )?;
            }
        }
        self.apply(
            height,
            state::Event::SeeHeader {
                eid: envelope.eid(),
                header: Box::new(header),
            },
        )?;
        self.header_bindings.insert(
            envelope.eid(),
            header_digest("SL1/adapter/header", opened.header())?,
        );
        Ok(opened)
    }

    pub fn authorize(
        &mut self,
        height: u64,
        eid: state::Eid,
        evidence: AuthorizationEvidence,
    ) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::Authorize {
                eid,
                verified: evidence.statement_verified,
            },
        )?;
        self.apply(
            height,
            state::Event::AuthFinal {
                eid,
                midnight_height: evidence.midnight_height,
                verified: evidence.inclusion_verified,
            },
        )
    }

    fn header_hash(&self, eid: state::Eid) -> BoardResult<state::Digest> {
        Ok(self
            .board
            .request(&eid)?
            .header
            .as_ref()
            .ok_or(state::SplitError::NotOpened)?
            .hash)
    }

    pub fn vote_opened(&mut self, height: u64, eid: state::Eid, node: u16) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::VoteOpened {
                eid,
                node,
                header_hash: self.header_hash(eid)?,
            },
        )
    }
    pub fn admit(
        &mut self,
        height: u64,
        eid: state::Eid,
        node: u16,
        obs: state::Observation,
    ) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::VoteAdmit {
                eid,
                node,
                header_hash: self.header_hash(eid)?,
                obs,
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn anchor(
        &mut self,
        height: u64,
        eid: state::Eid,
        generation: u16,
        node: u16,
        obs: state::Observation,
        deadline_verified: bool,
    ) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::AnchorGen {
                eid,
                generation,
                node,
                obs,
                deadline_verified,
            },
        )
    }

    pub fn selected_tickets(
        &self,
        eid: state::Eid,
        generation: u16,
        variant: u16,
    ) -> BoardResult<Vec<state::Digest>> {
        let header = self
            .board
            .request(&eid)?
            .header
            .as_ref()
            .ok_or(state::SplitError::NotOpened)?;
        let ticket_generation = if header.suite == state::Suite::Ecdsa {
            0
        } else {
            generation
        };
        let mut tickets: Vec<_> = header
            .tickets
            .iter()
            .filter(|t| t.variant == variant && t.generation == ticket_generation)
            .collect();
        tickets.sort_by_key(|t| t.input);
        if tickets.len() != usize::from(header.inputs) {
            return Err(state::SplitError::Ticket.into());
        }
        Ok(tickets.into_iter().map(|t| t.digest).collect())
    }

    /// `check_tickets` must perform the suite's release checks for precisely the
    /// selected envelope/variant/generation. An error emits no release event.
    #[allow(clippy::too_many_arguments)]
    pub fn release(
        &mut self,
        height: u64,
        eid: state::Eid,
        node: u16,
        generation: u16,
        variant: u16,
        evidence: ReleaseEvidence,
        check_tickets: impl FnOnce() -> crate::Result<()>,
    ) -> BoardResult<()> {
        let tickets = self.selected_tickets(eid, generation, variant)?;
        check_tickets()?;
        self.apply(
            height,
            state::Event::Release {
                eid,
                node,
                generation,
                variant,
                tickets,
                selection_verified: evidence.selection_verified,
                checks_verified: true,
                midnight_height: evidence.midnight_height,
                not_revoked_verified: evidence.not_revoked_verified,
            },
        )
    }

    /// Opens an independently ordered CONTRIB frame with real node shares.
    /// Public proof, dimensions and actor token are checked before attachment;
    /// sealed scalar contents are checked by the combiner after body release.
    #[allow(clippy::too_many_arguments)]
    pub fn open_contribution(
        &mut self,
        height: u64,
        frame: &envelope::Envelope,
        node_keys: &[(u16, Scalar)],
        target: &envelope::Envelope,
        target_opened: &envelope::OpenedHeader,
        qc_verified: bool,
    ) -> BoardResult<envelope::OpenedHeader> {
        if !qc_verified {
            return Err(state::SplitError::Evidence.into());
        }
        let partials = self.header_partials(height, frame, node_keys)?;
        let opened = frame.open_header(&partials)?;
        let header = opened.header();
        let target_header = target_opened.header();
        let payload = header
            .contribution
            .as_ref()
            .ok_or(BoardError::RequestKind)?;
        // Bind the supplied opened target to the target already accepted by this
        // adapter, including the token commitments and layout used below.
        let recorded = self
            .board
            .request(&target.eid())?
            .header
            .as_ref()
            .ok_or(state::SplitError::NotOpened)?;
        if recorded.hash != target.hd()
            || payload.target_hd != target.hd()
            || header.kind != envelope::RequestType::Contrib
            || (header.suite, header.k, header.l)
                != (target_header.suite, target_header.k, target_header.l)
            || self.header_bindings.get(&target.eid())
                != Some(&header_digest("SL1/adapter/header", target_header)?)
        {
            return Err(BoardError::ContributionTarget);
        }
        let actor = target_header
            .actors
            .iter()
            .find(|a| a.position == payload.position)
            .ok_or(BoardError::ContributionTarget)?;
        if actor.token_hash != envelope::token_hash(&payload.token) {
            return Err(BoardError::ContributionToken);
        }
        self.apply(
            height,
            state::Event::Contribute {
                contribution: state::Contribution {
                    frame: frame.eid(),
                    epoch: u64::from(frame.public().epoch),
                    dd: frame.dd(),
                    target_hd: payload.target_hd,
                    actor: u16::from(payload.position),
                    digest: header_digest("SL1/adapter/contribution", header)?,
                    verified: true,
                },
            },
        )?;
        self.contribution_payloads
            .insert(frame.eid(), payload.clone());
        Ok(opened)
    }

    pub fn final_vote(
        &mut self,
        height: u64,
        eid: state::Eid,
        node: u16,
        ciphertext: state::Digest,
    ) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::Final {
                eid,
                epoch: self.board.epoch,
                node,
                ciphertext,
            },
        )
    }
    pub fn fail(
        &mut self,
        height: u64,
        eid: state::Eid,
        reason: state::VoidReason,
        evidence_verified: bool,
    ) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::CombinerFailure {
                eid,
                reason,
                verified: evidence_verified,
            },
        )
    }
    pub fn attributed_failure(
        &mut self,
        height: u64,
        failure: AttributedFailure,
        evidence_verified: bool,
    ) -> BoardResult<()> {
        self.fail(height, failure.eid, failure.reason, evidence_verified)?;
        self.failures.push(failure);
        Ok(())
    }
    pub fn void_vote(
        &mut self,
        height: u64,
        eid: state::Eid,
        node: u16,
        reason: state::VoidReason,
    ) -> BoardResult<()> {
        self.apply(
            height,
            state::Event::Void {
                eid,
                epoch: self.board.epoch,
                node,
                reason,
            },
        )
    }
    /// Records the deadline predicate. Authenticated VOID votes settle STALLED.
    pub fn stall(&mut self, height: u64, eid: state::Eid) -> BoardResult<()> {
        self.apply(height, state::Event::Stall { eid })
    }
    pub fn expire(&mut self, height: u64, eid: state::Eid) -> BoardResult<()> {
        self.apply(height, state::Event::Expire { eid })
    }
}

fn header_digest(tag: &str, header: &envelope::Header) -> BoardResult<state::Digest> {
    let encoded = Zeroizing::new(header.encode()?);
    Ok(h(tag, &encoded))
}

fn slot_id(suite: state::Suite, epoch: u64, slot: u32) -> state::SlotId {
    let id = h(
        "SL1/adapter/slot",
        &[epoch.to_be_bytes().as_slice(), &slot.to_be_bytes()].concat(),
    );
    if suite == state::Suite::Ecdsa {
        state::SlotId::Ecdsa { record: id }
    } else {
        state::SlotId::Schnorr {
            suite,
            epoch,
            index: u64::from(slot),
        }
    }
}

fn translate_header(
    envelope: &envelope::Envelope,
    header: &envelope::Header,
    policy: HeaderPolicy,
) -> BoardResult<state::Header> {
    translate(
        header,
        u64::from(envelope.public().epoch),
        envelope.hd(),
        policy,
    )
}

fn translate(
    header: &envelope::Header,
    epoch: u64,
    header_hash: state::Digest,
    policy: HeaderPolicy,
) -> BoardResult<state::Header> {
    header.validate()?;
    if header.kind == envelope::RequestType::Contrib {
        return Err(BoardError::RequestKind);
    }
    let suite = match header.suite {
        1 => state::Suite::Ecdsa,
        2 => state::Suite::Bip340,
        3 => state::Suite::Ed25519,
        _ => return Err(BoardError::Parameters),
    };
    if (suite == state::Suite::Ecdsa || !policy.ticket_membership.is_empty())
        && policy.ticket_membership.len() != header.tickets.len()
    {
        return Err(BoardError::TicketMembership);
    }
    let slots = header
        .slots
        .iter()
        .map(|s| slot_id(suite, epoch, *s))
        .collect();
    let mut tickets = Vec::with_capacity(header.tickets.len());
    for (variant, generation) in header.labels() {
        for input in 1..=header.l {
            let index = tickets.len();
            let wire = &header.tickets[index];
            let slot = u32::from_be_bytes(wire[..4].try_into().map_err(|_| Error::Encoding)?);
            tickets.push(state::Ticket {
                variant: u16::from(variant),
                generation: u16::from(generation),
                input: u16::from(input),
                slot: slot_id(suite, epoch, slot),
                digest: h("SL1/adapter/ticket", wire),
                in_source_root: policy
                    .ticket_membership
                    .get(index)
                    .copied()
                    .unwrap_or(false),
            });
        }
    }
    Ok(state::Header {
        hash: header_hash,
        selection_rule: policy.selection_rule,
        charter: policy.charter,
        source: policy.source,
        record: policy.record,
        nf: policy.nf,
        pin: policy.pin,
        outputs: policy.outputs,
        checks: policy.source_checks,
        suite,
        variants: u16::from(header.k),
        inputs: u16::from(header.l),
        slots,
        tickets,
        actors: header
            .actors
            .iter()
            .map(|a| u16::from(a.position))
            .collect(),
        embedded: header
            .actors
            .iter()
            .filter(|a| a.embedded.is_some())
            .map(|a| u16::from(a.position))
            .collect(),
        valid: policy.header_checks_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_header(suite: u8) -> envelope::Header {
        let mut header =
            envelope::Header::request(envelope::RequestType::Spend, suite, 3, 2).unwrap();
        header.slots = (1..=header.slot_count() as u32).collect();
        for (variant, generation) in header.labels() {
            for input in 0..header.l {
                let group = if suite == 1 { variant } else { generation };
                let index = usize::from((group - 1) * header.l + input);
                let mut ticket = vec![0; header.ticket_len()];
                ticket[..4].copy_from_slice(&header.slots[index].to_be_bytes());
                ticket[4] = variant;
                header.tickets.push(ticket);
            }
        }
        header
    }

    #[test]
    fn schnorr_ticket_order_and_generation_slots_are_preserved() {
        for suite in [2, 3] {
            let wire = wire_header(suite);
            let policy = HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]);
            let header = translate(&wire, 8, [4; 32], policy.clone()).unwrap();
            assert_eq!(header.slots.len(), 4);
            assert_eq!(header.tickets.len(), 10);
            let positions: Vec<_> = header
                .tickets
                .iter()
                .map(|t| (t.variant, t.generation, t.input))
                .collect();
            assert_eq!(
                positions,
                vec![
                    (1, 1, 1),
                    (1, 1, 2),
                    (2, 1, 1),
                    (2, 1, 2),
                    (2, 2, 1),
                    (2, 2, 2),
                    (3, 1, 1),
                    (3, 1, 2),
                    (3, 2, 1),
                    (3, 2, 2)
                ]
            );
            assert_eq!(header.tickets[0].slot, header.tickets[2].slot);
            assert_ne!(header.tickets[0].digest, header.tickets[2].digest);
            let other_request = translate(&wire, 8, [5; 32], policy.clone()).unwrap();
            assert_eq!(header.slots, other_request.slots);
            assert_ne!(
                header.slots,
                translate(&wire, 9, [5; 32], policy).unwrap().slots
            );
        }
    }

    #[test]
    fn ecdsa_requires_explicit_membership_and_uses_slot_not_prehash() {
        let wire = wire_header(1);
        let mut policy = HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]);
        assert_eq!(
            translate(&wire, 8, [4; 32], policy.clone()),
            Err(BoardError::TicketMembership)
        );
        policy.ticket_membership = vec![true; wire.tickets.len()];
        policy.ticket_membership[2] = false;
        let header = translate(&wire, 8, [4; 32], policy.clone()).unwrap();
        assert_eq!(header.slots.len(), 6);
        assert!(header.tickets.iter().all(|t| t.generation == 0));
        assert!(!header.tickets[2].in_source_root);
        let mut changed = wire.clone();
        changed.tickets[0][4] ^= 1;
        let other = translate(&changed, 8, [5; 32], policy).unwrap();
        assert_eq!(header.slots, other.slots);
        assert_ne!(header.tickets[0].digest, other.tickets[0].digest);
    }

    #[test]
    fn malformed_ticket_length_or_slot_is_rejected_before_events() {
        let mut wire = wire_header(2);
        let policy = HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]);
        wire.tickets[0].pop();
        assert_eq!(
            translate(&wire, 8, [4; 32], policy.clone()),
            Err(BoardError::Crypto(Error::Encoding))
        );
        wire.tickets[0].push(0);
        wire.tickets[0][3] ^= 1;
        assert_eq!(
            translate(&wire, 8, [4; 32], policy),
            Err(BoardError::Crypto(Error::Encoding))
        );
    }

    // Reducer fixture for testing the release/evidence boundary. The request's
    // cryptographic construction and opening are covered by the end-to-end tests.
    fn admitted() -> BoardAdapter {
        let mut adapter = BoardAdapter::new(
            Committee { n: 1, f: 0 },
            8,
            10,
            256,
            false,
            false,
            vec![ProjectivePoint::GENERATOR],
        )
        .unwrap();
        adapter
            .apply(
                0,
                state::Event::Checkpoint {
                    pools: BTreeMap::from([(
                        state::PoolId {
                            suite: state::Suite::Bip340,
                            epoch: 8,
                        },
                        state::PoolCheckpoint {
                            h: 0,
                            pending_min: 1,
                            pending_root: [0; 32],
                            pending_count: 0,
                            pending: BTreeMap::new(),
                            pending_verified: true,
                        },
                    )]),
                },
            )
            .unwrap();
        let eid = [7; 32];
        let policy = HeaderPolicy::simulator_owner([1; 32], [2; 32], [3; 32]);
        let header = translate(&wire_header(2), 8, [4; 32], policy).unwrap();
        adapter
            .apply(
                1,
                state::Event::Post {
                    envelope: state::Envelope {
                        eid,
                        hd: [4; 32],
                        dd: [5; 32],
                        auth_ref: [6; 32],
                        epoch: 8,
                        exp: 100,
                        checks: state::PublicChecks::verified(),
                    },
                },
            )
            .unwrap();
        adapter.order(1, eid, true).unwrap();
        adapter
            .apply(
                1,
                state::Event::HeaderPartial {
                    eid,
                    node: 1,
                    share_verified: true,
                },
            )
            .unwrap();
        adapter
            .apply(
                1,
                state::Event::SeeHeader {
                    eid,
                    header: Box::new(header),
                },
            )
            .unwrap();
        adapter
            .authorize(
                1,
                eid,
                AuthorizationEvidence {
                    statement_verified: true,
                    inclusion_verified: true,
                    midnight_height: 1,
                },
            )
            .unwrap();
        adapter
            .admit(
                1,
                eid,
                1,
                state::Observation {
                    host_height: 1,
                    midnight_height: 1,
                },
            )
            .unwrap();
        adapter
    }

    #[test]
    fn rejected_release_checks_emit_no_release_and_selection_is_required() {
        let mut adapter = admitted();
        let eid = [7; 32];
        let evidence = ReleaseEvidence {
            selection_verified: true,
            midnight_height: 1,
            not_revoked_verified: true,
        };
        let position = adapter.board().position;
        assert_eq!(
            adapter.release(2, eid, 1, 1, 1, evidence, || Err(Error::Signature)),
            Err(BoardError::Crypto(Error::Signature))
        );
        assert_eq!(adapter.board().position, position);
        assert!(adapter.board().request(&eid).unwrap().releases.is_empty());
        assert_eq!(
            adapter.release(
                2,
                eid,
                1,
                1,
                1,
                ReleaseEvidence {
                    selection_verified: false,
                    ..evidence
                },
                || Ok(())
            ),
            Err(BoardError::Reducer(state::SplitError::Selection))
        );
        assert!(adapter.board().request(&eid).unwrap().releases.is_empty());
    }

    #[test]
    fn release_then_expire_preserves_pin_settlement() {
        let mut adapter = admitted();
        let eid = [7; 32];
        adapter
            .release(
                2,
                eid,
                1,
                1,
                1,
                ReleaseEvidence {
                    selection_verified: true,
                    midnight_height: 1,
                    not_revoked_verified: true,
                },
                || Ok(()),
            )
            .unwrap();
        assert_eq!(
            adapter.board().request(&eid).unwrap().state,
            state::State::Released {
                generation: 1,
                variant: 1
            }
        );
        adapter.expire(100, eid).unwrap();
        assert_eq!(
            adapter.board().request(&eid).unwrap().state,
            state::State::Expired
        );
        assert_eq!(
            adapter.board().request(&eid).unwrap().settlement,
            Some(state::Settlement::Released { pin: [3; 32] })
        );
    }

    #[test]
    fn attribution_is_retained_only_after_verified_terminal_failure() {
        let mut adapter = admitted();
        let failure = AttributedFailure {
            eid: [7; 32],
            party: ResponsibleParty::Initiator,
            reason: state::VoidReason::DealerFault,
        };
        assert_eq!(
            adapter.attributed_failure(2, failure, false),
            Err(BoardError::Reducer(state::SplitError::Evidence))
        );
        assert!(adapter.failures().is_empty());
        adapter.attributed_failure(2, failure, true).unwrap();
        assert_eq!(adapter.failures(), &[failure]);
        assert_eq!(
            adapter.board().request(&failure.eid).unwrap().state,
            state::State::Void(state::VoidReason::DealerFault)
        );
    }
}
