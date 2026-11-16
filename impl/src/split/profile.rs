//! Per-charter authorization sources (DESIGN §5.3, §5.8, DECISIONS 19–20).

pub type Destination = [u8; 32];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerChecks {
    pub covenants: bool,
    pub approvers: bool,
    /// Cumulative limits and vetoes read mutable Midnight state.
    pub stateful: bool,
}

/// Only P2 contains registry and hold parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Profile {
    P0,
    P1 {
        exit: Destination,
        owner_checks: OwnerChecks,
    },
    P2 {
        exit: Destination,
        registry: Destination,
        delta_hold: u64,
        owner_checks: OwnerChecks,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charter {
    pub profile: Profile,
    pub board_first: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Owner,
    Recovery,
    Seizure,
}

/// Results from the authorization adapter, never unchecked network claims.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceEvidence {
    pub covenant: bool,
    pub approvers: bool,
    pub blacklist_clear: bool,
    pub hold_clear: bool,
    pub recovery_transition: bool,
    pub settled_order: bool,
}
impl SourceEvidence {
    pub fn verified() -> Self {
        Self {
            covenant: true,
            approvers: true,
            blacklist_clear: true,
            hold_clear: true,
            recovery_transition: true,
            settled_order: true,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    Source,
    Destination,
    Covenant,
    Approvers,
    Blacklist,
    Hold,
    Recovery,
    Order,
    BoardFirst,
    Parameters,
}

impl Charter {
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.board_first
            && match &self.profile {
                Profile::P0 => false,
                Profile::P1 { owner_checks, .. } => owner_checks.stateful,
                Profile::P2 { .. } => true,
            }
        {
            return Err(ProfileError::BoardFirst);
        }
        if matches!(self.profile, Profile::P2 { delta_hold: 0, .. }) {
            return Err(ProfileError::Parameters);
        }
        Ok(())
    }
    pub fn delta_hold(&self) -> u64 {
        match self.profile {
            Profile::P2 { delta_hold, .. } => delta_hold,
            _ => 0,
        }
    }
    pub fn regulated(&self) -> bool {
        matches!(self.profile, Profile::P2 { .. })
    }
    pub fn check(
        &self,
        source: Source,
        outputs: &[Destination],
        evidence: SourceEvidence,
    ) -> Result<(), ProfileError> {
        self.validate()?;
        let destination = |expected| {
            if outputs.is_empty() || outputs.iter().any(|x| *x != expected) {
                Err(ProfileError::Destination)
            } else {
                Ok(())
            }
        };
        match (&self.profile, source) {
            (Profile::P0, Source::Owner) => Ok(()),
            (Profile::P0, _) | (Profile::P1 { .. }, Source::Seizure) => Err(ProfileError::Source),
            // Recovery transition and signing-set evidence belong to the common
            // authorization proof. P1 adds no policy predicates to that source.
            (Profile::P1 { exit, .. }, Source::Recovery) => destination(*exit),
            (Profile::P2 { exit, .. }, Source::Recovery) => {
                destination(*exit)?;
                if !evidence.hold_clear {
                    return Err(ProfileError::Hold);
                }
                Ok(())
            }
            (Profile::P2 { registry, .. }, Source::Seizure) => {
                destination(*registry)?;
                if !evidence.settled_order {
                    return Err(ProfileError::Order);
                }
                Ok(())
            }
            (
                Profile::P1 { owner_checks, .. } | Profile::P2 { owner_checks, .. },
                Source::Owner,
            ) => {
                if owner_checks.covenants && !evidence.covenant {
                    return Err(ProfileError::Covenant);
                }
                if owner_checks.approvers && !evidence.approvers {
                    return Err(ProfileError::Approvers);
                }
                if self.regulated() {
                    if !evidence.blacklist_clear {
                        return Err(ProfileError::Blacklist);
                    }
                    if !evidence.hold_clear {
                        return Err(ProfileError::Hold);
                    }
                }
                Ok(())
            }
        }
    }
}
