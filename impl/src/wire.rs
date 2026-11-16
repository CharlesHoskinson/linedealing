use crate::{algebra::*, Error, Result};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub script: Vec<u8>,
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub outputs: Vec<Output>,
    pub change_to: Vec<u8>,
    /// kind(1) || payload(71), including canonical zero padding.
    pub pin: [u8; 72],
    pub allowed: Vec<[u8; 36]>,
    pub fee_ceiling: u128,
    pub fee_rule: u16,
    pub bump_delay: u16,
    pub grid_ratio: [u8; 2],
    pub min_conf: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub suite: u8,
    pub mode: u8,
    pub addr_type: u8,
    pub on_rotation: u8,
    pub late_inputs: u8,
    pub chain_id: [u8; 32],
    pub board_id: [u8; 32],
    pub owner_nonce: [u8; 32],
    pub keylist_hash: [u8; 32],
    pub builder_hash: [u8; 32],
    pub public_key: ProjectivePoint,
    pub ephemeral: ProjectivePoint,
    pub address: Vec<u8>,
    pub epoch: u64,
    pub not_before: u64,
    pub expires: u64,
    pub n: u16,
    pub threshold: u16,
    pub f: u16,
    pub variants: u16,
    pub inputs: u16,
    pub generations: u16,
    pub trigger_id: u16,
    pub trigger_params: [u8; 32],
    pub intent: Intent,
}

fn padded(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.len() > 35 {
        return Err(Error::Encoding);
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out.resize(out.len() + 35 - value.len(), 0);
    Ok(())
}

impl Header {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !matches!(self.suite, 1 | 2)
            || !matches!(self.mode, 1 | 2)
            || !matches!(self.on_rotation, 1..=3)
            || self.late_inputs > 1
            // ceil((n+f+1)/2) quorums retain honest intersection for n >= 3f+1.
            || (self.n as u32) < 3 * self.f as u32 + 1
            || self.threshold == 0
            || (self.threshold != self.f + 1 && self.threshold != self.n - self.f)
            || (self.on_rotation == 2 && self.threshold != self.f + 1)
            || self.inputs == 0
            || self.not_before > self.expires
            || (self.mode == 1 && self.variants == 0)
            || (self.mode == 2 && self.generations == 0)
        {
            return Err(Error::Parameters);
        }
        encode_point(self.public_key)?;
        encode_point(self.ephemeral)?;
        if (self.suite == 1 && !matches!(self.addr_type, 1 | 2 | 3 | 5))
            || (self.suite == 2 && (self.addr_type != 4 || is_odd(self.public_key)?))
        {
            return Err(Error::Parameters);
        }
        let intent = &self.intent;
        if !(1..=2).contains(&intent.outputs.len())
            || intent.allowed.len() > 7
            || intent
                .outputs
                .iter()
                .filter(|o| o.amount == u128::MAX)
                .count()
                > 1
            || intent.grid_ratio[1] == 0
        {
            return Err(Error::Parameters);
        }
        let used = match intent.pin[0] {
            1 => 45,
            2 => 9,
            3 => 65,
            _ => return Err(Error::Encoding),
        };
        if intent.pin[used..].iter().any(|b| *b != 0) {
            return Err(Error::Encoding);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = vec![
            self.version,
            self.suite,
            self.mode,
            self.addr_type,
            self.on_rotation,
            self.late_inputs,
        ];
        for field in [
            &self.chain_id,
            &self.board_id,
            &self.owner_nonce,
            &self.keylist_hash,
            &self.builder_hash,
        ] {
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&encode_point(self.public_key)?);
        out.extend_from_slice(&encode_point(self.ephemeral)?);
        padded(&mut out, &self.address)?;
        for value in [self.epoch, self.not_before, self.expires] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.n,
            self.threshold,
            self.f,
            self.variants,
            self.inputs,
            self.generations,
            self.trigger_id,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.trigger_params);
        out.push(self.intent.outputs.len() as u8);
        for output in &self.intent.outputs {
            padded(&mut out, &output.script)?;
            out.extend_from_slice(&output.amount.to_be_bytes());
        }
        padded(&mut out, &self.intent.change_to)?;
        out.extend_from_slice(&self.intent.pin);
        out.push(self.intent.allowed.len() as u8);
        for allowed in &self.intent.allowed {
            out.extend_from_slice(allowed);
        }
        out.extend_from_slice(&self.intent.fee_ceiling.to_be_bytes());
        for value in [self.intent.fee_rule, self.intent.bump_delay] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.intent.grid_ratio);
        out.extend_from_slice(&self.intent.min_conf.to_be_bytes());
        Ok(out)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.byte()?;
        let suite = r.byte()?;
        let mode = r.byte()?;
        let addr_type = r.byte()?;
        let on_rotation = r.byte()?;
        let late_inputs = r.byte()?;
        let chain_id = r.array()?;
        let board_id = r.array()?;
        let owner_nonce = r.array()?;
        let keylist_hash = r.array()?;
        let builder_hash = r.array()?;
        let public_key = r.point()?;
        let ephemeral = r.point()?;
        let address = r.padded()?;
        let epoch = r.u64()?;
        let not_before = r.u64()?;
        let expires = r.u64()?;
        let n = r.u16()?;
        let threshold = r.u16()?;
        let f = r.u16()?;
        let variants = r.u16()?;
        let inputs = r.u16()?;
        let generations = r.u16()?;
        let trigger_id = r.u16()?;
        let trigger_params = r.array()?;
        let n_out = r.byte()?;
        if !(1..=2).contains(&n_out) {
            return Err(Error::Encoding);
        }
        let mut outputs = Vec::new();
        for _ in 0..n_out {
            outputs.push(Output {
                script: r.padded()?,
                amount: u128::from_be_bytes(r.array()?),
            });
        }
        let change_to = r.padded()?;
        let pin = r.array()?;
        let n_allowed = r.byte()?;
        if n_allowed > 7 {
            return Err(Error::Encoding);
        }
        let mut allowed = Vec::new();
        for _ in 0..n_allowed {
            allowed.push(r.array()?);
        }
        let intent = Intent {
            outputs,
            change_to,
            pin,
            allowed,
            fee_ceiling: u128::from_be_bytes(r.array()?),
            fee_rule: r.u16()?,
            bump_delay: r.u16()?,
            grid_ratio: r.array()?,
            min_conf: r.u16()?,
        };
        let header = Self {
            version,
            suite,
            mode,
            addr_type,
            on_rotation,
            late_inputs,
            chain_id,
            board_id,
            owner_nonce,
            keylist_hash,
            builder_hash,
            public_key,
            ephemeral,
            address,
            epoch,
            not_before,
            expires,
            n,
            threshold,
            f,
            variants,
            inputs,
            generations,
            trigger_id,
            trigger_params,
            intent,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn check_address(&self) -> Result<()> {
        let expected = address_for(self.addr_type, self.public_key)?;
        if self.address != expected {
            return Err(Error::Context);
        }
        Ok(())
    }

    pub(crate) fn check_address_wire(&self, key: &[u8]) -> Result<()> {
        let expected = match self.addr_type {
            1 | 3 => ripemd::Ripemd160::digest(Sha256::digest(key)).to_vec(),
            4 => {
                if key[0] != 2 {
                    return Err(Error::Point);
                }
                key[1..].to_vec()
            }
            // These address formats require the uncompressed key, which is
            // derived from the decoded point rather than sent on this wire.
            2 | 5 => address_for(self.addr_type, self.public_key)?,
            _ => return Err(Error::Parameters),
        };
        if self.address != expected {
            return Err(Error::Context);
        }
        Ok(())
    }
}

pub fn address_for(addr_type: u8, key: ProjectivePoint) -> Result<Vec<u8>> {
    encode_point(key)?;
    match addr_type {
        1..=3 => {
            let bytes = key.to_affine().to_encoded_point(addr_type != 2);
            Ok(ripemd::Ripemd160::digest(Sha256::digest(bytes.as_bytes())).to_vec())
        }
        4 => {
            if is_odd(key)? {
                return Err(Error::Point);
            }
            Ok(x_bytes(key)?.to_vec())
        }
        5 => {
            let bytes = key.to_affine().to_encoded_point(false);
            Ok(sha3::Keccak256::digest(&bytes.as_bytes()[1..])[12..].to_vec())
        }
        _ => Err(Error::Parameters),
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Encoding)?;
        let value = self.bytes.get(self.pos..end).ok_or(Error::Encoding)?;
        self.pos = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn point(&mut self) -> Result<ProjectivePoint> {
        decode_point(self.take(33)?)
    }
    pub fn scalar(&mut self) -> Result<k256::Scalar> {
        decode_scalar(&self.array()?)
    }
    pub fn padded(&mut self) -> Result<Vec<u8>> {
        let len = self.byte()? as usize;
        let value = self.take(35)?;
        if len > 35 || value[len..].iter().any(|b| *b != 0) {
            return Err(Error::Encoding);
        }
        Ok(value[..len].to_vec())
    }
}
