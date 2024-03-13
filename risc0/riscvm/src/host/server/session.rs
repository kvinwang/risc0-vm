// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module defines [Session] and [Segment] which provides a way to share
//! execution traces between the execution phase and the proving phase.

use std::collections::BTreeSet;

use anyhow::{ensure, Context, Result};
use risc0_binfmt::{MemoryImage, SystemState};
use risc0_zkvm_platform::WORD_SIZE;
use serde::{Deserialize, Serialize};

use crate::{
    host::server::exec::executor::SyscallRecord,
    receipt_claim::{Journal, Output},
    sha::Digest,
    ExitCode, ReceiptClaim,
};

#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct PageFaults {
    pub(crate) reads: BTreeSet<u32>,
    pub(crate) writes: BTreeSet<u32>,
}

/// The execution trace of a program.
///
/// The record of memory transactions of an execution that starts from an
/// initial memory image (which includes the starting PC) and proceeds until
/// either a sys_halt or a sys_pause syscall is encountered. This record is
/// stored as a vector of [Segment]s.
pub struct Session {
    /// The data publicly committed by the guest program.
    pub journal: Option<Journal>,

    /// The [ExitCode] of the session.
    pub exit_code: ExitCode,

    /// The final [MemoryImage] at the end of execution.
    pub post_image: MemoryImage,

    /// The hooks to be called during the proving phase.
    pub hooks: Vec<Box<dyn SessionEvents>>,

    /// The system state of the initial [MemoryImage].
    pub pre_state: SystemState,

    /// The system state of the final [MemoryImage] at the end of execution.
    pub post_state: SystemState,
}

/// A reference to a [Segment].
///
/// This allows implementors to determine the best way to represent this in an
/// pluggable manner. See the [SimpleSegmentRef] for a very basic
/// implmentation.
pub trait SegmentRef: Send {
    /// Resolve this reference into an actual [Segment].
    fn resolve(&self) -> Result<Segment>;
}

/// The execution trace of a portion of a program.
///
/// The record of memory transactions of an execution that starts from an
/// initial memory image, and proceeds until terminated by the system or user.
/// This represents a chunk of execution work that will be proven in a single
/// call to the ZKP system. It does not necessarily represent an entire program;
/// see [Session] for tracking memory transactions until a user-requested
/// termination.
#[derive(Clone, Serialize, Deserialize)]
pub struct Segment {
    pub(crate) pre_image: Box<MemoryImage>,
    // NOTE: segment.post_state is NOT EQUAL to segment.get_claim()?.post. This is because the
    // post SystemState on the ReceiptClaim struct has a PC that is shifted forward by 4.
    pub(crate) post_state: SystemState,
    pub(crate) output: Option<Output>,
    pub(crate) faults: PageFaults,
    pub(crate) syscalls: Vec<SyscallRecord>,
    pub(crate) split_insn: Option<u32>,
    pub(crate) exit_code: ExitCode,

    /// The number of cycles in powers of 2.
    pub po2: u32,

    /// The index of this [Segment] within the [Session]
    pub index: u32,

    /// The number of user cycles without any overhead for continuations or po2
    /// padding.
    pub cycles: u32,
}

/// The Events of [Session]
pub trait SessionEvents {
    /// Fired before the proving of a segment starts.
    #[allow(unused)]
    fn on_pre_prove_segment(&self, segment: &Segment) {}

    /// Fired after the proving of a segment ends.
    #[allow(unused)]
    fn on_post_prove_segment(&self, segment: &Segment) {}
}

impl Session {
    /// Construct a new [Session] from its constituent components.
    pub fn new(
        journal: Option<Vec<u8>>,
        exit_code: ExitCode,
        post_image: MemoryImage,
        pre_state: SystemState,
        post_state: SystemState,
    ) -> Self {
        Self {
            journal: journal.map(|x| Journal::new(x)),
            exit_code,
            post_image,
            hooks: Vec::new(),
            pre_state,
            post_state,
        }
    }

    /// Add a hook to be called during the proving phase.
    pub fn add_hook<E: SessionEvents + 'static>(&mut self, hook: E) {
        self.hooks.push(Box::new(hook));
    }

    /// Calculate for the [ReceiptClaim] associated with this [Session]. The
    /// [ReceiptClaim] is the claim that will be proven if this [Session]
    /// is passed to the [crate::Prover].
    pub fn get_claim(&self) -> Result<ReceiptClaim> {
        // Construct the Output struct for the session, checking internal consistency.
        // NOTE: The Session output if distinct from the final Segment output because in the
        // Session output any proven assumptions are not included.
        let output = if self.exit_code.expects_output() {
            self.journal
                .as_ref()
                .map(|journal| -> Result<_> {
                    Ok(Output {
                        journal: journal.bytes.clone().into(),
                    })
                })
                .transpose()?
        } else {
            ensure!(
                self.journal.is_none(),
                "Session with exit code {:?} has a journal",
                self.exit_code
            );
            None
        };

        Ok(ReceiptClaim {
            pre: self.pre_state.clone().into(),
            post: self.post_state.clone().into(),
            exit_code: self.exit_code,
            input: Digest::ZERO,
            output: output.into(),
        })
    }

    /// Log cycle information for this [Session].
    ///
    /// This logs the total and user cycles for this [Session] at the INFO level.
    pub fn log(&self) {}
}

impl Segment {
    /// Calculate for the [ReceiptClaim] associated with this [Segment]. The
    /// [ReceiptClaim] is the claim that will be proven if this [Segment]
    /// is passed to the [crate::Prover].
    pub fn get_claim(&self) -> Result<ReceiptClaim> {
        // NOTE: When a segment ends in a Halted(_) state, it may not update the post state
        // digest. As a result, it will be the same as the pre_image. All other exit codes require
        // the post state digest to reflect the final memory state.
        // NOTE: The PC on the the post state is stored "+ 4". See ReceiptClaim for more detail.
        let post_state = SystemState {
            pc: self
                .post_state
                .pc
                .checked_add(WORD_SIZE as u32)
                .context("invalid pc in segment post state")?,
            merkle_root: match self.exit_code {
                ExitCode::Halted(_) => self.pre_image.compute_root_hash()?,
                _ => self.post_state.merkle_root.clone(),
            },
        };

        Ok(ReceiptClaim {
            pre: self.pre_image.get_system_state()?.into(),
            post: post_state.into(),
            exit_code: self.exit_code,
            input: Digest::ZERO,
            output: self.output.clone().into(),
        })
    }
}

/// Implementation of a [SegmentRef] that does not save the segment.
///
/// This is useful for DevMode where the segments aren't needed.
#[derive(Serialize, Deserialize)]
pub struct NullSegmentRef {}

impl SegmentRef for NullSegmentRef {
    fn resolve(&self) -> anyhow::Result<Segment> {
        unimplemented!()
    }
}
