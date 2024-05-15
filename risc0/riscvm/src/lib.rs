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

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

//! The RISC Zero zkVM is a RISC-V virtual machine that produces [zero-knowledge
//! proofs] of code it executes. By using the zkVM, a cryptographic [receipt] is
//! produced which anyone can [verify][receipt-verify] was produced by the
//! zkVM's guest code. No additional information about the code execution (such
//! as, for example, the inputs provided) is revealed by publishing the
//! [receipt].
//!
//! Additional (non-reference) resources for using our zkVM that you may also
//! find helpful, especially if you're new to the RISC Zero zkVM. These include:
//!
//! * Our [zkVM Tutorial], which walks you through writing your first zkVM
//!   project.
//! * The [`cargo risczero` tool]. It includes a `new` command which generates
//!   code for building and launching a zkVM guest and guidance on where
//!   projects most commonly modify host and guest code.
//! * The [examples], which contains various examples using our zkVM.
//! * [This clip][zkHack] from our presentation at ZK Hack III gives an overview
//!   of the RISC Zero zkVM. [Our YouTube channel][YouTube] has many more videos
//!   as well.
//! * We track zkVM issues with known workarounds using the [rust guest
//!   workarounds] GitHub tag. If you're having problems running your code in
//!   the zkVM, you can see if there's a workaround, and if you're using a
//!   workaround, you can track when it gets resolved to a permanent solution.
//! * And more on [the RISC Zero developer website][dev-docs]!
//!
//! # Crate Feature Flags
//!
//! The following feature flags are supported.
//!
//! Note that in order to use `risc0-zkvm` in the guest, you must disable the
//! "prove" feature by setting `default-features = false`.
//!
//! | Feature          | Target(s)         | Implies    | Description                                                                                                                                                  |
//! | ---------------- | ----------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
//! | client           | all except rv32im | std        | Enables the client API.                                                                                                                                      |
//! | cuda             |                   | prove, std | Enables CUDA GPU acceleration for the prover. Requires CUDA toolkit to be installed.                                                                         |
//! | disable-dev-mode | all except rv32im |            | Disables dev mode so that proving and verifying may not be faked. Used to prevent a misplaced `RISC0_DEV_MODE` from breaking security in production systems. |
//! | metal            | macos             | prove, std | Enables Metal GPU acceleration for the prover.                                                                                                               |
//! | prove            | all except rv32im | std        | Enables the prover, incompatible within the zkvm guest.                                                                                                      |
//! | std              | all               |            | Support for the Rust stdlib.                                                                                                                                 |
//!
//! [`cargo risczero` tool]: https://crates.io/crates/cargo-risczero
//! [dev-docs]: https://dev.risczero.com
//! [examples]: https://dev.risczero.com/api/zkvm/examples
//! [receipt]: crate::host::receipt::Receipt
//! [receipt-verify]: crate::host::receipt::Receipt::verify
//! [rust guest workarounds]:
//!     https://github.com/risc0/risc0/issues?q=is%3Aissue+is%3Aopen+label%3A%22rust+guest+workarounds%22
//! [YouTube]: https://www.youtube.com/@risczero
//! [zero-knowledge proofs]: https://en.wikipedia.org/wiki/Zero-knowledge_proof
//! [zkHack]: https://youtu.be/cLqFvhmXiD0
//! [zkVM Tutorial]: https://dev.risczero.com/api/zkvm/tutorials/hello-world

extern crate alloc;

mod host;
mod receipt_claim;

mod sha;

use risc0_binfmt::SystemState;

use self::host::server::session::Session;

use receipt_claim::ReceiptClaim;

pub use host::client::env::{ExecutorEnv, ExecutorEnvBuilder};
pub use host::server::exec::executor::ExecutorImpl;
pub use receipt_claim::ExitCode;

/// Align the given address `addr` upwards to alignment `align`.
///
/// Requires that `align` is a power of two.
const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
