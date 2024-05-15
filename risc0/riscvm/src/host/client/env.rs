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

//! This module defines the [ExecutorEnv] and [ExecutorEnvBuilder].

use std::{
    cell::RefCell,
    collections::HashMap,
    io::{BufRead, BufReader, Cursor, Read, Write},
    mem,
    rc::Rc,
};

use anyhow::Result;
use bytemuck::Pod;
use bytes::Bytes;
use risc0_zkvm_platform::{self, fileno};

use crate::host::client::{
    exec::TraceEvent,
    posix_io::PosixIo,
    slice_io::{slice_io_from_fn, SliceIo, SliceIoTable},
};

/// A builder pattern used to construct an [ExecutorEnv].
#[derive(Default)]
pub struct ExecutorEnvBuilder<'a> {
    inner: ExecutorEnv<'a>,
}

/// A callback used to collect [TraceEvent]s.
pub trait TraceCallback {
    fn trace_callback(&mut self, event: TraceEvent) -> Result<()>;
}

impl<F> TraceCallback for F
where
    F: FnMut(TraceEvent) -> Result<()>,
{
    fn trace_callback(&mut self, event: TraceEvent) -> Result<()> {
        self(event)
    }
}

/// The [crate::Executor] is configured from this object.
///
/// The executor environment holds configuration details that inform how the
/// guest environment is set up prior to guest program execution.
#[derive(Default)]
pub struct ExecutorEnv<'a> {
    pub(crate) env_vars: HashMap<String, String>,
    pub(crate) args: Vec<String>,
    pub(crate) session_limit: Option<u64>,
    pub(crate) posix_io: Rc<RefCell<PosixIo<'a>>>,
    pub(crate) slice_io: Rc<RefCell<SliceIoTable<'a>>>,
    pub(crate) input: Vec<u8>,
    pub(crate) trace: Vec<Rc<RefCell<dyn TraceCallback + 'a>>>,
}

impl<'a> ExecutorEnv<'a> {
    /// Construct a [ExecutorEnvBuilder].
    ///
    /// # Example
    ///
    /// ```
    /// use risc0_zkvm::ExecutorEnv;
    ///
    /// let env = ExecutorEnv::builder().build();
    /// ```
    pub fn builder() -> ExecutorEnvBuilder<'a> {
        ExecutorEnvBuilder::default()
    }
}

impl<'a> ExecutorEnvBuilder<'a> {
    /// Finalize this builder to construct an [ExecutorEnv].
    ///
    /// # Example
    ///
    /// ```
    /// use risc0_zkvm::ExecutorEnv;
    ///
    /// let env = ExecutorEnv::builder().build().unwrap();
    /// ```
    ///
    /// After calling `build`, the [ExecutorEnvBuilder] will be reset to
    /// default.
    pub fn build(&mut self) -> Result<ExecutorEnv<'a>> {
        let inner = mem::take(&mut self.inner);

        if !inner.input.is_empty() {
            let reader = Cursor::new(inner.input.clone());
            inner
                .posix_io
                .borrow_mut()
                .with_read_fd(fileno::STDIN, reader);
        }

        Ok(inner)
    }

    /// Set a session limit, specified in number of cycles.
    ///
    /// # Example
    ///
    /// ```
    /// use risc0_zkvm::ExecutorEnv;
    ///
    /// let env = ExecutorEnv::builder()
    ///     .session_limit(Some(32 * 1024 * 1024)) // 32M cycles
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn session_limit(&mut self, limit: Option<u64>) -> &mut Self {
        self.inner.session_limit = limit;
        self
    }

    /// Add environment variables to the guest environment.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use risc0_zkvm::ExecutorEnv;
    ///
    /// let mut vars = HashMap::new();
    /// vars.insert("VAR1".to_string(), "SOME_VALUE".to_string());
    /// vars.insert("VAR2".to_string(), "SOME_VALUE".to_string());
    ///
    /// let env = ExecutorEnv::builder()
    ///     .env_vars(vars)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn env_vars(&mut self, vars: HashMap<String, String>) -> &mut Self {
        self.inner.env_vars = vars;
        self
    }

    /// Add an argument array to the guest environment.
    ///
    /// # Example
    /// ```
    /// # use risc0_zkvm::ExecutorEnv;
    ///
    /// let env = ExecutorEnv::builder()
    ///     .args(&["grep".to_string(), "-c".to_string(), "foo".to_string(), "-".to_string()])
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn args(&mut self, args: &[String]) -> &mut Self {
        self.inner.args.extend_from_slice(args);
        self
    }

    /// Add an environment variable to the guest environment.
    ///
    /// # Example
    ///
    /// ```
    /// use risc0_zkvm::ExecutorEnv;
    ///
    /// let env = ExecutorEnv::builder()
    ///     .env_var("VAR1", "SOME_VALUE")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn env_var(&mut self, name: &str, val: &str) -> &mut Self {
        self.inner
            .env_vars
            .insert(name.to_string(), val.to_string());
        self
    }

    /// Write input data to the zkVM guest stdin.
    ///
    /// This function writes a slice directly to the underlying buffer. A
    /// corresponding `env::read_slice` can be used within the guest to read the
    /// data.
    ///
    /// # Example
    ///
    /// ```
    /// use risc0_zkvm::ExecutorEnv;
    ///
    /// let slice1 = [0, 1, 2, 3];
    /// let slice2 = [3, 2, 1, 0];
    /// let env = ExecutorEnv::builder()
    ///     .write_slice(&slice1)
    ///     .write_slice(&slice2)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn write_slice<T: Pod>(&mut self, slice: &[T]) -> &mut Self {
        self.inner
            .input
            .extend_from_slice(bytemuck::cast_slice(slice));
        self
    }

    /// Add a posix-style standard input.
    pub fn stdin(&mut self, reader: impl Read + 'a) -> &mut Self {
        self.read_fd(fileno::STDIN, BufReader::new(reader))
    }

    /// Add a posix-style standard output.
    pub fn stdout(&mut self, writer: impl Write + 'a) -> &mut Self {
        self.write_fd(fileno::STDOUT, writer)
    }

    /// Add a posix-style standard error.
    pub fn stderr(&mut self, writer: impl Write + 'a) -> &mut Self {
        self.write_fd(fileno::STDERR, writer)
    }

    /// Add a posix-style file descriptor for reading.
    pub fn read_fd(&mut self, fd: u32, reader: impl BufRead + 'a) -> &mut Self {
        self.inner.posix_io.borrow_mut().with_read_fd(fd, reader);
        self
    }

    /// Add a posix-style file descriptor for writing.
    pub fn write_fd(&mut self, fd: u32, writer: impl Write + 'a) -> &mut Self {
        self.inner.posix_io.borrow_mut().with_write_fd(fd, writer);
        self
    }

    /// Add a handler for simple I/O handling.
    pub fn slice_io(&mut self, channel: &str, handler: impl SliceIo + 'a) -> &mut Self {
        self.inner
            .slice_io
            .borrow_mut()
            .with_handler(channel, handler);
        self
    }

    /// Add a handler for simple I/O handling.
    pub fn io_callback<C: AsRef<str>>(
        &mut self,
        channel: C,
        callback: impl Fn(Bytes) -> Result<Bytes> + 'a,
    ) -> &mut Self {
        self.inner
            .slice_io
            .borrow_mut()
            .with_handler(channel.as_ref(), slice_io_from_fn(callback));
        self
    }

    /// Add a callback handler for raw trace messages.
    pub fn trace_callback(&mut self, callback: impl TraceCallback + 'a) -> &mut Self {
        self.inner.trace.push(Rc::new(RefCell::new(callback)));
        self
    }
}
