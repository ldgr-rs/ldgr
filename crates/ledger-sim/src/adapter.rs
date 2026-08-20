//! Instruction-program adapter driving the deterministic async executor.
//!
//! The executor polls real futures; the reference workloads are instruction
//! programs. This adapter turns one `Vec<Instruction>` into a future that, on
//! each poll, executes EXACTLY ONE instruction and yields to the scheduler,
//! reproducing the instruction VM's one-scheduling-decision-per-instruction
//! discipline so journals stay byte-identical (see the executor parity test).
//!
//! Blocking instructions park the future: a `Sleep` registers a timer and
//! suspends until it fires; a `Receive` with no deliverable message re-queues
//! itself and suspends until the executor wakes the task. Resuming after a
//! park resumes at the next instruction (or re-runs the parked `Receive`),
//! never re-executing the instruction that parked.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::effects::Effects;
use crate::executor::Boundary;
use crate::runtime::Instruction;

/// One outcome of executing a single instruction.
enum Step {
    /// The instruction completed and the task is still runnable.
    Continue,
    /// The instruction parked the task (blocked on a timer or a message).
    Parked,
    /// The instruction finished the task.
    Finished,
}

/// A future executing one instruction program cooperatively.
pub(crate) struct ProgramFuture {
    boundary: Boundary,
    program: VecDeque<Instruction>,
}

impl ProgramFuture {
    pub(crate) fn new(boundary: Boundary, program: Vec<Instruction>) -> Self {
        Self {
            boundary,
            program: program.into(),
        }
    }

    /// Execute the next instruction, returning the step outcome.
    fn execute_one(&mut self) -> Result<Step, ledger_journal::JournalError> {
        let Some(instruction) = self.program.pop_front() else {
            return Ok(Step::Finished);
        };
        let step = match instruction {
            Instruction::Yield => {
                self.boundary.yield_block()?;
                Step::Continue
            }
            Instruction::Sleep(ticks) => {
                self.boundary.park_sleep(ticks)?;
                Step::Parked
            }
            Instruction::Send { to, payload } => {
                // Send returns bool; a failed append is already recorded
                // inside Boundary::send, so nothing is lost here.
                let _ = self.boundary.send(to, payload);
                Step::Continue
            }
            Instruction::SendTimed { to, payload, delay } => {
                // Same contract as Send: journal failures are recorded inside
                // Boundary::send_timed.
                let _ = self.boundary.send_timed(to, payload, delay);
                Step::Continue
            }
            Instruction::Receive => {
                if let Some(value) = self.boundary.recv_now() {
                    self.boundary.set_register(value);
                    Step::Continue
                } else {
                    self.program.push_front(Instruction::Receive);
                    self.boundary.park_message()?;
                    Step::Parked
                }
            }
            Instruction::Set(value) => {
                self.boundary.input_step(0, 0, value)?;
                self.boundary.set_register(value);
                Step::Continue
            }
            Instruction::Input {
                generator,
                replay,
                value,
            } => {
                self.boundary.input_step(generator, replay, value)?;
                self.boundary.set_register(value);
                Step::Continue
            }
            Instruction::ReadClock => {
                let now = self.boundary.read_clock()?;
                self.boundary.set_register(now);
                Step::Continue
            }
            Instruction::FsWrite { path, value } => {
                if let Err(error) = self.boundary.fs().write(&path, value) {
                    self.boundary.record_journal_error(error);
                }
                Step::Continue
            }
            Instruction::FsFsync => {
                if let Err(error) = self.boundary.fs().fsync() {
                    self.boundary.record_journal_error(error);
                }
                Step::Continue
            }
            Instruction::FsRead { path } => {
                match self.boundary.fs().read(&path) {
                    Ok(Some(value)) => self.boundary.set_register(value),
                    Ok(None) => {}
                    Err(error) => self.boundary.record_journal_error(error),
                }
                Step::Continue
            }
            Instruction::FsCrash => {
                self.boundary.fs().crash();
                Step::Continue
            }
            Instruction::Assert(passed) => {
                self.boundary.assert_entry(passed)?;
                Step::Continue
            }
            Instruction::Outcome => {
                let value = self.boundary.register();
                if let Err(error) = self.boundary.outcome(value) {
                    self.boundary.record_journal_error(error);
                }
                Step::Continue
            }
            Instruction::Done => {
                self.boundary.outcome_done()?;
                Step::Finished
            }
        };
        Ok(step)
    }
}

impl Future for ProgramFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        match this.execute_one() {
            Ok(Step::Continue) | Ok(Step::Parked) => Poll::Pending,
            Ok(Step::Finished) => Poll::Ready(()),
            // A journal append failure aborts the program future; record it
            // on the boundary so the run's journal_error slot surfaces it
            // instead of dropping it silently.
            Err(error) => {
                this.boundary.record_journal_error(error);
                Poll::Ready(())
            }
        }
    }
}

pub(crate) fn program_future(
    boundary: Boundary,
    program: Vec<Instruction>,
) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
    Box::pin(ProgramFuture::new(boundary, program))
}
