#![warn(unused_imports)]
// This reduced verifier port intentionally keeps upstream VM surfaces that are not all exercised
// by the current verifier-only build.
#![allow(dead_code)]

pub use zksync_types::vm::VmVersion;
pub use zksync_vm_interface as interface;

pub use crate::{
    glue::{
        history_mode::HistoryMode,
        tracers::{IntoOldVmTracer, MultiVmTracer, MultiVmTracerPointer},
    },
    versions::{vm_fast, vm_latest},
    vm_instance::{is_supported_by_fast_vm, FastVmInstance, LegacyVmInstance},
};

mod glue;
pub mod pubdata_builders;
pub mod tracers;
pub mod utils;
mod versions;
mod vm_instance;
