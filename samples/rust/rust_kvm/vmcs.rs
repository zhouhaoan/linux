// SPDX-License-Identifier: GPL-2.0
//! Virtual-machine control structure fields.
//!
//! See Intel SDM, Volume 3D, Appendix B.
use kernel::bindings;
use kernel::prelude::*;
//use kernel::sync::{Ref, UniqueRef};

/// VM-execution, VM-exit, and VM-entry control fields

/// Pin-based VM-execution controls.
///
/// A set of bitmask flags useful when setting up [`PINBASED_EXEC_CONTROLS`] VMCS field.
///
/// See Intel SDM, Volume 3C, Section 24.6.1.
pub(crate) struct PinbasedControls {
    pub(crate) value: u32,
}

/// Primary processor-based VM-execution controls.
///
/// A set of bitmask flags useful when setting up [`PRIMARY_PROCBASED_EXEC_CONTROLS`] VMCS field.
///
/// See Intel SDM, Volume 3C, Section 24.6.2, Table 24-6.
pub(crate) struct PrimaryControls {
    pub(crate) value: u32,
}

impl PrimaryControls {
    pub(crate) const HLT_EXITING: u32 = 1 << 7;
    pub(crate) const MWAIT_EXITING: u32 = 1 << 10;
    pub(crate) const MONITOR_EXITING: u32 = 1 << 29;
    pub(crate) const SECONDARY_CONTROLS: u32 = 1 << 31;
}

/// Secondary processor-based VM-execution controls.
///
/// A set of bitmask flags useful when setting up [`SECONDARY_PROCBASED_EXEC_CONTROLS`] VMCS field.
///
/// See Intel SDM, Volume 3C, Section 24.6.2, Table 24-7.
pub(crate) struct SecondaryControls {
    pub(crate) value: u32,
}

impl SecondaryControls {
    pub(crate) const UNRESTRICTED_GUEST: u32 = 1 << 7;
    pub(crate) const ENABLE_EPT: u32 = 1 << 1;
}

/// VM-entry controls.
///
/// A set of bitmask flags useful when setting up [`VMENTRY_CONTROLS`] VMCS field.
///
/// See Intel SDM, Volume 3C, Section 24.8.
pub(crate) struct EntryControls {
    pub(crate) value: u32,
}

impl EntryControls {
    pub(crate) const LOAD_DEBUG_CONTROLS: u32 = 1 << 2;
}

/// VM-exit controls.
///
/// A set of bitmask flags useful when setting up [`VMEXIT_CONTROLS`] VMCS field.
///
/// See Intel SDM, Volume 3C, Section 24.7.
pub(crate) struct ExitControls {
    pub(crate) value: u32,
}

impl ExitControls {
    pub(crate) const SAVE_DEBUG_CONTROLS: u32 = 1 << 2;
    pub(crate) const HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
    pub(crate) const ACK_INTERRUPT_ON_EXIT: u32 = 1 << 15;
}

#[derive(Copy, Clone)]
pub(crate) struct VmcsConfig {
    pub(crate) size: u32,
    pub(crate) basic_cap: u32,
    pub(crate) revision_id: u32,
    pub(crate) pin_based_exec_ctrl: u32,
    pub(crate) cpu_based_exec_ctrl: u32,
    pub(crate) cpu_based_2nd_exec_ctrl: u32,
    pub(crate) vmexit_ctrl: u32,
    pub(crate) vmentry_ctrl: u32,
}

impl VmcsConfig {
    pub(crate) fn new() -> Result<Self> {
        let config = Self {
            size: 32,
            basic_cap: 0,
            revision_id: 0,
            pin_based_exec_ctrl: 0,
            cpu_based_exec_ctrl: 0,
            cpu_based_2nd_exec_ctrl: 0,
            vmexit_ctrl: 0,
            vmentry_ctrl: 0,
        };
        Ok(config)
    }

    pub(crate) fn setup_config(&mut self) -> u32 {
        let mut v: u64 = 0;
        let mut _pin_based_exec_control: u32 = 0;
        let mut _cpu_based_exec_control: u32 = 0;
        let mut _cpu_based_2nd_exec_control: u32 = 0;
        let mut _vmexit_control: u32 = 0;
        let mut _vmentry_control: u32 = 0;

        _cpu_based_exec_control = PrimaryControls::HLT_EXITING
            | PrimaryControls::MWAIT_EXITING
            | PrimaryControls::MONITOR_EXITING
            | PrimaryControls::SECONDARY_CONTROLS;
        _cpu_based_2nd_exec_control =
            SecondaryControls::UNRESTRICTED_GUEST | SecondaryControls::ENABLE_EPT;
        _vmexit_control = ExitControls::ACK_INTERRUPT_ON_EXIT
            | ExitControls::HOST_ADDRESS_SPACE_SIZE
            | ExitControls::SAVE_DEBUG_CONTROLS;
        _vmentry_control = EntryControls::LOAD_DEBUG_CONTROLS;

        unsafe {
            v = bindings::rkvm_read_msr(bindings::MSR_IA32_VMX_BASIC);
        }
        let low: u32 = v as u32;
        let high: u32 = (v >> 32) as u32;
        self.size = high & 0x1fff;
        self.basic_cap = high & !0x1fff;
        self.revision_id = low;

        self.pin_based_exec_ctrl = _pin_based_exec_control;
        self.cpu_based_exec_ctrl = _cpu_based_exec_control;
        self.cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
        self.vmexit_ctrl = _vmexit_control;
        self.vmentry_ctrl = _vmentry_control;

        return 0;
    }
} //impl
