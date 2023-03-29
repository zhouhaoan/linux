// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;

#[repr(u32)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub(crate) enum LapicReg {
  LAPIC_REG_ID = 0x020,
  LAPIC_REG_VERSION = 0x030,
  LAPIC_REG_TASK_PRIORITY = 0x080,
  LAPIC_REG_PROCESSOR_PRIORITY = 0x0A0,
  LAPIC_REG_EOI = 0x0B0,
  LAPIC_REG_LOGICAL_DST = 0x0D0,
  LAPIC_REG_SPURIOUS_IRQ = 0x0F0,
  LAPIC_REG_ERROR_STATUS = 0x280,
  LAPIC_REG_LVT_CMCI = 0x2F0,
  LAPIC_REG_IRQ_CMD_LOW = 0x300,
  LAPIC_REG_IRQ_CMD_HIGH = 0x310,
  LAPIC_REG_LVT_TIMER = 0x320,
  LAPIC_REG_LVT_THERMAL = 0x330,
  LAPIC_REG_LVT_PERF = 0x340,
  LAPIC_REG_LVT_LINT0  = 0x350,
  LAPIC_REG_LVT_LINT1 = 0x360,
  LAPIC_REG_LVT_ERROR = 0x370,
  LAPIC_REG_INIT_COUNT = 0x380,
  LAPIC_REG_CURRENT_COUNT = 0x390,
  LAPIC_REG_DIVIDE_CONF = 0x3E0,
  // X2APIC
  LAPIC_X2APIC_MSR_BASE = 0x800,
  LAPIC_X2APIC_MSR_ICR = 0x830,
  LAPIC_X2APIC_MSR_SELF_IPI = 0x83f,

  SVR_APIC_ENABLE = 1 << 8,

  // Interrupt Command bitmasks
  ICR_DELIVERY_PENDING = 1 << 12,
  ICR_LEVEL_ASSERT = 1 << 14,
}

macro_rules! ICR_DST {
  ($x:expr) => {
     ($x as u32) << 24
  };
}

macro_rules! ICR_DELIVERY_MODE {
  ($x:expr) => {
     ($x as u32) << 8
  };
}

macro_rules! ICR_DST_SHORTHAND {
  ($x:expr) => {
     ($x as u32) << 18
  };
}


// ICR_DST_BROADCAST ICR_DST(0xff)
// ICR_DST_SELF ICR_DST_SHORTHAND(1)
// ICR_DST_ALL ICR_DST_SHORTHAND(2)
// ICR_DST_ALL_MINUS_SELF ICR_DST_SHORTHAND(3)

macro_rules! LAPIC_REG_IN_SERVICE {
  ($x:expr) => {
     0x100 as u32 + ($x as u32) << 4
  };
}

macro_rules! LAPIC_REG_TRIGGER_MODE {
  ($x:expr) => {
     0x180 as u32 + ($x as u32) << 4
  };
}

macro_rules! LAPIC_REG_IRQ_REQUEST {
  ($x:expr) => {
     0x200 as u32 + ($x as u32) << 4
  };
}

pub(crate) struct LapicReg {}

pub(crate) struct IntrTracker {

}


pub(crate) struct RkvmLapicState {
    pub(crate) base_address: u64,
    pub(crate) lapic_timer: RkvmTimer,
    pub(crate) timer_dconfig: u32,
    pub(crate) timer_init: u32,
    pub(crate) interrupt_bitmap: IntrTracker,
    /// The highest vector set in ISR; if -1 - invalid, must scan ISR.
    pub(crate) highest_isr_cache: u32,
    /// APIC register page.  The layout matches the register layout seen by
    /// the guest 1:1, because it is accessed by the vmx microcode.
    /// Note: Only one register, the TPR, is used by the microcode.
    regs: LapicReg,
    pub(crate) vapic_addr: u64,
}


