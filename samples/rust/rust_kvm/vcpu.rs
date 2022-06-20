// SPDX-License-Identifier: GPL-2.0
use kernel::bindings;
use kernel::pages::Pages;
use kernel::prelude::*;
use kernel::sync::{Mutex, Ref, UniqueRef};
use kernel::Result;
use core::arch::global_asm;
//use alloc::alloc::{AllocError};
use super::Guest;
use crate::exit::*;
use crate::mmu::*;
use crate::vmcs::*;
use crate::vmstat::*;
use core::ptr::NonNull;

#[repr(C)]
#[allow(dead_code)]
pub(crate) struct RkvmRun {
    /* in */
    pub(crate) request_interrupt_window: u8,
    pub(crate) immediate_exit: u8,
    pub(crate) padding1: u32,
    pub(crate) padding2: u16,
    /* out */
    pub(crate) exit_reason: u32,
    pub(crate) ready_for_interrupt_injection: u8,
    pub(crate) if_flag: u8,
    pub(crate) flags: u16,
}

#[allow(dead_code)]
pub(crate) struct Vcpu {
    pub(crate) guest: Ref<Mutex<Guest>>,
    pub(crate) vmx_state: Box<VmxState>,
    // DefMut trait for UniqueRef, List use it
    pub(crate) mmu: UniqueRef<RkvmMmu>,
    pub(crate) va_run: u64,
    pub(crate) run: *mut RkvmRun,
    pub(crate) vcpu_id: u32,
    pub(crate) launched: bool,
}

impl Vcpu {
    pub(crate) fn new(guest: Ref<Mutex<Guest>>) -> Result<Ref<Mutex<Self>>> {
        let state = Box::try_new(VmxState::new()?);
        let state = match state {
            Ok(state) => state,
            Err(_) => return Err(Error::ENOMEM),
        };
        let page = Pages::<0>::new();
        let run = match page {
            Ok(page) => page,
            Err(err) => return Err(err),
        };
        let mut va = unsafe { bindings::rkvm_page_address(run.pages) };
        let mut mmu = RkvmMmu::new()?;
        let ptr =  NonNull::new(va as *mut RkvmRun).unwrap().as_ptr();
        mmu.init_mmu_root();
        let vcpu = unsafe {
            Ref::try_new(Mutex::new(Self {
                guest: guest,
                vmx_state: state,
                mmu: mmu,
                va_run: va,
                run: ptr,
                vcpu_id: 0,
                launched: false,
            }))?
        };
        Ok(vcpu)
    }

    pub(crate) fn init(&self, vmcsconf: &VmcsConfig) {
        vmcsconf.vcpu_vmcs_init();
    }

    pub(crate) fn get_run(&self) -> u64 {
        self.va_run
    }

    pub(crate) fn vcpu_exit_handler(&mut self) -> Result {
        let exit_info = ExitInfo::from_vmcs();
        unsafe { (*self.run).exit_reason = exit_info.exit_reason as u32;}
        match exit_info.exit_reason {
            ExitReason::HLT => handle_hlt(&exit_info, self),
            //ExitReason::IO_INSTRUCTION => handle_io_instruction(&exit_info),
            ExitReason::EPT_VIOLATION => handle_ept_violation(&exit_info, self),
            _ => Err(Error::ENOSPC),
        };
        Ok(())
    }

    pub(crate) fn vcpu_run(&mut self) -> i64 {
        loop {
            unsafe {
                bindings::rkvm_irq_disable();
            }
            let has_err_ = unsafe { _vmx_vcpu_run(&mut self.vmx_state, self.launched) };

            if has_err_ == 1 {
                unsafe {
                    bindings::rkvm_irq_enable();
                }
                return -1;
            }
            unsafe {
                bindings::rkvm_irq_enable();
            }

            //match vmexit_handler
            let ret = self.vcpu_exit_handler();
            //according to ret, update run
        } // loop
    }
}

extern "C" {
    fn _vmx_vcpu_run(guest_state: &GuestState) -> u32;
}

global_asm!(
    "
.global _vmx_vcpu_run
_vmx_vcpu_run:
    push   rbp
    mov    rbp,rsp
    push   r15
    push   r14
    push   r13
    push   r12
    push   rbx

    mov     [rdi], rsp
    mov     rsp, rdi

    add     rsp, 8
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    add     rsp, 8 // skip rsp
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    cmp     byte ptr [rsp], 0
    je 3f
    vmresume
    jmp 4f
3:  vmlaunch

4:
    // We will only be here if vmlaunch or vmresume failed.
    // Restore host callee, RSP and return address.
    mov     rsp, [rsp - 17*8]
    pop     rbx
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    pop     rbp

    // return true
    mov     eax, 1
    ret
"
);

