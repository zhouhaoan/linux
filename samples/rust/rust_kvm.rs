// SPDX-License-Identifier: GPL-2.0

//! Rust KVM for VMX
//#![feature(asm)]
#[allow(dead_code)]

use kernel::prelude::*;
use kernel::{
    file::File,
    file_operations::{FileOperations, IoctlCommand, IoctlHandler}, 
    miscdev,
    sync::{CondVar, Mutex, Ref, RefBorrow, UniqueRef},
};

module! {
    type: RustMiscdev,
    name: b"rust_kvm",
    author: b"Peng Hao",
    description: b"Rust KVM VMX",
    license: b"GPL v2",
}

struct HostState {
  // Host stack pointer.
  rsp: u64,

  // Extended control registers.
  xcr0: u64,
}

#[allow(dead_code)]
struct GuestState {
  //  RIP, RSP, and RFLAGS are automatically saved by VMX in the VMCS.
  rax: u64,
  rcx: u64,
  rdx: u64,
  rbx: u64,
  rbp: u64,
  rsi: u64,
  rdi: u64,
  r8: u64,
  r9: u64,
  r10: u64,
  r11: u64,
  r12: u64,
  r13: u64,
  r14: u64,
  r15: u64,

  // Control registers.
  cr2: u64,

  // Extended control registers.
  xcr0: u64,
}
macro_rules! ONE {
     ($x: expr) => {
        (1 + (($x) - ($x)))
     }
}
macro_rules! BITS_SHIFT {
     ($x:expr, $high:expr, $low:expr) => {
        ((($x) >> ($low)) & ((ONE!($x) << (($high) - ($low) + 1)) - 1))
     }
 }

impl GuestState {
  // Convenience getters for accessing low 32-bits of common registers.
  #[allow(dead_code)]
  fn get_eax(&self) -> u32 { return self.rax as u32; }
  fn get_ecx(&self) -> u32 { return self.rcx as u32; }
  fn get_edx(&self) -> u32 { return self.rdx as u32; }
  fn get_ebx(&self) -> u32 { return self.rbx as u32; }

  // Convenience getter/setter for fetching the 64-bit value edx:eax, used by
  // several x86_64 instructions, such as `rdmsr` and `wrmsr`.
  //
  // For reads, the top bits of rax and rdx are ignored (c.f. Volume 2C,
  // WRMSR). For writes, the top bits of rax and rdx are set to zero, matching
  // the behaviour of x86_64 instructions such as `rdmsr` (c.f. Volume 2C,
  // RDMSR).
  #[allow(dead_code)]
  fn get_edx_eax(&self) -> u64 { return (self.get_edx() as u64) << 32 | (self.get_eax() as u64); }
  fn set_edx_eax(&mut self, value: u64) {
    self.rax = BITS_SHIFT!(value, 31, 0);
    self.rdx = BITS_SHIFT!(value, 63, 32);
  }
}

#[allow(dead_code)]
struct SharedStateInner {
    token_count: usize,
}

#[allow(dead_code)]
struct VmxState {
    host_state: HostState,
    guest_state: GuestState,
    state_changed: CondVar,
    inner: Mutex<SharedStateInner>,
}

// used for vmxon
struct VmxInfo {
  revision_id: u32,
  region_size: u16,
  write_back: bool,
  io_exit_info: bool,
  vmx_controls: bool,
}
/*
impl VmxInfo {
  fn VmxInfo();
}
*/
impl VmxState {
    fn try_new() -> Result<Ref<Self>> {
	pr_info!("VmxState try_new \n");
        let val: u64 = 0;
        let mut state = Pin::from(UniqueRef::try_new(Self {
            // SAFETY: `condvar_init!` is called below.
            host_state: HostState{rsp: 0, xcr0: 0},
            guest_state: GuestState{ rax: val, rcx: val, rdx: val, rbx: val, rbp: val, rsi: val, rdi: val, r8: val, r9: val, r10: val, r11: val, r12: val, r13: val, r14: val, r15: val, cr2: val, xcr0: val },
            state_changed: unsafe { CondVar::new() },
            // SAFETY: `mutex_init!` is called below.
            inner: unsafe { Mutex::new(SharedStateInner { token_count: 0 }) },
        })?);

        // SAFETY: `state_changed` is pinned when `state` is.
        let pinned = unsafe { state.as_mut().map_unchecked_mut(|s| &mut s.state_changed) };
        kernel::condvar_init!(pinned, "VmxState::state_changed");

        // SAFETY: `inner` is pinned when `state` is.
        let pinned = unsafe { state.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        kernel::mutex_init!(pinned, "VmxState::inner");

        Ok(state.into())
    }
}

struct KVM;
impl FileOperations for KVM {
    type Wrapper = Ref<VmxState>;
    type OpenData = Ref<VmxState>;

    kernel::declare_file_operations!(ioctl);

    fn open(shared: &Ref<VmxState>, _file: &File) -> Result<Self::Wrapper> {
        pr_info!("KVM open \n");	
        Ok(shared.clone())
    }

    fn ioctl(shared: RefBorrow<'_, VmxState>,file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        cmd.dispatch::<VmxState>(&shared, file)
    }        
}

struct RustMiscdev {
    _dev: Pin<Box<miscdev::Registration<KVM>>>,
}

impl KernelModule for RustMiscdev {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust kvm device sample (init)\n");

        let state = VmxState::try_new()?;
        /* vmxon percpu*/
        
        Ok(RustMiscdev {
            _dev: miscdev::Registration::new_pinned(name, state)?,
        })
    }
}

impl Drop for RustMiscdev {
    fn drop(&mut self) {
        pr_info!("Rust kvm device sample (exit)\n");
    }
}



const IOCTL_KVM_CREATE_VM: u32 = 0x00AE0100;
const IOCTL_KVM_CREATE_VCPU: u32 = 0x00AE4100;


impl IoctlHandler for VmxState {
    type Target<'a> = &'a VmxState;

    fn pure(_shared: &VmxState, _: &File, cmd: u32, _arg: usize) -> Result<i32> {
        match cmd {
            IOCTL_KVM_CREATE_VM => {
                pr_info!("Rust kvm: IOCTL_KVM_CREATE_VM\n");
                Ok(0)
            }
            IOCTL_KVM_CREATE_VCPU => {
		pr_info!("Rust kvm: IOCTL_KVM_CREATE_VCPU\n");
		Ok(0)
	    }
            _ => Err(Error::EINVAL),
        }
    }
}
