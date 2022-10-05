//===- ARMEliminatePrologEpilog.cpp - Binary raiser utility llvm-mctoll ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the part implementation of ARMMachineInstructionRaiser
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMMachineInstructionRaiser.h"
#include "ARMSubtarget.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

/// Return true if an operand in the instrs vector matches the passed register
/// number, otherwise false.
bool ARMMachineInstructionRaiser::checkRegister(
    unsigned Reg, std::vector<MachineInstr *> &Instrs) const {
  std::vector<MachineInstr *>::iterator Iter = Instrs.begin();
  for (; Iter < Instrs.end(); ++Iter) {
    MachineInstr *MI = *Iter;
    if (MI->mayStore()) {
      for (unsigned Idx = 0; Idx < MI->getNumOperands(); Idx++) {
        MachineOperand MO = MI->getOperand(Idx);

        // Compare the register number.
        if (MO.isReg() && MO.getReg() == Reg)
          return true;
      }
    }
  }
  return false;
}

/// Raise the function prolog.
///
/// Look for the following instructions and eliminate them:
///       str fp, [sp, #-4]!
///       add fp, sp, #0
///
///       sub sp, fp, #0
///       ldr fp, [sp], #4
/// AND
///       push {r11,lr}
///       add r11, sp, #4
///
///       sub sp, r11, #4
///       pop	{r11, pc}
/// AND
///       stmdb r13!, {r0-r3}
///       stmdb r13!, {r4-r12,r13,r14}
///
///       ldmia r13, {r4-r11, r13, r15}
/// AND
///       mov r12, r13
///       stmdb r13!, {r0-r3}
///       stmdb r13!, {r4-r12, r14}
///       sub r11, r12, #16
///
///       ldmdb r13, {r4-r11, r13, r15}
bool ARMMachineInstructionRaiser::eliminateProlog(MachineFunction &MF) const {
  std::vector<MachineInstr *> PrologInstrs;
  MachineBasicBlock &FrontMBB = MF.front();

  const ARMSubtarget &STI = MF.getSubtarget<ARMSubtarget>();
  const ARMBaseRegisterInfo *RegInfo = STI.getRegisterInfo();
  Register FramePtr = RegInfo->getFrameRegister(MF);

  for (MachineInstr &CurMachInstr : FrontMBB.instrs()) {

    // Push the MOVr instruction
    if (CurMachInstr.getOpcode() == ARM::MOVr) {
      if (CurMachInstr.getOperand(0).isReg() &&
          CurMachInstr.getOperand(0).getReg() == ARM::R11 &&
          CurMachInstr.getOperand(1).isReg() &&
          CurMachInstr.getOperand(1).getReg() == FramePtr)
        PrologInstrs.push_back(&CurMachInstr);
    }

    // Push the STORE instruction
    if (CurMachInstr.mayStore()) {
      MachineOperand StoreOperand = CurMachInstr.getOperand(0);
      if (StoreOperand.isReg() && StoreOperand.getReg() == FramePtr) {
        PrologInstrs.push_back(&CurMachInstr);
      }
    }

    // Push the ADDri instruction
    // add Rx, sp, #imm ; This kind of patten ought to be eliminated.
    if (CurMachInstr.getOpcode() == ARM::ADDri &&
        CurMachInstr.getOperand(0).getReg() == ARM::R11 &&
        CurMachInstr.getOperand(1).getReg() == FramePtr) {
      PrologInstrs.push_back(&CurMachInstr);
    }

    // Push the SUBri instruction
    if (CurMachInstr.getOpcode() == ARM::SUBri &&
        CurMachInstr.getOperand(0).getReg() == FramePtr &&
        CurMachInstr.getOperand(1).getReg() == FramePtr) {
      PrologInstrs.push_back(&CurMachInstr);
    }

    // Push sub r11, r12, #16
    if (CurMachInstr.getOpcode() == ARM::SUBri &&
        CurMachInstr.getOperand(0).getReg() == ARM::R11 &&
        CurMachInstr.getOperand(1).getReg() == ARM::R12) {
      PrologInstrs.push_back(&CurMachInstr);
    }
  }

  // Create the stack frame
  const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
  const MCPhysReg *CSRegs = TRI->getCalleeSavedRegs(&MF);

  std::vector<CalleeSavedInfo> CSI;
  for (unsigned Idx = 0; CSRegs[Idx]; ++Idx) {
    unsigned Reg = CSRegs[Idx];

    // Save register.
    if (checkRegister(Reg, PrologInstrs)) {
      CSI.push_back(CalleeSavedInfo(Reg));
    }
  }

  const TargetFrameLowering *TFI = MF.getSubtarget().getFrameLowering();
  MachineFrameInfo &MFI = MF.getFrameInfo();
  if (!TFI->assignCalleeSavedSpillSlots(MF, RegInfo, CSI)) {
    // If target doesn't implement this, use generic code.
    if (CSI.empty())
      return true; // Early exit if no callee saved registers are modified!

    unsigned NumFixedSpillSlots;
    const TargetFrameLowering::SpillSlot *FixedSpillSlots =
        TFI->getCalleeSavedSpillSlots(NumFixedSpillSlots);

    // Allocate stack slots for the registers that need to be saved and restored
    unsigned Offset = 0;
    for (auto &CS : CSI) {
      Register Reg = CS.getReg();
      const TargetRegisterClass *RC = RegInfo->getMinimalPhysRegClass(Reg);

      int FrameIdx;
      if (RegInfo->hasReservedSpillSlot(MF, Reg, FrameIdx)) {
        CS.setFrameIdx(FrameIdx);
        continue;
      }

      // Check if this physreg must be spilled to a particular stack slot for
      // this target
      const TargetFrameLowering::SpillSlot *FixedSlot = FixedSpillSlots;
      while (FixedSlot != FixedSpillSlots + NumFixedSpillSlots &&
             FixedSlot->Reg != Reg)
        ++FixedSlot;

      unsigned Size = RegInfo->getSpillSize(*RC);
      if (FixedSlot == FixedSpillSlots + NumFixedSpillSlots) {
        // Nope, just spill it anywhere convenient.
        Align Alignment(RegInfo->getSpillAlign(*RC));

        // The alignment is the minimum of the desired alignment of the
        // TargetRegisterClass and the stack alignment, whichever is smaller.
        Alignment = std::min(Alignment, TFI->getStackAlign());
        FrameIdx = MFI.CreateStackObject(Size, Alignment, true);
        Offset += Size;

        // Set the object offset
        MFI.setObjectOffset(FrameIdx, MFI.getObjectOffset(FrameIdx) - Offset);
      } else {
        // Spill to the stack.
        FrameIdx = MFI.CreateFixedSpillStackObject(Size, FixedSlot->Offset);
      }

      // Set the frame index
      CS.setFrameIdx(FrameIdx);
    }
    MFI.setCalleeSavedInfo(CSI);
  }

  // Eliminate the instructions identified in function prologue
  unsigned int DelInstSz = PrologInstrs.size();
  for (unsigned int Idx = 0; Idx < DelInstSz; Idx++) {
    FrontMBB.erase(PrologInstrs[Idx]);
  }

  return true;
}

bool ARMMachineInstructionRaiser::eliminateEpilog(MachineFunction &MF) const {
  const ARMSubtarget &STI = MF.getSubtarget<ARMSubtarget>();
  const ARMBaseRegisterInfo *RegInfo = STI.getRegisterInfo();
  const ARMBaseInstrInfo *TII = STI.getInstrInfo();
  Register FramePtr = RegInfo->getFrameRegister(MF);

  for (MachineBasicBlock &MBB : MF) {
    std::vector<MachineInstr *> EpilogInstrs;
    // MBBIter may be invalidated by the raising operation.
    // for (MachineBasicBlock::iterator MBBIter = MBB.begin();
    //     MBBIter != MBB.end(); MBBIter++) {
    //  MachineInstr &MI = (*MBBIter);
    for (MachineInstr &MI : MBB.instrs()) {
      // Push the LOAD instruction
      if (MI.mayLoad()) {
        MachineOperand LoadOperand = MI.getOperand(0);
        if (LoadOperand.isReg() && LoadOperand.getReg() == FramePtr) {
          // If the register list of current POP includes PC register,
          // it should be replaced with return instead of removed.
          if (MI.findRegisterUseOperandIdx(ARM::PC) != -1) {
            MachineInstrBuilder MIB =
                BuildMI(MBB, &MI, DebugLoc(), TII->get(ARM::BX_RET));
            int CpsrIdx = MI.findRegisterUseOperandIdx(ARM::CPSR);
            if (CpsrIdx == -1) {
              MIB.addImm(ARMCC::AL);
            } else {
              MIB.add(MI.getOperand(CpsrIdx - 1))
                  .add(MI.getOperand(CpsrIdx));
            }
            MIB.add(MI.getOperand(MI.getNumExplicitOperands() - 1));
          }
          EpilogInstrs.push_back(&MI);
        }
      }

      // Push the LDR instruction
      if (MI.getOpcode() == ARM::LDR_POST_IMM &&
          MI.getOperand(1).getReg() == FramePtr) {
        EpilogInstrs.push_back(&MI);
      }

      // Push the STR instruction
      if (MI.getOpcode() == ARM::STR_PRE_IMM &&
          MI.getOperand(0).getReg() == FramePtr) {
        EpilogInstrs.push_back(&MI);
      }

      // Push the ADDri instruction
      if (MI.getOpcode() == ARM::ADDri && MI.getOperand(0).isReg()) {
        if (MI.getOperand(0).getReg() == FramePtr) {
          EpilogInstrs.push_back(&MI);
        }
      }

      // Push the SUBri instruction
      if (MI.getOpcode() == ARM::SUBri &&
          MI.getOperand(0).getReg() == FramePtr) {
        EpilogInstrs.push_back(&MI);
      }

      if (MI.getOpcode() == ARM::MOVr) {
        if (MI.getOperand(1).isReg() && MI.getOperand(1).getReg() == ARM::R11 &&
            MI.getOperand(0).isReg() && MI.getOperand(0).getReg() == FramePtr)
          EpilogInstrs.push_back(&MI);
      }
    }

    // Eliminate the instructions identified in function epilogue
    unsigned int DelInstSz = EpilogInstrs.size();
    for (unsigned int Idx = 0; Idx < DelInstSz; Idx++) {
      MBB.erase(EpilogInstrs[Idx]);
    }
  }

  return true;
}

/// Analyze stack size base on moving sp.
/// Patterns like:
/// sub	sp, sp, #28
void ARMMachineInstructionRaiser::analyzeStackSize(MachineFunction &MF) {
  if (MF.size() < 1)
    return;

  const MachineBasicBlock &MBB = MF.front();

  for (const MachineInstr &MI : MBB.instrs()) {
    if (MI.getOpcode() == ARM::SUBri && MI.getNumOperands() >= 3 &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg() == ARM::SP &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg() == ARM::SP &&
        MI.getOperand(2).isImm() && MI.getOperand(2).getImm() > 0) {
      MF.getFrameInfo().setStackSize(MI.getOperand(2).getImm());
      break;
    }
  }
}

/// Analyze frame adjustment base on the offset between fp and base sp.
/// Patterns like:
/// add	fp, sp, #8
void ARMMachineInstructionRaiser::analyzeFrameAdjustment(MachineFunction &MF) {
  if (MF.size() < 1)
    return;

  const MachineBasicBlock &MBB = MF.front();

  for (const MachineInstr &MI : MBB.instrs()) {
    if (MI.getOpcode() == ARM::ADDri && MI.getNumOperands() >= 3 &&
        MI.getOperand(0).isReg() && MI.getOperand(0).getReg() == ARM::R11 &&
        MI.getOperand(1).isReg() && MI.getOperand(1).getReg() == ARM::SP &&
        MI.getOperand(2).isImm() && MI.getOperand(2).getImm() > 0) {
      MF.getFrameInfo().setOffsetAdjustment(MI.getOperand(2).getImm());
      break;
    }
  }
}

bool ARMMachineInstructionRaiser::eliminate() {
  LLVM_DEBUG(dbgs() << "ARMEliminatePrologEpilog start.\n");

  analyzeStackSize(MF);
  analyzeFrameAdjustment(MF);
  bool Success = eliminateProlog(MF);

  if (Success) {
    Success = eliminateEpilog(MF);
  }

  // For debugging.
  LLVM_DEBUG(MF.dump());
  LLVM_DEBUG(RaisedFunction->dump());
  LLVM_DEBUG(dbgs() << "ARMEliminatePrologEpilog end.\n");

  return !Success;
}

#undef DEBUG_TYPE
