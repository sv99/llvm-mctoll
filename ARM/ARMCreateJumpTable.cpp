//===- ARMCreateJumpTable.cpp - Binary raiser utility llvm-mctoll ---------===//
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

#include "ARMBaseInstrInfo.h"
#include "ARMMachineFunctionInfo.h"
#include "ARMMachineInstructionRaiser.h"
#include "ARMSubtarget.h"
#include "llvm/CodeGen/ISDOpcodes.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

/// Get the MachineBasicBlock to add the jump table instruction.
MachineBasicBlock *ARMMachineInstructionRaiser::checkJumpTableBB(MachineFunction &MF) {
  MachineBasicBlock *JumpTableBB = nullptr;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineBasicBlock::iterator BackMBBIter = MBB.begin();
         BackMBBIter != MBB.end(); BackMBBIter++) {
      MachineInstr &CurMachInstr = (*BackMBBIter);

      // Find the MI: %r0 = ADDri %pc
      if (CurMachInstr.getOpcode() == ARM::ADDri &&
          CurMachInstr.getOperand(1).getReg() == ARM::PC) {
        JumpTableBB = CurMachInstr.getParent();
      }
    }
  }

  // Remove the machine instructions which are no sense after building the
  // machine jump table.
  std::vector<MachineInstr *> Instrs;
  if (JumpTableBB && JumpTableBB->pred_size() == 1) {
    MachineBasicBlock *MBB = JumpTableBB->pred_begin()[0];
    for (MachineBasicBlock::iterator MIIter = MBB->begin();
         MIIter != MBB->end(); MIIter++) {
      MachineInstr &CurMI = (*MIIter);

      if (CurMI.getOpcode() == ARM::CMPri &&
          CurMI.getNextNode()->getOpcode() == ARM::STRi12) {
        Instrs.push_back(CurMI.getNextNode());
      }

      if (CurMI.getOpcode() == ARM::STRi12 &&
          CurMI.getNextNode()->getOpcode() == ARM::Bcc) {
        Instrs.push_back(CurMI.getNextNode());
      }
    }

    for (unsigned int Idx = 0; Idx < Instrs.size(); Idx++) {
      MBB->erase(Instrs[Idx]);
    }
  }
  return JumpTableBB;
}

bool ARMMachineInstructionRaiser::updateTheBranchInst(MachineBasicBlock &MBB) {
  MachineFunction *MF = MBB.getParent();
  const ARMSubtarget &STI = MF->getSubtarget<ARMSubtarget>();
  const ARMBaseInstrInfo *TII = STI.getInstrInfo();

  std::vector<MachineInstr *> Instrs;
  for (MachineBasicBlock::iterator MIIter = MBB.begin(); MIIter != MBB.end();
       MIIter++) {
    MachineInstr &CurMI = (*MIIter);

    if (CurMI.getOpcode() == ARM::Bcc) {
      for (unsigned int Idx = 0; Idx < CurMI.getNumOperands(); Idx++) {
        LLVM_DEBUG(CurMI.getOperand(Idx).dump());
      }
      BuildMI(&MBB, DebugLoc(), TII->get(ARM::B)).add(CurMI.getOperand(0));
      Instrs.push_back(&CurMI);
    }
  }

  for (unsigned int Idx = 0; Idx < Instrs.size(); Idx++) {
    MBB.erase(Instrs[Idx]);
  }
  return true;
}

/// Raise the machine jump table according to the CFG.
bool ARMMachineInstructionRaiser::raiseMachineJumpTable(MachineFunction &MF) {
  // A vector to record MBBs that need to be erased upon jump table creation.
  std::vector<MachineBasicBlock *> MBBsToBeErased;

  std::map<uint64_t, MCInstOrData> MCInstMapData;
  MCInstRaiser::const_mcinst_iter IterIn;

  // Save the ADDri and Calculate the start address of data.
  for (MachineBasicBlock &JmpTblBaseCalcMBB : MF) {
    for (MachineBasicBlock::iterator CurMBBIter = JmpTblBaseCalcMBB.begin();
         CurMBBIter != JmpTblBaseCalcMBB.end(); CurMBBIter++) {
      MachineInstr &JmpTblOffsetCalcMI = *CurMBBIter;
      // Find the MI: %r0 = ADDri %pc, #8
      // add     r0, pc, #8
      // ldr     r1, [sp]
      // ldr     r2, [r0, r1, lsl #2]
      // add     pc, r0, r2
      if (JmpTblOffsetCalcMI.getOpcode() == ARM::ADDri &&
          JmpTblOffsetCalcMI.getOperand(1).getReg() == ARM::PC &&
          JmpTblOffsetCalcMI.getOperand(2).getImm() == 8) {
        // If the fourth instruction in swith block is "add pc, rm, rn",
        // this library should be built with "-fPIC".
        bool IsFPIC = false;
        MachineBasicBlock::iterator FourthInstr = CurMBBIter;
        std::advance(FourthInstr, 3);
        if (FourthInstr != JmpTblBaseCalcMBB.end()) {
          MachineInstr &JGPC = *FourthInstr;
          if (JGPC.getOpcode() == ARM::ADDrr &&
              JGPC.getOperand(0).getReg() == ARM::PC) {
            IsFPIC = true;
          }
        }

        // A vector of switch target MBBs
        std::vector<MachineBasicBlock *> JmpTgtMBBvec;
        assert(
            InstRaiser != nullptr &&
            "Current function machine instruction raiser wasn't initialized!");
        for (IterIn = InstRaiser->const_mcinstr_begin();
             IterIn != InstRaiser->const_mcinstr_end(); IterIn++) {
          MCInstOrData MCInstorData = IterIn->second;
          if (MCInstorData.isData() && MCInstorData.getData() > 0) {
            // The 16 is 8 + 8. The first 8 is the PC offset, the second 8 is
            // the immediate value of current instruction.
            // If the current library is position-independent, the offset should
            // be CASE VALUE + PC + 8.
            // If the current library is not position-independent, the offset
            // should be CASE VALUE - text section address.
            uint64_t Offset =
                IsFPIC ? (MCInstorData.getData() +
                          InstRaiser->getMCInstIndex(JmpTblOffsetCalcMI) + 16)
                       : (MCInstorData.getData() - MR->getTextSectionAddress());
            auto MBBNo = InstRaiser->getMBBNumberOfMCInstOffset(Offset, MF);
            if (MBBNo != -1) {
              MachineBasicBlock *MBB = MF.getBlockNumbered(MBBNo);
              JmpTgtMBBvec.push_back(MBB);
            }
          }
        }

        // If no potential jump target addresses were found the current
        // instruction does not compute jump table base.
        if (JmpTgtMBBvec.size() == 0) {
          continue;
        }
        // Construct jump table. Current block is the block which would
        // potentially contain the start of jump targets. If current block has
        // multiple predecessors this may not be a jump table. For now assert
        // this to discover potential situations in binaries. Change the assert
        // to continue if the assumption is correct.
        assert((JmpTblBaseCalcMBB.pred_size() == 1) &&
               "Expect a single predecessor during jump table discovery");
        MachineBasicBlock *JmpTblPredMBB = *(JmpTblBaseCalcMBB.pred_begin());
        // Predecessor block of current block (MBB) - which is jump table block
        // - is expected to have exactly two successors; one the current block
        // and the other which should become the default MBB for the switch.
        assert((JmpTblPredMBB->succ_size() == 2) &&
               "Unexpected number of successors of switch block");
        JumpTableInfo JmpTblInfo;
        // Set predecessor of current block as condition block of jump table
        // info
        JmpTblInfo.ConditionMBB = JmpTblPredMBB;
        // Set default basic block in jump table info
        for (auto *Succ : JmpTblPredMBB->successors()) {
          if (Succ != &JmpTblBaseCalcMBB) {
            JmpTblInfo.DefaultMBB = Succ;
            break;
          }
        }
        MachineJumpTableInfo *JTI =
            MF.getOrCreateJumpTableInfo(llvm::MachineJumpTableInfo::EK_Inline);
        JmpTblInfo.JTIdx = JTI->createJumpTableIndex(JmpTgtMBBvec);
        // Verify the branch instruction of JmpTblPredMBB is a conditional jmp
        // that uses eflags. Go to the most recent instruction that defines
        // eflags. Remove that instruction as well as any subsequent instruction
        // that uses the register defined by that instruction.
        MachineInstr &BranchInstr = JmpTblPredMBB->instr_back();
        std::vector<MachineInstr *> MBBInstrsToErase;
        if (BranchInstr.isConditionalBranch()) {
          // Walk the basic block backwards to find the most recent instruction
          // that implicitly defines eflags.
          bool EflagsModifierFound = false;
          MachineBasicBlock::reverse_instr_iterator CurInstrIter =
              JmpTblPredMBB->instr_rbegin();
          for (auto LastInstIter = JmpTblPredMBB->instr_rend();
               ((CurInstrIter != LastInstIter) && (!EflagsModifierFound));
               ++CurInstrIter) {
            MachineInstr &CurInst = *CurInstrIter;
            if (CurInst.getDesc().hasImplicitDefOfPhysReg(ARM::CPSR)) {
              EflagsModifierFound = true;
            }
          }
          assert(EflagsModifierFound &&
                 "Failed to find eflags defining instruction during jump table "
                 "extraction.");
          // Note: decrement CurInstrIter to point to the eflags modifying
          // instruction.
          CurInstrIter--;
          // Find the registers that the eflags modifying instruction defines.
          // Delete all instructions that uses them since we will be deleting
          // the eflags modifying instruction.
          MachineInstr &EflagsModInstr = *CurInstrIter;
          std::set<unsigned int> EflagsDefRegs;
          for (auto MO : EflagsModInstr.defs()) {
            // Create a set of all physical registers this instruction defines.
            if (MO.isReg()) {
              Register DefReg = MO.getReg();
              if (Register::isPhysicalRegister(DefReg)) {
                EflagsDefRegs.insert(getARMCPSR(DefReg));
              }
            }
          }
          // Add EflagsModInstr to the list of instructions to delete
          MBBInstrsToErase.push_back(&EflagsModInstr);

          MachineBasicBlock::iterator InstrEndIter = JmpTblPredMBB->instr_end();
          // Start walking the block instructions forward to identify
          // instructions that need be deleted.
          MachineBasicBlock::iterator InstrFwdIter =
              MachineBasicBlock::instr_iterator(CurInstrIter);
          // Find instructions that use any of the register in the set
          // EflagsDefRegs. Add it to a list of instructions that can be
          // deleted.
          while (InstrFwdIter != InstrEndIter) {
            MachineInstr &CurInstr = *InstrFwdIter;
            for (auto MO : CurInstr.uses()) {
              // Check if this use register is defined by EflagsModInstr
              if (MO.isReg()) {
                auto UseReg = MO.getReg();
                if (Register::isPhysicalRegister(UseReg)) {
                  if (EflagsDefRegs.find(getARMCPSR(UseReg)) !=
                      EflagsDefRegs.end()) {
                    MBBInstrsToErase.push_back(&CurInstr);
                    // No need to look for other register uses.
                    break;
                  }
                }
              }
            }
            // If this instruction redefines any of the registers, remove that
            // register from EflagsDefRegs. Any instruction that uses this
            // redefined register and follows the current instruction, should
            // not be deleted.
            for (auto MO : CurInstr.defs()) {
              if (MO.isReg()) {
                Register DefReg = MO.getReg();
                if (Register::isPhysicalRegister(DefReg)) {
                  if (EflagsDefRegs.find(getARMCPSR(DefReg)) !=
                      EflagsDefRegs.end()) {
                    EflagsDefRegs.erase(DefReg);
                  }
                }
              }
            }
            InstrFwdIter++;
          }
          // Finally add BranchInstr to the list of instructions to be
          // deleted
          MBBInstrsToErase.push_back(&BranchInstr);
          // BranchInstr.dump();
          // Now delete the instructions
          for (auto *MI : MBBInstrsToErase) {
            JmpTblPredMBB->erase(MI);
          }
        }

        const ARMSubtarget &STI = MF.getSubtarget<ARMSubtarget>();
        const ARMBaseInstrInfo *TII = STI.getInstrInfo();
        MBBsToBeErased.push_back(&JmpTblBaseCalcMBB);
        MachineInstrBuilder MIB =
            BuildMI(JmpTblPredMBB, DebugLoc(), TII->get(ARM::BR_JTr))
                .addJumpTableIndex(JmpTblInfo.JTIdx);

        // The new machine instrucion should contain the metadata.
        // Create the metadata and add it to the machine instrucion.
        LLVMContext &Ctx(MF.getFunction().getContext());
        ConstantAsMetadata *CAM = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
        MDNode *MDnode = MDNode::get(Ctx, CAM);
        MIB.addMetadata(MDnode);
        JTList.push_back(JmpTblInfo);
      }
    }
  }

  // Delete MBBs
  for (auto *MBB : MBBsToBeErased) {
    MBB->eraseFromParent();
  }
  return true;
}

unsigned int ARMMachineInstructionRaiser::getARMCPSR(unsigned int PhysReg) {
  // Get the ARM CPSR.
  if (PhysReg == ARM::CPSR) {
    return PhysReg;
  }
  return -1;
}

bool ARMMachineInstructionRaiser::createJumpTable() {
  LLVM_DEBUG(dbgs() << "ARMCreateJumpTable start.\n");

  raiseMachineJumpTable(MF);

  // For debugging.
  LLVM_DEBUG(MF.dump());
  LLVM_DEBUG(RaisedFunction->dump());
  LLVM_DEBUG(dbgs() << "ARMCreateJumpTable end.\n");

  return false;
}

#undef DEBUG_TYPE
