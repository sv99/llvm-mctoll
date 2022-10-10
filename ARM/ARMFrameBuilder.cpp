//===- ARMFrameBuilder.cpp - Binary raiser utility llvm-mctoll ------------===//
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
#include "llvm/ADT/DenseMap.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/IR/DataLayout.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

static bool isLoadOP(unsigned Opcode) {
  switch (Opcode) {
  default:
    return false;
  case ARM::LDRi12:
  case ARM::LDRH:
  case ARM::LDRSH:
  case ARM::LDRBi12:
    return true;
  }
}

static bool isStoreOP(unsigned Opcode) {
  switch (Opcode) {
  default:
    return false;
  case ARM::STRi12:
  case ARM::STRH:
  case ARM::STRBi12:
    return true;
  }
}

static bool isAddOP(unsigned Opcode) {
  switch (Opcode) {
  default:
    return false;
  case ARM::ADDri:
    return true;
  }
}

static inline bool isHalfwordOP(unsigned Opcode) {
  bool Res;
  switch (Opcode) {
  default:
    Res = false;
    break;
  case ARM::STRH:
  case ARM::LDRH:
  case ARM::LDRSH:
    Res = true;
    break;
  }
  return Res;
}

unsigned ARMMachineInstructionRaiser::getBitCount(unsigned Opcode) {
  unsigned Ret;

  switch (Opcode) {
  default:
    Ret = Log2(M->getDataLayout().getStackAlignment());
    break;
  case ARM::LDRi12:
  case ARM::STRi12:
    Ret = 4;
    break;
  case ARM::LDRBi12:
  case ARM::STRBi12:
    Ret = 1;
    break;
  case ARM::STRH:
  case ARM::LDRH:
  case ARM::LDRSH:
    Ret = 2;
    break;
  case ARM::ADDri:
    Ret = 4;
    break;
  }

  return Ret;
}

Type *ARMMachineInstructionRaiser::getStackType(unsigned Size) {
  Type *T = nullptr;

  switch (Size) {
  default:
    T = Type::getIntNTy(Ctx, M->getDataLayout().getPointerSizeInBits());
    break;
  case 8:
    T = Type::getInt64Ty(Ctx);
    break;
  case 4:
    T = Type::getInt32Ty(Ctx);
    break;
  case 2:
    T = Type::getInt16Ty(Ctx);
    break;
  case 1:
    T = Type::getInt8Ty(Ctx);
    break;
  }

  return T;
}

/// Replace common regs assigned by SP to SP.
/// Patterns like:
/// mov r5, sp
/// ldr r3, [r5, #4]
/// In this case, r5 should be replace by sp.
bool ARMMachineInstructionRaiser::replaceNonSPBySP(MachineInstr &MI) {
  if (MI.getOpcode() == ARM::MOVr) {
    if (MI.getOperand(1).isReg() && MI.getOperand(1).getReg() == ARM::SP) {
      if (MI.getOperand(0).isReg() && MI.getOperand(0).isDef()) {
        RegAssignedBySP.push_back(MI.getOperand(0).getReg());
        return true;
      }
    }
  }

  // Replace regs which are assigned by sp.
  for (MachineOperand &MO : MI.uses()) {
    for (unsigned Odx : RegAssignedBySP) {
      if (MO.isReg() && MO.getReg() == Odx) {
        MO.ChangeToRegister(ARM::SP, false);
      }
    }
  }

  // Record regs which are assigned by sp.
  for (MachineOperand &MO : MI.defs()) {
    for (SmallVector<unsigned, 16>::iterator I = RegAssignedBySP.begin();
         I != RegAssignedBySP.end();) {
      if (MO.isReg() && MO.getReg() == *I) {
        RegAssignedBySP.erase(I);
      } else
        ++I;
    }
  }

  return false;
}

/// Analyze frame index of stack operands.
/// Some patterns like:
/// ldr r3, [sp, #12]
/// str r4, [fp, #-8]
/// add r0, sp, #imm
int64_t ARMMachineInstructionRaiser::identifyStackOp(const MachineInstr &MI) {
  unsigned Opc = MI.getOpcode();
  if (!isLoadOP(Opc) && !isStoreOP(Opc) && !isAddOP(Opc))
    return -1;

  if (MI.getNumOperands() < 3)
    return -1;

  int64_t Offset = -1;
  const MachineOperand &MO = MI.getOperand(1);

  if (!MO.isReg())
    return -1;

  if (isHalfwordOP(Opc))
    Offset = MI.getOperand(3).getImm();
  else
    Offset = MI.getOperand(2).getImm();

  if (MO.getReg() == ARM::SP && Offset >= 0)
    return Offset;

  if (MO.getReg() == ARM::R11) {
    if (Offset > 0) {
      if (isHalfwordOP(Opc))
        Offset = 0 - static_cast<int64_t>(static_cast<int8_t>(Offset));
      else
        return -1;
    }
    auto *MFI = &MF.getFrameInfo();
    return MFI->getStackSize() + Offset + MFI->getOffsetAdjustment();
  }

  return -1;
}

/// Find out all of frame relative operands, and update them.
void ARMMachineInstructionRaiser::searchStackObjects(MachineFunction &MF) {
  // <SPOffset, frame_element_ptr>
  std::map<int64_t, StackElement *, std::greater<int64_t>> SPOffElementMap;
  DenseMap<MachineInstr *, StackElement *> InstrToElementMap;

  std::vector<MachineInstr *> RemoveList;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB.instrs()) {

      if (replaceNonSPBySP(MI)) {
        RemoveList.push_back(&MI);
        continue;
      }

      int64_t Off = identifyStackOp(MI);
      if (Off >= 0) {
        StackElement *SE = nullptr;
        if (SPOffElementMap.count(Off) == 0) {
          SE = new StackElement();
          SE->Size = getBitCount(MI.getOpcode());
          SE->SPOffset = Off;
          SPOffElementMap.insert(std::make_pair(Off, SE));
        } else {
          SE = SPOffElementMap[Off];
        }

        if (SE != nullptr) {
          InstrToElementMap[&MI] = SE;
        }
      }
    }
  }

  // Remove instructions of MOV sp to non-sp.
  for (MachineInstr *MI : RemoveList)
    MI->removeFromParent();

  // TODO: Before generating StackObjects, we need to check whether there is
  // any missed StackElement.

  BasicBlock *EntryBB = &getRaisedFunction()->getEntryBlock();

  assert(EntryBB != nullptr && "There is no BasicBlock in this Function!");
  // Generate StackObjects.
  for (auto &OffElement : SPOffElementMap) {
    StackElement *SElm = OffElement.second;
    Align MALG(SElm->Size);
    AllocaInst *Alc =
        new AllocaInst(getStackType(SElm->Size), 0, nullptr, MALG, "", EntryBB);
    auto *MFI = &MF.getFrameInfo();
    int Idx = MFI->CreateStackObject(SElm->Size, Align(4), false, Alc);
    Alc->setName("stack." + std::to_string(Idx));
    MFI->setObjectOffset(Idx, SElm->SPOffset);
    SElm->ObjectIndex = Idx;
  }

  // Replace original SP operands by stack operands.
  for (auto &InstrToElement : InstrToElementMap) {
    MachineInstr *MI = InstrToElement.first;
    StackElement *SE = InstrToElement.second;
    MI->getOperand(1).ChangeToFrameIndex(SE->ObjectIndex);
    unsigned Opc = MI->getOpcode();
    if (isHalfwordOP(Opc)) {
      MI->removeOperand(3);
    }
    MI->removeOperand(2);
  }

  for (auto &Elm : SPOffElementMap)
    delete Elm.second;
}

bool ARMMachineInstructionRaiser::buildFrame() {
  LLVM_DEBUG(dbgs() << "ARMFrameBuilder start.\n");

  searchStackObjects(MF);

  // For debugging.
  LLVM_DEBUG(MF.dump());
  LLVM_DEBUG(RaisedFunction->dump());
  LLVM_DEBUG(dbgs() << "ARMFrameBuilder end.\n");

  return true;
}

#undef DEBUG_TYPE
