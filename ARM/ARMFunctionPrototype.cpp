//===- ARMFunctionPrototype.cpp - Binary raiser utility llvm-mctoll -------===//
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
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

/// Check the first reference of the reg is USE.
bool ARMMachineInstructionRaiser::isUsedRegiser(unsigned Reg,
                                         const MachineBasicBlock &MBB) {
  for (const MachineInstr &MI : MBB.instrs()) {
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && (MO.getReg() == Reg))
        return MO.isUse();
    }
  }

  return false;
}

/// Check the first reference of the reg is DEF.
void ARMMachineInstructionRaiser::genParameterTypes(std::vector<Type *> &ParamVec) {
  assert(!MF.empty() && "The function body is empty!!!");
  MF.getRegInfo().freezeReservedRegs(MF);
  LivePhysRegs LiveInPhysRegs;
  for (MachineBasicBlock &EMBB : MF)
    computeAndAddLiveIns(LiveInPhysRegs, EMBB);
  // Walk the CFG DFS to discover first register usage
  df_iterator_default_set<const MachineBasicBlock *, 16> Visited;
  DenseMap<unsigned, bool> ArgObtain;
  ArgObtain[ARM::R0] = false;
  ArgObtain[ARM::R1] = false;
  ArgObtain[ARM::R2] = false;
  ArgObtain[ARM::R3] = false;
  const MachineBasicBlock &MBBFront = MF.front();
  DenseMap<int, Type *> TyArr;
  int MaxIdx = -1; // When the MaxIdx is -1, means there is no argument.
  // Track register liveness on CFG.
  for (const MachineBasicBlock *Mbb : depth_first_ext(&MBBFront, Visited)) {
    for (unsigned IReg = ARM::R0; IReg < ARM::R4; IReg++) {
      if (!ArgObtain[IReg] && Mbb->isLiveIn(IReg)) {
        for (const MachineInstr &LMI : Mbb->instrs()) {
          auto RUses = LMI.uses();
          const auto *ResIter =
              std::find_if(RUses.begin(), RUses.end(),
                           [IReg](const MachineOperand &OP) -> bool {
                             return OP.isReg() && (OP.getReg() == IReg);
                           });
          if (ResIter != RUses.end()) {
            MaxIdx = IReg - ARM::R0;
            TyArr[MaxIdx] = getDefaultType();
            break;
          }
        }
        ArgObtain[IReg] = true;
      }
    }
  }
  // The rest of function arguments are from stack.
  for (const MachineBasicBlock &Mbb : MF) {
    for (const MachineInstr &Mi : Mbb.instrs()) {
      // Match pattern like ldr r1, [fp, #8].
      if (Mi.getOpcode() == ARM::LDRi12 && Mi.getNumOperands() > 2) {
        const MachineOperand &Mo = Mi.getOperand(1);
        const MachineOperand &Mc = Mi.getOperand(2);
        if (Mo.isReg() && Mo.getReg() == ARM::R11 && Mc.isImm()) {
          // TODO: Need to check the imm is larger than 0 and it is align
          // by 4(32 bit).
          int Imm = Mc.getImm();
          if (Imm >= 0) {
            // The start index of arguments on stack. If the library was
            // compiled by clang, it starts from 2. If the library was compiled
            // by GNU cross compiler, it starts from 1.
            // FIXME: For now, we only treat that the library was complied by
            // clang. We will enable the 'if condition' after we are able to
            // identify the library was compiled by which compiler.
            int Idxoff = 2;
            if (true /* clang */)
              Idxoff = 2;
            else /* gnu */
              Idxoff = 1;

            int Idx = Imm / 4 - Idxoff + 4; // Plus 4 is to guarantee the first
                                            // stack argument index is after all
                                            // of register arguments' indices.
            if (MaxIdx < Idx)
              MaxIdx = Idx;
            TyArr[Idx] = getDefaultType();
          }
        }
      }
    }
  }
  for (int Idx = 0; Idx <= MaxIdx; ++Idx) {
    if (TyArr[Idx] == nullptr)
      ParamVec.push_back(getDefaultType());
    else
      ParamVec.push_back(TyArr[Idx]);
  }
}

/// Get all arguments types of current MachineFunction.
bool ARMMachineInstructionRaiser::isDefinedRegiser(unsigned Reg,
                                            const MachineBasicBlock &MBB) {
  for (MachineBasicBlock::const_reverse_iterator Ii = MBB.rbegin(),
                                                 Ie = MBB.rend();
       Ii != Ie; ++Ii) {
    const MachineInstr &MI = *Ii;
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && (MO.getReg() == Reg)) {
        // The return register must not be tied to another register.
        // If it was, it should not be return register.
        if (MO.isTied())
          return false;

        return MO.isDef();
      }
    }
  }

  return false;
}

/// Get return type of current MachineFunction.
Type *ARMMachineInstructionRaiser::genReturnType() {
  // TODO: Need to track register liveness on CFG.
  Type *RetTy;
  RetTy = Type::getVoidTy(Ctx);
  for (const MachineBasicBlock &MBB : MF) {
    if (MBB.succ_empty()) {
      if (isDefinedRegiser(ARM::R0, MBB)) {
        // TODO: Need to identify data type, int, long, float or double.
        RetTy = getDefaultType();
        break;
      }
    }
  }

  return RetTy;
}

Function *ARMMachineInstructionRaiser::discoverPrototype() {
  LLVM_DEBUG(dbgs() << "ARMFunctionPrototype start.\n");

  Function &Fn = const_cast<Function &>(MF.getFunction());

  std::vector<Type *> ParamTys;
  genParameterTypes(ParamTys);
  Type *RetTy = genReturnType();
  FunctionType *FnTy = FunctionType::get(RetTy, ParamTys, false);

  MachineModuleInfo &Mmi = MF.getMMI();
  Module *Mdl = const_cast<Module *>(Mmi.getModule());
  Mdl->getFunctionList().remove(&Fn);
  Function *Pnfn =
      Function::Create(FnTy, GlobalValue::ExternalLinkage, Fn.getName(), Mdl);
  // When run as FunctionPass, the Function must not be empty, so add
  // EntryBlock at here.
  BasicBlock::Create(Pnfn->getContext(), "EntryBlock", Pnfn);

  LLVM_DEBUG(MF.dump());
  LLVM_DEBUG(Pnfn->dump());
  LLVM_DEBUG(dbgs() << "ARMFunctionPrototype end.\n");

  return Pnfn;
}

#undef DEBUG_TYPE
