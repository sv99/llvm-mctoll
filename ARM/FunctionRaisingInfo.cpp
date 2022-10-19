//===- FunctionRaisingInfo.cpp - Binary raiser utility llvm-mctoll --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of FunctionRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMMachineInstructionRaiser.h"
#include "ARMBaseRegisterInfo.h"
#include "FunctionRaisingInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;
using namespace llvm::mctoll;

/// Initialize this FunctionRaisingInfo with the given Function and its
/// associated MachineFunction.
void FunctionRaisingInfo::set(ARMMachineInstructionRaiser &TheMIR) {
  MIR = &TheMIR;
}

/// Clear out all the function-specific state. This returns this
/// FunctionRaisingInfo to an empty state, ready to be used for a
/// different function.
void FunctionRaisingInfo::clear() {
  MBBMap.clear();
  AllocaMap.clear();
  RetValMap.clear();
  RegVMap.clear();
  NPVMap.clear();
}

/// Check the stack slot index is represented argument or not.
bool FunctionRaisingInfo::isArgumentIndex(int FrameIndex) {
  assert(FrameIndex >= 0 && "The stack frame index must be larger than 0.");
  return FrameIndex > 0 &&
         (unsigned)FrameIndex <= MIR->getRaisedFunction()->arg_size();
}
/// Check the index is stack slot index or not.
bool FunctionRaisingInfo::isStackIndex(int FrameIndex) {
  assert(FrameIndex >= 0 && "The stack frame index must be larger than 0.");
  return (unsigned)FrameIndex > MIR->getRaisedFunction()->arg_size();
}

/// Get the corresponding BasicBlock of given MachineBasicBlock.
/// If does not give a MachineBasicBlock, it will create a new BasicBlock
/// on current Function, and returns it.
BasicBlock *FunctionRaisingInfo::getOrCreateBasicBlock(MachineBasicBlock *MBB) {
  // Function *Fn = getCRF();
  Function *Fn = MIR->getRaisedFunction();
  MachineFunction *MF = &MIR->getMF();

  if (MBB == nullptr)
    return BasicBlock::Create(Fn->getContext(), "", Fn);

  for (auto Block : MBBMap) {
    if (Block.second == MBB)
      return const_cast<BasicBlock *>(Block.first);
  }

  BasicBlock *Block = nullptr;
  if (&MF->front() == MBB)
    Block = &Fn->getEntryBlock();
  else
    Block = BasicBlock::Create(Fn->getContext(), "", Fn);

  MBBMap.insert(std::make_pair(Block, MBB));

  return Block;
}

Value *FunctionRaisingInfo::getOperand(const MachineInstr &MI, unsigned Num) {
  const MachineOperand &MO = MI.getOperand(Num);
  Value *Operand = nullptr;
  if (MO.isReg() && !MO.isDebug()) {
    auto Reg = MO.getReg();
    if (checkRegValue(Reg)) {
      Operand = RegVMap[Reg];
    } else {
      //      assert(ArgValMap.count(Reg) != 0 &&
      //             "Cannot find value for the corresponding register!");
      // TODO operand not exists
      Operand = ConstantInt::get(MIR->getDefaultType(), 0);
    }
  } else if (MO.isImm()) {
    Operand = ConstantInt::get(MIR->getDefaultType(), MO.getImm());
   } else if (MO.isFI()) {
    // Frame index
    int FI = MO.getIndex();
    const MachineFrameInfo &MFI = MI.getMF()->getFrameInfo();
    if (isStackIndex(FI)) {
      Operand = const_cast<AllocaInst *>(MFI.getObjectAllocation(FI));
    } else if (isArgumentIndex(FI)) {
      Operand = const_cast<Argument *>(MIR->getRaisedFunction()->arg_begin() + (FI - 1));
    } else if (isReturnIndex(FI)) {
      Operand = const_cast<AllocaInst *>(MFI.getObjectAllocation(0));
    } else {
      // Do nothing for now.
    }
  } else if (MO.isJTI()) {
    // Jump table index
    Operand = ConstantInt::get(MIR->getDefaultType(), MO.getIndex());
  } else if (MO.isSymbol()) {
    Operand = MIR->getModule()->getNamedGlobal(MO.getSymbolName());
  } else {
    dbgs() << "Warning: visit. An unmatch type! = "
           << (unsigned)(MO.getType()) << "\n";
  }
  return Operand;
}

Value *FunctionRaisingInfo::getOperand(NodePropertyInfo *NPI, unsigned Num) {
  if ((!NPI->IsTwoAddress) && (Num < 2)) {
    Num++;
  }
  return getOperand(*NPI->MI, Num);
}

NodePropertyInfo *FunctionRaisingInfo::initNPI(const MachineInstr &MI) {
  NodePropertyInfo *NodeInfo = new NodePropertyInfo();
  // Initialize the NodePropertyInfo properties.
  NodeInfo->MI = &MI;
  NodeInfo->HasCPSR = false;
  NodeInfo->UpdateCPSR = false;
  NodeInfo->IsCond = false;
  NodeInfo->IfBB = nullptr;
  NodeInfo->ElseBB = nullptr;

  // Number of operands for MachineInstr.
  int NumOps = MI.getNumOperands();

  // TODO: Now the predicate operand not stripped, so the two-address operands
  // more than two.
  // Set the MI is two-address. The default is three-address.
  if (NumOps < 4)
    NodeInfo->IsTwoAddress = true;

  // ARM::CPSR register use index in MachineInstr.
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // If the MachineInstr has explicit ARM::CPSR register,
  // update the NodePropertyInfo.
  if (Idx != -1 && !MI.getOperand(Idx).isImplicit()) {
    // MI with ARM::CPSR register.
    NodeInfo->HasCPSR = true;
    if (Idx != NumOps - 1 &&
        MI.getOperand(Idx + 1).isReg() &&
        MI.getOperand(Idx + 1).getReg() == ARM::CPSR) {
      // Find pattern: Imm<cond>, $cpsr, $cpsr, in the operands list.
      // Pattern matching: addseq r0, r0, 0
      assert(MI.getOperand(Idx - 1).isImm() &&
             "Attempt to get non-imm operand!");
      NodeInfo->Cond = MI.getOperand(Idx - 1).getImm();
      NodeInfo->UpdateCPSR = true;
      NodeInfo->IsCond = NodeInfo->Cond != ARMCC::AL;
    } else {
      // Find pattern: Imm<cond>, ... ,$cpsr in the operands list.
      // Pattern matching: add<cond> or adds
      for (int OpIdx = 1; OpIdx < NumOps; OpIdx++) {
        if (MI.getOperand(Idx - OpIdx).isImm()) {
          NodeInfo->Cond = MI.getOperand(Idx - OpIdx).getImm();
          NodeInfo->IsCond = NodeInfo->Cond != ARMCC::AL;
          NodeInfo->UpdateCPSR = NodeInfo->Cond == ARMCC::AL;
          break;
        }
      }
    }
  }
  NPMap[&MI] = NodeInfo;
  return NodeInfo;
}

void FunctionRaisingInfo::recordDefinition(NodePropertyInfo *NPI, Value *Val) {
  assert(Val != nullptr && "The new Value ptr is null when record define!");
  NPVMap[NPI] = Val;
  auto *Op = &NPI->MI->getOperand(0);
  if (Op->isReg()) {
    recordDefinition(Op->getReg(), Val);
  }

  if (Op->isFI() && isReturnIndex(Op->getIndex())) {
    recordDefinition(ARM::R0, Val);
  }
}

void FunctionRaisingInfo::recordDefinition(Register Reg, Value *Val) {
  RegVMap[Reg] = Val;
}
