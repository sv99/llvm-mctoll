//===- ARMSelectionDAGISel.cpp - Binary raiser utility llvm-mctoll --------===//
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
#include "FunctionRaisingInfo.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

void ARMMachineInstructionRaiser::initEntryBasicBlock() {
  BasicBlock *EntryBlock = &RaisedFunction->getEntryBlock();
  for (unsigned Idx = 0; Idx < 4; Idx++) {
    Align MALG(32);
    AllocaInst *Alloc = new AllocaInst(Type::getInt1Ty(Ctx), 0,
                                       nullptr, MALG, "", EntryBlock);
    FuncInfo->AllocaMap[Idx] = Alloc;
    new StoreInst(ConstantInt::getFalse(Ctx), Alloc, EntryBlock);
  }
}

bool ARMMachineInstructionRaiser::doSelection() {
  LLVM_DEBUG(dbgs() << "ARM raising start.\n");

  FuncInfo = new FunctionRaisingInfo();
  FuncInfo->set(*this);

  initEntryBasicBlock();
  for (MachineBasicBlock &Block : MF) {
    FuncInfo->getOrCreateBasicBlock(&Block);
    selectBasicBlock(&Block);
  }

  // Add an additional exit BasicBlock, all of original return BasicBlocks
  // will branch to this exit BasicBlock. This will lead to the function has
  // one and only exit. If the function has return value, this help return
  // R0.
  Function *CurFn = getRaisedFunction();
  BasicBlock *LBB = FuncInfo->getOrCreateBasicBlock();

  if (CurFn->getReturnType()) {
    PHINode *LPHI = PHINode::Create(getRaisedFunction()->getReturnType(),
                                    FuncInfo->RetValMap.size(), "", LBB);
    for (auto Pair : FuncInfo->RetValMap)
      LPHI->addIncoming(Pair.second, Pair.first);

    ReturnInst::Create(CurFn->getContext(), LPHI, LBB);
  } else
    ReturnInst::Create(CurFn->getContext(), LBB);

  for (auto &FBB : CurFn->getBasicBlockList())
    if (FBB.getTerminator() == nullptr)
      BranchInst::Create(LBB, &FBB);

  // For debugging.
  LLVM_DEBUG(MF.dump());
  LLVM_DEBUG(RaisedFunction->dump());
  LLVM_DEBUG(dbgs() << "ARM raising end.\n");

  return true;
}

void ARMMachineInstructionRaiser::selectBasicBlock(MachineBasicBlock *MBB) {

  auto *BB = FuncInfo->getOrCreateBasicBlock(MBB);
  IRBuilder<> IRB(BB);

  for (MachineInstr &MI : MBB->instrs()) {
    emitInstr(IRB, MI);
  }

  // If the current function has return value, records relationship between
  // BasicBlock and each Value which is mapped with R0. In order to record
  // the return Value of each exit BasicBlock.
  Type *RTy = getRaisedFunction()->getReturnType();
  if (RTy != nullptr && !RTy->isVoidTy() && MBB->succ_size() == 0) {
    auto *Val = FuncInfo->getRegValue(ARM::R0);
    Instruction *TInst = dyn_cast<Instruction>(Val);
    assert(TInst && "A def R0 was pointed to a non-instruction!!!");
    BasicBlock *TBB = TInst->getParent();
    // TBB may don't be equal BB after inserting condition block.
    FuncInfo->RetValMap[TBB] = TInst;
  }
}

#undef DEBUG_TYPE
