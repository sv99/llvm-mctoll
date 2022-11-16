//===-- ARMEliminatePrologEpilog.cpp ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of ARMMachineInstructionRaiser class
// for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMMachineInstructionRaiser.h"
#include "ARMModuleRaiser.h"
#include "ARMRaisedValueTracker.h"
#include "Raiser/MachineFunctionRaiser.h"
#include "llvm/Support/Debug.h"
#include <ARMSubtarget.h>

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

ARMMachineInstructionRaiser::ARMMachineInstructionRaiser(
    MachineFunction &MF, const ModuleRaiser *MR, MCInstRaiser *MCIR)
    : MachineInstructionRaiser(MF, MR, MCIR),
      MachineRegInfo(MF.getRegInfo()),
      TargetInfo(MF.getSubtarget<ARMSubtarget>()),
      Ctx(MR->getModule()->getContext()) {
  InstrInfo = TargetInfo.getInstrInfo();
  RegisterInfo = TargetInfo.getRegisterInfo();
  const ARMModuleRaiser *ConstAMR = dyn_cast<ARMModuleRaiser>(MR);
  TargetMR = const_cast<ARMModuleRaiser *>(ConstAMR);
  RaisedValues = new ARMRaisedValueTracker(this);
}

bool ARMMachineInstructionRaiser::raise() {
  eliminate();

  revise();
  raiseArgs();
  buildFrame();
  split();

  initEntryBasicBlock();
  for (MachineBasicBlock &Block : MF) {
    RaisedValues->getOrCreateBasicBlock(&Block);
    selectBasicBlock(&Block);
  }

  // Add an additional exit BasicBlock, all of original return BasicBlocks
  // will branch to this exit BasicBlock. This will lead to the function has
  // one and only exit. If the function has return value, this help return
  // R0.
  Function *CurFn = getRaisedFunction();
  BasicBlock *LBB = RaisedValues->getOrCreateBasicBlock();

  if (CurFn->getReturnType()) {
    PHINode *LPHI = PHINode::Create(getRaisedFunction()->getReturnType(),
                                    RaisedValues->RetValMap.size(), "", LBB);
    for (auto Pair : RaisedValues->RetValMap)
      LPHI->addIncoming(Pair.second, Pair.first);

    ReturnInst::Create(CurFn->getContext(), LPHI, LBB);
  } else
    ReturnInst::Create(CurFn->getContext(), LBB);

  for (auto &FBB : CurFn->getBasicBlockList())
    if (FBB.getTerminator() == nullptr)
      BranchInst::Create(LBB, &FBB);

  // For debugging.
  LLVM_DEBUG(dbgs() << "CFG : After ARM Raising\n");
  LLVM_DEBUG(MF.dump());
  LLVM_DEBUG(RaisedFunction->dump());

  return true;
}

int ARMMachineInstructionRaiser::getArgumentNumber(unsigned PReg) {
  // NYI
  assert(false &&
         "Unimplemented ARMMachineInstructionRaiser::getArgumentNumber()");
  return -1;
}

Value *ARMMachineInstructionRaiser::getRegOrArgValue(unsigned PReg, int MBBNo) {
  assert(false &&
         "Unimplemented ARMMachineInstructionRaiser::getRegOrArgValue()");
  return nullptr;
}

/// Create a new MachineFunctionRaiser object and add it to the list of
/// MachineFunction raiser objects of this module.
MachineFunctionRaiser *ARMModuleRaiser::CreateAndAddMachineFunctionRaiser(
    Function *F, const ModuleRaiser *MR, uint64_t Start, uint64_t End) {
  MachineFunctionRaiser *MFR = new MachineFunctionRaiser(
      *M, MR->getMachineModuleInfo()->getOrCreateMachineFunction(*F),
      MR, Start, End);
  MFR->setMachineInstrRaiser(new ARMMachineInstructionRaiser(
      MFR->getMachineFunction(), MR, MFR->getMCInstRaiser()));
  MFRaiserVector.push_back(MFR);
  return MFR;
}

void ARMMachineInstructionRaiser::initEntryBasicBlock() {
  BasicBlock *EntryBlock = &RaisedFunction->getEntryBlock();
  for (unsigned Idx = 0; Idx < 4; Idx++) {
    Align MALG(32);
    AllocaInst *Alloc = new AllocaInst(Type::getInt1Ty(Ctx), 0,
                                       nullptr, MALG, "", EntryBlock);
    RaisedValues->AllocaMap[Idx] = Alloc;
    new StoreInst(ConstantInt::getFalse(Ctx), Alloc, EntryBlock);
  }
}

void ARMMachineInstructionRaiser::selectBasicBlock(MachineBasicBlock *MBB) {

  auto *BB = RaisedValues->getOrCreateBasicBlock(MBB);
  IRBuilder<> IRB(BB);

  for (MachineInstr &MI : MBB->instrs()) {
    emitInstr(IRB, MI);
  }

  // If the current function has return value, records relationship between
  // BasicBlock and each Value which is mapped with R0. In order to record
  // the return Value of each exit BasicBlock.
  Type *RTy = getRaisedFunction()->getReturnType();
  if (RTy != nullptr && !RTy->isVoidTy() && MBB->succ_size() == 0) {
    auto *Val = RaisedValues->getRegValue(ARM::R0);
    Instruction *TInst = dyn_cast<Instruction>(Val);
    assert(TInst && "A def R0 was pointed to a non-instruction!!!");
    BasicBlock *TBB = TInst->getParent();
    // TBB may don't be equal BB after inserting condition block.
    RaisedValues->RetValMap[TBB] = TInst;
  }
}

#undef DEBUG_TYPE
