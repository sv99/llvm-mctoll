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

void ARMMachineInstructionRaiser::initEntryBasicBlock(FunctionRaisingInfo *FuncInfo) {
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
  LLVM_DEBUG(dbgs() << "ARMSelectionDAGISel start.\n");

  //MachineFunction &mf = *MF;
  SelectionDAG *CurDAG = new SelectionDAG(*MR->getTargetMachine(), CodeGenOpt::None);
  auto ORE = make_unique<OptimizationRemarkEmitter>(RaisedFunction);
  CurDAG->init(MF, *ORE.get(), nullptr, nullptr, nullptr, nullptr, nullptr);
  FunctionRaisingInfo *FuncInfo = new FunctionRaisingInfo();
  FuncInfo->set(*TargetMR, *getRaisedFunction(), MF, *CurDAG);

  initEntryBasicBlock(FuncInfo);
  for (MachineBasicBlock &Block : MF) {
    // MBB = &Block;
    FuncInfo->getOrCreateBasicBlock(&Block);
    selectBasicBlock(FuncInfo, &Block);
  }

  // Add an additional exit BasicBlock, all of original return BasicBlocks
  // will branch to this exit BasicBlock. This will lead to the function has
  // one and only exit. If the function has return value, this help return
  // R0.
  Function *CurFn = const_cast<Function *>(FuncInfo->Fn);
  BasicBlock *LBB = FuncInfo->getOrCreateBasicBlock();

  if (CurFn->getReturnType()) {
    PHINode *LPHI = PHINode::Create(FuncInfo->getCRF()->getReturnType(),
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
    LLVM_DEBUG(dbgs() << "ARMSelectionDAGISel end.\n");

  return true;
}

// Modified version SelectionDAG::dump() for support EXT_ARMISD::NodeType
// based on llvm/lib/CodeGen/SelectionDAG/SelectionDAGDumper.cpp

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
std::string getOperationName(const SelectionDAG *DAG, const SDNode *Node) {
#define MAKE_CASE(V)                                                           \
  case V:                                                                      \
    return #V;
  switch ((EXT_ARMISD::NodeType)Node->getOpcode()) {
    MAKE_CASE(EXT_ARMISD::BX_RET)
    MAKE_CASE(EXT_ARMISD::BRD)
    MAKE_CASE(EXT_ARMISD::LOAD)
    MAKE_CASE(EXT_ARMISD::STORE)
    MAKE_CASE(EXT_ARMISD::MSR)
    MAKE_CASE(EXT_ARMISD::MRS)
    MAKE_CASE(EXT_ARMISD::RSB)
    MAKE_CASE(EXT_ARMISD::RSC)
    MAKE_CASE(EXT_ARMISD::SBC)
    MAKE_CASE(EXT_ARMISD::TEQ)
    MAKE_CASE(EXT_ARMISD::TST)
    MAKE_CASE(EXT_ARMISD::BIC)
    MAKE_CASE(EXT_ARMISD::MLA)
    MAKE_CASE(EXT_ARMISD::UXTB)
  default:
    std::string Name = Node->getOperationName(DAG);
    if (!Name.empty()) return Name;
    return "<<Unknown Target Node #" + utostr(Node->getOpcode()) + ">>";
  }
}

void printTypes(const SDNode *Node) {
  for (unsigned Idx = 0, E = Node->getNumValues(); Idx != E; ++Idx) {
    if (Idx) dbgs() << ",";
    if (Node->getValueType(Idx) == MVT::Other)
      dbgs() << "ch";
    else
      dbgs() << Node->getValueType(Idx).getEVTString();
  }
}

/// Return true if this node is so simple that we should just print it inline
/// if it appears as an operand.
static bool shouldPrintInline(const SDNode &Node) {
  if (Node.getOpcode() == ISD::EntryToken)
    return false;
  return Node.getNumOperands() == 0;
}

bool printOperand(const SelectionDAG *DAG, const SDValue Value) {
  if (!Value.getNode()) {
    dbgs() << "<null>";
    return false;
  }

  if (shouldPrintInline(*Value.getNode())) {
    dbgs() << Value->getOperationName(DAG) << ':';
    Value->print_types(dbgs(), DAG);
    Value->print_details(dbgs(), DAG);
    return true;
  }

  dbgs() << 't' << Value.getNode()->PersistentId;
  if (unsigned RN = Value.getResNo())
    dbgs() << ':' << RN;
  return false;
}

void dumpNode(const SelectionDAG *DAG, const SDNode *Node) {
  dbgs() << 't' << Node->PersistentId << ": ";
  printTypes(Node);
  dbgs() << " = " << getOperationName(DAG, Node);
  Node->print_details(dbgs(), DAG);
  for (unsigned Idx = 0, End = Node->getNumOperands(); Idx != End; ++Idx) {
    if (Idx) dbgs() << ", "; else dbgs() << " ";
    printOperand(DAG, Node->getOperand(Idx));
  }
  dbgs() << '\n';
}

static void dumpNodes(const SelectionDAG *DAG, const SDNode *Node, unsigned Indent) {
  for (const SDValue &Op : Node->op_values()) {
    if (shouldPrintInline(*Op.getNode()))
      continue;
    if (Op.getNode()->hasOneUse())
      dumpNodes(DAG, Op.getNode(), Indent +2);
  }

  dbgs().indent(Indent);
  dumpNode(DAG, Node);
}

LLVM_DUMP_METHOD void ARMMachineInstructionRaiser::dumpDAG(SelectionDAG *CurDAG) {
  dbgs() << "SelectionDAG has " << CurDAG->allnodes_size() << " nodes:\n";

  auto *Root = CurDAG->getRoot().getNode();
  for (const SDNode &Node : CurDAG->allnodes()) {
    if (!Node.hasOneUse() && &Node != Root &&
        (!shouldPrintInline(Node) || Node.use_empty()))
      dumpNodes(CurDAG, &Node, 2);
  }

  if (CurDAG->getRoot().getNode())
    dumpNodes(CurDAG, Root, 2);
  dbgs() << "\n";
}
#endif

void ARMMachineInstructionRaiser::selectBasicBlock(
    FunctionRaisingInfo *FuncInfo, MachineBasicBlock *MBB) {

  auto *BB = FuncInfo->getOrCreateBasicBlock(MBB);
  auto *CurDAG = &FuncInfo->getCurDAG();

  for (MachineInstr &MI : MBB->instrs()) {
    emitInstr(FuncInfo, BB, MI);
  }

  LLVM_DEBUG(dbgs() << "DUG after start.\n");
  LLVM_DEBUG(dumpDAG(CurDAG));
  LLVM_DEBUG(dbgs() << "DUG after end.\n");

  // If the current function has return value, records relationship between
  // BasicBlock and each Value which is mapped with R0. In order to record
  // the return Value of each exit BasicBlock.
  Type *RTy = FuncInfo->Fn->getReturnType();
  if (RTy != nullptr && !RTy->isVoidTy() && MBB->succ_size() == 0) {
    auto *Reg = FuncInfo->RegValMap[ARM::R0];
    auto *Val = FuncInfo->getRealValue(Reg);
    Instruction *TInst = dyn_cast<Instruction>(Val);
    assert(TInst && "A def R0 was pointed to a non-instruction!!!");
    BasicBlock *TBB = TInst->getParent();
    FuncInfo->RetValMap[TBB] = TInst;
  }

  // Free the SelectionDAG state, now that we're finished with it.
  CurDAG->clear();
}

#undef DEBUG_TYPE
