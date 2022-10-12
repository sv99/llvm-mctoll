//===- DAGBuilder.cpp - Binary raiser utility llvm-mctoll -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of DAGBuilder class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMMachineInstructionRaiser.h"
#include "FunctionRaisingInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include <vector>

using namespace llvm;
using namespace llvm::mctoll;

#define DEBUG_TYPE "mctoll"

/// Collects the information of each MI to create SDNodes.
SDNode *ARMMachineInstructionRaiser::visit(FunctionRaisingInfo *FuncInfo,
                                           const MachineInstr &MI) {
  std::vector<SDValue> VCtv;
  std::vector<EVT> VCtt;
  auto *DAG = &FuncInfo->getCurDAG();

  for (const MachineOperand MO : MI.operands()) {

    if (MO.isReg() && !MO.isDebug()) {
      EVT Evt = EVT::getEVT(FuncInfo->getDefaultType());
      SDValue Sdv = DAG->getRegister(MO.getReg(), Evt);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isImm()) {
      EVT Evt = FuncInfo->getDefaultEVT();
      SDValue Sdv = DAG->getConstant(MO.getImm(), SDLoc(nullptr, 0), Evt);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isFI()) {
      // Frame index
      int FI = MO.getIndex();
      if (FuncInfo->isStackIndex(FI)) {
        const MachineFrameInfo &MFI = MI.getMF()->getFrameInfo();
        AllocaInst *V = const_cast<AllocaInst *>(MFI.getObjectAllocation(FI));
        EVT Evt = EVT::getEVT(V->getAllocatedType());
        SDValue Sdv = DAG->getFrameIndex(FI, Evt, false);
        FuncInfo->setRealValue(Sdv.getNode(), V);
        VCtv.push_back(Sdv);
        VCtt.push_back(Evt);
      } else if (FuncInfo->isArgumentIndex(FI)) {
        Argument *V =
            const_cast<Argument *>(
            FuncInfo->getRaisedFunction()->arg_begin() + (FI - 1));
        EVT Evt = EVT::getEVT(V->getType());
        SDValue Sdv = DAG->getFrameIndex(FI, Evt, false);
        FuncInfo->setRealValue(Sdv.getNode(), V);
        VCtv.push_back(Sdv);
        VCtt.push_back(Evt);
      } else if (FuncInfo->isReturnIndex(FI)) {
        EVT Evt = EVT::getEVT(FuncInfo->getRaisedFunction()->getReturnType());
        SDValue Sdv = DAG->getFrameIndex(0, Evt, false);
        VCtv.push_back(Sdv);
        VCtt.push_back(Evt);
      } else {
        // Do nothing for now.
      }
    } else if (MO.isJTI()) {
      // Jump table index
      EVT Evt = EVT::getEVT(FuncInfo->getDefaultType());
      SDValue Sdv = DAG->getConstant(MO.getIndex(), SDLoc(nullptr, 0), Evt);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isSymbol()) {
      GlobalVariable *V =
          FuncInfo->getModule()->getNamedGlobal(MO.getSymbolName());
      EVT Evt = EVT::getEVT(V->getValueType(), true);
      SDValue Sdv = DAG->getExternalSymbol(MO.getSymbolName(), Evt);
      FuncInfo->setRealValue(Sdv.getNode(), V);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else if (MO.isMetadata()) {
      const MDNode *MD = MO.getMetadata();
      Type *Ty = Type::getInt64Ty(FuncInfo->getRaisedFunction()->getContext());
      EVT Evt = EVT::getEVT(Ty);
      SDValue Sdv = DAG->getMDNode(MD);
      VCtv.push_back(Sdv);
      VCtt.push_back(Evt);
    } else {
      dbgs() << "Warning: visit. An unmatch type! = "
             << (unsigned)(MO.getType()) << "\n";
    }
  }

  // TODO: Add Glue value property. The cluster of MachineSDNode for schedule
  // with this, but we don't.
  VCtt.push_back(MVT::Glue);

  ArrayRef<SDValue> Ops(VCtv);
  ArrayRef<EVT> VTs(VCtt);

  SDLoc Sdl(nullptr, 0);
  return DAG->getMachineNode(MI.getOpcode(), Sdl, DAG->getVTList(VTs), Ops);
}

#undef DEBUG_TYPE