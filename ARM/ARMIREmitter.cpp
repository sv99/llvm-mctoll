//===- InstSelector.cpp - Binary raiser utility llvm-mctoll ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementaion of InstSelector class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARM.h"
#include "ARMMachineInstructionRaiser.h"
#include "FunctionRaisingInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;
using namespace llvm::mctoll;

/// Checks the SDNode is a function return or not.
bool ARMMachineInstructionRaiser::isReturnNode(FunctionRaisingInfo *FuncInfo,
                                               SDNode *Node) {
  if (!FrameIndexSDNode::classof(Node))
    return false;

  return FuncInfo->isReturnIndex(dyn_cast<FrameIndexSDNode>(Node)->getIndex());
}

/// Record the new defined Node, it uses to map the register number to Node.
/// In DAG emitter, emitter get a value of use base on this defined Node.
void ARMMachineInstructionRaiser::recordDefinition(
    FunctionRaisingInfo *FuncInfo, SDNode *OldNode, SDNode *NewNode) {
  assert(NewNode != nullptr &&
         "The new SDNode ptr is null when record define!");

  if (OldNode == nullptr) {
    outs() << "Warning: RecordDefine error, the SDNode ptr is null!\n";
    return;
  }

  if (RegisterSDNode::classof(OldNode)) {
    Register OpReg = static_cast<RegisterSDNode *>(OldNode)->getReg();
    FuncInfo->setValueByRegister(OpReg, SDValue(NewNode, 0));
    FuncInfo->NodeRegMap[NewNode] = OpReg;
  }

  if (isReturnNode(FuncInfo, OldNode)) {
    FuncInfo->setRetValue(SDValue(NewNode, 0));
    FuncInfo->setValueByRegister(ARM::R0, SDValue(NewNode, 0));
    FuncInfo->NodeRegMap[NewNode] = ARM::R0;
  }
}

/// Gets the Metadata of given SDNode.
SDValue ARMMachineInstructionRaiser::getMDOperand(SDNode *N) {
  for (auto &Sdv : N->ops()) {
    if (MDNodeSDNode::classof(Sdv.getNode())) {
      return Sdv.get();
    }
  }
  assert(false && "Should not run at here!");
  return SDValue();
}

EVT getDefaultEVT(FunctionRaisingInfo *FuncInfo) {
  return EVT::getEVT(FuncInfo->getDefaultType());
}

#define HANDLE_EMIT_CONDCODE_COMMON(OPC)                                       \
  BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());             \
  BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());           \
                                                                               \
  emitCondCode(FuncInfo, CondValue, BB, IfBB, ElseBB);                         \
                                                                               \
  Value *Inst = BinaryOperator::Create##OPC(S0, S1);                           \
  IfBB->getInstList().push_back(dyn_cast<Instruction>(Inst));                  \
  PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,          \
                                      dyn_cast<Instruction>(Inst));            \
  FuncInfo->setRealValue(Node, Phi);                                           \
  FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

#define HANDLE_EMIT_CONDCODE(OPC)                                              \
  HANDLE_EMIT_CONDCODE_COMMON(OPC)                                             \
                                                                               \
  IRB.SetInsertPoint(IfBB);                                                    \
  IRB.CreateBr(ElseBB);                                                        \

/// Emit Instruction and add to BasicBlock.
void ARMMachineInstructionRaiser::emitInstr(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB,
    const MachineInstr &MI) {

  IRBuilder<> IRB(BB);

  NodePropertyInfo *NPI = CreateNPI(MI);
  FuncInfo->NPMap[&MI] = NPI;
  auto *N = visit(FuncInfo, MI);
  auto *CurDAG = &FuncInfo->getCurDAG();
  SDLoc Dl(N);
  SDNode *Node = nullptr;

  switch (MI.getOpcode()) {
  default:
    break;
  /* ADC */
  case ARM::ADCrr:
  case ARM::ADCri:
  case ARM::ADCrsr:
  case ARM::ADCrsi:
  case ARM::tADC:
  case ARM::t2ADCrr:
  case ARM::t2ADCri:
  case ARM::t2ADCrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);
    if (NPI->IsTwoAddress) {
      // ADCS <Rdn>,<Rm>
      // ADC<c> <Rdn>,<Rm>
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::ADDC, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      // ADC{S}<c> <Rd>,<Rn>,#<const>
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::ADDC, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));
    Type *OperandTy = getDefaultType();

    if (NPI->HasCPSR) {
      if (NPI->UpdateCPSR) {
        // Create add emit.
        Value *CFlag =
            callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
        Value *Result = IRB.CreateAdd(S0, S1);
        Value *CZext = IRB.CreateZExt(CFlag, OperandTy);
        Value *InstADC = IRB.CreateAdd(Result, CZext);
        FuncInfo->setRealValue(Node, InstADC);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] =
            dyn_cast<Instruction>(InstADC);

        // Update CPSR.
        // TODO:
        // Should consider how to do this.
        if (1)
          emitCPSR(FuncInfo, S0, S1, BB, 1);
        else
          emitCPSR(FuncInfo, S0, S1, BB, 0);
      } else {
        // Create new BB for EQ instruction execute.
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);

        Value *CFlag =
            callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
        IRB.SetInsertPoint(IfBB);
        Value *InstAdd = IRB.CreateAdd(S0, S1);
        Value *CZext = IRB.CreateZExtOrTrunc(CFlag, OperandTy);
        Value *Inst = IRB.CreateAdd(InstAdd, CZext);
        PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        FuncInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *CFlag =
          callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
      Value *Inst = IRB.CreateAdd(S0, S1);
      Value *CTrunc = IRB.CreateZExtOrTrunc(CFlag, getDefaultType());
      Value *InstADC = IRB.CreateAdd(Inst, CTrunc);

      FuncInfo->setRealValue(Node, InstADC);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = InstADC;
    }
  } break;
  /* ADD */
  case ARM::ADDri:
  case ARM::ADDrr:
  case ARM::ADDrsi:
  case ARM::ADDrsr:
  case ARM::tADDspi:
  case ARM::tADDrSP:
  case ARM::tADDi3:
  case ARM::tADDrSPi:
  case ARM::tADDi8:
  case ARM::tADDhirr:
  case ARM::tADDrr:
  case ARM::tADDspr:
  case ARM::t2ADDrs:
  case ARM::t2ADDri:
  case ARM::t2ADDrr:
  case ARM::t2ADDri12: {
    // TODO:
    // 1. Check out MI is two-address or three-address
    // 2. Do with the displacement operation.(not yet implement.)
    // Judge the MI address module, then check out whether has the imm.
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);
    // <opcode>   {<cond>}{s}<Rd>，<Rn>{，<OP2>}
    if (FrameIndexSDNode::classof(N->getOperand(1).getNode())) {
      Node = CurDAG
                 ->getNode(EXT_ARMISD::LOAD, Dl, getDefaultEVT(FuncInfo), Rn,
                           getMDOperand(N))
                 .getNode();

      recordDefinition(FuncInfo, Rd.getNode(), Node);
      NPI->Node = Node;
      emitLoad(FuncInfo, BB, MI);
    } else {
      if (NPI->IsTwoAddress) {
        if (RegisterSDNode::classof(N->getOperand(1).getNode()))
          Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

        SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
        Node = CurDAG
                   ->getNode(ISD::ADD, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                             getMDOperand(N))
                   .getNode();
      } else {
        SDValue Op2 = N->getOperand(2);
        if (RegisterSDNode::classof(Op2.getNode()))
          Op2 = FuncInfo->getValFromRegMap(Op2);

        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
        Node = CurDAG
                   ->getNode(ISD::ADD, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                             getMDOperand(N))
                   .getNode();
      }

      recordDefinition(FuncInfo, Rd.getNode(), Node);
      NPI->Node = Node;
      emitBinaryAdd(FuncInfo, BB, MI);
    }
  } break;
  /* SUB */
  case ARM::SUBri:
  case ARM::SUBrr:
  case ARM::SUBrsi:
  case ARM::SUBrsr:
  case ARM::tSUBi3:
  case ARM::tSUBi8:
  case ARM::tSUBrr:
  case ARM::tSUBspi:
  case ARM::t2SUBri:
  case ARM::t2SUBri12:
  case ARM::t2SUBrr:
  case ARM::t2SUBrs:
  case ARM::t2SUBS_PC_LR: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);
    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::SUB, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);

      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::SUB, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinarySub(FuncInfo, BB, MI);
  } break;
  /* MOV */
  case ARM::MOVi16:
  case ARM::t2MOVi16:
  case ARM::MOVi32imm:
  case ARM::tMOVr:
  case ARM::MOVr:
  case ARM::t2MOVi:
  case ARM::t2MOVr:
  case ARM::MOVCCr:
  case ARM::t2MOVCCr:
  case ARM::t2MOVi32imm:
  case ARM::MOVTi16:
  case ARM::MOVi: {
    // Dispalcement operation need do.
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);
    if (RegisterSDNode::classof(Rn.getNode()))
      Rn = FuncInfo->getValFromRegMap(Rn);

    Node = CurDAG
               ->getNode(ARMISD::CMOV, Dl, getDefaultEVT(FuncInfo), Rn,
                         CurDAG->getConstant(0, Dl, getDefaultEVT(FuncInfo)))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryAdd(FuncInfo, BB, MI);
  } break;
  /* STR */
  case ARM::STRi12:
  case ARM::STRrs:
  case ARM::STRD:
  case ARM::STRD_POST:
  case ARM::STRD_PRE:
  case ARM::t2STREXD:
  case ARM::STREXB:
  case ARM::STREXD:
  case ARM::STREXH:
  case ARM::STREX:
  case ARM::STR_PRE_IMM:
  case ARM::STR_PRE_REG:
  case ARM::STR_POST_IMM:
  case ARM::STR_POST_REG: {
    SDValue Val = N->getOperand(0);
    SDValue Ptr = N->getOperand(1); // This is a pointer.

    if (RegisterSDNode::classof(Val.getNode()))
      Val = FuncInfo->getValFromRegMap(Val);

    if (RegisterSDNode::classof(Ptr.getNode()))
      Ptr = FuncInfo->getValFromRegMap(Ptr);

    Node = CurDAG
               ->getNode(EXT_ARMISD::STORE, Dl, getDefaultEVT(FuncInfo), Val,
                         Ptr, getMDOperand(N))
               .getNode();

    NPI->Node = Node;
    emitStore(FuncInfo, BB, MI);
  } break;
  case ARM::STRH:
  case ARM::STRH_PRE:
  case ARM::STRH_POST: {
    EVT InstTy = EVT::getEVT(Type::getInt16Ty(*CurDAG->getContext()));
    SDValue Val = N->getOperand(0);
    SDValue Op1 = N->getOperand(1);

    if (RegisterSDNode::classof(Val.getNode()))
      Val = FuncInfo->getValFromRegMap(Val);

    if (RegisterSDNode::classof(Op1.getNode()))
      Op1 = FuncInfo->getValFromRegMap(Op1);

    if (N->getNumOperands() < 5) {
      Node = CurDAG
                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      Op2 = FuncInfo->getValFromRegMap(Op2);
      Node = CurDAG
                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1, Op2,
                           getMDOperand(N))
                 .getNode();
    }

    NPI->Node = Node;
    emitStore(FuncInfo, BB, MI);
  } break;
  case ARM::STRBi12:
  case ARM::STRBrs:
  case ARM::STRB_PRE_IMM:
  case ARM::STRB_PRE_REG:
  case ARM::STRB_POST_IMM:
  case ARM::STRB_POST_REG: {
    EVT InstTy = EVT::getEVT(Type::getInt8Ty(*CurDAG->getContext()));
    SDValue Val = N->getOperand(0);
    SDValue Op1 = N->getOperand(1);

    if (RegisterSDNode::classof(Val.getNode()))
      Val = FuncInfo->getValFromRegMap(Val);

    if (RegisterSDNode::classof(Op1.getNode()))
      Op1 = FuncInfo->getValFromRegMap(Op1);

    if (N->getNumOperands() < 5) {
      Node = CurDAG
                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      Op2 = FuncInfo->getValFromRegMap(Op2);
      Node = CurDAG
                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1, Op2,
                           getMDOperand(N))
                 .getNode();
    }

    NPI->Node = Node;
    emitStore(FuncInfo, BB, MI);
  } break;
  /* LDR */
  case ARM::LDRi12:
  case ARM::LDRrs:
  case ARM::t2LDR_PRE:
  case ARM::t2LDR_POST:
  case ARM::tLDR_postidx:
  case ARM::LDR_PRE_IMM:
  case ARM::LDR_PRE_REG:
  case ARM::LDR_POST_IMM:
  case ARM::LDR_POST_REG: {
    EVT InstTy = EVT::getEVT(Type::getInt32Ty(*CurDAG->getContext()));
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(Rn.getNode()))
      Rn = FuncInfo->getValFromRegMap(Rn);

    Node = CurDAG->getNode(EXT_ARMISD::LOAD, Dl, InstTy, Rn, getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitLoad(FuncInfo, BB, MI);
  } break;
  case ARM::LDRH:
  case ARM::LDRSH:
  case ARM::t2LDRSH_PRE:
  case ARM::t2LDRSH_POST:
  case ARM::t2LDRH_PRE:
  case ARM::t2LDRH_POST:
  case ARM::LDRSH_PRE:
  case ARM::LDRSH_POST: {
    EVT InstTy = EVT::getEVT(Type::getInt16Ty(*CurDAG->getContext()));
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(Rn.getNode()))
      Rn = FuncInfo->getValFromRegMap(Rn);

    Node = CurDAG->getNode(EXT_ARMISD::LOAD, Dl, InstTy, Rn, getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitLoad(FuncInfo, BB, MI);
  } break;
  case ARM::LDRBi12:
  case ARM::LDRBrs:
  case ARM::t2LDRSB_PRE:
  case ARM::t2LDRSB_POST:
  case ARM::t2LDRB_PRE:
  case ARM::t2LDRB_POST:
  case ARM::LDRSB_PRE:
  case ARM::LDRSB_POST:
  case ARM::LDRB_PRE_IMM:
  case ARM::LDRB_POST_IMM:
  case ARM::LDRB_PRE_REG:
  case ARM::LDRB_POST_REG: {
    EVT InstTy = EVT::getEVT(Type::getInt8Ty(*CurDAG->getContext()));
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(Rn.getNode()))
      Rn = FuncInfo->getValFromRegMap(Rn);

    Node = CurDAG->getNode(EXT_ARMISD::LOAD, Dl, InstTy, Rn, getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitLoad(FuncInfo, BB, MI);
  } break;
  /* Branch */
  case ARM::Bcc:
  case ARM::tBcc:
  case ARM::t2Bcc: {
    SDValue Iftrue = N->getOperand(0);
    SDValue Cond = N->getOperand(1);

    if (NPI->HasCPSR) {
      Node = CurDAG
                 ->getNode(ISD::BRCOND, Dl, getDefaultEVT(FuncInfo), Iftrue,
                           Cond, getMDOperand(N))
                 .getNode();

      const MachineBasicBlock *LMBB = MI.getParent();
      if (LMBB->succ_size() == 0) {
        FuncInfo->setValueByRegister(ARM::R0, SDValue(Node, 0));
        FuncInfo->NodeRegMap[Node] = ARM::R0;
      }
      NPI->Node = Node;
      unsigned CondVal = cast<ConstantSDNode>(Node->getOperand(1))->getZExtValue();
      // br i1 %cmp, label %if.then, label %if.else
      MachineBasicBlock *MBB = FuncInfo->MBBMap[BB];
      MachineBasicBlock::succ_iterator SuI = MBB->succ_begin();
      BasicBlock *IfTrueP = FuncInfo->getOrCreateBasicBlock(*SuI);
      MachineBasicBlock *NextMBB = &*std::next(MBB->getIterator());
      BasicBlock *NextBB = FuncInfo->getOrCreateBasicBlock(NextMBB);

      emitCondCode(FuncInfo, CondVal, BB, IfTrueP, NextBB);
    } else {
      Node = CurDAG
                 ->getNode(ISD::BR, Dl, getDefaultEVT(FuncInfo), Iftrue,
                           getMDOperand(N))
                 .getNode();

      const MachineBasicBlock *LMBB = MI.getParent();
      if (LMBB->succ_size() == 0) {
        FuncInfo->setValueByRegister(ARM::R0, SDValue(Node, 0));
        FuncInfo->NodeRegMap[Node] = ARM::R0;
      }
      NPI->Node = Node;
      // br label %xxx
      MachineBasicBlock *LMBBVal = FuncInfo->MBBMap[BB];
      MachineBasicBlock::succ_iterator SuI = LMBBVal->succ_begin();
      if (SuI != LMBBVal->succ_end()) {
        BasicBlock *BrDest = FuncInfo->getOrCreateBasicBlock(*SuI);
        IRB.CreateBr(BrDest);
      } else {
        emitBRD(FuncInfo, BB, MI);
      }
    }
  } break;
  case ARM::B:
  case ARM::tB:
  case ARM::t2B: {
    SDValue BrBlock = N->getOperand(0);
    Node = CurDAG
               ->getNode(ISD::BR, Dl, getDefaultEVT(FuncInfo), BrBlock,
                         getMDOperand(N))
               .getNode();

    NPI->Node = Node;
    // br label %xxx
    MachineBasicBlock *LMBBVal = FuncInfo->MBBMap[BB];
    MachineBasicBlock::succ_iterator SuI = LMBBVal->succ_begin();
    if (SuI != LMBBVal->succ_end()) {
      BasicBlock *BrDest = FuncInfo->getOrCreateBasicBlock(*SuI);
      IRB.CreateBr(BrDest);
    } else {
      emitBRD(FuncInfo, BB, MI);
    }
  } break;
  case ARM::BL:
  case ARM::BL_pred:
  case ARM::tBL: {
    SDValue Func = N->getOperand(0);

    if (RegisterSDNode::classof(Func.getNode())) {
      Func = FuncInfo->getValFromRegMap(Func);
      Node = CurDAG
                 ->getNode(ISD::BRIND, Dl, getDefaultEVT(FuncInfo), Func,
                           getMDOperand(N))
                 .getNode();

      FuncInfo->setValueByRegister(ARM::R0, SDValue(Node, 0));
      FuncInfo->NodeRegMap[Node] = ARM::R0;
      NPI->Node = Node;
      Value *FuncVal = getIRValue(FuncInfo, Node->getOperand(0));
      unsigned NumDests = Node->getNumOperands();
      IRB.CreateIndirectBr(FuncVal, NumDests);
    } else {
      Node = CurDAG
                 ->getNode(EXT_ARMISD::BRD, Dl, getDefaultEVT(FuncInfo), Func,
                           getMDOperand(N))
                 .getNode();

      FuncInfo->setValueByRegister(ARM::R0, SDValue(Node, 0));
      FuncInfo->NodeRegMap[Node] = ARM::R0;
      NPI->Node = Node;
      emitBRD(FuncInfo, BB, MI);
    }
  } break;
  case ARM::BLX:
  case ARM::BLXi:
  case ARM::BLX_pred:
  case ARM::tBLXi:
  case ARM::tBLXr: {
    // outs() << "WARNING: ARM::BLX Not yet implemented!\n";
    SDValue Func = N->getOperand(0);

    if (RegisterSDNode::classof(Func.getNode())) {
      Func = FuncInfo->getValFromRegMap(Func);
      Node = CurDAG
                 ->getNode(ISD::BRIND, Dl, getDefaultEVT(FuncInfo), Func,
                           getMDOperand(N))
                 .getNode();

      FuncInfo->setValueByRegister(ARM::R0, SDValue(Node, 0));
      FuncInfo->NodeRegMap[Node] = ARM::R0;
      NPI->Node = Node;
      Value *FuncVal = getIRValue(FuncInfo, Node->getOperand(0));
      unsigned NumDests = Node->getNumOperands();
      IRB.CreateIndirectBr(FuncVal, NumDests);
    } else {
      Node = CurDAG
                 ->getNode(EXT_ARMISD::BRD, Dl, getDefaultEVT(FuncInfo), Func,
                           getMDOperand(N))
                 .getNode();

      FuncInfo->setValueByRegister(ARM::R0, SDValue(Node, 0));
      FuncInfo->NodeRegMap[Node] = ARM::R0;
      NPI->Node = Node;
      emitBRD(FuncInfo, BB, MI);
    }
  } break;
  case ARM::BR_JTr: {
    SDValue Rd = N->getOperand(0);

    Node = CurDAG
               ->getNode(ISD::BR_JT, Dl, getDefaultEVT(FuncInfo), Rd,
                         getMDOperand(N))
               .getNode();

    NPI->Node = Node;
    // Emit the switch instruction.
    if (JTList.size() > 0) {
      MachineBasicBlock *Mbb = FuncInfo->MBBMap[BB];
      MachineFunction *MF = Mbb->getParent();

      std::vector<JumpTableBlock> JTCases;
      const MachineJumpTableInfo *MJT = MF->getJumpTableInfo();
      unsigned JTIndex = Node->getConstantOperandVal(0);
      std::vector<MachineJumpTableEntry> JumpTables = MJT->getJumpTables();
      for (unsigned Idx = 0, MBBSz = JumpTables[JTIndex].MBBs.size(); Idx != MBBSz; ++Idx) {
        llvm::Type *I32Type = llvm::IntegerType::getInt32Ty(Ctx);
        llvm::ConstantInt *I32Val =
            cast<ConstantInt>(llvm::ConstantInt::get(I32Type, Idx, true));
        MachineBasicBlock *Succ = JumpTables[JTIndex].MBBs[Idx];
        ConstantInt *CaseVal = I32Val;
        JTCases.push_back(std::make_pair(CaseVal, Succ));
      }
      // main->getEntryBlock().setName("entry");

      unsigned int NumCases = JTCases.size();
      BasicBlock *DefBB =
          FuncInfo->getOrCreateBasicBlock(JTList[JTIndex].DefaultMBB);

      BasicBlock *CondBB =
          FuncInfo->getOrCreateBasicBlock(JTList[JTIndex].ConditionMBB);

      // condition instruction
      Instruction *CondInst = nullptr;
      for (BasicBlock::iterator DI = CondBB->begin(); DI != CondBB->end(); DI++) {
        Instruction *Ins = dyn_cast<Instruction>(DI);
        if (isa<LoadInst>(DI) && !CondInst) {
          CondInst = Ins;
        }

        if (CondInst && (Ins->getOpcode() == Instruction::Sub)) {
          if (isa<ConstantInt>(Ins->getOperand(1))) {
            ConstantInt *IntOp = dyn_cast<ConstantInt>(Ins->getOperand(1));
            if (IntOp->uge(0)) {
              CondInst = Ins;
            }
          }
        }
      }

      SwitchInst *Inst = IRB.CreateSwitch(CondInst, DefBB, NumCases);
      for (unsigned Idx = 0, Cnt = NumCases; Idx != Cnt; ++Idx) {
        BasicBlock *CaseBB =
            FuncInfo->getOrCreateBasicBlock(JTCases[Idx].second);
        Inst->addCase(JTCases[Idx].first, CaseBB);
      }
    }
  } break;
  case ARM::BX:
  case ARM::BX_CALL:
  case ARM::BX_pred:
  case ARM::tBX:
  case ARM::tBX_CALL: {
    SDValue CallReg = N->getOperand(0);
    if (RegisterSDNode::classof(CallReg.getNode()))
      CallReg = FuncInfo->getValFromRegMap(CallReg);

    Node = CurDAG
               ->getNode(ISD::BRIND, Dl, getDefaultEVT(FuncInfo), CallReg,
                         getMDOperand(N))
               .getNode();

    NPI->Node = Node;
    Value *FuncVal = getIRValue(FuncInfo, Node->getOperand(0));
    unsigned NumDests = Node->getNumOperands();
    IRB.CreateIndirectBr(FuncVal, NumDests);
  } break;
  case ARM::BX_RET:
  case ARM::tBX_RET:
    // assert(0 && "Branch instructions are removed in previous stage. should
    // not get here!");
    break;
  case ARM::tCMPhir:
  case ARM::CMPrr:
  case ARM::t2CMPri:
  case ARM::CMPri:
  case ARM::tCMPi8:
  case ARM::t2CMPrr:
  case ARM::tCMPr: {
    SDValue Cmpl = N->getOperand(0);
    SDValue Cmph = N->getOperand(1);
    if (RegisterSDNode::classof(Cmph.getNode()))
      Cmph = FuncInfo->getValFromRegMap(N->getOperand(1));
    Cmpl = FuncInfo->getValFromRegMap(Cmpl);

    // Create condition SDValuleR
    // TODO: It should be verified why this type node can not be added Metadata
    // Operand.
    Node = CurDAG
               ->getNode(ISD::SETCC, Dl, getDefaultEVT(FuncInfo), Cmpl, Cmph
                         /* , getMDOperand(N) */)
               .getNode();

    NPI->Node = Node;
  } break;
  /* AND */
  case ARM::ANDri:
  case ARM::ANDrr:
  case ARM::ANDrsi:
  case ARM::ANDrsr:
  case ARM::tAND:
  case ARM::t2ANDri:
  case ARM::t2ANDrr:
  case ARM::t2ANDrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      // AND<c> <Rdn>,<Rm>
      // ANDS <Rdn>,<Rm>
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::AND, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      // AND{S}<c> <Rd>,<Rn>,#<const>
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);

      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::AND, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryAnd(FuncInfo, BB, MI);
    // TODO:
    // AND{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
    // AND{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}
    // AND{S}<c> <Rd>,<Rn>,<Rm>,<type> <Rs>
  } break;
  /* ASR */
  case ARM::ASRr:
  case ARM::ASRi:
  case ARM::tASRrr:
  case ARM::tASRri:
  case ARM::t2ASRrr:
  case ARM::t2ASRri: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::SRA, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);

      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::SRA, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryAShr(FuncInfo, BB, MI);
  } break;
  /* CMN */
  case ARM::CMNri:
  case ARM::CMNzrr:
  case ARM::tCMNz:
  case ARM::t2CMNri:
  case ARM::t2CMNzrr:
  case ARM::t2CMNzrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(N->getOperand(1).getNode()))
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
    Rd = FuncInfo->getValFromRegMap(Rd);
    Node = CurDAG
               ->getNode(ARMISD::CMN, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                         getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));
    if (NPI->HasCPSR) {
      unsigned CondValue = NPI->Cond;
      HANDLE_EMIT_CONDCODE_COMMON(Add)
      emitCPSR(FuncInfo, S0, S1, IfBB, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      Value *Inst = IRB.CreateAdd(S0, S1);
      FuncInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
      emitCPSR(FuncInfo, S0, S1, BB, 0);
    }
  } break;
  /* EOR */
  case ARM::EORri:
  case ARM::EORrr:
  case ARM::EORrsi:
  case ARM::EORrsr:
  case ARM::tEOR:
  case ARM::t2EORrr:
  case ARM::t2EORrs:
  case ARM::t2EORri: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      // EORS <Rdn>,<Rm>
      // EOR<c> <Rdn>,<Rm>
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::XOR, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      // EOR{S}<c> <Rd>,<Rn>,#<const>
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::XOR, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryXor(FuncInfo, BB, MI);
    // TODO:
    // EOR{S}<c>.W <Rd>,<Rn>,<Rm>{,<shift>}
    // EOR{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}
    // EOR{S}<c> <Rd>,<Rn>,<Rm>,<type> <Rs>
  } break;
  /* MSR */
  case ARM::MSR:
  case ARM::MSRi:
  case ARM::MSRbanked:
  case ARM::t2MSR_M:
  case ARM::t2MSR_AR:
  case ARM::t2MSRbanked: {
    // Update the CPSR.
    SDValue Cond = N->getOperand(1);

    if (RegisterSDNode::classof(N->getOperand(1).getNode()))
      Cond = FuncInfo->getValFromRegMap(N->getOperand(1));

    Node = CurDAG
               ->getNode(EXT_ARMISD::MSR, Dl, getDefaultEVT(FuncInfo), Cond,
                         getMDOperand(N))
               .getNode();

    NPI->Node = Node;
    Value *CondVal = getIRValue(FuncInfo, Node->getOperand(0));
    // 1 1 1 1
    // N set 1 0 0 0   8
    // Z set 0 1 0 0   4
    // C set 0 0 1 0   2
    // Z set 0 0 0 1   1
    IRB.CreateStore(CondVal, dyn_cast<Value>(M->getGlobalVariable("Reserved")));
    // Pattern msr CPSR_f, Rn
    if (1) {
      Value *ShiftNum = IRB.getInt32(28);
      Value *Shift = IRB.CreateLShr(CondVal, ShiftNum);
      // Update N Flag.
      Value *NCmp = IRB.getInt32(8);
      Value *NFlag = IRB.CreateICmpEQ(Shift, NCmp);
      IRB.CreateStore(NFlag, FuncInfo->AllocaMap[0]);
      // Update Z Flag.
      Value *ZCmp = IRB.getInt32(4);
      Value *ZFlag = IRB.CreateICmpEQ(Shift, ZCmp);
      IRB.CreateStore(ZFlag, FuncInfo->AllocaMap[1]);
      // Update C Flag.
      Value *CCmp = IRB.getInt32(2);
      Value *CFlag = IRB.CreateICmpEQ(Shift, CCmp);
      IRB.CreateStore(CFlag, FuncInfo->AllocaMap[2]);
      // Update V Flag.
      Value *VCmp = IRB.getInt32(1);
      Value *VFlag = IRB.CreateICmpEQ(Shift, VCmp);
      IRB.CreateStore(VFlag, FuncInfo->AllocaMap[3]);
    } else {
      // Pattern msr CSR_f, #const.
    }
  } break;
  /* MUL */
  case ARM::MUL:
  case ARM::tMUL:
  case ARM::t2MUL: {
    /* MULS <Rd>, <Rn>, <Rm> */
    /* MUL<c> <Rd>, <Rn>, <Rm> */
    /* MUL{S}<c> <Rd>, <Rn>, <Rm> */
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    SDValue Op2 = N->getOperand(2);
    Op2 = FuncInfo->getValFromRegMap(Op2);
    Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
    Node = CurDAG
               ->getNode(ISD::MUL, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                         getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryMul(FuncInfo, BB, MI);
  } break;
  /* MVN */
  case ARM::MVNi:
  case ARM::MVNr:
  case ARM::MVNsi:
  case ARM::MVNsr:
  case ARM::tMVN:
  case ARM::t2MVNi:
  case ARM::t2MVNr:
  case ARM::t2MVNs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(N->getOperand(1).getNode()))
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

    Node = CurDAG
               ->getNode(ISD::XOR, Dl, getDefaultEVT(FuncInfo), Rn,
                         CurDAG->getConstant(-1, Dl, getDefaultEVT(FuncInfo)))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
  } break;
  /* LSL */
  case ARM::LSLi:
  case ARM::LSLr:
  case ARM::tLSLri:
  case ARM::tLSLrr:
  case ARM::t2LSLri:
  case ARM::t2LSLrr: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::SHL, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);

      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::SHL, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryShl(FuncInfo, BB, MI);
  } break;
  /* LSR */
  case ARM::LSRi:
  case ARM::LSRr:
  case ARM::tLSRri:
  case ARM::tLSRrr:
  case ARM::t2LSRri:
  case ARM::t2LSRrr: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::SRL, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::SRL, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryLShr(FuncInfo, BB, MI);
  } break;
  /* ORR */
  case ARM::ORRri:
  case ARM::ORRrr:
  case ARM::ORRrsi:
  case ARM::ORRrsr:
  case ARM::tORR:
  case ARM::t2ORRri:
  case ARM::t2ORRrr:
  case ARM::t2ORRrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    // <opcode>   {<cond>}{s}<Rd>，<Rn>{，<OP2>}
    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::OR, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);

      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::OR, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    emitBinaryOr(FuncInfo, BB, MI);
  } break;
  /* ROR */
  case ARM::RORi:
  case ARM::RORr:
  case ARM::tROR:
  case ARM::t2RORri:
  case ARM::t2RORrr: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(ISD::ROTR, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(ISD::ROTR, Dl, getDefaultEVT(FuncInfo), Rn, Op2,
                           getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));
    Type *Ty = getDefaultType();
    Value *Val = ConstantInt::get(Ty, 32, true);

    if (NPI->HasCPSR) {
      if (NPI->UpdateCPSR) {
        Value *InstSub = IRB.CreateSub(Val, S1);
        Value *InstLShr = IRB.CreateLShr(S0, S1);
        Value *InstShl = IRB.CreateShl(S0, InstSub);
        Value *Inst = IRB.CreateOr(InstLShr, InstShl);
        FuncInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        emitSpecialCPSR(FuncInfo, Inst, BB, 0);
      } else {
        // Create new BB for EQ instruction execute.
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);
        IRB.SetInsertPoint(IfBB);
        Value *InstSub = IRB.CreateSub(Val, S1);
        Value *InstLShr = IRB.CreateLShr(S0, S1);
        Value *InstShl = IRB.CreateShl(S0, InstSub);
        Value *Inst = IRB.CreateOr(InstLShr, InstShl);
        PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        FuncInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstSub = IRB.CreateSub(Val, S1);
      Value *InstLShr = IRB.CreateLShr(S0, S1);
      Value *InstShl = IRB.CreateShl(S0, InstSub);
      Value *Inst = IRB.CreateOr(InstLShr, InstShl);
      FuncInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  /* RRX */
  case ARM::RRX: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

    Node = CurDAG
               ->getNode(ARMISD::RRX, Dl, getDefaultEVT(FuncInfo), Rn,
                         getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Type *Ty = getDefaultType();
    Value *Val1 = ConstantInt::get(Ty, 1, true);
    Value *Val2 = ConstantInt::get(Ty, 31, true);
    if (NPI->HasCPSR) {
      if (NPI->UpdateCPSR) {
        Value *InstLShr = IRB.CreateLShr(S0, Val1);
        Value *CFlag =
            callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
        CFlag = IRB.CreateZExt(CFlag, Ty);
        Value *Bit31 = IRB.CreateShl(CFlag, Val2);
        Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
        FuncInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        /**************************************/
        emitSpecialCPSR(FuncInfo, Inst, BB, 0);
        // Update C flag.
        // c flag = s0[0]
        CFlag = IRB.CreateAnd(S0, Val1);
        IRB.CreateStore(CFlag, FuncInfo->AllocaMap[2]);
      } else {
        // Create new BB for EQ instruction execute.
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);
        IRB.SetInsertPoint(IfBB);
        Value *InstLShr = IRB.CreateLShr(S0, Val1);
        Value *CFlag = nullptr;

        CFlag =
            callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
        CFlag = IRB.CreateZExt(CFlag, Ty);
        Value *Bit31 = IRB.CreateShl(CFlag, Val2);
        Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
        PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        FuncInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstLShr = IRB.CreateLShr(S0, Val1);
      Value *CFlag =
          callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
      CFlag = IRB.CreateZExt(CFlag, Ty);
      Value *Bit31 = IRB.CreateShl(CFlag, Val2);
      Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
      FuncInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  /* RSB */
  case ARM::RSBri:
  case ARM::RSBrr:
  case ARM::RSBrsi:
  case ARM::RSBrsr:
  case ARM::tRSB:
  case ARM::t2RSBri:
  case ARM::t2RSBrr:
  case ARM::t2RSBrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(EXT_ARMISD::RSB, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(EXT_ARMISD::RSB, Dl, getDefaultEVT(FuncInfo), Op2,
                           Rn, getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));

    if (NPI->HasCPSR) {
      unsigned CondValue = NPI->Cond;
      if (NPI->UpdateCPSR) {
        // Create add emit.
        Value *Inst = IRB.CreateSub(S0, S1);
        FuncInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        Value *InstNot = IRB.CreateNot(S1);
        emitCPSR(FuncInfo, InstNot, S0, BB, 1);
      } else {
        HANDLE_EMIT_CONDCODE(Sub)
      }
    } else {
      Value *Inst = IRB.CreateSub(S0, S1);
      FuncInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  /* RSC */
  case ARM::RSCri:
  case ARM::RSCrr:
  case ARM::RSCrsi:
  case ARM::RSCrsr: {
    // RSC{S}<c> <Rd>,<Rn>, #0
    // RSC{S}<c>.W <Rd>,<Rn>,#<const>
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(EXT_ARMISD::RSC, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(EXT_ARMISD::RSC, Dl, getDefaultEVT(FuncInfo), Rn,
                           Op2, getMDOperand(N))
                 .getNode();
    }
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));

    Value *CFlag =
        callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
    Value *CZext = IRB.CreateZExt(CFlag, getDefaultType());

    Value *Inst = IRB.CreateAdd(S0, CZext);
    Inst = IRB.CreateSub(S1, Inst);
    FuncInfo->setRealValue(Node, Inst);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
  } break;
  /* CLZ */
  case ARM::CLZ:
  case ARM::t2CLZ: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

    Node = CurDAG
               ->getNode(ISD::CTLZ, Dl, getDefaultEVT(FuncInfo), Rn,
                         getMDOperand(N))
               .getNode();
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Function *CTLZ = Intrinsic::getDeclaration(BB->getParent()->getParent(),
                                               Intrinsic::ctlz, S0->getType());
    Type *I1ype = llvm::IntegerType::getInt1Ty(Ctx);
    Value *IsZeroUndef = ConstantInt::get(I1ype, true, true);

    std::vector<Value *> Vec;
    Vec.push_back(S0);
    Vec.push_back(IsZeroUndef);
    ArrayRef<Value *> Args(Vec);

    Value *Inst = IRB.CreateCall(CTLZ, Args);
    FuncInfo->setRealValue(Node, Inst);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
  } break;
  /* SBC */
  case ARM::SBCrr:
  case ARM::SBCri:
  case ARM::tSBC: {
    SDValue Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
    SDValue Operand2 = FuncInfo->getValFromRegMap(N->getOperand(2));
    Node = CurDAG
               ->getNode(EXT_ARMISD::SBC, Dl, getDefaultEVT(FuncInfo), Rn,
                         Operand2, getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rn.getNode(), Node);
    NPI->Node = Node;
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S2 = getIRValue(FuncInfo, Node->getOperand(1));
    Type *Ty = getDefaultType();

    if (NPI->HasCPSR) {
      if (NPI->UpdateCPSR) {
        Value *InstSub = IRB.CreateSub(S1, S2);
        Value *CFlag = nullptr;
        CFlag =
            callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
        Value *CZext = IRB.CreateZExt(CFlag, Ty);
        Value *InstSBC = IRB.CreateAdd(InstSub, CZext);
        FuncInfo->setRealValue(Node, InstSBC);
        Value *InstNot = IRB.CreateNot(S2);
        if (1)
          emitCPSR(FuncInfo, S1, InstNot, BB, 0);
        else
          emitCPSR(FuncInfo, S1, InstNot, BB, 1);
      } else {
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);

        IRB.SetInsertPoint(IfBB);
        Value *InstSub = IRB.CreateSub(S1, S2);
        Value *CFlag = nullptr;
        CFlag =
            callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
        Value *CZext = IRB.CreateZExt(CFlag, Ty);
        Value *Inst = IRB.CreateAdd(InstSub, CZext);
        PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        FuncInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstSub = IRB.CreateSub(S1, S2);
      Value *CFlag = nullptr;
      CFlag =
          callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
      Value *CZext = IRB.CreateZExt(CFlag, Ty);
      Value *InstSBC = IRB.CreateAdd(InstSub, CZext);
      FuncInfo->setRealValue(Node, InstSBC);
    }
  } break;
  /* TEQ */
  case ARM::TEQri:
  case ARM::TEQrr:
  case ARM::TEQrsi:
  case ARM::TEQrsr:
  case ARM::t2TEQri:
  case ARM::t2TEQrr:
  case ARM::t2TEQrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(N->getOperand(1).getNode()))
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

    Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
    Node = CurDAG
               ->getNode(EXT_ARMISD::TEQ, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                         getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));

    if (NPI->HasCPSR) {
      // Create new BB for EQ instruction execute.
      BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

      // TODO:
      // This instruction not change def, consider phi later.

      emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);
      IRB.SetInsertPoint(IfBB);
      Value *Inst = IRB.CreateXor(S0, S1);
      emitSpecialCPSR(FuncInfo, Inst, IfBB, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      Value *Inst = IRB.CreateXor(S0, S1);
      emitSpecialCPSR(FuncInfo, Inst, BB, 0);
    }
  } break;
  /* TST */
  case ARM::TSTrsi:
  case ARM::TSTrr:
  case ARM::TSTri:
  case ARM::TSTrsr:
  case ARM::tTST:
  case ARM::t2TSTri:
  case ARM::t2TSTrr:
  case ARM::t2TSTrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (RegisterSDNode::classof(N->getOperand(1).getNode()))
      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

    Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
    Node = CurDAG
               ->getNode(EXT_ARMISD::TST, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                         getMDOperand(N))
               .getNode();

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));

    if (NPI->HasCPSR) {
      // Create new BB for EQ instruction execute.
      BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

      // TODO:
      // Not change def. Consider how to use PHI.
      // PHINode *Phi = createAndEmitPHINode(Node, BB, ElseBB);

      emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);
      IRB.SetInsertPoint(IfBB);
      Value *Inst = IRB.CreateAnd(S0, S1);
      emitSpecialCPSR(FuncInfo, Inst, IfBB, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);
    } else {
      Value *Inst = IRB.CreateAnd(S0, S1);
      emitSpecialCPSR(FuncInfo, Inst, BB, 0);
    }
  } break;
  /* BIC */
  case ARM::BICri:
  case ARM::BICrr:
  case ARM::BICrsi:
  case ARM::BICrsr:
  case ARM::tBIC:
  case ARM::t2BICri:
  case ARM::t2BICrr:
  case ARM::t2BICrs: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = N->getOperand(1);

    if (NPI->IsTwoAddress) {
      if (RegisterSDNode::classof(N->getOperand(1).getNode()))
        Rn = FuncInfo->getValFromRegMap(N->getOperand(1));

      SDValue Rd = FuncInfo->getValFromRegMap(N->getOperand(0));
      Node = CurDAG
                 ->getNode(EXT_ARMISD::BIC, Dl, getDefaultEVT(FuncInfo), Rd, Rn,
                           getMDOperand(N))
                 .getNode();
    } else {
      SDValue Op2 = N->getOperand(2);
      if (RegisterSDNode::classof(Op2.getNode()))
        Op2 = FuncInfo->getValFromRegMap(Op2);

      Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
      Node = CurDAG
                 ->getNode(EXT_ARMISD::BIC, Dl, getDefaultEVT(FuncInfo), Rn,
                           Op2, getMDOperand(N))
                 .getNode();
    }

    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));
    Type *Ty = getDefaultType();
    Value *Val = ConstantInt::get(Ty, -1, true);

    if (NPI->HasCPSR) {
      if (NPI->UpdateCPSR) {
        Value *InstXor = IRB.CreateXor(Val, S1);
        Value *Inst = IRB.CreateAnd(S0, InstXor);

        FuncInfo->setRealValue(Node, Inst);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;

        emitSpecialCPSR(FuncInfo, Inst, BB, 0);
        // Update C flag.
        // C flag not change.

        // Update V flag.
        // unchanged.
      } else {
        // Create new BB for EQ instruction execute.
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Emit the condition code.
        emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);
        IRB.SetInsertPoint(IfBB);
        Value *InstXor = IRB.CreateXor(Val, S1);
        Value *Inst = IRB.CreateAnd(S0, InstXor);
        PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        FuncInfo->setRealValue(Node, Phi);
        FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Phi;

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstXor, *Inst;
      InstXor = IRB.CreateXor(Val, S1);
      Inst = IRB.CreateAnd(S0, InstXor);
      FuncInfo->setRealValue(Node, Inst);
      FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
    }
  } break;
  /* MLA */
  case ARM::MLA:
  case ARM::t2MLA: {
    SDValue Rd = N->getOperand(0);
    SDValue Rn = FuncInfo->getValFromRegMap(N->getOperand(1));
    SDValue Rm = FuncInfo->getValFromRegMap(N->getOperand(2));
    SDValue Ra = FuncInfo->getValFromRegMap(N->getOperand(3));

    Node = CurDAG
               ->getNode(EXT_ARMISD::MLA, Dl, getDefaultEVT(FuncInfo), Rn, Rm,
                         Ra, getMDOperand(N))
               .getNode();
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S0 = getIRValue(FuncInfo, Node->getOperand(0));
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));
    Value *S2 = getIRValue(FuncInfo, Node->getOperand(2));

    Value *InstMul = IRB.CreateMul(S0, S1);
    Value *Inst = IRB.CreateAdd(InstMul, S2);

    FuncInfo->setRealValue(Node, Inst);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = Inst;
  } break;
  /* UXTB */
  case ARM::UXTB: {
    SDValue Rd = N->getOperand(0);
    SDValue Rm = N->getOperand(1);
    SDValue Rotation = N->getOperand(2);

    if (RegisterSDNode::classof(N->getOperand(1).getNode()))
      Rm = FuncInfo->getValFromRegMap(N->getOperand(1));
    Node = CurDAG
               ->getNode(EXT_ARMISD::UXTB, Dl, getDefaultEVT(FuncInfo), Rd, Rm,
                         Rotation, getMDOperand(N))
               .getNode();
    recordDefinition(FuncInfo, Rd.getNode(), Node);
    NPI->Node = Node;
    Value *S1 = getIRValue(FuncInfo, Node->getOperand(1));
    Value *RotationVal = getIRValue(FuncInfo, Node->getOperand(2));
    Value *RorVal = ConstantInt::get(getDefaultType(), 8, true);
    Value *AddVal = ConstantInt::get(getDefaultType(), 0, true);
    Value *AndVal = ConstantInt::get(getDefaultType(), 0xff, true);
    Value *InstMul = IRB.CreateMul(RotationVal, RorVal);
    Value *InstLshr = IRB.CreateLShr(S1, InstMul);
    Value *InstAdd = IRB.CreateAdd(InstLshr, AddVal);
    Value *InstAnd = IRB.CreateAnd(InstAdd, AndVal);
    FuncInfo->setRealValue(Node, InstAnd);
  } break;
  case ARM::MCR:
  case ARM::MCRR:
  case ARM::t2MCR:
  case ARM::t2MCRR:
  case ARM::VMSR:
  case ARM::VMSR_FPEXC:
  case ARM::VMSR_FPSID:
  case ARM::VMSR_FPINST:
  case ARM::VMSR_FPINST2: {
    outs() << "WARNING: ARM::MCR Not yet implemented!\n";
  } break;
  case ARM::MRS:
  case ARM::MRSsys:
  case ARM::t2MRS_AR:
  case ARM::t2MRSsys_AR: {
    SDValue Rn = N->getOperand(0);
    if (RegisterSDNode::classof(Rn.getNode()))
      Rn = FuncInfo->getValFromRegMap(Rn);

    Node = CurDAG
               ->getNode(EXT_ARMISD::MRS, Dl, getDefaultEVT(FuncInfo), Rn,
                         getMDOperand(N))
               .getNode();
    NPI->Node = Node;
    Value *RnVal = getIRValue(FuncInfo, Node->getOperand(0));
    // Reserved || N_Flag << 31 || Z_Flag << 30 || C_Flag << 29 || V_Flag << 28
    PointerType *PtrTy = PointerType::getInt32PtrTy(Ctx);
    Type *Ty = Type::getInt32Ty(Ctx);

    Value *BitNShift = IRB.getInt32(31);
    Value *BitZShift = IRB.getInt32(30);
    Value *BitCShift = IRB.getInt32(29);
    Value *BitVShift = IRB.getInt32(28);

    Value *NFlag =
        callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[0]));
    Value *ZFlag =
        callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[1]));
    Value *CFlag =
        callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[2]));
    Value *VFlag =
        callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(FuncInfo->AllocaMap[3]));

    NFlag = IRB.CreateZExt(NFlag, Ty);
    ZFlag = IRB.CreateZExt(ZFlag, Ty);
    CFlag = IRB.CreateZExt(CFlag, Ty);
    VFlag = IRB.CreateZExt(VFlag, Ty);

    Value *NShift = IRB.CreateShl(NFlag, BitNShift);
    Value *ZShift = IRB.CreateShl(ZFlag, BitZShift);
    Value *CShift = IRB.CreateShl(CFlag, BitCShift);
    Value *VShift = IRB.CreateShl(VFlag, BitVShift);
    Value *NZVal = IRB.CreateAdd(NShift, ZShift);
    Value *CVVal = IRB.CreateAdd(CShift, VShift);
    Value *NZCVVal = IRB.CreateAdd(NZVal, CVVal);
    Value *Reserved =
        callCreateAlignedLoad(BB, M->getGlobalVariable("Reserved"));

    Value *CPSRVal = IRB.CreateAdd(NZCVVal, Reserved);
    Value *RnPtr = IRB.CreateIntToPtr(RnVal, PtrTy);
    Value *RnStore = IRB.CreateStore(CPSRVal, RnPtr);

    FuncInfo->setRealValue(Node, RnStore);
    FuncInfo->ArgValMap[FuncInfo->NodeRegMap[Node]] = RnStore;
  } break;
  /* ABS */
  case ARM::ABS:
  case ARM::t2ABS: {
    outs() << "WARNING: ARM::ABS Not yet implemented!\n";
  } break;
  case ARM::tLDRpci:
  case ARM::LDRcp: {
    outs() << "WARNING: ARM::LDRcp Not yet implemented!\n";
  } break;
  case ARM::t2SBFX:
  case ARM::SBFX:
  case ARM::t2UBFX:
  case ARM::UBFX: {
    outs() << "WARNING: ARM::UBFX Not yet implemented!\n";
  } break;
  case ARM::t2UMAAL:
  case ARM::UMAAL: {
    outs() << "WARNING: ARM::UMAAL Not yet implemented!\n";
  } break;
  case ARM::t2UMLAL:
  case ARM::UMLAL:
  case ARM::UMLALv5: {
    outs() << "WARNING: ARM::UMLAL Not yet implemented!\n";
  } break;
  case ARM::t2SMLAL:
  case ARM::SMLAL:
  case ARM::SMLALv5: {
    outs() << "WARNING: ARM::SMLAL Not yet implemented!\n";
  } break;
  case ARM::t2SMMLS:
  case ARM::SMMLS: {
    outs() << "WARNING: ARM::SMMLS Not yet implemented!\n";
  } break;
  case ARM::VZIPd8:
  case ARM::VZIPd16:
  case ARM::VZIPq8:
  case ARM::VZIPq16:
  case ARM::VZIPq32: {
    outs() << "WARNING: ARM::VZIP Not yet implemented!\n";
  } break;
  case ARM::VUZPd8:
  case ARM::VUZPd16:
  case ARM::VUZPq8:
  case ARM::VUZPq16:
  case ARM::VUZPq32: {
    outs() << "WARNING: ARM::VUZP Not yet implemented!\n";
  } break;
  case ARM::VTRNd8:
  case ARM::VTRNd16:
  case ARM::VTRNd32:
  case ARM::VTRNq8:
  case ARM::VTRNq16:
  case ARM::VTRNq32: {
    outs() << "WARNING: ARM::VTRN Not yet implemented!\n";
  } break;
    // TODO: Need to add other pattern matching here.
  }
}
