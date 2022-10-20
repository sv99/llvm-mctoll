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
#include "ARMRaisedValueTracker.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;
using namespace llvm::mctoll;

#define HANDLE_EMIT_CONDCODE_COMMON(OPC)                                       \
  BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());             \
  BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());           \
                                                                               \
  emitCondCode(IRB, IfBB, ElseBB, CondValue);                                   \
                                                                               \
  Value *Inst = BinaryOperator::Create##OPC(S0, S1);                           \
  IfBB->getInstList().push_back(dyn_cast<Instruction>(Inst));                  \
  PHINode *Phi = createAndEmitPHINode(IRB, AMI, IfBB, ElseBB,                    \
                                      dyn_cast<Instruction>(Inst));            \
  RaisedValues->recordDefinition(AMI, Phi);

#define HANDLE_EMIT_CONDCODE(OPC)                                              \
  HANDLE_EMIT_CONDCODE_COMMON(OPC)                                             \
                                                                               \
  IRB.SetInsertPoint(IfBB);                                                    \
  IRB.CreateBr(ElseBB);                                                        \

/// Emit Instruction and add to BasicBlock.
void ARMMachineInstructionRaiser::emitInstr(
    IRBuilder<> &IRB, const MachineInstr &MI) {

  ARMMachineInstr *AMI = RaisedValues->initMachineInstr(MI);
  auto *BB = IRB.GetInsertBlock();

  switch (MI.getOpcode()) {
  default: {
    // Print names for all unimplemented instructions.
    auto *TII = getMF().getSubtarget().getInstrInfo();
    outs() << "WARNING: ARM::" << TII->getName(MI.getOpcode())
           << " Not yet implemented!\n";
  } break;
  /* ADC */
  case ARM::ADCrr:
  case ARM::ADCri:
  case ARM::ADCrsr:
  case ARM::ADCrsi:
  case ARM::tADC:
  case ARM::t2ADCrr:
  case ARM::t2ADCri:
  case ARM::t2ADCrs: {
    Value * InstADC = emitADC(IRB, AMI);
    RaisedValues->recordDefinition(AMI, InstADC);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryAdd(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinarySub(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
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
    // Get exactly second operand.
    Value *S1 = RaisedValues->getOperand(*AMI->MI, 1);
    Value *Inst = emitBinaryAdd(IRB, AMI, S1, IRB.getInt32(0));
    RaisedValues->recordDefinition(AMI, Inst);
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
    emitStore(IRB, AMI);
  } break;
  case ARM::STRH:
  case ARM::STRH_PRE:
  case ARM::STRH_POST: {
//    EVT InstTy = EVT::getEVT(Type::getInt16Ty(*CurDAG->getContext()));
//    SDValue Val = N->getOperand(0);
//    SDValue Op1 = N->getOperand(1);
//
//    if (RegisterSDNode::classof(Val.getNode()))
//      Val = RaisedValues->getSDValueByRegister(Val);
//
//    if (RegisterSDNode::classof(Op1.getNode()))
//      Op1 = RaisedValues->getSDValueByRegister(Op1);
//
//    if (N->getNumOperands() < 5) {
//      Node = CurDAG
//                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1,
//                           getMDOperand(N))
//                 .getNode();
//    } else {
//      SDValue Op2 = N->getOperand(2);
//      Op2 = RaisedValues->getSDValueByRegister(Op2);
//      Node = CurDAG
//                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1, Op2,
//                           getMDOperand(N))
//                 .getNode();
//    }
//
//    AMI->Node = Node;
    emitStore(IRB, AMI);
  } break;
  case ARM::STRBi12:
  case ARM::STRBrs:
  case ARM::STRB_PRE_IMM:
  case ARM::STRB_PRE_REG:
  case ARM::STRB_POST_IMM:
  case ARM::STRB_POST_REG: {
//    EVT InstTy = EVT::getEVT(Type::getInt8Ty(*CurDAG->getContext()));
//    SDValue Val = N->getOperand(0);
//    SDValue Op1 = N->getOperand(1);
//
//    if (RegisterSDNode::classof(Val.getNode()))
//      Val = RaisedValues->getSDValueByRegister(Val);
//
//    if (RegisterSDNode::classof(Op1.getNode()))
//      Op1 = RaisedValues->getSDValueByRegister(Op1);
//
//    if (N->getNumOperands() < 5) {
//      Node = CurDAG
//                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1,
//                           getMDOperand(N))
//                 .getNode();
//    } else {
//      SDValue Op2 = N->getOperand(2);
//      Op2 = RaisedValues->getSDValueByRegister(Op2);
//      Node = CurDAG
//                 ->getNode(EXT_ARMISD::STORE, Dl, InstTy, Val, Op1, Op2,
//                           getMDOperand(N))
//                 .getNode();
//    }
//
//    AMI->Node = Node;
    emitStore(IRB, AMI);
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
    Value *LoadInst = emitLoad(IRB, AMI);
    RaisedValues->recordDefinition(AMI, LoadInst);
  } break;
  case ARM::LDRH:
  case ARM::LDRSH:
  case ARM::t2LDRSH_PRE:
  case ARM::t2LDRSH_POST:
  case ARM::t2LDRH_PRE:
  case ARM::t2LDRH_POST:
  case ARM::LDRSH_PRE:
  case ARM::LDRSH_POST: {
    Value *LoadInst = emitLoad(IRB, AMI);
    RaisedValues->recordDefinition(AMI, LoadInst);
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
    Value *LoadInst = emitLoad(IRB, AMI);
    RaisedValues->recordDefinition(AMI, LoadInst);
  } break;
  /* Branch */
  case ARM::Bcc:
  case ARM::tBcc:
  case ARM::t2Bcc: {
//    const MachineBasicBlock *LMBB = MI.getParent();
//    if (LMBB->succ_size() == 0) {
//      RaisedValues->setSDValueByRegister(ARM::R0, SDValue(Node, 0));
//      RaisedValues->setNodeReg(Node, ARM::R0);
//    }
//    AMI->Node = Node;
    // emit
    if (AMI->HasCPSR) {
      // br i1 %cmp, label %if.then, label %if.else
      unsigned CondVal = AMI->Cond;
      MachineBasicBlock *MBB = RaisedValues->getMBB(BB);
      MachineBasicBlock::succ_iterator SuI = MBB->succ_begin();
      BasicBlock *IfTrueP = RaisedValues->getOrCreateBasicBlock(*SuI);
      MachineBasicBlock *NextMBB = &*std::next(MBB->getIterator());
      BasicBlock *NextBB = RaisedValues->getOrCreateBasicBlock(NextMBB);

      emitCondCode(IRB, IfTrueP, NextBB, CondVal);
    } else {
      // br label %xxx
      MachineBasicBlock *LMBBVal = RaisedValues->getMBB(BB);
      MachineBasicBlock::succ_iterator SuI = LMBBVal->succ_begin();
      if (SuI != LMBBVal->succ_end()) {
        BasicBlock *BrDest = RaisedValues->getOrCreateBasicBlock(*SuI);
        IRB.CreateBr(BrDest);
      } else {
        Value *Inst = emitBRD(IRB, AMI);
        RaisedValues->recordDefinition(ARM::R0, Inst);
      }
    }
  } break;
  case ARM::B:
  case ARM::tB:
  case ARM::t2B: {
    // br label %xxx
    MachineBasicBlock *LMBBVal = RaisedValues->getMBB(BB);
    MachineBasicBlock::succ_iterator SuI = LMBBVal->succ_begin();
    if (SuI != LMBBVal->succ_end()) {
      BasicBlock *BrDest = RaisedValues->getOrCreateBasicBlock(*SuI);
      IRB.CreateBr(BrDest);
    } else {
      Value *Inst = emitBRD(IRB, AMI);
      RaisedValues->recordDefinition(ARM::R0, Inst);
    }
  } break;
  case ARM::BL:
  case ARM::BL_pred:
  case ARM::tBL: {
    emitBL(IRB, AMI);
   } break;
  case ARM::BLX:
  case ARM::BLXi:
  case ARM::BLX_pred:
  case ARM::tBLXi:
  case ARM::tBLXr: {
    // Exchange instruction set A32 <-> T32 and branch.
    // For raising instruction set not important simply BL.
    emitBL(IRB, AMI);
  } break;
  case ARM::BR_JTr: {
    emitSwitchInstr(IRB, AMI, BB);
  } break;
  case ARM::BX:
  case ARM::BX_CALL:
  case ARM::BX_pred:
  case ARM::tBX:
  case ARM::tBX_CALL: {
    // Get exactly first argument.
    Value *FuncVal = RaisedValues->getOperand(MI, 0);
    unsigned NumDests = MI.getNumOperands(); // Node->getNumOperands();
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
    // set flags by result <Op1> - <Op2>
    // SBBS without store result
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    emitCMP(IRB, S0, S1);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryAnd(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryAShr(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* CMN */
  case ARM::CMNri:
  case ARM::CMNzrr:
  case ARM::tCMNz:
  case ARM::t2CMNri:
  case ARM::t2CMNzrr:
  case ARM::t2CMNzrs: {
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);
    emitCMN(IRB, S0, S1);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryXor(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
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
    Value *CondVal = RaisedValues->getOperand(MI, 0);
    // 1 1 1 1
    // N set 1 0 0 0   8
    // Z set 0 1 0 0   4
    // C set 0 0 1 0   2
    // Z set 0 0 0 1   1
    IRB.CreateStore(CondVal, dyn_cast<Value>(
                                 getModule()->getGlobalVariable("Reserved")));
    // Pattern msr CPSR_f, Rn
    if (1) {
      Value *ShiftNum = IRB.getInt32(28);
      Value *Shift = IRB.CreateLShr(CondVal, ShiftNum);
      // Update N Flag.
      Value *NCmp = IRB.getInt32(8);
      Value *NFlag = IRB.CreateICmpEQ(Shift, NCmp);
      saveNFlag(IRB, NFlag);
      // Update Z Flag.
      Value *ZCmp = IRB.getInt32(4);
      Value *ZFlag = IRB.CreateICmpEQ(Shift, ZCmp);
      saveZFlag(IRB, ZFlag);
      // Update C Flag.
      Value *CCmp = IRB.getInt32(2);
      Value *CFlag = IRB.CreateICmpEQ(Shift, CCmp);
      saveCFlag(IRB, CFlag);
      // Update V Flag.
      Value *VCmp = IRB.getInt32(1);
      Value *VFlag = IRB.CreateICmpEQ(Shift, VCmp);
      saveVFlag(IRB, VFlag);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryMul(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryXor(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* LSL */
  case ARM::LSLi:
  case ARM::LSLr:
  case ARM::tLSLri:
  case ARM::tLSLrr:
  case ARM::t2LSLri:
  case ARM::t2LSLrr: {
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryShl(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* LSR */
  case ARM::LSRi:
  case ARM::LSRr:
  case ARM::tLSRri:
  case ARM::tLSRrr:
  case ARM::t2LSRri:
  case ARM::t2LSRrr: {
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryLShr(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(AMI, 0);
    Value *S1 = RaisedValues->getOperand(AMI, 1);
    Value *Inst = emitBinaryOr(IRB, AMI, S0, S1);
    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* ROR */
  case ARM::RORi:
  case ARM::RORr:
  case ARM::tROR:
  case ARM::t2RORri:
  case ARM::t2RORrr: {
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);
    Type *Ty = getDefaultType();
    Value *Val = ConstantInt::get(Ty, 32, true);

    if (AMI->HasCPSR) {
      if (AMI->UpdateCPSR) {
        Value *InstSub = IRB.CreateSub(Val, S1);
        Value *InstLShr = IRB.CreateLShr(S0, S1);
        Value *InstShl = IRB.CreateShl(S0, InstSub);
        Value *Inst = IRB.CreateOr(InstLShr, InstShl);
        RaisedValues->recordDefinition(AMI, Inst);

        emitSpecialCPSR(IRB, Inst, 0);
      } else {
        // Create new BB for EQ instruction execute.
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
        IRB.SetInsertPoint(IfBB);
        Value *InstSub = IRB.CreateSub(Val, S1);
        Value *InstLShr = IRB.CreateLShr(S0, S1);
        Value *InstShl = IRB.CreateShl(S0, InstSub);
        Value *Inst = IRB.CreateOr(InstLShr, InstShl);
        PHINode *Phi = createAndEmitPHINode(IRB, AMI, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        RaisedValues->recordDefinition(AMI, Phi);
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstSub = IRB.CreateSub(Val, S1);
      Value *InstLShr = IRB.CreateLShr(S0, S1);
      Value *InstShl = IRB.CreateShl(S0, InstSub);
      Value *Inst = IRB.CreateOr(InstLShr, InstShl);
      RaisedValues->recordDefinition(AMI, Inst);
    }
  } break;
  /* RRX */
  case ARM::RRX: {
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Type *Ty = getDefaultType();
    Value *Val1 = ConstantInt::get(Ty, 1, true);
    Value *Val2 = ConstantInt::get(Ty, 31, true);
    if (AMI->HasCPSR) {
      if (AMI->UpdateCPSR) {
        Value *InstLShr = IRB.CreateLShr(S0, Val1);
        Value *CFlag = loadCFlag(IRB);
        CFlag = IRB.CreateZExt(CFlag, Ty);
        Value *Bit31 = IRB.CreateShl(CFlag, Val2);
        Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
        RaisedValues->recordDefinition(AMI, Inst);

        /**************************************/
        emitSpecialCPSR(IRB, Inst, 0);
        // Update C flag.
        // c flag = s0[0]
        CFlag = IRB.CreateAnd(S0, Val1);
        saveCFlag(IRB, CFlag);
      } else {
        // Create new BB for EQ instruction execute.
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        // Create new BB to update the DAG BB.
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        // Emit the condition code.
        emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
        IRB.SetInsertPoint(IfBB);
        Value *InstLShr = IRB.CreateLShr(S0, Val1);
        Value *CFlag = nullptr;

        CFlag = loadCFlag(IRB);
        CFlag = IRB.CreateZExt(CFlag, Ty);
        Value *Bit31 = IRB.CreateShl(CFlag, Val2);
        Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
        PHINode *Phi = createAndEmitPHINode(IRB, AMI, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        RaisedValues->recordDefinition(AMI, Phi);
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstLShr = IRB.CreateLShr(S0, Val1);
      Value *CFlag = loadCFlag(IRB);
      CFlag = IRB.CreateZExt(CFlag, Ty);
      Value *Bit31 = IRB.CreateShl(CFlag, Val2);
      Value *Inst = IRB.CreateAdd(InstLShr, Bit31);
      RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);

    if (AMI->HasCPSR) {
      unsigned CondValue = AMI->Cond;
      if (AMI->UpdateCPSR) {
        // Create add emit.
        Value *Inst = IRB.CreateSub(S0, S1);
        RaisedValues->recordDefinition(AMI, Inst);

        Value *InstNot = IRB.CreateNot(S1);
        emitCPSR(IRB, InstNot, S0, 1);
      } else {
        HANDLE_EMIT_CONDCODE(Sub)
      }
    } else {
      Value *Inst = IRB.CreateSub(S0, S1);
      RaisedValues->recordDefinition(AMI, Inst);
    }
  } break;
  /* RSC */
  case ARM::RSCri:
  case ARM::RSCrr:
  case ARM::RSCrsi:
  case ARM::RSCrsr: {
    // RSC{S}<c> <Rd>,<Rn>, #0
    // RSC{S}<c>.W <Rd>,<Rn>,#<const>
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);

    Value *CFlag = loadCFlag(IRB);
    Value *CZext = IRB.CreateZExt(CFlag, getDefaultType());

    Value *Inst = IRB.CreateAdd(S0, CZext);
    Inst = IRB.CreateSub(S1, Inst);
    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* CLZ */
  case ARM::CLZ:
  case ARM::t2CLZ: {
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Function *CTLZ = Intrinsic::getDeclaration(BB->getParent()->getParent(),
                                               Intrinsic::ctlz, S0->getType());
    Type *I1ype = llvm::IntegerType::getInt1Ty(Ctx);
    Value *IsZeroUndef = ConstantInt::get(I1ype, true, true);

    std::vector<Value *> Vec;
    Vec.push_back(S0);
    Vec.push_back(IsZeroUndef);
    ArrayRef<Value *> Args(Vec);

    Value *Inst = IRB.CreateCall(CTLZ, Args);
    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* SBC */
  case ARM::SBCrr:
  case ARM::SBCri:
  case ARM::tSBC: {
    Value *S1 = RaisedValues->getOperand(MI, 0);
    Value *S2 = RaisedValues->getOperand(MI, 1);
    Type *Ty = getDefaultType();

    if (AMI->HasCPSR) {
      if (AMI->UpdateCPSR) {
        Value *InstSub = IRB.CreateSub(S1, S2);
        Value *CFlag = nullptr;
        CFlag = loadCFlag(IRB);
        Value *CZext = IRB.CreateZExt(CFlag, Ty);
        Value *InstSBC = IRB.CreateAdd(InstSub, CZext);
        RaisedValues->recordDefinition(AMI, InstSBC);
        Value *InstNot = IRB.CreateNot(S2);
        if (1)
          emitCPSR(IRB, S1, InstNot, 0);
        else
          emitCPSR(IRB, S1, InstNot, 1);
      } else {
        BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
        BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

        emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);

        IRB.SetInsertPoint(IfBB);
        Value *InstSub = IRB.CreateSub(S1, S2);
        Value *CFlag = nullptr;
        CFlag = loadCFlag(IRB);
        Value *CZext = IRB.CreateZExt(CFlag, Ty);
        Value *Inst = IRB.CreateAdd(InstSub, CZext);
        PHINode *Phi = createAndEmitPHINode(IRB, AMI, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        RaisedValues->recordDefinition(AMI, Phi);
        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstSub = IRB.CreateSub(S1, S2);
      Value *CFlag = nullptr;
      CFlag = loadCFlag(IRB);
      Value *CZext = IRB.CreateZExt(CFlag, Ty);
      Value *InstSBC = IRB.CreateAdd(InstSub, CZext);
      RaisedValues->recordDefinition(AMI, InstSBC);
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
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);

    if (AMI->HasCPSR) {
      // Create new BB for EQ instruction execute.
      BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

      // TODO:
      // This instruction not change def, consider phi later.

      emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
      IRB.SetInsertPoint(IfBB);
      Value *Inst = IRB.CreateXor(S0, S1);
      emitSpecialCPSR(IRB, Inst, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);

      RaisedValues->recordDefinition(AMI, Inst);
    } else {
      Value *Inst = IRB.CreateXor(S0, S1);
      emitSpecialCPSR(IRB, Inst, 0);

      RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);

    if (AMI->HasCPSR) {
      // Create new BB for EQ instruction execute.
      BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
      // Create new BB to update the DAG BB.
      BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

      // TODO:
      // Not change def. Consider how to use PHI.
      // PHINode *Phi = createAndEmitPHINode(Node, BB, ElseBB);

      emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
      IRB.SetInsertPoint(IfBB);
      Value *Inst = IRB.CreateAnd(S0, S1);
      emitSpecialCPSR(IRB, Inst, 0);
      IRB.CreateBr(ElseBB);
      IRB.SetInsertPoint(ElseBB);

      RaisedValues->recordDefinition(AMI, Inst);
    } else {
      Value *Inst = IRB.CreateAnd(S0, S1);
      emitSpecialCPSR(IRB, Inst, 0);

      RaisedValues->recordDefinition(AMI, Inst);
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
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);
    Type *Ty = getDefaultType();
    Value *Val = ConstantInt::get(Ty, -1, true);

    if (AMI->HasCPSR) {
      if (AMI->UpdateCPSR) {
        Value *InstXor = IRB.CreateXor(Val, S1);
        Value *Inst = IRB.CreateAnd(S0, InstXor);

        RaisedValues->recordDefinition(AMI, Inst);

        emitSpecialCPSR(IRB, Inst, 0);
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
        emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
        IRB.SetInsertPoint(IfBB);
        Value *InstXor = IRB.CreateXor(Val, S1);
        Value *Inst = IRB.CreateAnd(S0, InstXor);
        PHINode *Phi = createAndEmitPHINode(IRB, AMI, IfBB, ElseBB,
                                            dyn_cast<Instruction>(Inst));
        RaisedValues->recordDefinition(AMI, Phi);

        IRB.CreateBr(ElseBB);
        IRB.SetInsertPoint(ElseBB);
      }
    } else {
      Value *InstXor, *Inst;
      InstXor = IRB.CreateXor(Val, S1);
      Inst = IRB.CreateAnd(S0, InstXor);
      RaisedValues->recordDefinition(AMI, Inst);
    }
  } break;
  /* MLA */
  case ARM::MLA:
  case ARM::t2MLA: {
    Value *S0 = RaisedValues->getOperand(MI, 0);
    Value *S1 = RaisedValues->getOperand(MI, 1);
    Value *S2 = RaisedValues->getOperand(MI, 2);

    Value *InstMul = IRB.CreateMul(S0, S1);
    Value *Inst = IRB.CreateAdd(InstMul, S2);

    RaisedValues->recordDefinition(AMI, Inst);
  } break;
  /* UXTB */
  case ARM::UXTB: {
    Value *S1 = RaisedValues->getOperand(MI, 1);
    Value *RotationVal = RaisedValues->getOperand(MI, 2);
    Value *RorVal = ConstantInt::get(getDefaultType(), 8, true);
    Value *AddVal = ConstantInt::get(getDefaultType(), 0, true);
    Value *AndVal = ConstantInt::get(getDefaultType(), 0xff, true);
    Value *InstMul = IRB.CreateMul(RotationVal, RorVal);
    Value *InstLshr = IRB.CreateLShr(S1, InstMul);
    Value *InstAdd = IRB.CreateAdd(InstLshr, AddVal);
    Value *InstAnd = IRB.CreateAnd(InstAdd, AndVal);
    RaisedValues->recordDefinition(AMI, InstAnd);
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
    Value *RnVal = RaisedValues->getOperand(MI, 0);
    // Reserved || N_Flag << 31 || Z_Flag << 30 || C_Flag << 29 || V_Flag << 28
    PointerType *PtrTy = PointerType::getInt32PtrTy(Ctx);
    Type *Ty = Type::getInt32Ty(Ctx);

    Value *BitNShift = IRB.getInt32(31);
    Value *BitZShift = IRB.getInt32(30);
    Value *BitCShift = IRB.getInt32(29);
    Value *BitVShift = IRB.getInt32(28);

    Value *NFlag = loadNFlag(IRB);
    Value *ZFlag = loadZFlag(IRB);
    Value *CFlag = loadCFlag(IRB);
    Value *VFlag = loadVFlag(IRB);

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
        callCreateAlignedLoad(BB,
                              getModule()->getGlobalVariable("Reserved"));

    Value *CPSRVal = IRB.CreateAdd(NZCVVal, Reserved);
    Value *RnPtr = IRB.CreateIntToPtr(RnVal, PtrTy);
    Value *RnStore = IRB.CreateStore(CPSRVal, RnPtr);

    RaisedValues->recordDefinition(AMI, RnStore);
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
