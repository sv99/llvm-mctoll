//===- IREmitter.cpp - Binary raiser utility llvm-mctoll ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of IREmitter class or use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARMMachineInstructionRaiser.h"
#include "ARMModuleRaiser.h"
#include "ARMRaisedValueTracker.h"
#include "Raiser/ModuleRaiser.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;
using namespace llvm::mctoll;

static const std::vector<StringRef> CPSR({"N_Flag", "Z_Flag", "C_Flag",
                                          "V_Flag"});

/// Create PHINode for value use selection when running.
PHINode *ARMMachineInstructionRaiser::createAndEmitPHINode(
    IRBuilder<> &IRB, ARMMachineInstr *AMI,
    BasicBlock *IfBB, BasicBlock *ElseBB, Value *IfInst) {
  PHINode *Phi = PHINode::Create(getDefaultType(), 2, "", ElseBB);

  auto *BB = IRB.GetInsertBlock();
  if (RaisedValues->checkRegValue(ARM::R0)) {
    Phi->addIncoming(RaisedValues->getRegValue(ARM::R0), BB);
  } else {
    auto *Zero = ConstantInt::get(getDefaultType(), 0, true);
    Instruction *TermInst = BB->getTerminator();
    Value *AddVal = BinaryOperator::CreateAdd(Zero, Zero, "", TermInst);
    Phi->addIncoming(AddVal, BB);
  }

  Phi->addIncoming(IfInst, IfBB);
  return Phi;
}

/// Match condition state, make corresponding processing.
void ARMMachineInstructionRaiser::emitCondCode(
    IRBuilder<> &IRB, BasicBlock *IfBB, BasicBlock *ElseBB, unsigned CondValue) {
  switch (CondValue) {
  default:
    break;
  case ARMCC::EQ: { // EQ  Z set
    Value *ZFlag = loadZFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(ZFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::NE: { // NE Z clear
    Value *ZFlag = loadZFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(ZFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::HS: { // CS  C set
    Value *CFlag = loadCFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(CFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::LO: { // CC  C clear
    Value *CFlag = loadCFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(CFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::MI: { // MI  N set
    Value *NFlag = loadNFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(NFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::PL: { // PL  N clear
    Value *NFlag = loadNFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(NFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::VS: { // VS  V set
    Value *VFlag = loadVFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(VFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::VC: { // VC  V clear
    Value *VFlag = loadVFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(VFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::HI: { // HI  C set & Z clear
    Value *CFlag = loadCFlag(IRB);
    Value *ZFlag = loadZFlag(IRB);
    Value *InstCEQ = IRB.CreateICmpEQ(CFlag, IRB.getTrue());
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getFalse());
    Value *CondPass = IRB.CreateICmpEQ(InstCEQ, InstZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::LS: { // LS  C clear or Z set
    Value *CFlag = loadCFlag(IRB);
    Value *ZFlag = loadZFlag(IRB);
    Value *InstCEQ = IRB.CreateICmpEQ(CFlag, IRB.getFalse());
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getTrue());
    Value *CondPass = IRB.CreateXor(InstCEQ, InstZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::GE: { // GE  N = V
    Value *NFlag = loadNFlag(IRB);
    Value *VFlag = loadVFlag(IRB);
    Value *InstEQ = IRB.CreateICmpEQ(NFlag, VFlag);
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::LT: { // LT  N != V
    Value *NFlag = loadNFlag(IRB);
    Value *VFlag = loadVFlag(IRB);
    Value *InstNE = IRB.CreateICmpNE(NFlag, VFlag);
    IRB.CreateCondBr(InstNE, IfBB, ElseBB);
  } break;
  case ARMCC::GT: { // GT  Z clear & N = V
    Value *NFlag = loadNFlag(IRB);
    Value *ZFlag = loadZFlag(IRB);
    Value *VFlag = loadVFlag(IRB);
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getFalse());
    Value *InstNZEQ = IRB.CreateICmpEQ(NFlag, VFlag);
    Value *CondPass = IRB.CreateICmpEQ(InstZEQ, InstNZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::LE: { // LE  Z set or N != V
    Value *NFlag = loadNFlag(IRB);
    Value *ZFlag = loadZFlag(IRB);
    Value *VFlag = loadVFlag(IRB);
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getTrue());
    Value *InstNZNE = IRB.CreateICmpNE(NFlag, VFlag);
    Value *CondPass = IRB.CreateXor(InstZEQ, InstNZNE);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::AL: { // AL Execute Always
    // assert(false && "Emit conditional code [ARMCC::AL]. Should not get here!");
  } break;
  }
}

/// Update the N Z C V flags of global variable.
/// Implement AddWithCarry of encoding of instruction.
/// AddWithCarry(Operand0, Operand1, Flag);
void ARMMachineInstructionRaiser::emitCPSR(
    IRBuilder<> &IRB, Value *Operand0, Value *Operand1, unsigned Flag) {
  auto *BB = IRB.GetInsertBlock();
  Type *Ty = IRB.getInt1Ty();
  Type *OperandTy = getDefaultType();
  Function *FSigned =
      Intrinsic::getDeclaration(getModule(), Intrinsic::sadd_with_overflow, OperandTy);
  Function *FUnsigned =
      Intrinsic::getDeclaration(getModule(), Intrinsic::uadd_with_overflow, OperandTy);
  Value *Args[] = {Operand0, Operand1};
  Value *UnsignedSum;
  Value *SignedSum;
  if (Flag) {
    Value *OperandFlag = IRB.CreateAdd(Operand0, IRB.getInt32(1));
    Value *ArgsFlag[] = {Operand1, OperandFlag};
    UnsignedSum = IRB.CreateCall(FUnsigned, ArgsFlag);
    SignedSum = IRB.CreateCall(FSigned, ArgsFlag);
  } else {
    UnsignedSum = IRB.CreateCall(FUnsigned, Args);
    SignedSum = IRB.CreateCall(FSigned, Args);
  }

  Value *Sum = ExtractValueInst::Create(UnsignedSum, 0, "", BB);
  // Update the corresponding flags.
  // Update N flag.
  Value *NFlag = IRB.CreateLShr(Sum, IRB.getInt32(31));
  Value *NTrunc = IRB.CreateTrunc(NFlag, Ty);
  saveNFlag(IRB, NTrunc);

  // Update Z flag.
  Value *ZFlag = IRB.CreateICmpEQ(Sum, IRB.getInt32(0));
  Value *ZTrunc = IRB.CreateTrunc(ZFlag, Ty);
  saveZFlag(IRB, ZTrunc);

  // Update C flag.
  Value *CFlag = ExtractValueInst::Create(UnsignedSum, 1, "", BB);
  saveCFlag(IRB, CFlag);

  // Update V flag.
  Value *VFlag = ExtractValueInst::Create(SignedSum, 1, "", BB);
  saveVFlag(IRB, VFlag);
}

/// Update the N Z C V flags of global variable.
/// Set flag by result of Operand0 + Operand1.
void ARMMachineInstructionRaiser::emitCMN(
    IRBuilder<> &IRB, Value *Operand0, Value *Operand1) {
  auto *BB = IRB.GetInsertBlock();
  Type *Ty = IRB.getInt1Ty();
  Type *OperandTy = getDefaultType();
  Function *FSigned =
      Intrinsic::getDeclaration(getModule(), Intrinsic::sadd_with_overflow, OperandTy);
  Function *FUnsigned =
      Intrinsic::getDeclaration(getModule(), Intrinsic::uadd_with_overflow, OperandTy);
  Value *Args[] = {Operand0, Operand1};
  Value *UnsignedSum;
  Value *SignedSum;
  UnsignedSum = IRB.CreateCall(FUnsigned, Args);
  SignedSum = IRB.CreateCall(FSigned, Args);

  Value *Sum = ExtractValueInst::Create(UnsignedSum, 0, "", BB);
  // Update the corresponding flags.
  // Update N flag.
  Value *NFlag = IRB.CreateLShr(Sum, IRB.getInt32(31));
  Value *NTrunc = IRB.CreateTrunc(NFlag, Ty);
  saveNFlag(IRB, NTrunc);

  // Update Z flag.
  Value *ZFlag = IRB.CreateICmpEQ(Sum, IRB.getInt32(0));
  Value *ZTrunc = IRB.CreateTrunc(ZFlag, Ty);
  saveZFlag(IRB, ZTrunc);

  // Update C flag.
  Value *CFlag = ExtractValueInst::Create(UnsignedSum, 1, "", BB);
  saveCFlag(IRB, CFlag);

  // Update V flag.
  Value *VFlag = ExtractValueInst::Create(SignedSum, 1, "", BB);
  saveVFlag(IRB, VFlag);
}

/// Update the N Z C V flags of global variable.
/// Set flag by result of Operand0 - Operand1.
void ARMMachineInstructionRaiser::emitCMP(
    IRBuilder<> &IRB, Value *Operand0, Value *Operand1) {
  auto * BB = IRB.GetInsertBlock();
  Type *Ty = IRB.getInt1Ty();
  Type *OperandTy = getDefaultType();
  Function *FSigned =
      Intrinsic::getDeclaration(getModule(), Intrinsic::ssub_with_overflow, OperandTy);
  Function *FUnsigned =
      Intrinsic::getDeclaration(getModule(), Intrinsic::usub_with_overflow, OperandTy);
  Value *Args[] = {Operand0, Operand1};
  Value *UnsignedSum;
  Value *SignedSum;
  UnsignedSum = IRB.CreateCall(FUnsigned, Args);
  SignedSum = IRB.CreateCall(FSigned, Args);

  Value *Sum = ExtractValueInst::Create(UnsignedSum, 0, "", BB);
  // Update the corresponding flags.
  // Update N flag.
  Value *NFlag = IRB.CreateLShr(Sum, IRB.getInt32(31));
  Value *NTrunc = IRB.CreateTrunc(NFlag, Ty);
  saveNFlag(IRB, NTrunc);

  // Update Z flag.
  Value *ZFlag = IRB.CreateICmpEQ(Sum, IRB.getInt32(0));
  Value *ZTrunc = IRB.CreateTrunc(ZFlag, Ty);
  saveZFlag(IRB, ZTrunc);

  // Update C flag.
  Value *CFlag = ExtractValueInst::Create(UnsignedSum, 1, "", BB);
  saveCFlag(IRB, CFlag);

  // Update V flag.
  Value *VFlag = ExtractValueInst::Create(SignedSum, 1, "", BB);
  saveVFlag(IRB, VFlag);
}

/// Update the N Z flags of global variable.
void ARMMachineInstructionRaiser::emitSpecialCPSR(
    IRBuilder<> &IRB, Value *Result, unsigned Flag) {
  Type *Ty = IRB.getInt1Ty();
  // Update N flag.
  Value *NFlag = IRB.CreateLShr(Result, IRB.getInt32(31));
  NFlag = IRB.CreateTrunc(NFlag, Ty);
  saveNFlag(IRB, NFlag);
  // Update Z flag.
  Value *ZFlag = IRB.CreateICmpEQ(Result, IRB.getInt32(0));
  saveZFlag(IRB, ZFlag);
}

/// Load N flag from stack allocation.
Value *ARMMachineInstructionRaiser::loadNFlag(IRBuilder<> &IRB) {
  return callCreateAlignedLoad(IRB, RaisedValues->AllocaMap[0]);
}

/// Load Z flag from stack allocation.
Value *ARMMachineInstructionRaiser::loadZFlag(IRBuilder<> &IRB) {
  return callCreateAlignedLoad(IRB, RaisedValues->AllocaMap[1]);
}

/// Load C flag from stack allocation.
Value *ARMMachineInstructionRaiser::loadCFlag(IRBuilder<> &IRB) {
  return callCreateAlignedLoad(IRB, RaisedValues->AllocaMap[2]);
}

/// Load V flag from stack allocation.
Value *ARMMachineInstructionRaiser::loadVFlag(IRBuilder<> &IRB) {
  return callCreateAlignedLoad(IRB, RaisedValues->AllocaMap[3]);
}

void ARMMachineInstructionRaiser::saveNFlag(IRBuilder<> &IRB, Value *NFlag) {
  IRB.CreateStore(NFlag, RaisedValues->AllocaMap[0]);
}

void ARMMachineInstructionRaiser::saveZFlag(IRBuilder<> &IRB, Value *ZFlag) {
  IRB.CreateStore(ZFlag, RaisedValues->AllocaMap[1]);
}

void ARMMachineInstructionRaiser::saveCFlag(IRBuilder<> &IRB, Value *CFlag) {
  IRB.CreateStore(CFlag, RaisedValues->AllocaMap[2]);
}
void ARMMachineInstructionRaiser::saveVFlag(IRBuilder<> &IRB, Value *VFlag) {
  IRB.CreateStore(VFlag, RaisedValues->AllocaMap[3]);
}

Type *ARMMachineInstructionRaiser::getIntTypeByPtr(Type *PTy) {
  assert(PTy && PTy->isPointerTy() && "The input type is not a pointer!");
  Type *Ty = nullptr;

  if (PTy == Type::getInt64PtrTy(Ctx))
    Ty = Type::getInt64Ty(Ctx);
  else if (PTy == Type::getInt32PtrTy(Ctx))
    Ty = Type::getInt32Ty(Ctx);
  else if (PTy == Type::getInt16PtrTy(Ctx))
    Ty = Type::getInt16Ty(Ctx);
  else if (PTy == Type::getInt8PtrTy(Ctx))
    Ty = Type::getInt8Ty(Ctx);
  else if (PTy == Type::getInt1PtrTy(Ctx))
    Ty = Type::getInt1Ty(Ctx);
  else
    Ty = getDefaultType();

  return Ty;
}

void ARMMachineInstructionRaiser::emitBinaryCPSRAdd(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  Value *S0 = RaisedValues->getOperand(MI, 0);
  Value *S1 = RaisedValues->getOperand(MI, 1);
  emitCPSR(IRB, S0, S1, 0);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRSub(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  Value *S0 = RaisedValues->getOperand(MI, 0);
  Value *S1 = RaisedValues->getOperand(MI, 1);

  Value *InstNot = nullptr;
  if (auto *Const = dyn_cast<Constant>(S1)) {
    Value *InstTp = IRB.CreateSub(S0, S0);
    Value *InstAdd = IRB.CreateAdd(InstTp, S1);
    InstNot = IRB.CreateNot(InstAdd);
  } else {
    InstNot = IRB.CreateNot(S1, "");
  }
  emitCPSR(IRB, S0, InstNot, 1);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRMul(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  emitSpecialCPSR(IRB, Inst, 0);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRShl(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  Value *S0 = RaisedValues->getOperand(MI, 0);
  Value *S1 = RaisedValues->getOperand(MI, 1);

  emitSpecialCPSR(IRB, Inst, 0);

  // Update C flag.
  // extended_x = x : Zeros(shift), c flag = extend_x[N];
  // c flag = (s0 lsl (s1 -1))[31]
  Type *Ty = IRB.getInt1Ty();
  Value *Val = dyn_cast<Value>(ConstantInt::get(getDefaultType(), 1, true));
  Value *CFlag = IRB.CreateSub(S1, Val);
  CFlag = IRB.CreateShl(S0, CFlag);
  CFlag = IRB.CreateLShr(CFlag, IRB.getInt32(31));
  Value *CTrunc = IRB.CreateTrunc(CFlag, Ty);
  saveCFlag(IRB, CTrunc);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRLShr(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  Value *S0 = RaisedValues->getOperand(MI, 0);
  Value *S1 = RaisedValues->getOperand(MI, 1);

  emitSpecialCPSR(IRB, Inst, 0);

  // Update C flag.
  // c flag = (s0 lsr (s1 -1))[0]
  Type *Ty = IRB.getInt1Ty();
  Value *Val = cast<Value>(ConstantInt::get(getDefaultType(), 1, true));
  Value *CFlag = IRB.CreateSub(S1, Val);
  CFlag = IRB.CreateLShr(S0, CFlag);
  CFlag = IRB.CreateAnd(CFlag, Val);
  Value *CTrunc = IRB.CreateTrunc(CFlag, Ty);
  saveCFlag(IRB, CTrunc);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRAShr(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  Value *S0 = RaisedValues->getOperand(MI, 0);
  Value *S1 = RaisedValues->getOperand(MI, 1);

  emitSpecialCPSR(IRB, Inst, 0);

  // Update C flag.
  // c flag = (s0 asr (s1 -1))[0]
  Type *Ty = IRB.getInt1Ty();
  Value *Val = ConstantInt::get(getDefaultType(), 1, true);
  Value *CFlag = IRB.CreateSub(S1, Val);
  CFlag = IRB.CreateAShr(S0, CFlag);
  CFlag = IRB.CreateAnd(CFlag, Val);
  Value *CTrunc = IRB.CreateTrunc(CFlag, Ty);
  saveCFlag(IRB, CTrunc);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRAnd(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  emitSpecialCPSR(IRB, Inst, 0);
}

void ARMMachineInstructionRaiser::emitBinaryCPSROr(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  emitSpecialCPSR(IRB, Inst, 0);
  /* How to deal with C Flag? */
}
void ARMMachineInstructionRaiser::emitBinaryCPSRXor(
    IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst) {
  emitSpecialCPSR(IRB, Inst, 0);
  /* How to deal with C Flag? */
}

#define HANDLE_BINARY_FUNC(OPCODE)                                             \
  checkConditionBegin(IRB, AMI);                                               \
  Value *Result = IRB.Insert(BinaryOperator::Create##OPCODE(S0, S1));          \
  auto EmitUpdate = [&, this]() {                                              \
    emitBinaryCPSR##OPCODE(IRB, *AMI->MI, Result);                             \
  };                                                                           \
  return checkConditionEnd( IRB, AMI, Result, EmitUpdate);

Value *ARMMachineInstructionRaiser::emitBinaryAdd(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(Add)
}
Value *ARMMachineInstructionRaiser::emitBinarySub(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(Sub)
}
Value *ARMMachineInstructionRaiser::emitBinaryMul(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(Mul)
}
Value *ARMMachineInstructionRaiser::emitBinaryShl(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(Shl)
}
Value *ARMMachineInstructionRaiser::emitBinaryLShr(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(LShr)
}
Value *ARMMachineInstructionRaiser::emitBinaryAShr(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(AShr)
}
Value *ARMMachineInstructionRaiser::emitBinaryAnd(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(And)
}
Value *ARMMachineInstructionRaiser::emitBinaryOr(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(Or)
}
Value *ARMMachineInstructionRaiser::emitBinaryXor(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *S0, Value *S1) {
  HANDLE_BINARY_FUNC(Xor)
}

// Extract the offset of MachineInstr MI from the Metadata operand.
static uint64_t getMCInstIndex(const MachineInstr &MI) {
  unsigned NumExpOps = MI.getNumExplicitOperands();
  const MachineOperand &MO = MI.getOperand(NumExpOps);
  assert(MO.isMetadata() &&
         "Unexpected non-metadata operand in branch instruction!");
  const MDNode *MDN = MO.getMetadata();
  // Unwrap metadata of the instruction to get the MCInstIndex of
  // the MCInst corresponding to this MachineInstr.
  ConstantAsMetadata *CAM = dyn_cast<ConstantAsMetadata>(MDN->getOperand(0));
  assert(CAM != nullptr && "Unexpected metadata type!");
  Constant *CV = CAM->getValue();
  ConstantInt *CI = dyn_cast<ConstantInt>(CV);
  assert(CI != nullptr && "Unexpected metadata constant type!");
  APInt ArbPrecInt = CI->getValue();
  return ArbPrecInt.getSExtValue();
}

void ARMMachineInstructionRaiser::checkConditionBegin(
    IRBuilder<> &IRB, ARMMachineInstr *AMI) {
  // Check condition pattern ADC<c> <Rdn>,<Rm>
  if (AMI->HasCPSR && AMI->IsCond) {
    // Condition pattern ADC<c> <Rdn>,<Rm>
    // Create new BB for EQ instruction execute.
    AMI->IfBB = RaisedValues->createBasicBlock(AMI);
    // Create new BB to update the DAG BB.
    AMI->ElseBB = RaisedValues->createBasicBlock(AMI);
    // Emit the condition code.
    emitCondCode(IRB, AMI->IfBB, AMI->ElseBB, AMI->Cond);
    IRB.SetInsertPoint(AMI->IfBB);
  }
}

Value *ARMMachineInstructionRaiser::checkConditionEnd(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, Value *Result,
    std::function<void()> EmitUpdate) {
  if (AMI->HasCPSR) {
    if (AMI->UpdateCPSR) {
      // Pattern: ADCS <Rdn>,<Rm>
      // S suffix - call lambda for update flags.
      EmitUpdate();
    }
    // If exists condition block then emit Phi node
    if (AMI->IsCond) {
      // ADC<c> <Rdn>,<Rm>
      Result = createAndEmitPHINode(IRB, AMI, AMI->IfBB, AMI->ElseBB, Result);
      IRB.CreateBr(AMI->ElseBB);
      IRB.SetInsertPoint(AMI->ElseBB);
    }
  }
  return Result;
}

Value *ARMMachineInstructionRaiser::emitADC(
    IRBuilder<> &IRB, ARMMachineInstr *AMI) {
  Value *S0 = RaisedValues->getOperand(AMI, 0);
  Value *S1 = RaisedValues->getOperand(AMI, 1);
  // Check condition begin.
  checkConditionBegin(IRB, AMI);
  // Calculate block.
  Value *CFlag = loadCFlag(IRB);
  Value *CZext = IRB.CreateZExtOrTrunc(CFlag, getDefaultType());
  Value *Op0 = IRB.CreateAdd(S0, CZext);
  Value *Result = IRB.CreateAdd(Op0, S1);
  // Check condition end.
  auto EmitUpdate = [&, this]() {
    emitCMN(IRB, Op0, S1);
  };
  return checkConditionEnd( IRB, AMI, Result, EmitUpdate);
}

Value *ARMMachineInstructionRaiser::emitLoad(
    IRBuilder<> &IRB, ARMMachineInstr *AMI) {
  Value *Result = nullptr;
  auto *BB = IRB.GetInsertBlock();
  auto *DLT = &getDataLayout();
  IRB.SetCurrentDebugLocation(AMI->MI->getDebugLoc());

  Value *S = RaisedValues->getOperand(AMI, 0);
  Value *Ptr = nullptr;
  if (S->getType()->isPointerTy())
    Ptr = S;
  else
    Ptr = IRB.CreateIntToPtr(S, S->getType()->getPointerTo());

  if (AMI->HasCPSR) {
    // Create new BB for EQ instruction execute.
    BasicBlock *IfBB = RaisedValues->createBasicBlock(AMI);
    // Create new BB to update the DAG BB.
    BasicBlock *ElseBB = RaisedValues->createBasicBlock(AMI);

    // Emit the condition code.
    emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
    IRB.SetInsertPoint(IfBB);
    Value *Inst = nullptr;
    if (GlobalVariable::classof(Ptr))
      Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
    else
      Inst = callCreateAlignedLoad(
          BB, getDefaultType(), Ptr,
          MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

    Result = createAndEmitPHINode(IRB, AMI, IfBB, ElseBB, Inst);
    IRB.CreateBr(ElseBB);
    IRB.SetInsertPoint(ElseBB);
  } else {
    if (GlobalVariable::classof(Ptr)) {
      auto *Glob = cast<GlobalVariable>(Ptr);
      // Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
      // Inst = new PtrToIntInst(Ptr, getDefaultType(), "", BB);
      Type *Ty = Glob->getValueType();
      if (Ty->isArrayTy()) {
        Result = IRB.CreatePtrToInt(Ptr, getDefaultType());
        //Ty = Ty->getArrayElementType();
        //Ptr->mutateType(PointerType::getUnqual(Ty));
      } else {
        // if (Ty->isAggregateType()) {}
        auto *Pty = cast<PointerType>(Ptr->getType());
        if (Pty->isOpaqueOrPointeeTypeMatches(Ty))
          Result = IRB.CreateLoad(Ty, Ptr);
      }
    } else {
      Type *ElemTy = getIntTypeByPtr(Ptr->getType());
      Value *Inst = callCreateAlignedLoad(
          BB, ElemTy, Ptr, MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

      // TODO:
      // Temporary method for this.
      if (Inst->getType() == Type::getInt64Ty(Ctx))
        Result = IRB.CreateTrunc(Inst, getDefaultType());
      else if (Inst->getType() != getDefaultType())
        Result = IRB.CreateSExt(Inst, getDefaultType());
    }
  }
  return Result;
}

void ARMMachineInstructionRaiser::emitStore(
    IRBuilder<> &IRB, ARMMachineInstr *AMI) {
  auto &MI = *AMI->MI;
  auto *DLT = &getDataLayout();
  IRB.SetCurrentDebugLocation(MI.getDebugLoc());

  Value *Val = RaisedValues->getOperand(MI, 0);
  Value *S = RaisedValues->getOperand(MI, 1);
  Value *Ptr = nullptr;
  Type *Nty = Val->getType();

  if (Val->getType() != Nty) {
    Val = IRB.CreateTrunc(Val, Nty);
  }

  if (S->getType()->isPointerTy()) {
    if (S->getType() != Nty->getPointerTo()) {
      Ptr = IRB.CreateBitCast(S, Nty->getPointerTo());
    } else {
      Ptr = S;
    }
  } else {
    Ptr = IRB.CreateIntToPtr(S, Nty->getPointerTo());
  }

  if (AMI->HasCPSR) {
    // Create new BB for EQ instruction execute.
    BasicBlock *IfBB = RaisedValues->createBasicBlock(AMI);
    // Create new BB to update the DAG BB.
    BasicBlock *ElseBB = RaisedValues->createBasicBlock(AMI);

    // Emit the condition code.
    emitCondCode(IRB, IfBB, ElseBB, AMI->Cond);
    IRB.SetInsertPoint(IfBB);

    IRB.CreateAlignedStore(
        Val, Ptr, MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

    IRB.CreateBr(ElseBB);
    IRB.SetInsertPoint(ElseBB);
  } else {
    IRB.CreateAlignedStore(
        Val, Ptr, MaybeAlign(Log2(DLT->getPointerPrefAlignment())));
  }
}

void ARMMachineInstructionRaiser::emitBL(
    IRBuilder<> &IRB, ARMMachineInstr *AMI) {
  auto &MI = *AMI->MI;
  if (MI.getOperand(0).isReg()) {
    Value *FuncVal = RaisedValues->getOperand(MI, 0);
    unsigned NumDests = MI.getNumOperands(); //Node->getNumOperands();
    IRB.CreateIndirectBr(FuncVal, NumDests);
  } else {
    Value *Inst = emitBRD(IRB, AMI);
    RaisedValues->recordDefinition(ARM::R0, Inst);
  }
}

void ARMMachineInstructionRaiser::emitSwitchInstr(
    IRBuilder<> &IRB, ARMMachineInstr *AMI, BasicBlock *BB) {
  // Emit the switch instruction.
  if (JTList.size() > 0) {
    MachineBasicBlock *Mbb = RaisedValues->getMBB(BB);
    MachineFunction *MF = Mbb->getParent();

    std::vector<JumpTableBlock> JTCases;
    const MachineJumpTableInfo *MJT = MF->getJumpTableInfo();
    Value *S0 = RaisedValues->getOperand(*AMI->MI, 0);
    unsigned JTIndex = dyn_cast<ConstantInt>(S0)->getZExtValue(); // AMI->Node->getConstantOperandVal(0);
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
        RaisedValues->getOrCreateBasicBlock(JTList[JTIndex].DefaultMBB);

    BasicBlock *CondBB =
        RaisedValues->getOrCreateBasicBlock(JTList[JTIndex].ConditionMBB);

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
          RaisedValues->getOrCreateBasicBlock(JTCases[Idx].second);
      Inst->addCase(JTCases[Idx].first, CaseBB);
    }
  }
}

Value *ARMMachineInstructionRaiser::emitBRD(
    IRBuilder<> &IRB, ARMMachineInstr *AMI) {
  auto *BB = IRB.GetInsertBlock();
  auto *DLT = &getDataLayout();
  IRB.SetCurrentDebugLocation(AMI->MI->getDebugLoc());

  // Get the function call Index.
  Value *S0 = RaisedValues->getOperand(*AMI->MI, 0);
  uint64_t Index = dyn_cast<ConstantInt>(S0)->getZExtValue(); // AMI->Node->getConstantOperandVal(0);
  // Get function from ModuleRaiser.
  Function *CallFunc = MR->getRaisedFunctionAt(Index);
  unsigned IFFuncArgNum = 0; // The argument number which gets from analyzing
                             // variadic function prototype.
  bool IsSyscall = false;
  if (CallFunc == nullptr) {
    // According to MI to get BL instruction address.
    // uint64_t callAddr = RaisedValues->getAMI(MI)->InstAddr;
    uint64_t CallAddr = MR->getTextSectionAddress() +
                        getMCInstIndex(*AMI->MI);
    auto *ArmMR =
        const_cast<ARMModuleRaiser *>(dyn_cast<ARMModuleRaiser>(MR));
    Function *IndefiniteFunc = ArmMR->getCallFunc(CallAddr);
    CallFunc = ArmMR->getSyscallFunc(Index);
    if (CallFunc != nullptr && IndefiniteFunc != nullptr) {
      IFFuncArgNum = ArmMR->getFunctionArgNum(CallAddr);
      IsSyscall = true;
    }
  }
  assert(CallFunc && "Failed to get called function!");
  // Get argument number from callee.
  unsigned ArgNum = CallFunc->arg_size();
  if (IFFuncArgNum > ArgNum)
    ArgNum = IFFuncArgNum;
  Argument *CalledFuncArgs = CallFunc->arg_begin();
  std::vector<Value *> CallInstFuncArgs;
  CallInst *Inst = nullptr;
  if (ArgNum > 0) {
    Value *ArgVal = nullptr;
    const MachineFrameInfo &MFI = MF.getFrameInfo();
    unsigned StackArg = 0; // Initialize argument size on stack to 0.
    if (ArgNum > 4) {
      StackArg = ArgNum - 4;

      unsigned StackNum = MFI.getNumObjects() - 2;
      if (StackNum > StackArg)
        StackArg = StackNum;
    }
    for (unsigned Idx = 0; Idx < ArgNum; Idx++) {
      if (Idx < 4)
        ArgVal = RaisedValues->getRegValue(ARM::R0 + Idx);
      else {
        const AllocaInst *StackAlloc =
            MFI.getObjectAllocation(StackArg - Idx - 4 + 1);
        ArgVal = callCreateAlignedLoad(
            BB, const_cast<AllocaInst *>(StackAlloc),
            MaybeAlign(Log2(DLT->getPointerPrefAlignment())));
      }
      if (IsSyscall && Idx < CallFunc->arg_size() &&
          ArgVal->getType() != CalledFuncArgs[Idx].getType()) {
        CastInst *CInst = CastInst::Create(
            CastInst::getCastOpcode(ArgVal, false,
                                    CalledFuncArgs[Idx].getType(), false),
            ArgVal, CalledFuncArgs[Idx].getType());
        IRB.GetInsertBlock()->getInstList().push_back(CInst);
        ArgVal = CInst;
      }
      CallInstFuncArgs.push_back(ArgVal);
    }
    Inst = IRB.CreateCall(CallFunc, ArrayRef<Value *>(CallInstFuncArgs));
  } else
    Inst = IRB.CreateCall(CallFunc);

  return Inst;
}
