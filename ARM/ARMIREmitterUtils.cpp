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
#include "FunctionRaisingInfo.h"
#include "Raiser/ModuleRaiser.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;
using namespace llvm::mctoll;

static const std::vector<StringRef> CPSR({"N_Flag", "Z_Flag", "C_Flag",
                                          "V_Flag"});

/// Match condition state, make corresponding processing.
void ARMMachineInstructionRaiser::emitCondCode(
    FunctionRaisingInfo *FuncInfo, unsigned CondValue,
    BasicBlock *BB, BasicBlock *IfBB, BasicBlock *ElseBB) {
  IRBuilder<> IRB(BB);

  switch (CondValue) {
  default:
    break;
  case ARMCC::EQ: { // EQ  Z set
    Value *ZFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[1]);
    Value *InstEQ = IRB.CreateICmpEQ(ZFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::NE: { // NE Z clear
    Value *ZFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[1]);
    Value *InstEQ = IRB.CreateICmpEQ(ZFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::HS: { // CS  C set
    Value *CFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[2]);
    Value *InstEQ = IRB.CreateICmpEQ(CFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::LO: { // CC  C clear
    Value *CFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[2]);
    Value *InstEQ = IRB.CreateICmpEQ(CFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::MI: { // MI  N set
    Value *NFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[0]);
    Value *InstEQ = IRB.CreateICmpEQ(NFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::PL: { // PL  N clear
    Value *NFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[0]);
    Value *InstEQ = IRB.CreateICmpEQ(NFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::VS: { // VS  V set
    Value *VFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[3]);
    Value *InstEQ = IRB.CreateICmpEQ(VFlag, IRB.getTrue());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::VC: { // VC  V clear
    Value *VFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[3]);
    Value *InstEQ = IRB.CreateICmpEQ(VFlag, IRB.getFalse());
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::HI: { // HI  C set & Z clear
    Value *CFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[2]);
    Value *ZFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[1]);
    Value *InstCEQ = IRB.CreateICmpEQ(CFlag, IRB.getTrue());
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getFalse());
    Value *CondPass = IRB.CreateICmpEQ(InstCEQ, InstZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::LS: { // LS  C clear or Z set
    Value *CFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[2]);
    Value *ZFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[1]);
    Value *InstCEQ = IRB.CreateICmpEQ(CFlag, IRB.getFalse());
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getTrue());
    Value *CondPass = IRB.CreateXor(InstCEQ, InstZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::GE: { // GE  N = V
    Value *NFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[0]);
    Value *VFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[3]);
    Value *InstEQ = IRB.CreateICmpEQ(NFlag, VFlag);
    IRB.CreateCondBr(InstEQ, IfBB, ElseBB);
  } break;
  case ARMCC::LT: { // LT  N != V
    Value *NFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[0]);
    Value *VFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[3]);
    Value *InstNE = IRB.CreateICmpNE(NFlag, VFlag);
    IRB.CreateCondBr(InstNE, IfBB, ElseBB);
  } break;
  case ARMCC::GT: { // GT  Z clear & N = V
    Value *NFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[0]);
    Value *ZFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[1]);
    Value *VFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[3]);
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getFalse());
    Value *InstNZEQ = IRB.CreateICmpEQ(NFlag, VFlag);
    Value *CondPass = IRB.CreateICmpEQ(InstZEQ, InstNZEQ);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::LE: { // LE  Z set or N != V
    Value *NFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[0]);
    Value *ZFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[1]);
    Value *VFlag =
        callCreateAlignedLoad(BB, FuncInfo->AllocaMap[3]);
    Value *InstZEQ = IRB.CreateICmpEQ(ZFlag, IRB.getTrue());
    Value *InstNZNE = IRB.CreateICmpNE(NFlag, VFlag);
    Value *CondPass = IRB.CreateXor(InstZEQ, InstNZNE);
    IRB.CreateCondBr(CondPass, IfBB, ElseBB);
  } break;
  case ARMCC::AL: { // AL
    assert(false && "Emit conditional code [ARMCC::AL]. Should not get here!");
  } break;
  }
}

/// Create PHINode for value use selection when running.
PHINode *ARMMachineInstructionRaiser::createAndEmitPHINode(
    FunctionRaisingInfo *FuncInfo, const MachineInstr &MI,
    BasicBlock *BB, BasicBlock *IfBB, BasicBlock *ElseBB, Instruction *IfInst) {
  PHINode *Phi = PHINode::Create(getDefaultType(), 2, "", ElseBB);

  auto *Node = FuncInfo->getNPI(MI)->Node;
  if (FuncInfo->checkArgValue(Node)) {
    Phi->addIncoming(FuncInfo->getArgValue(Node), BB);
  } else {
    auto *Zero = ConstantInt::get(getDefaultType(), 0, true);
    Instruction *TermInst = BB->getTerminator();
    Value *AddVal = BinaryOperator::CreateAdd(Zero, Zero, "", TermInst);
    Phi->addIncoming(AddVal, BB);
  }

  Phi->addIncoming(IfInst, IfBB);
  return Phi;
}

/// Update the N Z C V flags of global variable.
/// Implement AddWithCarry of encoding of instruction.
/// AddWithCarry(Operand0, Operand1, Flag);
void ARMMachineInstructionRaiser::emitCPSR(
    FunctionRaisingInfo *FuncInfo, Value *Operand0, Value *Operand1,
    BasicBlock *BB, unsigned Flag) {
  IRBuilder<> IRB(BB);
  Type *Ty = IRB.getInt1Ty();
  Type *OperandTy = getDefaultType();
  Function *FSigned =
      Intrinsic::getDeclaration(M, Intrinsic::sadd_with_overflow, OperandTy);
  Function *FUnsigned =
      Intrinsic::getDeclaration(M, Intrinsic::uadd_with_overflow, OperandTy);
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
  Value *Result = Sum;
  // Update the corresponding flags.
  // Update N flag.
  Value *NFlag = IRB.CreateLShr(Result, IRB.getInt32(31));
  Value *NTrunc = IRB.CreateTrunc(NFlag, Ty);
  IRB.CreateStore(NTrunc, FuncInfo->AllocaMap[0]);

  // Update Z flag.
  Value *ZFlag = IRB.CreateICmpEQ(Result, IRB.getInt32(0));
  Value *ZTrunc = IRB.CreateTrunc(ZFlag, Ty);
  IRB.CreateStore(ZTrunc, FuncInfo->AllocaMap[1]);

  // Update C flag.
  Value *CFlag = ExtractValueInst::Create(UnsignedSum, 1, "", BB);
  IRB.CreateStore(CFlag, FuncInfo->AllocaMap[2]);

  // Update V flag.
  Value *VFlag = ExtractValueInst::Create(SignedSum, 1, "", BB);
  IRB.CreateStore(VFlag, FuncInfo->AllocaMap[3]);
}

void ARMMachineInstructionRaiser::emitSpecialCPSR(
    FunctionRaisingInfo *FuncInfo,
    Value *Result, BasicBlock *BB, unsigned Flag) {
  IRBuilder<> IRB(BB);
  Type *Ty = IRB.getInt1Ty();
  // Update N flag.
  Value *NFlag = IRB.CreateLShr(Result, IRB.getInt32(31));
  NFlag = IRB.CreateTrunc(NFlag, Ty);
  IRB.CreateStore(NFlag, FuncInfo->AllocaMap[0]);
  // Update Z flag.
  Value *ZFlag = IRB.CreateICmpEQ(Result, IRB.getInt32(0));

  IRB.CreateStore(ZFlag, FuncInfo->AllocaMap[1]);
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
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  IRBuilder<> IRB(BB);
  auto *Node = FuncInfo->getNPI(MI)->Node;
  Value *S0 = FuncInfo->getIRValue(Node->getOperand(0));
  Value *S1 = FuncInfo->getIRValue(Node->getOperand(1));

  emitCPSR(FuncInfo, S0, S1, BB, 0);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRSub(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  IRBuilder<> IRB(BB);
  auto *Node = FuncInfo->getNPI(MI)->Node;
  Value *S0 = FuncInfo->getIRValue(Node->getOperand(0));
  Value *S1 = FuncInfo->getIRValue(Node->getOperand(1));

  Value *InstNot = nullptr;
  if (ConstantSDNode::classof(Node->getOperand(1).getNode())) {
    Value *InstTp = IRB.CreateSub(S0, S0);
    Value *InstAdd = IRB.CreateAdd(InstTp, S1);
    InstNot = IRB.CreateNot(InstAdd);
  } else {
    InstNot = IRB.CreateNot(S1, "");
  }
  emitCPSR(FuncInfo, S0, InstNot, BB, 1);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRMul(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  emitSpecialCPSR(FuncInfo, Inst, BB, 0);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRShl(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  IRBuilder<> IRB(BB);
  auto *Node = FuncInfo->getNPI(MI)->Node;
  Value *S0 = FuncInfo->getIRValue(Node->getOperand(0));
  Value *S1 = FuncInfo->getIRValue(Node->getOperand(1));

  emitSpecialCPSR(FuncInfo, Inst, BB, 0);

  // Update C flag.
  // extended_x = x : Zeros(shift), c flag = extend_x[N];
  // c flag = (s0 lsl (s1 -1))[31]
  Type *Ty = IRB.getInt1Ty();
  Value *Val = cast<Value>(ConstantInt::get(getDefaultType(), 1, true));
  Value *CFlag = IRB.CreateSub(S1, Val);
  CFlag = IRB.CreateShl(S0, CFlag);
  CFlag = IRB.CreateLShr(CFlag, IRB.getInt32(31));
  Value *CTrunc = IRB.CreateTrunc(CFlag, Ty);

  IRB.CreateStore(CTrunc, FuncInfo->AllocaMap[2]);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRLShr(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  IRBuilder<> IRB(BB);
  auto *Node = FuncInfo->getNPI(MI)->Node;
  Value *S0 = FuncInfo->getIRValue(Node->getOperand(0));
  Value *S1 = FuncInfo->getIRValue(Node->getOperand(1));

  emitSpecialCPSR(FuncInfo, Inst, BB, 0);

  // Update C flag.
  // c flag = (s0 lsr (s1 -1))[0]
  Type *Ty = IRB.getInt1Ty();
  Value *Val = cast<Value>(ConstantInt::get(getDefaultType(), 1, true));
  Value *CFlag = IRB.CreateSub(S1, Val);
  CFlag = IRB.CreateLShr(S0, CFlag);
  CFlag = IRB.CreateAnd(CFlag, Val);
  Value *CTrunc = IRB.CreateTrunc(CFlag, Ty);

  IRB.CreateStore(CTrunc, FuncInfo->AllocaMap[2]);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRAShr(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  IRBuilder<> IRB(BB);
  auto *Node = FuncInfo->getNPI(MI)->Node;
  Value *S0 = FuncInfo->getIRValue(Node->getOperand(0));
  Value *S1 = FuncInfo->getIRValue(Node->getOperand(1));

  emitSpecialCPSR(FuncInfo, Inst, BB, 0);

  // Update C flag.
  // c flag = (s0 asr (s1 -1))[0]
  Type *Ty = IRB.getInt1Ty();
  Value *Val = ConstantInt::get(getDefaultType(), 1, true);
  Value *CFlag = IRB.CreateSub(S1, Val);
  CFlag = IRB.CreateAShr(S0, CFlag);
  CFlag = IRB.CreateAnd(CFlag, Val);
  Value *CTrunc = IRB.CreateTrunc(CFlag, Ty);
  IRB.CreateStore(CTrunc, FuncInfo->AllocaMap[2]);
}

void ARMMachineInstructionRaiser::emitBinaryCPSRAnd(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  emitSpecialCPSR(FuncInfo, Inst, BB, 0);
}

void ARMMachineInstructionRaiser::emitBinaryCPSROr(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  emitSpecialCPSR(FuncInfo, Inst, BB, 0);
  /* How to deal with C Flag? */
}
void ARMMachineInstructionRaiser::emitBinaryCPSRXor(
    FunctionRaisingInfo *FuncInfo, Value *Inst, BasicBlock *BB,
    const MachineInstr &MI) {
  emitSpecialCPSR(FuncInfo, Inst, BB, 0);
  /* How to deal with C Flag? */
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
  FuncInfo->setArgValue(Node, Phi);

#define HANDLE_EMIT_CONDCODE(OPC)                                              \
  HANDLE_EMIT_CONDCODE_COMMON(OPC)                                             \
                                                                               \
  IRB.SetInsertPoint(IfBB);                                                    \
  IRB.CreateBr(ElseBB);                                                        \
  IRB.SetInsertPoint(ElseBB);

#define HANDLE_BINARY_FUNC(OPCODE)                                             \
  auto *NPI = FuncInfo->getNPI(MI);                                            \
  auto *Node = NPI->Node;                                                      \
  IRBuilder<> IRB(BB);                                                         \
  Value *S0 = FuncInfo->getIRValue(Node->getOperand(0));                       \
  Value *S1 = FuncInfo->getIRValue(Node->getOperand(1));                       \
  if (NPI->HasCPSR) {                                                          \
    unsigned CondValue = NPI->Cond;                                            \
    if (!(NPI->UpdateCPSR)) {                                                  \
      HANDLE_EMIT_CONDCODE(OPCODE)                                             \
    } else if (NPI->Special) {                                                 \
      HANDLE_EMIT_CONDCODE_COMMON(OPCODE)                                      \
      emitBinaryCPSR##OPCODE(FuncInfo, Inst, IfBB, MI);                       \
      IRB.CreateBr(ElseBB);                                                    \
      IRB.SetInsertPoint(ElseBB);                                              \
    } else {                                                                   \
      Value *Inst = IRB.Create##OPCODE(S0, S1);                                \
      FuncInfo->setRealValue(Node, Inst);                                      \
      FuncInfo->setArgValue(Node, Inst);                  \
      emitBinaryCPSR##OPCODE(FuncInfo, Inst, BB, MI);                         \
    }                                                                          \
  } else {                                                                     \
    Value *Inst = BinaryOperator::Create##OPCODE(S0, S1);                      \
    BasicBlock *CBB = IRB.GetInsertBlock();                                    \
    CBB->getInstList().push_back(dyn_cast<Instruction>(Inst));                 \
    FuncInfo->setRealValue(Node, Inst);                                        \
    FuncInfo->setArgValue(Node, Inst);                                         \
  }

void ARMMachineInstructionRaiser::emitBinaryAdd(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(Add)
}
void ARMMachineInstructionRaiser::emitBinarySub(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(Sub)
}
void ARMMachineInstructionRaiser::emitBinaryMul(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(Mul)
}
void ARMMachineInstructionRaiser::emitBinaryShl(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(Shl)
}
void ARMMachineInstructionRaiser::emitBinaryLShr(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(LShr)
}
void ARMMachineInstructionRaiser::emitBinaryAShr(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(AShr)
}
void ARMMachineInstructionRaiser::emitBinaryAnd(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(And)
}
void ARMMachineInstructionRaiser::emitBinaryOr(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
  HANDLE_BINARY_FUNC(Or)
}
void ARMMachineInstructionRaiser::emitBinaryXor(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB, const MachineInstr &MI) {
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

void ARMMachineInstructionRaiser::emitLoad(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB,
    const MachineInstr &MI) {
  auto *NPI = FuncInfo->getNPI(MI);
  auto *Node = NPI->Node;
  //unsigned Opc = Node->getOpcode();
  IRBuilder<> IRB(BB);
  auto *DLT = &M->getDataLayout();
  IRB.SetCurrentDebugLocation(Node->getDebugLoc());

  Value *S = FuncInfo->getIRValue(Node->getOperand(0));
  Value *Ptr = nullptr;
  if (S->getType()->isPointerTy())
    Ptr = S;
  else
    Ptr = IRB.CreateIntToPtr(
        S, Node->getValueType(0).getTypeForEVT(Ctx)->getPointerTo());

  Value *Inst = nullptr;
  if (NPI->HasCPSR) {
    unsigned CondValue = NPI->Cond;
    // Create new BB for EQ instruction execute.
    BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
    // Create new BB to update the DAG BB.
    BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

    // Emit the condition code.
    emitCondCode(FuncInfo, CondValue, BB, IfBB, ElseBB);
    IRB.SetInsertPoint(IfBB);
    if (GlobalVariable::classof(Ptr))
      Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
    else
      Inst = callCreateAlignedLoad(BB,
                                   getDefaultType(), Ptr,
                                   MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

    PHINode *Phi = createAndEmitPHINode(FuncInfo, MI, BB, IfBB, ElseBB,
                                        dyn_cast<Instruction>(Inst));
    FuncInfo->setRealValue(Node, Phi);
    FuncInfo->setArgValue(Node, Phi);

    IRB.CreateBr(ElseBB);
    IRB.SetInsertPoint(ElseBB);
  } else {
    if (GlobalVariable::classof(Ptr)) {
      auto *Glob = cast<GlobalVariable>(Ptr);
      // Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
      // Inst = new PtrToIntInst(Ptr, getDefaultType(), "", BB);
      Type *Ty = Glob->getValueType();
      if (Ty->isArrayTy()) {
        Inst = IRB.CreatePtrToInt(Ptr, getDefaultType());
        //Ty = Ty->getArrayElementType();
        //Ptr->mutateType(PointerType::getUnqual(Ty));
      } else {
        // if (Ty->isAggregateType()) {}
        auto *Pty = cast<PointerType>(Ptr->getType());
        if (Pty->isOpaqueOrPointeeTypeMatches(Ty))
          Inst = IRB.CreateLoad(Ty, Ptr);
      }
    } else {
      Type *ElemTy = getIntTypeByPtr(Ptr->getType());
      Inst = callCreateAlignedLoad(BB,
                                   ElemTy, Ptr, MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

      // TODO:
      // Temporary method for this.
      if (Inst->getType() == Type::getInt64Ty(Ctx))
        Inst = IRB.CreateTrunc(Inst, getDefaultType());
      else if (Inst->getType() != getDefaultType())
        Inst = IRB.CreateSExt(Inst, getDefaultType());
    }

    FuncInfo->setRealValue(Node, Inst);
    FuncInfo->setArgValue(Node, Inst);
  }
}

void ARMMachineInstructionRaiser::emitStore(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB,
    const MachineInstr &MI) {
  auto *NPI = FuncInfo->getNPI(MI);
  auto *Node = NPI->Node;
  //unsigned Opc = Node->getOpcode();
  IRBuilder<> IRB(BB);
  auto *DLT = &M->getDataLayout();
  IRB.SetCurrentDebugLocation(Node->getDebugLoc());

  Value *Val = FuncInfo->getIRValue(Node->getOperand(0));
  Value *S = FuncInfo->getIRValue(Node->getOperand(1));
  Value *Ptr = nullptr;
  Type *Nty = Node->getValueType(0).getTypeForEVT(Ctx);

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

  if (NPI->HasCPSR) {
    // Create new BB for EQ instruction execute.
    BasicBlock *IfBB = BasicBlock::Create(Ctx, "", BB->getParent());
    // Create new BB to update the DAG BB.
    BasicBlock *ElseBB = BasicBlock::Create(Ctx, "", BB->getParent());

    // Emit the condition code.
    emitCondCode(FuncInfo, NPI->Cond, BB, IfBB, ElseBB);
    IRB.SetInsertPoint(IfBB);

    IRB.CreateAlignedStore(Val, Ptr,
                           MaybeAlign(Log2(DLT->getPointerPrefAlignment())));

    IRB.CreateBr(ElseBB);
    IRB.SetInsertPoint(ElseBB);
  } else {
    IRB.CreateAlignedStore(Val, Ptr,
                           MaybeAlign(Log2(DLT->getPointerPrefAlignment())));
  }
}

void ARMMachineInstructionRaiser::emitBRD(
    FunctionRaisingInfo *FuncInfo, BasicBlock *BB,
    const MachineInstr &MI) {
  auto *NPI = FuncInfo->getNPI(MI);
  auto *Node = NPI->Node;
  // unsigned Opc = Node->getOpcode();
  IRBuilder<> IRB(BB);
  auto *DLT = &M->getDataLayout();
  IRB.SetCurrentDebugLocation(Node->getDebugLoc());

  // Get the function call Index.
  uint64_t Index = Node->getConstantOperandVal(0);
  // Get function from ModuleRaiser.
  Function *CallFunc = MR->getRaisedFunctionAt(Index);
  unsigned IFFuncArgNum = 0; // The argument number which gets from analyzing
                             // variadic function prototype.
  bool IsSyscall = false;
  if (CallFunc == nullptr) {
    // According to MI to get BL instruction address.
    // uint64_t callAddr = FuncInfo->getNPI(MI)->InstAddr;
    uint64_t CallAddr = MR->getTextSectionAddress() +
                        getMCInstIndex(MI);
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
    const MachineFrameInfo &MFI = FuncInfo->getFrameInfo();
    unsigned StackArg = 0; // Initialize argument size on stack to 0.
    if (ArgNum > 4) {
      StackArg = ArgNum - 4;

      unsigned StackNum = MFI.getNumObjects() - 2;
      if (StackNum > StackArg)
        StackArg = StackNum;
    }
    for (unsigned Idx = 0; Idx < ArgNum; Idx++) {
      if (Idx < 4)
        ArgVal = FuncInfo->getArgValue(ARM::R0 + Idx);
      else {
        const AllocaInst *StackAlloc =
            MFI.getObjectAllocation(StackArg - Idx - 4 + 1);
        ArgVal = callCreateAlignedLoad(BB,
                                       const_cast<AllocaInst *>(StackAlloc),
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

  FuncInfo->setRealValue(Node, Inst);
}
