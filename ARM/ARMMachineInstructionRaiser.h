//===-- ARMEliminatePrologEpilog.h ------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMMachineInstructionRaiser class for
// use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H

#include "ARMSubtarget.h"
#include "FunctionRaisingInfo.h"
#include "Raiser/MachineInstructionRaiser.h"

namespace llvm {

// Forward declaration
class ARMSubtarget;
class ARMBaseInstrInfo;
class ARMBaseRegisterInfo;

namespace mctoll {

// Forward declaration
class ARMModuleRaiser;
class FunctionRaisingInfo;

// Type alias for Map of MBBNo -> BasicBlock * used to keep track of
// MachineBasicBlock and corresponding raised BasicBlock
using MBBNumToBBMap = std::map<unsigned int, BasicBlock *>;

class ARMMachineInstructionRaiser : public MachineInstructionRaiser {
public:
  ARMMachineInstructionRaiser() = delete;
  ARMMachineInstructionRaiser(MachineFunction &MF, const ModuleRaiser *MR,
                              MCInstRaiser *MCIR);
  bool raise() override;
  FunctionType *getRaisedFunctionPrototype() override;
  int getArgumentNumber(unsigned PReg) override;
  Value *getRegOrArgValue(unsigned PReg, int MBBNo) override;
  bool buildFuncArgTypeVector(const std::set<MCPhysReg> &,
                              std::vector<Type *> &) override;

  std::vector<JumpTableInfo> JTList;

private:
  // Commonly used LLVM data structures during this phase
  MachineRegisterInfo &MachineRegInfo;
  const ARMSubtarget &TargetInfo;
  const ARMBaseInstrInfo *InstrInfo;
  const ARMBaseRegisterInfo *RegisterInfo;
  ARMModuleRaiser *TargetMR;
  Module *M;
  LLVMContext &Ctx;
  /// The function raising state storage.
  FunctionRaisingInfo *FuncInfo;

  // A map of MachineFunctionBlock number to BasicBlock *
  MBBNumToBBMap MbbToBBMap;

  /// Discover machine function prototype.
  Function *discoverPrototype(MachineFunction &MF);
  /// Get default Int type.
  Type *getDefaultType() {
    return Type::getIntNTy(Ctx, M->getDataLayout().getPointerSizeInBits());
  };
  /// Check the first reference of the reg is USE.
  bool isUsedRegiser(unsigned Reg, const MachineBasicBlock &MBB);
  /// Check the first reference of the reg is DEF.
  bool isDefinedRegiser(unsigned Reg, const MachineBasicBlock &MBB);
  /// Get all arguments types of current MachineFunction.
  void genParameterTypes(std::vector<Type *> &ParamTypes);
  /// Get return type of current MachineFunction.
  Type *genReturnType();

  // 1 step: Revise MI
  bool revise();
  bool reviseMI(MachineInstr &MI);
  /// Remove some useless operations of instructions.
  bool removeNeedlessInst(MachineInstr *MInst);
  /// Create function for external function.
  uint64_t getCalledFunctionAtPLTOffset(uint64_t PLTEndOff, uint64_t CallAddr);
  /// Relocate call branch instructions in object files.
  void relocateBranch(MachineInstr &MInst);
  /// Address PC relative data in function, and create corresponding global
  /// value.
  void addressPCRelativeData(MachineInstr &MInst);
  /// Decode modified immediate constants in some instructions with immediate
  /// operand.
  void decodeModImmOperand(MachineInstr &MInst);
  /// Find global value by PC offset.
  const Value *getGlobalValueByOffset(int64_t MCInstOffset, uint64_t PCOffset);

  // 2 step: Eliminate prolog-epilog
  bool eliminate();
  bool checkRegister(unsigned Reg, std::vector<MachineInstr *> &Instrs) const;
  bool eliminateProlog(MachineFunction &MF) const;
  bool eliminateEpilog(MachineFunction &MF) const;
  /// Analyze stack size base on moving sp.
  void analyzeStackSize(MachineFunction &MF);
  /// Analyze frame adjustment base on the offset between fp and base sp.
  void analyzeFrameAdjustment(MachineFunction &MF);

  // 3 step: create jump table
  bool createJumpTable();
  unsigned int getARMCPSR(unsigned int PhysReg);
  bool raiseMachineJumpTable(MachineFunction &MF);
  /// Get the MachineBasicBlock to add the jumptable instruction.
  MachineBasicBlock *checkJumpTableBB(MachineFunction &MF);
  bool updateTheBranchInst(MachineBasicBlock &MBB);

  // 4 step: raise arguments
  bool raiseArgs();
  /// Change all return relative register operands to stack 0.
  void updateReturnRegister(MachineFunction &MF);
  /// Change all function arguments of registers into stack elements with
  /// same indexes of arguments.
  void updateParameterRegister(unsigned Reg, MachineBasicBlock &MBB);
  /// Change rest of function arguments on stack frame into stack elements.
  void updateParameterFrame(MachineFunction &MF);
  /// Using newly created stack elements replace relative operands in
  /// MachineInstr.
  void updateParameterInstr(MachineFunction &MF);
  /// Move arguments which are passed by ARM registers(R0 - R3) from function
  /// arg.x to corresponding registers in entry block.
  void moveArgumentToRegister(unsigned Reg, MachineBasicBlock &MBB);

  struct StackElement {
    uint64_t Size;
    int64_t SPOffset;
    int64_t ObjectIndex = -1; // If it is -1, means the corresponding
                              // StackObject has not been created.
  };

  // 5 step: build frame
  /// Build ARM abstract stack frame by analyzing ARM SP
  /// register operations. Simultaneously, converts MI SP operands to
  /// MO_FrameIndex type.
  bool buildFrame();
  unsigned getBitCount(unsigned Opcode);
  Type *getStackType(unsigned Size);
  /// Replace common regs assigned by SP to SP.
  bool replaceNonSPBySP(MachineInstr &MI);
  /// Analyze frame index of stack operands.
  int64_t identifyStackOp(const MachineInstr &MI);
  /// Find out all of frame relative operands, and update them.
  void searchStackObjects(MachineFunction &MF);
  /// Records of assigned common registers by sp.
  SmallVector<unsigned, 16> RegAssignedBySP;

  // 6 step: split instruction
  bool split();
  /// Check if the MI has shift pattern.
  unsigned checkIsShifter(unsigned Opcode);
  /// Get the shift opcode in MI.
  unsigned getShiftOpcode(ARM_AM::ShiftOpc SOpc, unsigned OffSet);
  /// Split LDRxxx/STRxxx<c><q> <Rd>, [<Rn>, +/-<Rm>{, <shift>}] to:
  /// Rm shift #imm, but write result to VReg.
  /// Add VReg, Rn, Rm
  /// LDRxxx/STRxxx Rd, [VReg]
  MachineInstr* splitLDRSTR(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRPre(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRPreImm(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitLDRSTRImm(MachineBasicBlock &MBB, MachineInstr &MI);
  MachineInstr *splitCommon(MachineBasicBlock &MBB, MachineInstr &MI,
                            unsigned NewOpc);
  MachineInstr *splitS(MachineBasicBlock &MBB, MachineInstr &MI,
                       unsigned NewOpc, int Idx);
  MachineInstr *splitC(MachineBasicBlock &MBB, MachineInstr &MI,
                       unsigned NewOpc, int Idx);
  MachineInstr *splitCS(MachineBasicBlock &MBB, MachineInstr &MI,
                        unsigned NewOpc, int Idx);
  /// True if the ARM instruction performs Shift_C().
  bool isShift_C(unsigned Opcode); // NOLINT(readability-identifier-naming)
  /// No matter what pattern of Load/Store is, change the Opcode to xxxi12.
  unsigned getLoadStoreOpcode(unsigned Opcode);
  /// If the MI is load/store which needs wback, it will return true.
  bool isLDRSTRPre(unsigned Opcode);
  MachineInstrBuilder &addOperand(MachineInstrBuilder &MIB, MachineOperand &MO,
                                  bool IsDef = false);

  // step 7: select instruction (without intermediate SelectionDAG state)
  bool doSelection();
  void initEntryBasicBlock();
  void selectBasicBlock(MachineBasicBlock *MBB);
  void dumpDAG(SelectionDAG *CurDAG);

  // Functions from removed DAG folder

  /// Gets the Metadata of given SDNode.
  SDValue getMDOperand(SDNode *N);

  /// visit - create SDNodes from MI.
  SDNode *visit(const MachineInstr &MI);

  // IR emitter functions

  /// Emit code for single MachineInstruction.
  void emitInstr(IRBuilder<> &IRB, const MachineInstr &MI);

  /// Check if instruction is conditional and emit begin for the If-Else block.
  void checkConditionBegin(IRBuilder<> &IRB, NodePropertyInfo *NPI);
  /// For conditional instruction emit end for the If-Elseblock.
  Value *checkConditionEnd(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                           Value *Result, std::function<void()> EmitUpdate);

  // Emit binary operations.
  Value *emitBinaryAdd(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                     Value *S0, Value *S1);
  Value *emitBinarySub(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                     Value *S0, Value *S1);
  Value *emitBinaryMul(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                     Value *S0, Value *S1);
  Value *emitBinaryShl(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                     Value *S0, Value *S1);
  Value *emitBinaryLShr(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                      Value *S0, Value *S1);
  Value *emitBinaryAShr(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                      Value *S0, Value *S1);
  Value *emitBinaryAnd(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                     Value *S0, Value *S1);
  Value *emitBinaryOr(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                    Value *S0, Value *S1);
  Value *emitBinaryXor(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                     Value *S0, Value *S1);

  // Update the N Z C V flags for binary operation, called from macros.
  void emitBinaryCPSRAdd(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRSub(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRMul(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRShl(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRLShr(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRAShr(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRAnd(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSROr(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);
  void emitBinaryCPSRXor(IRBuilder<> &IRB, const MachineInstr &MI, Value *Inst);

  // Working with flags.

  /// Update the N Z C V flags of global variable.
  void emitCPSR(IRBuilder<> &IRB, Value *Operand0, Value *Operand1,
                unsigned Flag);
  void emitCMN(IRBuilder<> &IRB, Value *Operand0, Value *Operand1);
  void emitCMP(IRBuilder<> &IRB, Value *Operand0, Value *Operand1);
  /// Update the N Z flags of global variable.
  void emitSpecialCPSR(IRBuilder<> &IRB, Value *Result, unsigned Flag);
  void emitCondCode(IRBuilder<> &IRB, BasicBlock *IfBB, BasicBlock *ElseBB,
                    unsigned CondValue);
  Value *loadNFlag(IRBuilder<> &IRB);
  Value *loadZFlag(IRBuilder<> &IRB);
  Value *loadCFlag(IRBuilder<> &IRB);
  Value *loadVFlag(IRBuilder<> &IRB);
  void saveNFlag(IRBuilder<> &IRB, Value *NFlag);
  void saveZFlag(IRBuilder<> &IRB, Value *ZFlag);
  void saveCFlag(IRBuilder<> &IRB, Value *CFlag);
  void saveVFlag(IRBuilder<> &IRB, Value *VFlag);

  Value *emitADC(IRBuilder<> &IRB, NodePropertyInfo *NPI);
  Value *emitLoad(IRBuilder<> &IRB, const MachineInstr &MI);
  void emitStore(IRBuilder<> &IRB, const MachineInstr &MI);
  Value *emitBRD(IRBuilder<> &IRB, const MachineInstr &MI);
  /// Create PHINode for value use selection when running.
  PHINode *createAndEmitPHINode(IRBuilder<> &IRB, NodePropertyInfo *NPI,
                                BasicBlock *IfBB, BasicBlock *ElseBB,
                                Instruction *IfInst);

  PointerType *getPointerType() {
    return Type::getIntNPtrTy(Ctx, MF.getDataLayout().getPointerSizeInBits());
  }
  Type *getIntTypeByPtr(Type *PTy);

  // Wrapper to call new  Create*Load APIs
  //  LoadInst *callCreateAlignedLoad(Value *ValPtr,
  //                                  MaybeAlign Align = MaybeAlign()) {
  //    return IRB.CreateAlignedLoad(ValPtr->getType()->getPointerElementType(),
  //                                 ValPtr, Align, "");
  //  }
  LoadInst *callCreateAlignedLoad(BasicBlock *BB, Type *Ty, Value *ValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    IRBuilder<> IRB(BB);
    return IRB.CreateAlignedLoad(Ty, ValPtr, Align, "");
  }
  LoadInst *callCreateAlignedLoad(BasicBlock *BB, AllocaInst *ValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    IRBuilder<> IRB(BB);
    return IRB.CreateAlignedLoad(ValPtr->getAllocatedType(),
                                 ValPtr, Align, "");
  }
  LoadInst *callCreateAlignedLoad(BasicBlock *BB, Value *AllocaValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    return callCreateAlignedLoad(BB, dyn_cast<AllocaInst>(AllocaValPtr),
                                 Align);
  }
  LoadInst *callCreateAlignedLoad(BasicBlock *BB, GlobalValue *ValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    IRBuilder<> IRB(BB);
    return IRB.CreateAlignedLoad(ValPtr->getValueType(),
                                 ValPtr, Align, "");
  }

  LoadInst *callCreateAlignedLoad(IRBuilder<> &IRB, Type *Ty, Value *ValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    return IRB.CreateAlignedLoad(Ty, ValPtr, Align, "");
  }
  LoadInst *callCreateAlignedLoad(IRBuilder<> &IRB, AllocaInst *ValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    return IRB.CreateAlignedLoad(ValPtr->getAllocatedType(),
                                 ValPtr, Align, "");
  }
  LoadInst *callCreateAlignedLoad(IRBuilder<> &IRB, Value *AllocaValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    return callCreateAlignedLoad(IRB, dyn_cast<AllocaInst>(AllocaValPtr),
                                 Align);
  }
  LoadInst *callCreateAlignedLoad(IRBuilder<> &IRB, GlobalValue *ValPtr,
                                  MaybeAlign Align = MaybeAlign()) {
    return IRB.CreateAlignedLoad(ValPtr->getValueType(),
                                 ValPtr, Align, "");
  }
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
