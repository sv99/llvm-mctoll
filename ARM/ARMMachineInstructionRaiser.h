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
class DAGRaisingInfo;

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

  // A map of MachineFunctionBlock number to BasicBlock *
  MBBNumToBBMap MbbToBBMap;

  /// Discover machine function prototype.
  Function *discoverPrototype(MachineFunction &mf);
  /// Get default Int type.
  Type *getDefaultType() {
    return Type::getIntNTy(Ctx, MF.getDataLayout().getPointerSizeInBits());
  };
  /// Check the first reference of the reg is USE.
  bool isUsedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// Check the first reference of the reg is DEF.
  bool isDefinedRegiser(unsigned reg, const MachineBasicBlock &mbb);
  /// Get all arguments types of current MachineFunction.
  void genParameterTypes(std::vector<Type *> &paramTypes);
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
  void moveArgumentToRegister(unsigned Reg, MachineBasicBlock &PMBB);

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
  void initEntryBasicBlock(FunctionRaisingInfo *FuncInfo);
  void selectBasicBlock(FunctionRaisingInfo *FuncInfo,
                        DAGRaisingInfo *DAGInfo,
                        MachineBasicBlock *MBB);
  void dumpDAG(SelectionDAG *CurDAG);

};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARMMACHINEINSTRUCTIONRAISER_H
