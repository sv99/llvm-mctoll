//===- FunctionRaisingInfo.h ------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of FunctionRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_FUNCTION_RAISING_INFO_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_FUNCTION_RAISING_INFO_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/CodeGen/MachineFunction.h"

namespace llvm {
namespace mctoll {

class ARMMachineInstructionRaiser;

/// This structure is to extend MI properties with some additional
/// properties which are used it the raising process.
typedef struct {
  bool HasCPSR;
  bool UpdateCPSR;
  bool IsCond;
  bool IsTwoAddress;
  unsigned Cond;
  const MachineInstr *MI;
  /// If basic block for conditional instruction.
  BasicBlock *IfBB;
  /// Else basic block for conditional instruction.
  BasicBlock *ElseBB;
} NodePropertyInfo;

/// This contains information that is global to a function that is used when
/// raising a region of the function.
class FunctionRaisingInfo {
public:
  /// Initialize this FunctionRaisingInfo with the given Function and its
  /// associated MachineFunction.
  void set(ARMMachineInstructionRaiser &TheMIR);

  /// Function return IR value mapping with its parent BasicBlock, it is used
  /// to create exit BasicBlock.
  DenseMap<BasicBlock *, Value *> RetValMap;
  /// NZCV flags Alloca mapping.
  DenseMap<unsigned, Value *> AllocaMap;

  /// Clear out all the function-specific state. This returns this
  /// FunctionRaisingInfo to an empty state, ready to be used for a
  /// different function.
  void clear();

  /// Get the corresponding BasicBlock of given MachineBasicBlock. If does not
  /// give a MachineBasicBlock, it will create a new BasicBlock on current
  /// Function, and returns it.
  BasicBlock *getOrCreateBasicBlock(MachineBasicBlock *MBB = nullptr);
  MachineBasicBlock *getMBB(BasicBlock *BB) { return MBBMap[BB]; }

  /// Check the stack slot index is represented return element or not.
  bool isReturnIndex(int FrameIndex) { return FrameIndex == 0; }

  /// Check the stack slot index is represented argument or not.
  bool isArgumentIndex(int FrameIndex);
  /// Check the index is stack slot index or not.
  bool isStackIndex(int FrameIndex);

  NodePropertyInfo *getNPI(const MachineInstr &MI) {
    return NPMap[&MI];
  }
  /// Analyzes CPSR register information of MI to collect conditional
  /// code properties.
  NodePropertyInfo * initNPI(const MachineInstr &MI);

  /// Record the destination Value for NPI.
  void recordDefinition(NodePropertyInfo *NPI, Value *Val);
  /// Record the register in which the value is stored.
  void recordDefinition(Register Reg, Value *Val);

  /// Get IR value for the MI operand.
  Value *getOperand(const MachineInstr &MI, unsigned Num);
  /// Get IR value for the NPI operand corrected by NPI->IsTwoAddress.
  /// Internally call getOperand for MI.
  Value *getOperand(NodePropertyInfo *NPI, unsigned Num);

  Value *getRegValue(Register Reg) { return RegVMap[Reg]; }
  bool checkRegValue(Register Reg) { return RegVMap.count(Reg) > 0; }

private:
  ARMMachineInstructionRaiser *MIR;

  /// MBBMap - A mapping from LLVM basic blocks to their machine code entry.
  DenseMap<const BasicBlock*, MachineBasicBlock *> MBBMap;
  /// The map of the physical register with related IR value. It is used to
  /// convert physical registers to SSA form IR Values.
  DenseMap<Register, Value *> RegVMap;
  /// The map of the NodePropertyInfo for related MI.
  DenseMap<const MachineInstr *, NodePropertyInfo *> NPMap;
  /// The map for the NodePropertyInfo with related IR value (last).
  DenseMap<NodePropertyInfo *, Value *> NPVMap;
};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_FUNCTION_RAISING_INFO_H
