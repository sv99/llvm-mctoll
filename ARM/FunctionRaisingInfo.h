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

#include "ARMISelLowering.h"
#include "ARMModuleRaiser.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/CodeGen/FunctionLoweringInfo.h"
#include "llvm/CodeGen/ISDOpcodes.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"

/// This is the start index of EXT_ARMISD. Because node types which start
/// from ARMISD::VLD1DUP (Next to ARMISD::MEMCPY) are identified as
/// TARGET_MEMORY_OPCODE, we set EXTARMISD_OP_BEGIN index after ARMISD::MEMCPY,
/// plugs 40 to keep long time with no confliction.
#define EXTARMISD_OP_BEGIN (ARMISD::MEMCPY + 40)

namespace llvm {
namespace mctoll {

namespace EXT_ARMISD {

enum NodeType {
  BX_RET = EXTARMISD_OP_BEGIN,
  BRD, // Direct branch
  LOAD,
  STORE,
  MSR,
  MRS,
  RSB,
  RSC,
  SBC,
  TEQ,
  TST,
  BIC,
  MLA,
  UXTB,
  EXT_ARMISD_OP_END
};

} // namespace EXT_ARMISD

/// This structure is to extend SDNode properties, some additional SDNode
/// properties which are used by llvm-mctoll will be kept at here.
typedef struct {
  bool HasCPSR;
  bool Special;
  bool UpdateCPSR;
  bool IsCond;
  bool IsTwoAddress;
  unsigned Cond;
  const MachineInstr *MI;
  SDNode *Node;
  /// If basic block for conditional instruction.
  BasicBlock *IfBB;
  /// Else basic block for conditional instruction.
  BasicBlock *ElseBB;
} NodePropertyInfo;

/// This contains information that is global to a function that is used when
/// raising a region of the function.
class FunctionRaisingInfo { //: public FunctionLoweringInfo {
public:
  /// NZCV mapping.
  DenseMap<unsigned, Value *> AllocaMap;
  /// Function return IR value mapping with its parent BasicBlock, it is used
  /// to create exit BasicBlock.
  DenseMap<BasicBlock *, Value *> RetValMap;

  /// Initialize this FunctionRaisingInfo with the given Function and its
  /// associated MachineFunction.
  void set(ARMModuleRaiser &MRVal, Function &FNVal, MachineFunction &MFVal,
           SelectionDAG &DAGVal);

  /// Clear out all the function-specific state. This returns this
  /// FunctionRasisingInfo to an empty state, ready to be used for a
  /// different function.
  void clear();

  /// Gets corresponding SelectionDAG object.
  SelectionDAG &getCurDAG() { return *DAG; }
  /// Get current raised llvm::Function.
  Function *getRaisedFunction() { return Fn; }
  const MachineFrameInfo &getFrameInfo() { return MF->getFrameInfo(); }
  Module *getModule() const { return MR->getModule(); }
  /// Get the corresponding BasicBlock of given MachineBasicBlock. If does not
  /// give a MachineBasicBlock, it will create a new BasicBlock on current
  /// Function, and returns it.
  BasicBlock *getOrCreateBasicBlock(MachineBasicBlock *MBB = nullptr);
  MachineBasicBlock *getMBB(BasicBlock *BB) { return MBBMap[BB]; }

  /// Check the stack slot index is represented return element or not.
  bool isReturnIndex(int FrameIndex) { return FrameIndex == 0; }
  /// Checks the SDNode is a function return or not.
  bool isReturnNode(SDNode *Node);

  /// Check the stack slot index is represented argument or not.
  bool isArgumentIndex(int FrameIndex) {
    assert(FrameIndex >= 0 && "The stack frame index must be larger than 0.");
    return FrameIndex > 0 && (unsigned)FrameIndex <= Fn->arg_size();
  }
  /// Check the index is stack slot index or not.
  bool isStackIndex(int FrameIndex) {
    assert(FrameIndex >= 0 && "The stack frame index must be larger than 0.");
    return (unsigned)FrameIndex > Fn->arg_size();
  }

  Type *getDefaultType() { return DefaultType; }
  EVT getDefaultEVT() { return EVT::getEVT(DefaultType); }

  LLVMContext *CTX;
  const DataLayout *DLT;
  Type *DefaultType;

  NodePropertyInfo *getNPI(const MachineInstr &MI) {
    return NPMap[&MI];
  }
  /// Analyzes CPSR register information of MI to collect conditional
  /// code properties.
  NodePropertyInfo * initNPI(const MachineInstr &MI);

  // Trace SDNodes and values in the raising process.

  /// Record the new defined Node, it uses to map the register number to Node.
  /// In DAG emitter, emitter get a value of use base on this defined Node.
  void recordDefinition(SDNode *OldOpNode, SDNode *NewNode);
  void recordDefinition(NodePropertyInfo *NPI, Value *Val);
  void recordDefinition(Register Reg, Value *Val);

  SDValue getSDValueByRegister(unsigned Reg);
  SDValue getSDValueByRegister(SDValue Val);
  void setSDValueByRegister(unsigned Reg, SDValue Val);

  /// Gets the related IR Value of given SDNode.
  Value *getRealValue(SDNode *Node);
  /// Set the related IR Value to SDNode.
  void setRealValue(SDNode *Node, Value *V);
  /// Gets the related IR Value of given Register.
  Value *getRegisterValue(Register Reg);
  /// Set the related IR Value to Register.
  void setRegisterValue(Register Reg, Value *V);
  /// Get IR value for the MI operand.
  Value *getOperand(const MachineInstr &MI, unsigned Num);
  /// Get IR value for the NPI operand corrected by IsTwoAddress.
  /// Internally call getOperand for MI.
  Value *getOperand(NodePropertyInfo *NPI, unsigned Num);
  /// Get IR value for the SDValue operand.
  Value *getIRValue(SDValue Val);

  Value *getArgValue(SDNode *Node) { return ArgValMap[NodeRegMap[Node]]; }
  Value *getArgValue(Register Reg) { return ArgValMap[Reg]; }
  void setNodeReg(SDNode *Node, Register Reg) { NodeRegMap[Node] = Reg; }
  void setArgValue(SDNode *Node, Value *V) { ArgValMap[NodeRegMap[Node]] = V; }
  bool checkArgValue(SDNode *Node) {
    return checkArgValue(NodeRegMap[Node]);
  }
  Value *getNodeValue(NodePropertyInfo *NPI) { return NPVMap[NPI]; }
  bool checkArgValue(Register Reg) {
    return ArgValMap.count(Reg) > 0;
  }

private:
  Function *Fn;
  MachineFunction *MF;
  ARMModuleRaiser *MR;
  SelectionDAG *DAG;
  /// MBBMap - A mapping from LLVM basic blocks to their machine code entry.
  DenseMap<const BasicBlock*, MachineBasicBlock *> MBBMap;

  /// The map of physical register with related IR Value. It is used to convert
  /// physical registers to SSA form IR Values.
  DenseMap<Register, SDNode *> RegNodeMap;
  /// The map of the physical register with related IR value.
  DenseMap<Register, Value *> RegVMap;
  /// The map for each SDNode with its IR value.
  DenseMap<SDNode *, Value *> VMap;
  /// The map for each MI with its additional property.
  //DenseMap<SDNode *, NodePropertyInfo *> NPMap;
  DenseMap<const MachineInstr *, NodePropertyInfo *> NPMap;
  /// Set the Value for Register mapping.
  DenseMap<Register, Value *> ArgValMap;
  /// Set register for SDNode mapping.
  DenseMap<SDNode *, Register> NodeRegMap;
  /// The map for the NodePropertyInfo its IR value (last).
  DenseMap<NodePropertyInfo *, Value *> NPVMap;


  /// ValueMap - Since we emit code for the function a basic block at a time,
  /// we must remember which virtual registers hold the values for
  /// cross-basic-block values.
  // DenseMap<const Value *, Register> ValueMap;

};

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_FUNCTION_RAISING_INFO_H
