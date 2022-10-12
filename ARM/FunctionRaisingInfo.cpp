//===- FunctionRaisingInfo.cpp - Binary raiser utility llvm-mctoll --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of FunctionRaisingInfo class for use
// by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "FunctionRaisingInfo.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/IR/Constants.h"

using namespace llvm;
using namespace llvm::mctoll;

/// Initialize this FunctionRaisingInfo with the given Function and its
/// associated MachineFunction.
void FunctionRaisingInfo::set(
    ARMModuleRaiser &MRVal, Function &FNVal, MachineFunction &MFVal,
    SelectionDAG &DAGVal) {
  MR = &MRVal;
  Fn = &FNVal;
  MF = &MFVal;
  DAG = &DAGVal;
  CTX = &MR->getModule()->getContext();
  DLT = &MR->getModule()->getDataLayout();

  DefaultType = Type::getIntNTy(*CTX, DLT->getPointerSizeInBits());
}

SDValue FunctionRaisingInfo::getSDValueByRegister(unsigned Reg) {
  assert((RegNodeMap.count(Reg) != 0) &&
         "Can not find the corresponding value!");
  return SDValue(RegNodeMap[Reg], 0);
}

void FunctionRaisingInfo::setSDValueByRegister(unsigned Reg, SDValue Val) {
  assert((Val.getNode() != nullptr) && "Can not map a nullptr to a register!");
  RegNodeMap[Reg] = Val.getNode();
}

SDValue FunctionRaisingInfo::getSDValueByRegister(SDValue Val) {
  Register Reg = static_cast<RegisterSDNode *>(Val.getNode())->getReg();
  return (RegNodeMap.count(Reg) == 0) ? Val : SDValue(RegNodeMap[Reg], 0);
}

/// Clear out all the function-specific state. This returns this
/// FunctionRaisingInfo to an empty state, ready to be used for a
/// different function.
void FunctionRaisingInfo::clear() {
  MBBMap.clear();
  // ValueMap.clear();
  RegNodeMap.clear();
  ArgValMap.clear();
  NodeRegMap.clear();
  AllocaMap.clear();
  RetValMap.clear();
  NPMap.clear();
  VMap.clear();
  RegVMap.clear();
}

/// Get the corresponding BasicBlock of given MachineBasicBlock.
/// If does not give a MachineBasicBlock, it will create a new BasicBlock
/// on current Function, and returns it.
BasicBlock *FunctionRaisingInfo::getOrCreateBasicBlock(MachineBasicBlock *MBB) {
  // Function *Fn = getCRF();
  if (MBB == nullptr)
    return BasicBlock::Create(Fn->getContext(), "", Fn);

  for (auto Block : MBBMap) {
    if (Block.second == MBB)
      return const_cast<BasicBlock *>(Block.first);
  }

  BasicBlock *Block = nullptr;
  if (&MF->front() == MBB)
    Block = &Fn->getEntryBlock();
  else
    Block = BasicBlock::Create(Fn->getContext(), "", Fn);

  MBBMap.insert(std::make_pair(Block, MBB));

  return Block;
}

/// Gets the related IR Value of given SDNode.
Value *FunctionRaisingInfo::getRealValue(SDNode *Node) {
  assert(Node != nullptr && "Node cannot be nullptr!");
  assert(VMap.count(Node) != 0 &&
         "Cannot find value for the corresponding node!");
  return VMap[Node];
}

/// Set the related IR Value to SDNode.
void FunctionRaisingInfo::setRealValue(SDNode *Node, Value *V) {
  VMap[Node] = V;
}

/// Gets the related IR Value of given Register.
Value *FunctionRaisingInfo::getRegisterValue(Register Reg) {
  assert(RegVMap.count(Reg) != 0 &&
         "Cannot find value for the corresponding register!");
  return RegVMap[Reg];
}

/// Set the related IR Value to Register.
void FunctionRaisingInfo::setRegisterValue(Register Reg, Value *V) {
  RegVMap[Reg] = V;
}

Value *FunctionRaisingInfo::getIRValue(SDValue Val) {
  SDNode *N = Val.getNode();

  if (ConstantSDNode::classof(N))
    return const_cast<ConstantInt *>(
        (static_cast<ConstantSDNode *>(N))->getConstantIntValue());

  return getRealValue(N);
}

Value *FunctionRaisingInfo::getOperand(const MachineInstr &MI, unsigned Num) {
  const MachineOperand &MO = MI.getOperand(Num);
  Value *Operand = nullptr;
  if (MO.isReg() && !MO.isDebug()) {
    Operand = getRegisterValue(MO.getReg());
  } else if (MO.isImm()) {
    Operand = const_cast<ConstantInt *>(MO.getCImm()); //ConstantInt::get(getDefaultType(), MO.getImm());
  } else if (MO.isFI()) {
    // Frame index
    int FI = MO.getIndex();
    if (isStackIndex(FI)) {
      const MachineFrameInfo &MFI = MI.getMF()->getFrameInfo();
      Operand = const_cast<AllocaInst *>(MFI.getObjectAllocation(FI));
    } else if (isArgumentIndex(FI)) {
      Operand = const_cast<Argument *>(getRaisedFunction()->arg_begin() + (FI - 1));
    } else if (isReturnIndex(FI)) {
      const MachineFrameInfo &MFI = MI.getMF()->getFrameInfo();
      Operand = const_cast<AllocaInst *>(MFI.getObjectAllocation(0));
    } else {
      // Do nothing for now.
    }
  } else if (MO.isJTI()) {
    // Jump table index
    Operand = ConstantInt::get(getDefaultType(), MO.getIndex());
  } else if (MO.isSymbol()) {
    Operand = MR->getModule()->getNamedGlobal(MO.getSymbolName());
  } else {
    dbgs() << "Warning: visit. An unmatch type! = "
           << (unsigned)(MO.getType()) << "\n";
  }
  return Operand;
}

NodePropertyInfo * FunctionRaisingInfo::initNPI(const MachineInstr &MI) {
  NodePropertyInfo *NodeInfo = new NodePropertyInfo();
  // Initialize the NodePropertyInfo properties.
  NodeInfo->HasCPSR = false;
  NodeInfo->Special = false;
  NodeInfo->UpdateCPSR = false;

  // ARM::CPSR register use index in MachineInstr.
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // Number of operands for MachineInstr.
  int NumOps = MI.getNumOperands();

  // TODO: Now the predicate operand not stripped, so the two-address operands
  // more than two.
  // Set the MI is two-address. The default is three-address.
  if (NumOps < 4)
    NodeInfo->IsTwoAddress = true;

  // If the MachineInstr has ARM::CPSR register, update the NodePropertyInfo
  // properties.
  if (Idx != -1 && !MI.getOperand(Idx).isImplicit()) {
    // MI with ARM::CPSR register.
    if (Idx != NumOps - 1) {
      if (MI.getOperand(Idx + 1).isReg() &&
          MI.getOperand(Idx + 1).getReg() == ARM::CPSR) {
        // Pattern matching: addseq r0, r0, 0
        assert(MI.getOperand(Idx - 1).isImm() &&
               "Attempt to get non-imm operand!");

        NodeInfo->Cond = MI.getOperand(Idx - 1).getImm();
        NodeInfo->Special = true;
      } else {
        // Pattern matching: addeq r0, r0, 0
        for (int OpIdx = 1; OpIdx < NumOps; OpIdx++) {
          if (MI.getOperand(Idx - OpIdx).isImm()) {
            NodeInfo->Cond = MI.getOperand(Idx - OpIdx).getImm();
            break;
          }
        }
      }
    } else {
      if (MI.getOperand(Idx - 1).isReg() &&
          MI.getOperand(Idx - 1).getReg() == ARM::CPSR) {
        for (int OpIdx = 1; OpIdx < NumOps; OpIdx++) {
          if (MI.getOperand(Idx - OpIdx).isImm()) {
            NodeInfo->Special = true;
            NodeInfo->Cond = MI.getOperand(Idx - OpIdx).getImm();
            break;
          }
        }
      }
    }
    // Pattern matching: adds r0, r0, 0
    if (NodeInfo->Cond == ARMCC::AL)
      NodeInfo->UpdateCPSR = true;

    NodeInfo->HasCPSR = true;
  }
  NPMap[&MI] = NodeInfo;
  return NodeInfo;
}

/// Checks the SDNode is a function return or not.
bool FunctionRaisingInfo::isReturnNode(SDNode *Node) {
  if (!FrameIndexSDNode::classof(Node))
    return false;

  return isReturnIndex(dyn_cast<FrameIndexSDNode>(Node)->getIndex());
}

/// Record the new defined Node, it uses to map the register number to Node.
/// In DAG emitter, emitter get a value of use base on this defined Node.
void FunctionRaisingInfo::recordDefinition(SDNode *OldOpNode, SDNode *NewNode) {
  assert(NewNode != nullptr &&
         "The new SDNode ptr is null when record define!");

  if (OldOpNode == nullptr) {
    outs() << "Warning: RecordDefine error, the SDNode ptr is null!\n";
    return;
  }

  if (RegisterSDNode::classof(OldOpNode)) {
    Register OpReg = static_cast<RegisterSDNode *>(OldOpNode)->getReg();
    setSDValueByRegister(OpReg, SDValue(NewNode, 0));
    NodeRegMap[NewNode] = OpReg;
  }

  if (isReturnNode(OldOpNode)) {
    //FuncInfo->setRetSDValue(SDValue(NewNode, 0));
    setSDValueByRegister(ARM::R0, SDValue(NewNode, 0));
    NodeRegMap[NewNode] = ARM::R0;
  }
}
