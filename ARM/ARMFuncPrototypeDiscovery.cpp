//===- ARMFunctionPrototype.cpp - Binary raiser utility llvm-mctoll -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the part implementation of ARMMachineInstructionRaiser
// class for use by llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "ARM.h"
#include "ARMMachineInstructionRaiser.h"
#include "ARMRaisedValueTracker.h"
#include "ARMSubtarget.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/LoopTraversal.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Object/ELFObjectFile.h"
#include <set>
#include <vector>

using namespace llvm;
using namespace llvm::mctoll;

/// Check the first reference of the reg in the MBB is USE.
bool ARMMachineInstructionRaiser::isUsedRegister(unsigned Reg,
                                         const MachineBasicBlock &MBB) {
  for (const MachineInstr &MI : MBB.instrs()) {
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && (MO.getReg() == Reg))
        return MO.isUse();
    }
  }

  return false;
}

/// Check the first reference of the reg is DEF.
void ARMMachineInstructionRaiser::genParameterTypes(std::vector<Type *> &ParamVec) {
  assert(!MF.empty() && "The function body is empty!!!");
  MF.getRegInfo().freezeReservedRegs(MF);
  LivePhysRegs LiveInPhysRegs;
  for (MachineBasicBlock &EMBB : MF)
    computeAndAddLiveIns(LiveInPhysRegs, EMBB);
  // Walk the CFG DFS to discover first register usage
  df_iterator_default_set<const MachineBasicBlock *, 16> Visited;
  DenseMap<unsigned, bool> ArgObtain;
  ArgObtain[ARM::R0] = false;
  ArgObtain[ARM::R1] = false;
  ArgObtain[ARM::R2] = false;
  ArgObtain[ARM::R3] = false;
  const MachineBasicBlock &MBBFront = MF.front();
  DenseMap<int, Type *> TyArr;
  int MaxIdx = -1; // When the MaxIdx is -1, means there is no argument.
  // Track register liveness on CFG.
  for (const MachineBasicBlock *Mbb : depth_first_ext(&MBBFront, Visited)) {
    for (unsigned IReg = ARM::R0; IReg < ARM::R4; IReg++) {
      if (!ArgObtain[IReg] && Mbb->isLiveIn(IReg)) {
        for (const MachineInstr &LMI : Mbb->instrs()) {
          auto RUses = LMI.uses();
          const auto *ResIter =
              std::find_if(RUses.begin(), RUses.end(),
                           [IReg](const MachineOperand &OP) -> bool {
                             return OP.isReg() && (OP.getReg() == IReg);
                           });
          if (ResIter != RUses.end()) {
            MaxIdx = IReg - ARM::R0;
            TyArr[MaxIdx] = getDefaultType();
            break;
          }
        }
        ArgObtain[IReg] = true;
      }
    }
  }
  // The rest of function arguments are from stack.
  for (const MachineBasicBlock &Mbb : MF) {
    for (const MachineInstr &Mi : Mbb.instrs()) {
      // Match pattern like ldr r1, [fp, #8].
      if (Mi.getOpcode() == ARM::LDRi12 && Mi.getNumOperands() > 2) {
        const MachineOperand &Mo = Mi.getOperand(1);
        const MachineOperand &Mc = Mi.getOperand(2);
        if (Mo.isReg() && Mo.getReg() == ARM::R11 && Mc.isImm()) {
          // TODO: Need to check the imm is larger than 0 and it is align
          // by 4(32 bit).
          int Imm = Mc.getImm();
          if (Imm >= 0) {
            // The start index of arguments on stack. If the library was
            // compiled by clang, it starts from 2. If the library was compiled
            // by GNU cross compiler, it starts from 1.
            // FIXME: For now, we only treat that the library was complied by
            // clang. We will enable the 'if condition' after we are able to
            // identify the library was compiled by which compiler.
            int Idxoff = 2;
            if (true /* clang */)
              Idxoff = 2;
            else /* gnu */
              Idxoff = 1;

            int Idx = Imm / 4 - Idxoff + 4; // Plus 4 is to guarantee the first
                                            // stack argument index is after all
                                            // of register arguments' indices.
            if (MaxIdx < Idx)
              MaxIdx = Idx;
            TyArr[Idx] = getDefaultType();
          }
        }
      }
    }
  }
  for (int Idx = 0; Idx <= MaxIdx; ++Idx) {
    if (TyArr[Idx] == nullptr)
      ParamVec.push_back(getDefaultType());
    else
      ParamVec.push_back(TyArr[Idx]);
  }
}

/// Check the last reference of the reg in the MBB is DEF.
bool ARMMachineInstructionRaiser::isDefinedRegister(
    unsigned Reg, const MachineBasicBlock &MBB) {
  for (MachineBasicBlock::const_reverse_iterator Ii = MBB.rbegin(),
                                                 Ie = MBB.rend();
       Ii != Ie; ++Ii) {
    const MachineInstr &MI = *Ii;
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && (MO.getReg() == Reg)) {
        // The return register must not be tied to another register.
        // If it was, it should not be return register.
        if (MO.isTied())
          return false;

        return MO.isDef();
      }
    }
  }

  return false;
}

/// Get return type of current MachineFunction.
Type *ARMMachineInstructionRaiser::genReturnType() {
  // TODO: Need to track register liveness on CFG.
  Type *RetTy;
  RetTy = Type::getVoidTy(Ctx);
  for (const MachineBasicBlock &MBB : MF) {
    if (MBB.succ_empty()) {
      if (isDefinedRegister(ARM::R0, MBB)) {
        // TODO: Need to identify data type, int, long, float or double.
        RetTy = getDefaultType();
        break;
      }
    }
  }

  return RetTy;
}

// Add Reg to LiveInSet. This function adds the actual register Reg - not its
// 64-bit super register variant because we'll need the actual register to
// determine the argument type.
void ARMMachineInstructionRaiser::addRegisterToFunctionLiveInSet(
    MCPhysRegSet &LiveInSet, unsigned Reg) {

  // Nothing to do if Reg is already in the set.
  if (LiveInSet.find(Reg) != LiveInSet.end())
    return;

  // Find if LiveInSet already has a sub-register of Reg
  const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
  unsigned PrevLiveInReg = ARM::NoRegister;
  for (MCSubRegIterator SubRegs(Reg, TRI, /*IncludeSelf=*/false);
       (SubRegs.isValid() && (PrevLiveInReg == ARM::NoRegister)); ++SubRegs) {
    if (LiveInSet.find(*SubRegs) != LiveInSet.end())
      PrevLiveInReg = *SubRegs;
  }

  // If a sub-register of Reg is already in LiveInSet, replace it with Reg
  if (PrevLiveInReg != ARM::NoRegister) {
    // Delete the sub-register and add the Reg
    LiveInSet.erase(PrevLiveInReg);
    // Insert UseReg
    LiveInSet.insert(Reg);
    return;
  }

  // No sub-register is in the current livein set.
  // Check if LiveInSet already has a super-register of Reg
  for (MCSuperRegIterator SuperRegs(Reg, TRI, /*IncludeSelf=*/false);
       (SuperRegs.isValid() && (PrevLiveInReg == ARM::NoRegister));
       ++SuperRegs) {
    if (LiveInSet.find(*SuperRegs) != LiveInSet.end())
      PrevLiveInReg = *SuperRegs;
  }

  // If no super register of Reg is in current liveins, add Reg to set
  if (PrevLiveInReg == ARM::NoRegister)
    LiveInSet.insert(Reg);

  // If a super-register of Reg is in LiveInSet, there is nothing to be done.
  // The fact that Reg is livein, is already noted by the presence of its
  // super register.
}

Type *ARMMachineInstructionRaiser::getFunctionReturnType() {
  Type *ReturnType = nullptr;

  // Find a return block. It is sufficient to get one of the return blocks to
  // find the return type. This type should be the same on any of the paths from
  // entry to any other return blocks.
  SmallVector<MachineBasicBlock *, 8> WorkList;
  for (MachineBasicBlock &MBB : MF) {
    if (MBB.isReturnBlock()) {
      // Push return block to ensure we look at the return block first.
      WorkList.push_back(&MBB);
      break;
    }
  }

  while (!WorkList.empty() && ReturnType == nullptr) {
    MachineBasicBlock *MBB = WorkList.pop_back_val();
    ReturnType = getReachingReturnType(*MBB);
  }

  // If return type is still not discovered, assume it to be void
  if (ReturnType == nullptr)
    ReturnType = Type::getVoidTy(MF.getFunction().getContext());

  return ReturnType;
}

FunctionType *ARMMachineInstructionRaiser::getRaisedFunctionPrototype() {
  raiseMachineJumpTable();

  if (RaisedFunction != nullptr)
   return RaisedFunction->getFunctionType();

  // Cleanup NOOP instructions from all MachineBasicBlocks
  // deleteNOOPInstrMF();
  // Clean up any empty basic blocks
  // unlinkEmptyMBBs();

  MF.getRegInfo().freezeReservedRegs(MF);
  std::vector<Type *> ArgTypeVector;

  // Discover function arguments.

  // Function livein set will contain the actual registers that are
  // livein - not sub or super registers
  MCPhysRegSet FunctionLiveInRegs;
  // Set of registers defined in a block.
  std::set<Register> MBBDefRegs;

  PerMBBDefinedRegs.clear();

  Type *DiscoveredRetType = nullptr;

  // Walk the CFG DFS to discover first register usage
  LoopTraversal Traversal;
  LoopTraversal::TraversalOrder TraversedMBBOrder = Traversal.traverse(MF);
  for (LoopTraversal::TraversedMBBInfo TraversedMBB : TraversedMBBOrder) {
    MachineBasicBlock *MBB = TraversedMBB.MBB;
    if (MBB->empty())
      continue;

    int MBBNo = MBB->getNumber();
    // TODO: LoopTraversal assumes fully-connected CFG. However, need to
    //       handle blocks with terminator instruction that could potentially
    //       result in a disconnected CFG - such as branch with register
    //       target.
    MachineInstr &TermInst = MBB->instr_back();
    if (TermInst.isBranch()) {
      auto OpType = TermInst.getOperand(0).getType();
      assert(
          ((OpType == MachineOperand::MachineOperandType::MO_Immediate) ||
           (OpType == MachineOperand::MachineOperandType::MO_JumpTableIndex)) &&
          "Unexpected block terminator found");
    }

    // Union of defined registers of all predecessors
    for (auto *PredMBB : MBB->predecessors()) {
      auto PredMBBRegsIter =
          PerMBBDefinedRegs.find(PredMBB->getNumber());
      // Register defs of all predecessors may not be available if MBB
      // is not ready for final round of processing.
      if (PredMBBRegsIter != PerMBBDefinedRegs.end()) {
        for (auto Reg : PredMBBRegsIter->second) {
          MBBDefRegs.insert(Reg);
        }
      }
    }

    for (MachineInstr &MI : *MBB) {
      unsigned Opc = MI.getOpcode();
      // MI is not a tail call instruction, unless determined otherwise.
      bool IsTailCall = false;

      auto *AMI = RaisedValues->initMachineInstr(MI);
      // ARM clear register idiom:
      // eor reg, reg
      // If reg happens to be an argument register, it should not be considered
      // as such. Record it as such.
      if (Opc == ARM::EORri || Opc == ARM::EORrr || Opc == ARM::EORrsi ||
          Opc == ARM::EORrsr || Opc == ARM::tEOR || Opc == ARM::t2EORrr ||
          Opc == ARM::t2EORrs || Opc == ARM::t2EORri) {
        unsigned DestOpIndx = 0, SrcOp1Indx = 1, SrcOp2Indx = 2;
        if (AMI->IsTwoAddress) {
          SrcOp1Indx = 0, SrcOp2Indx = 1;
        }
        const MachineOperand &DestOp = MI.getOperand(DestOpIndx);
        const MachineOperand &Use1Op = MI.getOperand(SrcOp1Indx);
        const MachineOperand &Use2Op = MI.getOperand(SrcOp2Indx);

        assert(Use1Op.isReg() && Use2Op.isReg() && DestOp.isReg() &&
               (MI.findTiedOperandIdx(SrcOp1Indx) == DestOpIndx) &&
               "Expecting register operands for xor instruction");

        // If the source regs are not the same
        if (Use1Op.getReg() != Use2Op.getReg()) {
          // If the source register has not been used before, add it to
          // the list of first use registers.
          Register UseReg = Use1Op.getReg();
          if (MBBDefRegs.find(UseReg) == MBBDefRegs.end())
            addRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);

          UseReg = Use2Op.getReg();
          if (MBBDefRegs.find(UseReg) == MBBDefRegs.end())
            addRegisterToFunctionLiveInSet(FunctionLiveInRegs, UseReg);
        }

        // Add def reg to MBBDefRegs set
        Register DestReg = DestOp.getReg();
        // We need the last definition. Even if there is a previous definition,
        // it is correct to just overwrite the size information.
        // Save fixed 32 bit register size.
        MBBDefRegs.insert(DestReg);
      } else if (MI.isCall() || MI.isUnconditionalBranch()) {
        // If this is an unconditional branch, check if it is a tail call.
        if (MI.isUnconditionalBranch()) {
          if ((MI.getNumOperands() > 0) && MI.getOperand(0).isImm()) {
            int64_t BranchOffset = MI.getOperand(0).getImm();

            // Get the (MCInst) offset of the instruction in the binary
            uint64_t MCInstOffset = InstRaiser->getMCInstIndex(MI);
            int64_t BranchTargetOffset = MCInstOffset +
                                         InstRaiser->getMCInstSize(MCInstOffset) +
                                         BranchOffset;
            // This may be a tail call if there is no MBB corresponding to the
            // branch target offset.
            if (InstRaiser->getMBBNumberOfMCInstOffset(BranchTargetOffset, MF) ==
                -1) {
              // It is a tail call only if there are no other instructions
              // after this unconditional branch instruction.
              IsTailCall = (MI.getNextNode() == nullptr);
            }
          }
        }

        // If the instruction is a call or a potential tail call,
        // attempt to find the called function.
        if (MI.isCall() || IsTailCall) {
          // Check if the first use of argument registers is as
          // arguments of a call or a tail-call.
          unsigned int Opcode = MI.getOpcode();
          if ((Opcode == ARM::BL) || (Opcode == ARM::BL_pred) ||
              (Opcode == ARM::tBL)) {
            Function *CalledFunc = getCalledFunction(MI);
            // If the called function is found, consider argument
            // registers as use registers.
            if (CalledFunc != nullptr) {
              unsigned ArgRegVecIndex = 0;
              for (auto &Arg : CalledFunc->args()) {
                unsigned Reg = getArgumentReg(ArgRegVecIndex++, Arg.getType());
                // If Reg use has no previous def
                if (MBBDefRegs.find(Reg) == MBBDefRegs.end())
                  addRegisterToFunctionLiveInSet(FunctionLiveInRegs, Reg);
              }

              // Check for return type and set return register as a
              // defined register
              Type *RetTy = CalledFunc->getReturnType();
              if (!RetTy->isVoidTy()) {
                // Mark it as defined register
                MBBDefRegs.insert(ARM::R0);
              }

              if (IsTailCall)
                DiscoveredRetType = RetTy;
            }
          }
        }
      } else {
        for (MachineOperand MO : MI.operands()) {
          if (!MO.isReg())
            continue;

          Register Reg = MO.getReg();
          if (MO.isUse()) {
            // If Reg use has no previous def
            if (MBBDefRegs.find(Reg) == MBBDefRegs.end())
              addRegisterToFunctionLiveInSet(FunctionLiveInRegs, Reg);
          }

          if (MO.isDef()) {
            // We need the last definition. Even if there is a previous
            // definition, it is correct to just overwrite the size
            // information.
            MBBDefRegs.insert(Reg);
          }
        }
      }
    }

    // Save the per-MBB define register definition information
    if (PerMBBDefinedRegs.find(MBBNo) != PerMBBDefinedRegs.end()) {
      // Per-MBB reg def info is expected to exist only if this is not
      // the primary pass of the MBB.
      assert((!TraversedMBB.PrimaryPass) &&
             "Unexpected state of register definition information");
      // Clear the existing map to allow for adding new map
      PerMBBDefinedRegs.erase(MBBNo);
    }
    PerMBBDefinedRegs.emplace(MBBNo, MBBDefRegs);
  }

  // Use the first register usage list to form argument vector using
  // first argument register usage.
  buildFuncArgTypeVector(FunctionLiveInRegs, ArgTypeVector);
  // 2. Discover function return type
  Type *ReturnType = DiscoveredRetType != nullptr ? DiscoveredRetType
                                                  : getFunctionReturnType();
  if (ReturnType == nullptr)
    return nullptr;

  // The Function object associated with current MachineFunction object
  // is only a placeholder. It was created to facilitate creation of
  // MachineFunction object with a prototype void functionName(void).
  // The Module object contains this place-holder Function object in its
  // FunctionList. Since the return type and arguments are now
  // discovered, we need to replace this placeholder Function object in
  // module with the correct Function object being created now.

  // 1. Get the current function name
  StringRef FunctionName = MF.getFunction().getName();
  Module *M = getModule();

  // 2. Get the corresponding Function* registered in module
  Function *TempFunctionPtr = M->getFunction(FunctionName);
  assert(TempFunctionPtr != nullptr && "Function not found in module list");

  // 4. Delete the tempFunc from module list to allow for the creation of the
  //    real function to add the correct one to FunctionList of the module.
  M->getFunctionList().remove(TempFunctionPtr);

  // 3. Create a function type using the discovered arguments and return value.
  FunctionType *FT =
      FunctionType::get(ReturnType, ArgTypeVector, false /* isVarArg*/);

  // 4. Create the real Function now that we have discovered the arguments.
  RaisedFunction =
      Function::Create(FT, GlobalValue::ExternalLinkage, FunctionName, M);

  // Set C calling convention
  RaisedFunction->setCallingConv(CallingConv::C);
  // Set the function to be in the same linkage unit
  RaisedFunction->setDSOLocal(true);
  // TODO : Set other function attributes as needed.
  // Add argument names to the function.
  // Note: Call to arg_begin() calls Function::BuildLazyArguments()
  // to build the arguments.
  int ArgIdx = 1;
  for (Argument &Arg : RaisedFunction->args())
    Arg.setName("arg." + std::to_string(ArgIdx++));

  // Insert the map of raised function to tempFunctionPointer.
  const_cast<ModuleRaiser *>(MR)->insertPlaceholderRaisedFunctionMap(
      RaisedFunction, TempFunctionPtr);

  return RaisedFunction->getFunctionType();
//  Function &Fn = MF.getFunction();
//
//  std::vector<Type *> ParamTys;
//  genParameterTypes(ParamTys);
//  Type *RetTy = genReturnType();
//  FunctionType *FnTy = FunctionType::get(RetTy, ParamTys, false);
//
//  MachineModuleInfo &Mmi = MF.getMMI();
//  Module *Mdl = const_cast<Module *>(Mmi.getModule());
//  Mdl->getFunctionList().remove(&Fn);
//  RaisedFunction =
//      Function::Create(FnTy, GlobalValue::ExternalLinkage, Fn.getName(), Mdl);
//  // When run as FunctionPass, the Function must not be empty, so add
//  // EntryBlock at here.
//  BasicBlock::Create(Ctx, "EntryBlock", RaisedFunction);
//
//  Function *Ori = const_cast<Function *>(&MF.getFunction());
//  // Insert the map of raised function to tempFunctionPointer.
//  const_cast<ModuleRaiser *>(MR)->insertPlaceholderRaisedFunctionMap(
//      RaisedFunction, Ori);
//
//  return RaisedFunction->getFunctionType();
}

// Discover and return the type of return register (viz., RAX or its
// sub-register) definition that reaches MBB. Only definition of return register
// after the last call instruction or that found on a reverse traversal without
// encountering any call instruction, are considered to be indicative of return
// value set up.
Type *ARMMachineInstructionRaiser::getReachingReturnType(
    const MachineBasicBlock &MBB) {
  bool HasCall = false;
  // Find return type in MBB
  Type *ReturnType = getReturnTypeFromMBB(MBB, HasCall);
  // If the MBB has no call instruction and return type is not found, traverse
  // up its predecessors to find the type of reaching definition of return
  // register.
  if (!HasCall) {
    if (ReturnType == nullptr) {
      // Initialize a bit vector tracking visited basic blocks
      BitVector BlockVisited(MF.getNumBlockIDs(), false);
      SmallVector<MachineBasicBlock *, 8> WorkList;
      Type *ReturnTypeOnPath = nullptr;

      for (auto *P : MBB.predecessors()) {
        WorkList.insert(WorkList.begin(), P);
      }

      while (!WorkList.empty() && !ReturnType) {
        MachineBasicBlock *PredMBB = WorkList.pop_back_val();
        int CurPredMBBNo = PredMBB->getNumber();
        if (!BlockVisited[CurPredMBBNo]) {
          // Mark block as visited
          BlockVisited.set(CurPredMBBNo);
          // Get function return type from MBB
          ReturnTypeOnPath = getReturnTypeFromMBB(*PredMBB, HasCall);
          // If PredMBB has no call and has no return  register definition,
          // continue traversal.
          if (!HasCall && ReturnTypeOnPath == nullptr) {
            // If PredMBB is the entry block and return type is not found, it
            // implies that there is at least one path that doesn't set return
            // register. Hence, there is no further need for further traversal.
            if (PredMBB->isEntryBlock()) {
              ReturnType = nullptr;
              break;
            }
            // Continue traversal
            for (auto *Pred : PredMBB->predecessors()) {
              if (!BlockVisited[Pred->getNumber()])
                WorkList.insert(WorkList.begin(), Pred);
            }
          } else {
            // ReturnTypeOnPath is found
            if (ReturnTypeOnPath) {
              // Ensure it is the same as any found along other reverse
              // traversals.
              if (ReturnType)
                assert(ReturnType == ReturnTypeOnPath);
              else
                // Return type found on this traversal
                ReturnType = ReturnTypeOnPath;
            }
          }
        }
      }
    }
  }
  return ReturnType;
}

// Discover and return the type of return register definition in the block
// MBB. Return type is constructed based on the last definition of RAX (or
// its sub-register) in MBB. Only definitions of return register after the
// last call instruction, if one exists, in the block are considered to be
// indicative of return value set up.
Type *
ARMMachineInstructionRaiser::getReturnTypeFromMBB(const MachineBasicBlock &MBB,
                                                  bool &HasCall) {
  Type *ReturnType = nullptr;
  HasCall = false;

  // Walk the block backwards
  for (MachineBasicBlock::const_reverse_instr_iterator I = MBB.instr_rbegin(),
                                                       E = MBB.instr_rend();
       I != E; I++) {
    // No need to inspect instructions prior to the last call instruction since
    // the function prototype will indicate if the called function has a return
    // value. The return type of the called function is the return type of this
    // function.
    if (I->isCall()) {
      Function *CalledFunc = getCalledFunction(*I);
      HasCall = true;
      // Raised function prototype of the called function may not yet be
      // constructed. In that case, consider return type to be void.
      ReturnType =
          (CalledFunc == nullptr)
              ? nullptr /* Type::getVoidTy(MF.getFunction().getContext()) */
              : CalledFunc->getReturnType();
      break;
    }

    if (ReturnType)
      return ReturnType;

    // No need to inspect return instruction
    if (I->isReturn())
      continue;

    // No need to inspect padding instructions. ld uses nop and lld uses int3
    // for alignment padding in text section.
    auto Opcode = I->getOpcode();
    if (isNoop(Opcode) || (Opcode == X86::INT3))
      continue;

    unsigned DefReg = ARM::NoRegister;
    const TargetRegisterInfo *TRI = MF.getRegInfo().getTargetRegisterInfo();
    // Check if any of RAX, EAX, AX or AL are explicitly defined
    if (I->getDesc().getNumDefs() != 0) {
      const MachineOperand &MO = I->getOperand(0);
      if (MO.isReg()) {
        Register PReg = MO.getReg();
        if (!Register::isPhysicalRegister(PReg))
          continue;

        // Check if PReg is any of the sub-registers of RAX (including itself)
        for (MCSubRegIterator SubRegs(X86::RAX, TRI,
                                      /*IncludeSelf=*/true);
             (SubRegs.isValid() && DefReg == ARM::NoRegister); ++SubRegs) {
          if (*SubRegs == PReg.asMCReg()) {
            DefReg = *SubRegs;
            break;
          }
        }
        if (DefReg == ARM::NoRegister && PReg == X86::XMM0) {
          DefReg = X86::XMM0;
          ReturnType = RaisedValues->getSSEInstructionType(
              *I, 128 /* Size of XMM0 */, Ctx);
        }
      }
    }

    // If explicitly defined register is not a return register, check if
    // any of the sub-registers of RAX (including itself) is implicitly
    // defined.
    for (MCSubRegIterator SubRegs(X86::RAX, TRI, /*IncludeSelf=*/true);
         (SubRegs.isValid() && DefReg == ARM::NoRegister); ++SubRegs) {
      if (hasExactImplicitDefOfPhysReg(*I, *SubRegs, TRI)) {
        DefReg = *SubRegs;
        break;
      }
    }

    if (DefReg == ARM::NoRegister &&
        hasExactImplicitDefOfPhysReg(*I, X86::XMM0, TRI)) {
      DefReg = X86::XMM0;
      ReturnType = getRaisedValues()->getSSEInstructionType(
          *I, 128 /* Size of XMM0 */, Ctx);
    }

    // If the defined register is a return register
    if (DefReg != ARM::NoRegister) {
      if (!Register::isPhysicalRegister(DefReg))
        continue;

      if (ReturnType == nullptr) {
        ReturnType = getPhysRegType(DefReg);
        // Stop processing any further instructions as the return type is found.
        break;
      }
    }
  }

  return ReturnType;
}

// Construct argument type vector from the physical register vector.
// Requirements : PhysRegs is a set of registers each with no super or
// sub-registers.
bool ARMMachineInstructionRaiser::buildFuncArgTypeVector(
    const std::set<MCPhysReg> &PhysRegs, std::vector<Type *> &ArgTyVec) {
  // A map of argument number and type as discovered
  std::map<unsigned int, Type *> ArgNumTypeMap;
  std::map<unsigned int, Type *> SSEArgNumTypeMap;
  int MaxGPArgNum = 0;
  int MaxSSEArgNum = 0;

  for (MCPhysReg PReg : PhysRegs) {
    // If Reg is an argument register per C standard calling convention
    // construct function argument.
    int ArgNum = getArgumentNumber(PReg);
    if (ArgNum > 0) {

      if (isGPReg(PReg)) {
        if (ArgNum > MaxGPArgNum)
          MaxGPArgNum = ArgNum;

        // Make sure each argument position is discovered only once
        assert(ArgNumTypeMap.find(ArgNum) == ArgNumTypeMap.end());
        if (is8BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt8Ty(Ctx)));
        } else if (is16BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt16Ty(Ctx)));
        } else if (is32BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt32Ty(Ctx)));
        } else if (is64BitPhysReg(PReg)) {
          ArgNumTypeMap.insert(
              std::make_pair(ArgNum, Type::getInt64Ty(Ctx)));
        }
      } else if (isSSE2Reg(PReg)) {
        if (ArgNum > MaxSSEArgNum)
          MaxSSEArgNum = ArgNum;

        // Make sure each argument position is discovered only once
        assert(SSEArgNumTypeMap.find(ArgNum) == SSEArgNumTypeMap.end());
        SSEArgNumTypeMap.insert(
            std::make_pair(ArgNum, Type::getDoubleTy(Ctx)));
      } else {
        outs() << RegisterInfo->getRegAsmName(PReg) << "\n";
        llvm_unreachable("Unhandled register type encountered in binary");
      }
    }
  }

  // Build argument type vector that will be used to build FunctionType
  // while sanity checking arguments discovered
  for (int Idx = 1; Idx <= MaxGPArgNum; Idx++) {
    auto ArgIter = ArgNumTypeMap.find(Idx);
    if (ArgIter == ArgNumTypeMap.end()) {
      // Argument register not used. It is most likely optimized.
      // The argument is not used. Safe to consider it to be of 64-bit
      // type.
      ArgTyVec.push_back(Type::getInt64Ty(Ctx));
    } else
      ArgTyVec.push_back(ArgNumTypeMap.find(Idx)->second);
  }
  // TODO: for now we just assume that SSE registers are always the last
  // arguments This may work when compiling to X86 using the System V ABI, not
  // necessarily for other ABIs.
  for (int Idx = 1; Idx <= MaxSSEArgNum; Idx++) {
    auto ArgIter = SSEArgNumTypeMap.find(Idx);
    if (ArgIter == SSEArgNumTypeMap.end()) {
      ArgTyVec.push_back(Type::getDoubleTy(Ctx));
    } else {
      ArgTyVec.push_back(ArgIter->second);
    }
  }
  return true;
}

// If MI is a call or tail call (i.e., branch to call target) return Function *
// corresponding to the callee. Return nullptr in all other cases.
Function *
ARMMachineInstructionRaiser::getCalledFunction(const MachineInstr &MI) {
  Function *CalledFunc = nullptr;
  unsigned int Opcode = MI.getOpcode();

  const MCInstrDesc &MCID = MI.getDesc();
  assert(ARM::isImmPCRel(MCID.TSFlags) &&
         "PC-Relative control transfer expected");

  // Get target offset of the call instruction
  const MachineOperand &MO = MI.getOperand(0);
  assert(MO.isImm() && "Expected immediate operand not found");
  int64_t RelCallTargetOffset = MO.getImm();

  // Get MCInst offset of the corresponding call instruction in the binary.
  uint64_t MCInstOffset = InstRaiser->getMCInstIndex(MI);
  uint64_t MCInstSize = InstRaiser->getMCInstSize(MCInstOffset);
  // First check if PC-relative call target embedded in the call
  // instruction can be used to get called function.
  int64_t CallTargetIndex = MCInstOffset + MR->getTextSectionAddress() +
                            MCInstSize + RelCallTargetOffset;
  // Get the function at index CalltargetIndex
  CalledFunc = MR->getRaisedFunctionAt(CallTargetIndex);

  // Search the called function from the excluded set of function filter.
  if (CalledFunc == nullptr) {
    auto *Filter = MR->getFunctionFilter();
    CalledFunc = Filter->findFunctionByIndex(
        MCInstOffset + RelCallTargetOffset + MCInstSize,
        FunctionFilter::FILTER_EXCLUDE);
  }

  // If not, use text section relocations to get the
  // call target function.
  if (CalledFunc == nullptr)
    CalledFunc =
        MR->getCalledFunctionUsingTextReloc(MCInstOffset, MCInstSize);

  // Look up the PLT to find called function
  if (CalledFunc == nullptr)
    CalledFunc = getTargetFunctionAtPLTOffset(MI, CallTargetIndex);

  return CalledFunc;
}
