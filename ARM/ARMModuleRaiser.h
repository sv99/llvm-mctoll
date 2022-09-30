//===-- ARMModuleRaiser.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of ARMModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_ARM_ARM_MODULE_RAISER_H
#define LLVM_TOOLS_LLVM_MCTOLL_ARM_ARM_MODULE_RAISER_H

#include "Raiser/ModuleRaiser.h"

namespace llvm {
namespace  mctoll {

class ARMModuleRaiser : public ModuleRaiser {
public:
  // support LLVM-style RTTI dyn_cast
  static bool classof(const ModuleRaiser *MR) {
    return MR->getArch() == Triple::arm;
  }
  ARMModuleRaiser() : ModuleRaiser() { Arch = Triple::arm; }

  // Create a new MachineFunctionRaiser object and add it to the list of
  // MachineFunction raiser objects of this module.
  MachineFunctionRaiser *
  CreateAndAddMachineFunctionRaiser(Function *Fn, const ModuleRaiser *MR,
                                    uint64_t Start, uint64_t End) override;
  bool collectDynamicRelocations() override;
  bool addPasses(PassManagerBase &PM) override;

  void collectRodataInstAddr(uint64_t InstAddr) {
    InstArgCollect.push_back(InstAddr);
  }

  void fillInstArgMap(uint64_t RodataAddr, uint64_t ArgNum) {
    InstArgNumMap[RodataAddr] = ArgNum;
  }

  void fillInstAddrFuncMap(uint64_t CallAddr, Function *Fn) {
    InstAddrFuncMap[CallAddr] = Fn;
  }

  Function *getCallFunc(uint64_t CallAddr) { return InstAddrFuncMap[CallAddr]; }

  // Get function arg number.
  uint64_t getFunctionArgNum(uint64_t);

  // Accoring call instruction to get the rodata instruction addr.
  uint64_t getArgNumInstrAddr(uint64_t);
  // Method to map syscall.
  void setSyscallMapping(uint64_t Idx, Function *Fn) { SyscallMap[Idx] = Fn; }

  Function *getSyscallFunc(uint64_t Idx) { return SyscallMap[Idx]; }

  const Value *getRODataValueAt(uint64_t Offset) const;

  void addRODataValueAt(Value *V, uint64_t Offset) const;

private:
  // Commonly used data structures for ARM.
  // This is for call instruction. (BL instruction)
  DenseMap<uint64_t, Function *> InstAddrFuncMap;
  // Instruction address and function call arg number map.
  // <instruction address of first argument from, argument count>
  DenseMap<uint64_t, uint64_t> InstArgNumMap;
  // Collect instruction address about rodata.
  std::vector<uint64_t> InstArgCollect;
  // Map index to its corresponding function.
  std::map<uint64_t, Function *> SyscallMap;
  // Map of read-only data (i.e., from .rodata) to its corresponding global
  // value.
  // NOTE: A const version of ModuleRaiser object is constructed during the
  // raising process. Making this map mutable since this map is expected to be
  // updated throughout the raising process.
  mutable std::map<uint64_t, Value *> GlobalRODataValues;
};

} // end namespace mctoll
} // end namespace llvm

extern "C" void registerARMModuleRaiser();

#endif // LLVM_TOOLS_LLVM_MCTOLL_ARM_ARM_MODULE_RAISER_H
