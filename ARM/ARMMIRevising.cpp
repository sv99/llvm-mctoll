//===- ARMMIRevising.cpp - Binary raiser utility llvm-mctoll --------------===//
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

#include "ARMMachineInstructionRaiser.h"
#include "ARMModuleRaiser.h"
#include "ARMSubtarget.h"
#include "Raiser/IncludedFileInfo.h"
#include "Raiser/MCInstRaiser.h"
#include "Raiser/MachineFunctionRaiser.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::object;
using namespace llvm::mctoll;

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

template <class ELFT>
uint64_t getLoadAlignProgramHeader(const ELFFile<ELFT> *Obj) {
  typedef ELFFile<ELFT> ELFO;
  auto ProgramHeaderOrError = Obj->program_headers();

  if (!ProgramHeaderOrError)
    report_fatal_error(
        errorToErrorCode(ProgramHeaderOrError.takeError()).message());

  for (const typename ELFO::Elf_Phdr &Phdr : *ProgramHeaderOrError) {
    if (Phdr.p_type == ELF::PT_LOAD)
      return (uint64_t)Phdr.p_align;
  }

  assert(false && "Failed to get Phdr p_align!");
  return 0;
}

/// Create function for external function.
uint64_t ARMMachineInstructionRaiser::getCalledFunctionAtPLTOffset(
    uint64_t PLTEndOff, uint64_t CallAddr) {
  const ELF32LEObjectFile *Elf32LEObjFile =
      dyn_cast<ELF32LEObjectFile>(MR->getObjectFile());
  assert(Elf32LEObjFile != nullptr &&
         "Only 32-bit ELF binaries supported at present!");
  unsigned char ExecType = Elf32LEObjFile->getELFFile().getHeader().e_type;

  assert((ExecType == ELF::ET_DYN) || (ExecType == ELF::ET_EXEC));
  // Find the section that contains the offset. That must be the PLT section
  for (auto &Section : Elf32LEObjFile->sections()) {
    uint64_t SecStart = Section.getAddress();
    uint64_t SecEnd = SecStart + Section.getSize();
    if ((SecStart <= PLTEndOff) && (SecEnd >= PLTEndOff)) {
      StringRef SecName;
      if (auto NameOrErr = Section.getName())
        SecName = *NameOrErr;
      else {
        consumeError(NameOrErr.takeError());
        assert(false && "Failed to get section name with PLT offset");
      }
      if (SecName.compare(".plt") != 0) {
        assert(false && "Unexpected section name of PLT offset");
      }

      auto StrOrErr = Section.getContents();
      assert(StrOrErr && "Failed to get the content of section!");
      auto SecData = *StrOrErr;
      ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(SecData.data()),
                              SecData.size());

      MCInst InstAddIP;
      uint64_t InstAddIPSz;
      bool Success = MR->getMCDisassembler()->getInstruction(
          InstAddIP, InstAddIPSz, Bytes.slice(PLTEndOff + 4 - SecStart),
          PLTEndOff + 4, nulls());
      assert(Success && "Failed to disassemble instruction in PLT");

      unsigned int OpcAddIP = InstAddIP.getOpcode();
      MCInstrDesc MCIDAddIP = MR->getMCInstrInfo()->get(OpcAddIP);

      if (OpcAddIP != ARM::ADDri && (MCIDAddIP.getNumOperands() != 6)) {
        assert(false && "Failed to find function entry from .plt.");
      }

      MCOperand OpdAddIP = InstAddIP.getOperand(2);
      assert(OpdAddIP.isImm() && "Unexpected immediate for offset.");
      unsigned Bits = OpdAddIP.getImm() & 0xFF;
      unsigned Rot = (OpdAddIP.getImm() & 0xF00) >> 7;
      int64_t PAlign = static_cast<int64_t>(ARM_AM::rotr32(Bits, Rot));

      MCInst Inst;
      uint64_t InstSz;
      Success = MR->getMCDisassembler()->getInstruction(
          Inst, InstSz, Bytes.slice(PLTEndOff + 8 - SecStart), PLTEndOff + 8,
          nulls());
      assert(Success && "Failed to disassemble instruction in PLT");
      unsigned int Opcode = Inst.getOpcode();
      MCInstrDesc MCID = MR->getMCInstrInfo()->get(Opcode);

      if (Opcode != ARM::LDRi12 && (MCID.getNumOperands() != 6)) {
        assert(false && "Failed to find function entry from .plt.");
      }

      MCOperand Operand = Inst.getOperand(3);
      assert(Operand.isImm() && "Unexpected immediate for offset.");

      uint64_t Index = Operand.getImm();

      uint64_t GotPltRelocOffset = PLTEndOff + Index + PAlign + 8;
      const RelocationRef *GotPltReloc =
          MR->getDynRelocAtOffset(GotPltRelocOffset);
      assert(GotPltReloc != nullptr &&
             "Failed to get dynamic relocation for jmp target of PLT entry");

      assert((GotPltReloc->getType() == ELF::R_ARM_JUMP_SLOT) &&
             "Unexpected relocation type for PLT jmp instruction");
      symbol_iterator CalledFuncSym = GotPltReloc->getSymbol();
      assert(CalledFuncSym != Elf32LEObjFile->symbol_end() &&
             "Failed to find relocation symbol for PLT entry");
      Expected<StringRef> CalledFuncSymName = CalledFuncSym->getName();
      assert(CalledFuncSymName &&
             "Failed to find symbol associated with dynamic "
             "relocation of PLT jmp target.");
      Expected<uint64_t> CalledFuncSymAddr = CalledFuncSym->getAddress();
      assert(CalledFuncSymAddr &&
             "Failed to get called function address of PLT entry");

      if (CalledFuncSymAddr.get() == 0) {
        // Set CallTargetIndex for plt offset to map undefined function symbol
        // for emit CallInst use.
        Function *CalledFunc =
            IncludedFileInfo::CreateFunction(*CalledFuncSymName, *TargetMR);
        // Bail out if function prototype is not available
        if (!CalledFunc)
          exit(-1);
        TargetMR->setSyscallMapping(PLTEndOff, CalledFunc);
        TargetMR->fillInstAddrFuncMap(CallAddr, CalledFunc);
      }
      return CalledFuncSymAddr.get();
    }
  }
  return 0;
}

/// Relocate call branch instructions in object files.
void ARMMachineInstructionRaiser::relocateBranch(MachineInstr &MI) {
  int64_t RelCallTargetOffset = MI.getOperand(0).getImm();
  const ELF32LEObjectFile *Elf32LEObjFile =
      dyn_cast<ELF32LEObjectFile>(MR->getObjectFile());
  assert(Elf32LEObjFile != nullptr &&
         "Only 32-bit ELF binaries supported at present.");

  auto EType = Elf32LEObjFile->getELFFile().getHeader().e_type;
  if ((EType == ELF::ET_DYN) || (EType == ELF::ET_EXEC)) {
    int64_t TextSectionAddress = MR->getTextSectionAddress();
    assert(TextSectionAddress >= 0 && "Failed to find text section address");

    // Get MCInst offset - the offset of machine instruction in the binary
    // and instruction size
    int64_t MCInstOffset = getMCInstIndex(MI);
    int64_t CallAddr = MCInstOffset + TextSectionAddress;
    int64_t CallTargetIndex = CallAddr + RelCallTargetOffset + 8;
    assert(InstRaiser != nullptr && "MCInstRaiser was not initialized");
    int64_t CallTargetOffset = CallTargetIndex - TextSectionAddress;
    if (CallTargetOffset < 0 || !InstRaiser->isMCInstInRange(CallTargetOffset)) {
      Function *CalledFunc = nullptr;
      uint64_t MCInstSize = InstRaiser->getMCInstSize(MCInstOffset);
      uint64_t Index = 1;
      CalledFunc = MR->getRaisedFunctionAt(CallTargetIndex);
      if (CalledFunc == nullptr) {
        CalledFunc =
            MR->getCalledFunctionUsingTextReloc(MCInstOffset, MCInstSize);
      }
      // Look up the PLT to find called function.
      if (CalledFunc == nullptr)
        Index = getCalledFunctionAtPLTOffset(CallTargetIndex, CallAddr);

      if (CalledFunc == nullptr) {
        if (Index == 0)
          MI.getOperand(0).setImm(CallTargetIndex);
        else if (Index != 1)
          MI.getOperand(0).setImm(Index);
        else
          assert(false && "Failed to get the call function!");
      } else
        MI.getOperand(0).setImm(CallTargetIndex);
    }
  } else {
    uint64_t Offset = getMCInstIndex(MI);
    const RelocationRef *Reloc = MR->getTextRelocAtOffset(Offset, 4);
    assert(Reloc && "Failed to get relocation ref");
    auto ImmValOrErr = (*Reloc->getSymbol()).getValue();
    assert(ImmValOrErr && "Failed to get immediate value");
    MI.getOperand(0).setImm(*ImmValOrErr);
  }
}

/// Find global value by PC offset.
const Value *ARMMachineInstructionRaiser::getGlobalValueByOffset(
    int64_t MCInstOffset, uint64_t PCOffset) {
  const Value *GlobVal = nullptr;
  const ELF32LEObjectFile *ObjFile =
      dyn_cast<ELF32LEObjectFile>(MR->getObjectFile());
  assert(ObjFile != nullptr &&
         "Only 32-bit ELF binaries supported at present.");

  // Get the text section address
  int64_t TextSecAddr = MR->getTextSectionAddress();
  assert(TextSecAddr >= 0 && "Failed to find text section address");

  uint64_t InstAddr = TextSecAddr + MCInstOffset;
  uint64_t Offset = InstAddr + PCOffset;

  // Start to search the corresponding symbol.
  const SymbolRef *Symbol = nullptr;
  const RelocationRef *DynReloc = MR->getDynRelocAtOffset(Offset);
  if (DynReloc && (DynReloc->getType() == ELF::R_ARM_ABS32 ||
                   DynReloc->getType() == ELF::R_ARM_GLOB_DAT))
    Symbol = &*DynReloc->getSymbol();

  assert(InstRaiser != nullptr && "MCInstRaiser was not initialized!");
  if (Symbol == nullptr) {
    auto Iter = InstRaiser->getMCInstAt(Offset - TextSecAddr);
    uint64_t OffVal = static_cast<uint64_t>((*Iter).second.getData());

    for (auto &Sym : ObjFile->symbols()) {
      if (Sym.getELFType() == ELF::STT_OBJECT) {
        auto SymAddr = Sym.getAddress();
        assert(SymAddr && "Failed to lookup symbol for global address!");
        auto SymAddrVal = SymAddr.get();
        if (OffVal >= SymAddrVal &&
            OffVal < (SymAddrVal + Sym.getSize())) {
          Symbol = &Sym;
          break;
        }
      }
    }
  }

  if (Symbol != nullptr) {
    // If the symbol is found.
    Expected<StringRef> SymNameVal = Symbol->getName();
    assert(SymNameVal &&
           "Failed to find symbol associated with dynamic relocation.");
    auto SymName = SymNameVal.get();
    GlobVal = getModule()->getGlobalVariable(SymName);
    if (GlobVal == nullptr) {
      DataRefImpl SymImpl = Symbol->getRawDataRefImpl();
      auto SymbOrErr = ObjFile->getSymbol(SymImpl);
      if (!SymbOrErr)
        consumeError(SymbOrErr.takeError());
      else {
        auto *Symb = SymbOrErr.get();
        assert((Symb->getType() == ELF::STT_OBJECT) &&
               "Object symbol type is expected. But not found!");
        GlobalValue::LinkageTypes Linkage;
        switch (Symb->getBinding()) {
        case ELF::STB_GLOBAL:
          Linkage = GlobalValue::ExternalLinkage;
          break;
        default:
          assert(false && "Unhandled dynamic symbol");
        }
        uint64_t SymSz = Symb->st_size;
        Type *GlobValTy = nullptr;
        switch (SymSz) {
        case 4:
          GlobValTy = Type::getInt32Ty(Ctx);
          break;
        case 2:
          GlobValTy = Type::getInt16Ty(Ctx);
          break;
        case 1:
          GlobValTy = Type::getInt8Ty(Ctx);
          break;
        default:
          GlobValTy = ArrayType::get(Type::getInt8Ty(Ctx), SymSz);
          break;
        }

        auto SymOrErr = Symbol->getValue();
        if (!SymOrErr)
          reportError(SymOrErr.takeError(), "Can not find the symbol!");

        uint64_t SymVirtAddr = *SymOrErr;
        auto SecOrErr = Symbol->getSection();
        if (!SecOrErr)
          reportError(SecOrErr.takeError(),
                       "Can not find the section which is the symbol in!");

        section_iterator SecIter = *SecOrErr;
        Constant *GlobInit = nullptr;
        if (SecIter->isBSS()) {
          Linkage = GlobalValue::CommonLinkage;
          if (ArrayType::classof(GlobValTy))
            GlobInit = ConstantAggregateZero::get(GlobValTy);
          else
            GlobInit = ConstantInt::get(GlobValTy, 0);
        } else {
          auto StrOrErr = SecIter->getContents();
          if (!StrOrErr)
            reportError(StrOrErr.takeError(),
                         "Failed to get the content of section!");
          StringRef SecData = *StrOrErr;
          // Currently, Symbol->getValue() is virtual address.
          unsigned Index = SymVirtAddr - SecIter->getAddress();
          const unsigned char *Beg = SecData.bytes_begin() + Index;
          char Shift = 0;
          uint64_t InitVal = 0;
          while (SymSz-- > 0) {
            // We know this is little-endian
            InitVal = ((*Beg++) << Shift) | InitVal;
            Shift += 8;
          }
          GlobInit = ConstantInt::get(GlobValTy, InitVal);
        }

        auto *GlobVar = new GlobalVariable(*getModule(), GlobValTy, false /* isConstant */,
                                          Linkage, GlobInit, SymName);
        uint64_t Align = 32;
        switch (SymSz) {
        default:
        case 4:
          // When the symbol size is bigger than 4 bytes, identify the object as
          // array or struct and set alignment to 32 bits.
          Align = 32;
          break;
        case 2:
          Align = 16;
          break;
        case 1:
          Align = 8;
          break;
        }
        MaybeAlign MA(Align);
        GlobVar->setAlignment(MA);
        GlobVar->setDSOLocal(true);
        GlobVal = GlobVar;
      }
    }
  } else {
    // If we can not find the corresponding symbol.
    GlobVal = TargetMR->getRODataValueAt(Offset);
    if (GlobVal == nullptr) {
      uint64_t Index = Offset - TextSecAddr;
      std::string LocalName("ROConst");
      if (InstRaiser->getMCInstAt(Index) != InstRaiser->const_mcinstr_end()) {
        LocalName.append(std::to_string(Index));
      }
      StringRef LocalNameRef(LocalName);

      // Find if a global value associated with symbol name is already
      // created
      GlobVal = getModule()->getGlobalVariable(LocalNameRef);
      if (GlobVal == nullptr) {
        uint64_t DataAddr = Offset;
        if (InstRaiser->getMCInstAt(Index) != InstRaiser->const_mcinstr_end()) {
          MCInstOrData MD = InstRaiser->getMCInstAt(Index)->second;
          uint32_t Data = MD.getData();
          DataAddr = (uint64_t)Data;
        }
        // Check if this is an address in .rodata
        for (section_iterator SecIter : ObjFile->sections()) {
          uint64_t SecStart = SecIter->getAddress();
          uint64_t SecEnd = SecStart + SecIter->getSize();

          if ((SecStart <= DataAddr) && (SecEnd >= DataAddr)) {
            if (SecIter->isData()) {
              auto StrOrErr = SecIter->getContents();
              assert(StrOrErr && "Failed to get the content of section!");
              StringRef SecData = *StrOrErr;
              uint64_t DataOffset = DataAddr - SecStart;
              const unsigned char *RODataBegin =
                  SecData.bytes_begin() + DataOffset;

              unsigned char C;
              uint64_t ArgNum = 0;
              const unsigned char *Str = RODataBegin;
              do {
                C = (unsigned char)*Str++;
                if (C == '%') {
                  ArgNum++;
                }
              } while (C != '\0');
              if (ArgNum != 0) {
                TargetMR->collectRodataInstAddr(InstAddr);
                TargetMR->fillInstArgMap(InstAddr, ArgNum + 1);
              }
              StringRef ROStringRef(
                  reinterpret_cast<const char *>(RODataBegin));
              Constant *StrConstant =
                  ConstantDataArray::getString(Ctx, ROStringRef);
              auto *GlobalStrConstVal = new GlobalVariable(
                  *getModule(), StrConstant->getType(), /* isConstant */ true,
                  GlobalValue::PrivateLinkage, StrConstant, "RO-String");
              // Record the mapping between offset and global value
              TargetMR->addRODataValueAt(GlobalStrConstVal, Offset);
              GlobVal = GlobalStrConstVal;
              break;
            }
          }
        }

        if (GlobVal == nullptr) {
          Type *Ty = Type::getInt32Ty(Ctx);
          MCInstOrData MD = InstRaiser->getMCInstAt(Index)->second;
          uint32_t Data = MD.getData();
          Constant *GlobInit = ConstantInt::get(Ty, Data);
          auto *GlobVar = new GlobalVariable(*getModule(), Ty,
                                             /* isConstant */ true,
                                            GlobalValue::PrivateLinkage,
                                            GlobInit, LocalNameRef);
          MaybeAlign MA(32);
          GlobVar->setAlignment(MA);
          GlobVar->setDSOLocal(true);
          GlobVal = GlobVar;
        }
      }
    }
  }

  return GlobVal;
}

/// Address PC relative data in function, and create corresponding global value.
void ARMMachineInstructionRaiser::addressPCRelativeData(MachineInstr &MI) {
  int64_t Imm = 0;
  // To match the pattern: OPCODE Rx, [PC, #IMM]
  if (MI.getNumOperands() > 2) {
    assert(MI.getOperand(2).isImm() &&
           "The third operand must be immediate data!");
    Imm = MI.getOperand(2).getImm();
  }
  // Get MCInst offset - the offset of machine instruction in the binary
  // and instruction size
  int64_t MCInstOffset = getMCInstIndex(MI);
  const Value *GlobVal =
      getGlobalValueByOffset(MCInstOffset, static_cast<uint64_t>(Imm) + 8);

  // Check the next instruction whether it is also related to PC relative data
  // of global variable.
  // It should like:
  // ldr     r1, [pc, #32]
  // ldr     r1, [pc, r1]
  // or
  // add     r1, pc, r1
  // second instruction may be with negative offset
  MachineInstr *NInst = MI.getNextNode();
  // To match the pattern: OPCODE Rx, [PC, Rd], Rd must be the def of previous
  // instruction.
  if (NInst->getNumOperands() >= 2 && NInst->getOperand(1).isReg() &&
      NInst->getOperand(1).getReg() == ARM::PC &&
      NInst->getOperand(2).isReg() &&
      NInst->getOperand(2).getReg() == MI.getOperand(0).getReg()) {
    auto *GV = dyn_cast<GlobalVariable>(GlobVal);
    if (GV != nullptr && GV->isConstant()) {
      // Firstly, read the PC relative data according to PC offset.
      auto *Init = GV->getInitializer();
      uint64_t GVData = Init->getUniqueInteger().getSExtValue();
      int64_t MCInstOff = getMCInstIndex(*NInst);
      // Search the global symbol of object by PC relative data.
      GlobVal = getGlobalValueByOffset(MCInstOff, GVData + 8);
      // If the global symbol is exists, erase current ldr instruction.
      if (GlobVal != nullptr)
        NInst->eraseFromParent();
    }
  }

  assert(GlobVal && "A not addressed pc-relative data!");

  // Replace PC relative operands to symbol operand.
  // The pattern will be generated.
  // ldr r3, [pc, #20] => ldr r3, @globalvalue
  MI.getOperand(1).ChangeToES(GlobVal->getName().data());

  if (MI.getNumOperands() > 2) {
    MI.removeOperand(2);
  }
}

/// Decode modified immediate constants in some instructions with immediate
/// operand.
void ARMMachineInstructionRaiser::decodeModImmOperand(MachineInstr &MI) {
  switch (MI.getOpcode()) {
  default:
    break;
  case ARM::ORRri:
    MachineOperand &MO = MI.getOperand(2);
    unsigned Bits = MO.getImm() & 0xFF;
    unsigned Rot = (MO.getImm() & 0xF00) >> 7;
    int64_t Rotated = static_cast<int64_t>(ARM_AM::rotr32(Bits, Rot));
    MO.setImm(Rotated);
    break;
  }
}

/// Remove some useless operations of instructions. Some instructions like
/// NOP (mov r0, r0).
bool ARMMachineInstructionRaiser::removeNeedlessInst(MachineInstr *MI) {
  if (MI->getOpcode() == ARM::MOVr && MI->getNumOperands() >= 2 &&
      MI->getOperand(0).isReg() && MI->getOperand(1).isReg() &&
      MI->getOperand(0).getReg() == MI->getOperand(1).getReg()) {
    return true;
  }

  return false;
}

/// The entry function of this class.
bool ARMMachineInstructionRaiser::reviseMI(MachineInstr &MI) {
  decodeModImmOperand(MI);
  // Relocate BL target in same section.
  if (MI.getOpcode() == ARM::BL || MI.getOpcode() == ARM::BL_pred ||
      MI.getOpcode() == ARM::Bcc) {
    MachineOperand &MO0 = MI.getOperand(0);
    if (MO0.isImm())
      relocateBranch(MI);
  }

  if (MI.getOpcode() == ARM::LDRi12 || MI.getOpcode() == ARM::STRi12) {
    if (MI.getNumOperands() >= 2 && MI.getOperand(1).isReg() &&
        MI.getOperand(1).getReg() == ARM::PC) {
      addressPCRelativeData(MI);
    }
  }

  return true;
}

bool ARMMachineInstructionRaiser::revise() {
  bool Res = false;

  vector<MachineInstr *> RMVec;
  for (MachineFunction::iterator MBBIter = MF.begin(), MBBEnd = MF.end();
       MBBIter != MBBEnd; ++MBBIter) {
    for (MachineBasicBlock::iterator MIIter = MBBIter->begin(),
                                     MIEnd = MBBIter->end();
         MIIter != MIEnd; ++MIIter) {
      if (removeNeedlessInst(&*MIIter)) {
        RMVec.push_back(&*MIIter);
        Res = true;
      } else
        Res = reviseMI(*MIIter);
    }
  }

  for (MachineInstr *PMI : RMVec)
    PMI->eraseFromParent();

  LLVM_DEBUG(dbgs() << "CFG : After ARM MI Revising\n");
  LLVM_DEBUG(MF.dump());

  return Res;
}

#undef DEBUG_TYPE
