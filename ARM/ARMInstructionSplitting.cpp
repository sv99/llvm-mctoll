//===- ARMInstructionSplitting.cpp - Binary raiser utility llvm-mctoll ----===//
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

#include "ARMBaseInstrInfo.h"
#include "ARMMachineInstructionRaiser.h"
#include "ARMSubtarget.h"
#include "MCTargetDesc/ARMAddressingModes.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineOperand.h"

#define DEBUG_TYPE "mctoll"

using namespace llvm;
using namespace llvm::mctoll;

/// Check if the MI has shift pattern.
unsigned ARMMachineInstructionRaiser::checkIsShifter(unsigned Opcode) {
  switch (Opcode) {
  case ARM::MOVsr:
  case ARM::MOVsi:
    return ARM::MOVr;
  case ARM::ADCrsi:
  case ARM::ADCrsr:
    return ARM::ADCrr;
  case ARM::ADDrsi:
  case ARM::ADDrsr:
    return ARM::ADDrr;
  case ARM::ANDrsi:
  case ARM::ANDrsr:
    return ARM::ANDrr;
  case ARM::BICrsr:
  case ARM::BICrsi:
    return ARM::BICrr;
  case ARM::CMNzrsi:
  case ARM::CMNzrsr:
    return ARM::CMNzrr;
  case ARM::CMPrsi:
  case ARM::CMPrsr:
    return ARM::CMPrr;
  case ARM::EORrsr:
  case ARM::EORrsi:
    return ARM::EORrr;
  case ARM::MVNsr:
  case ARM::MVNsi:
    return ARM::MVNr;
  case ARM::ORRrsi:
  case ARM::ORRrsr:
    return ARM::ORRrr;
  case ARM::RSBrsi:
  case ARM::RSBrsr:
    return ARM::RSBrr;
  case ARM::SUBrsi:
  case ARM::SUBrsr:
    return ARM::SUBrr;
  case ARM::TEQrsr:
  case ARM::TEQrsi:
    return ARM::TEQrr;
  case ARM::TSTrsr:
  case ARM::TSTrsi:
    return ARM::TSTrr;
  default:
    return 0;
  }
}

/// If the MI is load/store which needs wback, it will return true.
bool ARMMachineInstructionRaiser::isLDRSTRPre(unsigned Opcode) {
  switch (Opcode) {
  case ARM::LDR_PRE_REG:
  case ARM::LDR_PRE_IMM:
  case ARM::LDRB_PRE_REG:
  case ARM::LDRB_PRE_IMM:
  case ARM::STR_PRE_REG:
  case ARM::STR_PRE_IMM:
  case ARM::STRB_PRE_REG:
  case ARM::STRB_PRE_IMM:
    return true;
  default:
    return false;
  }
}

/// No matter what pattern of Load/Store is, change the Opcode to xxxi12.
unsigned ARMMachineInstructionRaiser::getLoadStoreOpcode(unsigned Opcode) {
  switch (Opcode) {
  case ARM::LDRrs:
  case ARM::LDRi12:
  case ARM::LDR_PRE_REG:
  case ARM::LDR_PRE_IMM:
    return ARM::LDRi12;
  case ARM::LDRBrs:
  case ARM::LDRBi12:
  case ARM::LDRB_PRE_REG:
  case ARM::LDRB_PRE_IMM:
    return ARM::LDRBi12;
  case ARM::STRrs:
  case ARM::STRi12:
  case ARM::STR_PRE_REG:
  case ARM::STR_PRE_IMM:
    return ARM::STRi12;
  case ARM::STRBrs:
  case ARM::STRBi12:
  case ARM::STRB_PRE_REG:
  case ARM::STRB_PRE_IMM:
    return ARM::STRBi12;
  default:
    return 0;
  }
}

/// True if the ARM instruction performs ShiftC().
bool ARMMachineInstructionRaiser::isShiftC(unsigned Opcode) {
  switch (Opcode) {
  case ARM::ANDrsr:
  case ARM::ANDrsi:
  case ARM::BICrsr:
  case ARM::BICrsi:
  case ARM::EORrsr:
  case ARM::EORrsi:
  case ARM::MVNsr:
  case ARM::MVNsi:
  case ARM::ORRrsr:
  case ARM::ORRrsi:
  case ARM::TEQrsr:
  case ARM::TEQrsi:
  case ARM::TSTrsr:
  case ARM::TSTrsi:
    return true;
  default:
    return false;
  }
}

MachineInstr* ARMMachineInstructionRaiser::splitLDRSTR(MachineBasicBlock &MBB, MachineInstr &MI) {

  auto *TII = TargetInfo.getInstrInfo();
  unsigned Simm = MI.getOperand(3).getImm();
  unsigned SOffSet = ARM_AM::getAM2Offset(Simm);
  ARM_AM::ShiftOpc SOpc = ARM_AM::getAM2ShiftOpc(Simm);
  Register SVReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);
  Register AVReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);
  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);
  unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
  // Get Metadata for the fisrt insturction.
  ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
  MDNode *MDNFir = MDNode::get(Ctx, CMDFir);
  // Get Metadata for the second insturction.
  ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
  MDNode *MDNSec = MDNode::get(Ctx, CMDSec);
  // Get Metadata for the third insturction.
  ConstantAsMetadata *CMD_thd = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 2, false)));
  MDNode *N_thd = MDNode::get(Ctx, CMD_thd);
  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  if (SOffSet > 0) {
    // Split LDRxxx/STRxxx Rd, [Rn, Rm, shift]
    MachineInstrBuilder Fst = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rm);
    Fst.addImm(SOffSet);
    MachineInstrBuilder Sec = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(ARM::ADDrr), AVReg);
    addOperand(Sec, Rn);
    Sec.addReg(SVReg);
    MachineInstrBuilder Thd = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Thd, Rd);
    else
      addOperand(Thd, Rd, true);

    Thd.addReg(AVReg);
    // Add CPSR if the MI has.
    if (Idx != -1) {
      Fst.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Fst, MI.getOperand(Idx));
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
      Thd.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Thd, MI.getOperand(Idx));
    }
    Fst.addMetadata(MDNFir);
    Sec.addMetadata(MDNSec);
    Thd.addMetadata(N_thd);
  } else if (ShiftOpc == ARM::RRX) {
    // Split LDRxxx/STRxxx Rd, [Rn, Rm, rrx]
    MachineInstrBuilder Fst = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rm);
    MachineInstrBuilder Sec = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(ARM::ADDrr), AVReg);
    addOperand(Sec, Rn);
    Sec.addReg(SVReg);
    MachineInstrBuilder Thd = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Thd, Rd);
    else
      addOperand(Thd, Rd, true);

    Thd.addReg(AVReg);
    // Add CPSR if the MI has.
    if (Idx != -1) {
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
      Thd.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Thd, MI.getOperand(Idx));
    }
    Fst.addMetadata(MDNFir);
    Sec.addMetadata(MDNSec);
    Thd.addMetadata(N_thd);
  } else {
    // Split LDRxxx/STRxxx Rd, [Rn, Rm]
    MachineInstrBuilder Fst = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(ARM::ADDrr), AVReg);
    addOperand(Fst, Rn);
    addOperand(Fst, Rm);
    MachineInstrBuilder Sec = BuildMI(MBB, MI, MI.getDebugLoc(),
                                      TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Sec, Rd);
    else
      addOperand(Sec, Rd, true);

    Sec.addReg(AVReg);
    // Add CPSR if the MI has.
    if (Idx != -1) {
      Fst.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Fst, MI.getOperand(Idx));
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
    }
    Fst.addMetadata(MDNFir);
    Sec.addMetadata(MDNSec);
  }

  return &MI;
}

/// Get the shift opcode in MI.
unsigned ARMMachineInstructionRaiser::getShiftOpcode(ARM_AM::ShiftOpc SOpc,
                                                 unsigned OffSet) {
  unsigned RetVal = 0;

  switch (SOpc) {
  case ARM_AM::asr:
    RetVal = (OffSet != 0) ? ARM::ASRi : ARM::ASRr;
    break;
  case ARM_AM::lsl:
    RetVal = (OffSet != 0) ? ARM::LSLi : ARM::LSLr;
    break;
  case ARM_AM::lsr:
    RetVal = (OffSet != 0) ? ARM::LSRi : ARM::LSRr;
    break;
  case ARM_AM::ror:
    RetVal = (OffSet != 0) ? ARM::RORi : ARM::RORr;
    break;
  case ARM_AM::rrx:
    RetVal = ARM::RRX;
    break;
  case ARM_AM::no_shift:
  default:
    RetVal = 0;
  }
  return RetVal;
}

MachineInstrBuilder &
ARMMachineInstructionRaiser::addOperand(MachineInstrBuilder &MIB,
                                    MachineOperand &MO, bool IsDef) {
  switch (MO.getType()) {
  default:
    assert(false && "Unsupported MachineOperand type!");
    break;
  case MachineOperand::MO_Register: {
    if (IsDef)
      MIB.addDef(MO.getReg());
    else
      MIB.addUse(MO.getReg());
  } break;
  case MachineOperand::MO_FrameIndex: {
    MIB.addFrameIndex(MO.getIndex());
  } break;
  }

  return MIB;
}

/// Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, #+/-<imm>]! to:
/// ADD Rn, Rn, #imm
/// LDRxxx/STRxxx Rt, [Rn]
MachineInstr *ARMMachineInstructionRaiser::splitLDRSTRPreImm(MachineBasicBlock &MBB,
                                                         MachineInstr &MI) {
  auto *TII = TargetInfo.getInstrInfo();
  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);
  MachineOperand &Rs = MI.getOperand(3);

  // MI is splitted into 2 instructions.
  // So get Metadata for the first instruction.
  ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
  MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

  // Get Metadata for the second instruction.
  ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
  MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  // Add Rm,[Rm, #imm]!
  MachineInstrBuilder Fst =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
  addOperand(Fst, Rm, true);
  addOperand(Fst, Rm);
  Fst.addImm(Rs.getImm());

  MachineInstrBuilder Sec =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
  if (MI.mayStore())
    // STRxxx Rn, [Rm]
    addOperand(Sec, Rn);
  else if (MI.mayLoad())
    // LDRxxx Rd, [Rm]
    addOperand(Sec, Rd, true);
  addOperand(Sec, Rm);

  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // Add CPSR if the MI has.
  if (Idx != -1) {
    Fst.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Fst, MI.getOperand(Idx));
    Sec.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Sec, MI.getOperand(Idx));
  }
  Fst.addMetadata(MDNFir);
  Sec.addMetadata(MDNSec);
  return &MI;
}

/// Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>{, <shift>}]! to:
/// Rm shift #imm, but write result to VReg.
/// Add Rn, Rm
/// LDRxxx/STRxxx Rt, [Rn]
MachineInstr *ARMMachineInstructionRaiser::splitLDRSTRPre(MachineBasicBlock &MBB,
                                                      MachineInstr &MI) {
  auto *TII = TargetInfo.getInstrInfo();
  unsigned Simm = MI.getOperand(4).getImm();
  unsigned SOffSet = ARM_AM::getAM2Offset(Simm);
  ARM_AM::ShiftOpc SOpc = ARM_AM::getAM2ShiftOpc(Simm);
  Register SVReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);

  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);
  MachineOperand &Rs = MI.getOperand(3);
  unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);

  // Get Metadata for the first instruction.
  ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
  MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

  // Get Metadata for the second instruction.
  ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
  MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

  // Get Metadata for the third instruction.
  ConstantAsMetadata *CMDThd = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 2, false)));
  MDNode *MDNThd = MDNode::get(Ctx, CMDThd);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  if (SOffSet > 0) {
    // LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>{, <shift>}]!

    // Rs shift #imm and write result to VReg.
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rs);
    Fst.addImm(SOffSet);

    // Add Rm, VReg
    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
    addOperand(Sec, Rm, true);
    addOperand(Sec, Rm);
    Sec.addReg(SVReg);

    MachineInstrBuilder Thd =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
    if (MI.mayStore())
      // STRxxx Rn, [Rm]
      addOperand(Thd, Rn);
    else if (MI.mayLoad())
      // LDRxxx Rd, [Rm]
      addOperand(Thd, Rd, true);
    addOperand(Thd, Rm);

    // Add CPSR if the MI has.
    if (Idx != -1) {
      Fst.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Fst, MI.getOperand(Idx));
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
      Thd.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Thd, MI.getOperand(Idx));
    }
    Fst.addMetadata(MDNFir);
    Sec.addMetadata(MDNSec);
    Thd.addMetadata(MDNThd);
  } else if (ShiftOpc == ARM::RRX) {
    // Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>, RRX]!
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), SVReg);
    addOperand(Fst, Rs);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
    addOperand(Sec, Rm, true);
    addOperand(Sec, Rm);
    Sec.addReg(SVReg);

    MachineInstrBuilder Thd =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Thd, Rn);
    else if (MI.mayLoad())
      addOperand(Thd, Rd, true);
    addOperand(Thd, Rm);

    // Add CPSR if the MI has.
    if (Idx != -1) {
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
      Thd.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Thd, MI.getOperand(Idx));
    }
    Fst.addMetadata(MDNFir);
    Sec.addMetadata(MDNSec);
    Thd.addMetadata(MDNThd);
  } else {
    // Split LDRxxx/STRxxx<c><q> <Rt>, [<Rn>, +/-<Rm>]!
    MachineInstrBuilder Fst =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr));
    addOperand(Fst, Rm, true);
    addOperand(Fst, Rm);
    addOperand(Fst, Rs);

    MachineInstrBuilder Sec =
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
    if (MI.mayStore())
      addOperand(Sec, Rn);
    else if (MI.mayLoad())
      addOperand(Sec, Rd, true);
    addOperand(Sec, Rm);

    // Add CPSR if the MI has.
    if (Idx != -1) {
      Fst.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Fst, MI.getOperand(Idx));
      Sec.addImm(MI.getOperand(Idx - 1).getImm());
      addOperand(Sec, MI.getOperand(Idx));
    }
    Fst.addMetadata(MDNFir);
    Sec.addMetadata(MDNSec);
  }
  return &MI;
}

/// Split LDRxxx/STRxxx<c><q> <Rd>, [<Rn>, +/-<#imm>] to:
/// Add VReg, Rn, #imm
/// LDRxxx/STRxxx Rd, [VReg]
MachineInstr *ARMMachineInstructionRaiser::splitLDRSTRImm(MachineBasicBlock &MBB,
                                                      MachineInstr &MI) {
  auto *TII = TargetInfo.getInstrInfo();
  Register VReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);
  MachineOperand &Rd = MI.getOperand(0);
  MachineOperand &Rn = MI.getOperand(1);
  MachineOperand &Rm = MI.getOperand(2);

  // The MI is splitted into 2 instructions.
  // Get Metadata for the first instruction.
  ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
  MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

  // Get Metadata for the first instruction.
  ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
      ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
  MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

  unsigned NewOpc = getLoadStoreOpcode(MI.getOpcode());
  // Add VReg, Rn, #imm
  MachineInstrBuilder Fst =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ARM::ADDrr), VReg);
  addOperand(Fst, Rn);
  Fst.addImm(Rm.getImm());

  // LDRxxx/STRxxx Rd, [VReg]
  MachineInstrBuilder Sec =
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
  if (MI.mayStore())
    addOperand(Sec, Rd);
  else
    addOperand(Sec, Rd, true);
  Sec.addReg(VReg);

  int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);
  // Add CPSR if the MI has.
  if (Idx != -1) {
    Fst.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Fst, MI.getOperand(Idx));
    Sec.addImm(MI.getOperand(Idx - 1).getImm());
    addOperand(Sec, MI.getOperand(Idx));
  }
  Fst.addMetadata(MDNFir);
  Sec.addMetadata(MDNSec);
  return &MI;
}

/// Split 'Opcode Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMMachineInstructionRaiser::splitCommon(MachineBasicBlock &MBB,
                                                   MachineInstr &MI,
                                                   unsigned NewOpc) {
  auto *TII = TargetInfo.getInstrInfo();
  MachineInstr *ResMI = nullptr;
  for (unsigned OpIdx = 0; OpIdx < MI.getNumOperands(); OpIdx++) {
    if (MI.getOperand(OpIdx).isImm()) {
      unsigned Simm = MI.getOperand(OpIdx).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);

      Register VReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);
      if (ShiftOpc) {
        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(OpIdx - 2);
        MachineOperand &Rm = MI.getOperand(OpIdx - 1);

        ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
        MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

        ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
        MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

        if (SOffSet) {
          // Split Opcode Rd, Rn, Rm, shift #imm

          // Rm shifts SOffset and writes result to VReg.
          MachineInstrBuilder Fst =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
          addOperand(Fst, Rm);
          Fst.addImm(SOffSet);
          Fst.addMetadata(MDNFir);

          // Build 'opcode Rd, Rn, VReg'
          MachineInstrBuilder Sec =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
          addOperand(Sec, Rd, true);
          for (unsigned N = 1; N < (OpIdx - 1); N++) {
            addOperand(Sec, MI.getOperand(N));
          }
          Sec.addReg(VReg);
          Sec.addMetadata(MDNSec);
        } else {
          if (ShiftOpc == ARM::RRX) {
            // Split 'opcode Rd, Rn, Rm, RRX'
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addMetadata(MDNFir);

            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < OpIdx - 1; N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addMetadata(MDNSec);
          } else {
            // Split 'opcode Rd, Rn, Rm, shift Rs'

            // Build 'ShiftOpc VReg, Rn, Rm'
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rn);
            addOperand(Fst, Rm);
            Fst.addMetadata(MDNFir);

            // Build 'opcode Rd, Rn, VReg'
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < (OpIdx - 2); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addMetadata(MDNSec);
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

/// Split 'opcode<s> Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMMachineInstructionRaiser::splitS(MachineBasicBlock &MBB,
                                              MachineInstr &MI, unsigned NewOpc,
                                              int Idx) {
  auto *TII = TargetInfo.getInstrInfo();
  MachineInstr *ResMI = nullptr;
  for (unsigned OpIdx = 0; OpIdx < MI.getNumOperands(); OpIdx++) {
    if (MI.getOperand(OpIdx).isImm()) {
      unsigned Simm = MI.getOperand(OpIdx).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
      Register VReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);

      if (ShiftOpc) {
        ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
        MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

        ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
        MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(OpIdx - 2);
        MachineOperand &Rm = MI.getOperand(OpIdx - 1);

        // C flag is affected by Shift_c() if isShift_C is true.
        if (isShiftC(MI.getOpcode())) {
          if (SOffSet) {
            // Split opcode<s> Rd, Rn, Rm, shift #imm.

            // Rm shift #imm and  the new MI updates CPSR.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addImm(ARMCC::AL);
            addOperand(Fst, MI.getOperand(Idx));
            Fst.addMetadata(MDNFir);

            // Build 'opcode<s> Rd, Rn, VReg'
            // The new MI updates CPSR.
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (OpIdx - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(ARMCC::AL);
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(MDNSec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s> Rd, Rn, Rm, RRX.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(MDNFir);
              // XXX: RRX implicit CPSR, how to add cpsr?

              // Build base instructions
              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(MDNSec);
            } else {
              // Split opcode<s> Rd, Rn, Rm, shift Rs.
              // The new MI updates CPSR.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addImm(ARMCC::AL);
              addOperand(Fst, MI.getOperand(Idx));
              Fst.addMetadata(MDNFir);

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(MDNSec);
            }
          }
        } else {
          if (SOffSet) {
            // Split opcode<s> Rd, Rn, Rm, shift #imm.

            // Rm shift #imm,  and the new MI doesn't update CPSR.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addMetadata(MDNFir);

            // Build 'opcode<s> Rd, Rn, VReg'
            // The new MI updates CPSR.
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (OpIdx - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(ARMCC::AL);
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(MDNSec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s> Rd, Rn, Rm, rrx.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(MDNFir);
              // RRX implicit CPSR, how to add cpsr?

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(MDNSec);
            } else {
              // Split opcode<s> Rd, Rn, Rm, shift Rs.

              // Rm shift reg,  and the new MI doesn't update CPSR.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addMetadata(MDNFir);

              // Build 'opcode<s> Rd, Rn, VReg'
              // The new MI updates CPSR.
              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(ARMCC::AL);
              addOperand(Sec, MI.getOperand(Idx));
              Sec.addMetadata(MDNSec);
            }
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

/// Split 'opcode<c> Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMMachineInstructionRaiser::splitC(MachineBasicBlock &MBB,
                                              MachineInstr &MI, unsigned NewOpc,
                                              int Idx) {
  auto *TII = TargetInfo.getInstrInfo();
  MachineInstr *ResMI = nullptr;
  for (unsigned OpIdx = 0; OpIdx < MI.getNumOperands(); OpIdx++) {
    if (MI.getOperand(OpIdx).isImm()) {
      unsigned Simm = MI.getOperand(OpIdx).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
      Register VReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);

      if (ShiftOpc) {
        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(OpIdx - 2);
        MachineOperand &Rm = MI.getOperand(OpIdx - 1);

        ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
        MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

        ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
        MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

        if (SOffSet) {
          // Split opcode<c> Rd, Rn, Rm, shift #imm
          // The new MI checks CondCode.

          MachineInstrBuilder Fst =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
          addOperand(Fst, Rm);
          Fst.addImm(SOffSet);
          Fst.addImm(MI.getOperand(Idx - 1).getImm());
          addOperand(Fst, MI.getOperand(Idx));
          Fst.addMetadata(MDNFir);

          MachineInstrBuilder Sec =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
          addOperand(Sec, Rd, true);
          for (unsigned N = 1; N < (OpIdx - 1); N++) {
            addOperand(Sec, MI.getOperand(N));
          }
          Sec.addReg(VReg);
          Sec.addImm(MI.getOperand(Idx - 1).getImm());
          addOperand(Sec, MI.getOperand(Idx));
          Sec.addMetadata(MDNSec);
        } else {
          if (ShiftOpc == ARM::RRX) {
            // Split opcode<c> Rd, Rn, Rm, RRX
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addMetadata(MDNFir);
            // XXX: RRX implicit CPSR, how to add cpsr?

            // Build base instructions
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < (OpIdx - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(MDNSec);
          } else {
            // Split opcode<c> Rd, Rn, Rm, shift Rs
            // The new MI checks CondCode.

            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rn);
            addOperand(Fst, Rm);
            Fst.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Fst, MI.getOperand(Idx));
            Fst.addMetadata(MDNFir);

            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);

            for (unsigned N = 1; N < (OpIdx - 2); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            Sec.addMetadata(MDNSec);
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

/// Split 'opcode<s><c> Rd, Rn, Rm, shift' except LDRxxx/STRxxx.
MachineInstr *ARMMachineInstructionRaiser::splitCS(MachineBasicBlock &MBB,
                                               MachineInstr &MI,
                                               unsigned NewOpc, int Idx) {
  auto *TII = TargetInfo.getInstrInfo();
  MachineInstr *ResMI = nullptr;
  for (unsigned OpIdx = 0; OpIdx < MI.getNumOperands(); OpIdx++) {
    if (MI.getOperand(OpIdx).isImm()) {
      unsigned Simm = MI.getOperand(OpIdx).getImm();
      unsigned SOffSet = ARM_AM::getSORegOffset(Simm);
      ARM_AM::ShiftOpc SOpc = ARM_AM::getSORegShOp(Simm);
      unsigned ShiftOpc = getShiftOpcode(SOpc, SOffSet);
      Register VReg = MachineRegInfo.createVirtualRegister(&ARM::GPRnopcRegClass);

      if (ShiftOpc) {
        MachineOperand &Rd = MI.getOperand(0);
        MachineOperand &Rn = MI.getOperand(OpIdx - 2);
        MachineOperand &Rm = MI.getOperand(OpIdx - 1);

        ConstantAsMetadata *CMDFir = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 0, false)));
        MDNode *MDNFir = MDNode::get(Ctx, CMDFir);

        ConstantAsMetadata *CMDSec = ConstantAsMetadata::get(
            ConstantInt::get(Ctx, llvm::APInt(64, 1, false)));
        MDNode *MDNSec = MDNode::get(Ctx, CMDSec);

        // C flag is affected by Shift_c() if isShift_C is true.
        if (isShiftC(MI.getOpcode())) {
          if (SOffSet) {
            // Split opcode<s><c> Rd, Rn, Rm, shift #imm

            // The new MI both updates CPSR and checks CondCode.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Fst, MI.getOperand(Idx));
            addOperand(Fst, MI.getOperand(Idx + 1));
            Fst.addMetadata(MDNFir);

            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (OpIdx - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            addOperand(Sec, MI.getOperand(Idx + 1));
            Sec.addMetadata(MDNSec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s><c> Rd, Rn, Rm, RRX
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(MDNFir);
              // RRX implicit CPSR, how to add cpsr?

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(MDNSec);
            } else {
              // Split opcode<s><c> Rd, Rn, Rm, shift Rs

              // The new MI both updates CPSR and checks CondCode.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Fst, MI.getOperand(Idx));
              addOperand(Fst, MI.getOperand(Idx + 1));
              Fst.addMetadata(MDNFir);

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(MDNSec);
            }
          }
        } else {
          // Shifter doesn't update cpsr
          if (SOffSet) {
            // Split 'opcode<s><c> Rd, Rn, Rm, shift #imm'

            // Rm shifts #imm
            // The new MI checks CondCode, doesn't update CPSR.
            MachineInstrBuilder Fst =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
            addOperand(Fst, Rm);
            Fst.addImm(SOffSet);
            Fst.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Fst, MI.getOperand(Idx));
            Fst.addMetadata(MDNFir);

            // Build 'newOpc<s><c> Rd, Rn, VReg'
            // The new MI both updates CPSR and checks CondCode.
            MachineInstrBuilder Sec =
                BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
            addOperand(Sec, Rd, true);
            for (unsigned N = 1; N < (OpIdx - 1); N++) {
              addOperand(Sec, MI.getOperand(N));
            }
            Sec.addReg(VReg);
            Sec.addImm(MI.getOperand(Idx - 1).getImm());
            addOperand(Sec, MI.getOperand(Idx));
            addOperand(Sec, MI.getOperand(Idx + 1));
            Sec.addMetadata(MDNSec);
          } else {
            if (ShiftOpc == ARM::RRX) {
              // Split opcode<s><c> Rd, Rn, Rm, RRX
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rm);
              Fst.addMetadata(MDNFir);
              // RRX implicit CPSR, how to add cpsr?

              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 1); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(MDNSec);
            } else {
              // Split opcode<s><c> Rd, Rn, Rm, shift Rs

              // Rm shift #imm.
              // The new MI checks CondCode, doesn't update CPSR.
              MachineInstrBuilder Fst =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(ShiftOpc), VReg);
              addOperand(Fst, Rn);
              addOperand(Fst, Rm);
              Fst.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Fst, MI.getOperand(Idx));
              Fst.addMetadata(MDNFir);

              // Build 'newOpc<s><c> Rd, Rn, VReg'
              // The new MI both updates CPSR and checks CondCode.
              MachineInstrBuilder Sec =
                  BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(NewOpc));
              addOperand(Sec, Rd, true);

              for (unsigned N = 1; N < (OpIdx - 2); N++) {
                addOperand(Sec, MI.getOperand(N));
              }
              Sec.addReg(VReg);
              Sec.addImm(MI.getOperand(Idx - 1).getImm());
              addOperand(Sec, MI.getOperand(Idx));
              addOperand(Sec, MI.getOperand(Idx + 1));
              Sec.addMetadata(MDNSec);
            }
          }
        }
        ResMI = &MI;
        break;
      }
    }
  }

  return ResMI;
}

bool ARMMachineInstructionRaiser::split() {
  std::vector<MachineInstr *> RemoveList;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      MachineInstr *RemoveMI = nullptr;

      unsigned Opcode, NewOpc;
      Opcode = MI.getOpcode();
      NewOpc = checkIsShifter(Opcode);

      // Need to split
      if (getLoadStoreOpcode(Opcode)) {
        // Split the MI about Load and Store.

        // TODO: LDRSH/LDRSB/LDRH/LDRD split.
        if (isLDRSTRPre(Opcode)) {
          if (MI.getOperand(3).isReg())
            RemoveMI = splitLDRSTRPre(MBB, MI);
          else if (MI.getOperand(3).isImm() && MI.getOperand(3).getImm() != 0)
            RemoveMI = splitLDRSTRPreImm(MBB, MI);
          if (RemoveMI)
            RemoveList.push_back(RemoveMI);
        } else if (MI.getOperand(1).isReg() &&
                   MI.getOperand(1).getReg() != ARM::SP &&
                   MI.getOperand(1).getReg() != ARM::PC) {
          if (MI.getOperand(2).isReg())
            RemoveMI = splitLDRSTR(MBB, MI);
          else if (MI.getOperand(2).isImm() && MI.getOperand(2).getImm() != 0)
            RemoveMI = splitLDRSTRImm(MBB, MI);
          if (RemoveMI)
            RemoveList.push_back(RemoveMI);
        }
      } else if (NewOpc) {
        // Split the MI except Load and Store.

        bool UpdateCPSR = false;
        bool CondCode = false;
        int Idx = MI.findRegisterUseOperandIdx(ARM::CPSR);

        // Check if MI contains CPSR
        if (Idx != -1) {
          if (MI.getOperand(Idx + 1).isReg() &&
              MI.getOperand(Idx + 1).getReg() == ARM::CPSR) {
            UpdateCPSR = true;
            CondCode = true;
          } else if (MI.getOperand(Idx - 1).isImm() &&
                     MI.getOperand(Idx - 1).getImm() != ARMCC::AL) {
            CondCode = true;
          } else
            UpdateCPSR = true;
        }

        if (!UpdateCPSR && !CondCode)
          // Split the MI has no cpsr.
          RemoveMI = splitCommon(MBB, MI, NewOpc);
        else if (UpdateCPSR && !CondCode)
          // Split the MI updates cpsr.
          RemoveMI = splitS(MBB, MI, NewOpc, Idx);
        else if (!UpdateCPSR && CondCode)
          // Split the MI checks CondCode.
          RemoveMI = splitC(MBB, MI, NewOpc, Idx);
        else
          // Split the MI both updates cpsr and check CondCode
          RemoveMI = splitCS(MBB, MI, NewOpc, Idx);

        if (RemoveMI)
          RemoveList.push_back(RemoveMI);
      }
    }
  }

  // Remove old MI.
  for (MachineInstr *MI : RemoveList)
    MI->removeFromParent();

  // For debugging.
  LLVM_DEBUG(dbgs() << "CFG : After ARM Instruction Splitting\n");
  LLVM_DEBUG(MF.dump());

  return true;
}

#undef DEBUG_TYPE
