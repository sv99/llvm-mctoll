//===-- llvm-mctoll.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MCTOLL_LLVM_MCTOLL_H
#define LLVM_TOOLS_LLVM_MCTOLL_LLVM_MCTOLL_H

#include "llvm/DebugInfo/DIContext.h"
#include "llvm/Object/Archive.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/DataTypes.h"

namespace llvm {
class StringRef;

namespace object {
class COFFObjectFile;
class COFFImportFile;
class MachOObjectFile;
class ObjectFile;
class Archive;
class RelocationRef;
} // namespace object

namespace mctoll {

extern std::string TargetName;
extern std::string TripleName;
extern std::string SysRoot;
extern std::string ArchName;
extern std::vector<std::string> FilterSections;
extern bool Disassemble;
extern std::vector<std::string> IncludeFileNames;
extern std::string CompilationDBDir;

// Various helper functions.
bool isRelocAddressLess(object::RelocationRef A, object::RelocationRef B);
void parseInputMachO(StringRef Filename);
void printCOFFUnwindInfo(const object::COFFObjectFile *O);
void printCOFFFileHeader(const object::ObjectFile *O);
void printCOFFSymbolTable(const object::COFFImportFile *I);
void printCOFFSymbolTable(const object::COFFObjectFile *O);
void printMachOFileHeader(const object::ObjectFile *O);
void printMachOLoadCommands(const object::ObjectFile *O);

} // end namespace mctoll
} // end namespace llvm

#endif // LLVM_TOOLS_LLVM_MCTOLL_LLVM_MCTOLL_H
