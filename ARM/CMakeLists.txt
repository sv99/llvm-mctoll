include_directories(
  ${LLVM_MAIN_SRC_DIR}/lib/Target/ARM
  ${LLVM_BINARY_DIR}/lib/Target/ARM
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/.
)

if(NOT LLVM_MCTOLL_BUILT_STANDALONE)
  set(LLVM_MCTOLL_DEPS intrinsics_gen ARMCommonTableGen)
endif()

add_llvm_library(mctollARMRaiser
  ARMModuleRaiser.cpp
  ARMFunctionPrototype.cpp
  ARMMIRevising.cpp
  ARMEliminatePrologEpilog.cpp
    ARMJumpTable.cpp
  ARMArgumentRaiser.cpp
  ARMFrameBuilder.cpp
  ARMInstructionSplitting.cpp
  ARMRaisedValueTracker.cpp
  ARMSelectionDAGISel.cpp
  ARMMachineInstructionRaiser.cpp
  ARMIREmitter.cpp
  ARMIREmitterUtils.cpp

  LINK_COMPONENTS
  Analysis
  Core
  BitWriter
  ARMCodeGen
  DebugInfoDWARF
  DebugInfoPDB
  Demangle
  MC
  MCDisassembler
  Object
  Symbolize
  Support
  Target
  )

target_link_libraries(mctollARMRaiser PRIVATE mctollRaiser)
