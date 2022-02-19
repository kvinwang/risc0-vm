#pragma once

#include "risc0/core/util.h"
#include "risc0/zkp/circuit/compute_cycle.h"
#include "risc0/zkp/circuit/decode_cycle.h"
#include "risc0/zkp/circuit/divide_cycle.h"
#include "risc0/zkp/circuit/final_cycle.h"
#include "risc0/zkp/circuit/mem_io_regs.h"
#include "risc0/zkp/circuit/multiply_cycle.h"
#include "risc0/zkp/circuit/sha_cycle.h"

namespace risc0 {

struct DataRegs {
  static constexpr size_t kMemCheckSize = 16;
  static constexpr size_t kCycleRegs = 128;
  static constexpr size_t kNormalDigits = 100;
  static constexpr size_t kFinalDigits = 32;
  static constexpr size_t kRest = kDataSize - kCycleRegs - kMemCheckSize;
  Buffer buf;
  BufAlloc restAlloc;
  Buffer memCheckBuf;
  MemIORegs memIO;

  DataRegs(CodeRegs& code, Buffer buf)
      : buf(buf)
      , restAlloc(buf.slice(kCycleRegs, 0), buf.slice(kCycleRegs, kRest))
      , memCheckBuf(buf.slice(kCycleRegs + kRest, kMemCheckSize))
      , memIO(restAlloc) {}

  BufAlloc normalAlloc() {
    return BufAlloc(buf.slice(0, kNormalDigits).requireDigits(2),
                    buf.slice(kNormalDigits, kCycleRegs - kNormalDigits));
  }
  BufAlloc finalAlloc() {
    return BufAlloc(buf.slice(0, kFinalDigits).requireDigits(2),
                    buf.slice(kFinalDigits, kCycleRegs - kFinalDigits));
  }
  BufAlloc shaAlloc() {
    return BufAlloc(buf.slice(0, kNormalDigits).requireDigits(1),
                    buf.slice(kNormalDigits, kCycleRegs - kNormalDigits));
  }

  RegMux<DataCycleType::NUM_CYCLE_TYPES> getCycleType() const {
    BufAlloc copyRest = restAlloc;
    return RegMux<DataCycleType::NUM_CYCLE_TYPES>(copyRest);
  }

  void setExec(StepState& state);
  void setMemCheck(StepState& state);

  // There should only be used for 'back' versions
  DecodeCycle asDecode() {
    REQUIRE(buf.back() > 0);
    auto alloc = normalAlloc();
    return DecodeCycle(alloc);
  }
  ComputeCycle asCompute() {
    REQUIRE(buf.back() > 0);
    auto alloc = normalAlloc();
    return ComputeCycle(alloc);
  }
  FinalCycle asFinal() {
    REQUIRE(buf.back() > 0);
    auto alloc = finalAlloc();
    return FinalCycle(alloc);
  }
  ShaCycle asSha() {
    REQUIRE(buf.back() > 0);
    auto alloc = shaAlloc();
    return ShaCycle(alloc);
  }
};

} // namespace risc0
