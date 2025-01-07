# Package

version       = "0.5.0"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]

# Dependencies
requires "secp256k1#2acbbdcc0e63002a013fff49f015708522875832" # >= 0.5.2 & < 0.6.0
requires "protobuf_serialization#5a31137a82c2b6a989c9ed979bb636c7a49f570e" # >= 0.2.0 & < 0.3.0
requires "nimcrypto >= 0.5.4"
requires "bearssl == 0.2.5"
requires "chronicles >= 0.10.2 & < 0.11.0"
requires "chronos >= 4.0.3 & < 4.1.0"
requires "libp2p == 1.5.0"
requires "metrics#cacfdc12454a0804c65112b9f4f50d1375208dcd"
requires "stew >= 0.2.0"
requires "stint#3236fa68394f1e3a06e2bc34218aacdd2d675923"
requires "https://github.com/codex-storage/nim-datastore#b5635ef82f50255bc5ff2fe411722d870bcb587c"
requires "questionable >= 0.10.15 & < 0.11.0"

task testAll, "Run all test suites":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble testAll"

task test, "Run the test suite":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble test"

task testPart1, "Run the test suite part 1":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble testPart1"

task testPart2, "Run the test suite part 2":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble testPart2"
