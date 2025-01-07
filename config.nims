
switch("define", "libp2p_pki_schemes=secp256k1")
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config

when (NimMajor, NimMinor) >= (2, 0):
  --mm:refc
