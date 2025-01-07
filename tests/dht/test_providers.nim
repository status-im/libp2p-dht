#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.used.}

import
  std/[options],
  asynctest/chronos/unittest2,
  bearssl/rand,
  chronicles,
  chronos,
  libp2p/crypto/[crypto, secp],
  libp2p/[multiaddress, multicodec, multihash, routing_record, signed_envelope],
  codexdht/discv5/crypto as dhtcrypto,
  codexdht/discv5/protocol as discv5_protocol,
  test_helper

proc bootstrapNodes(
    nodecount: int,
    bootnodes: seq[SignedPeerRecord],
    rng = newRng(),
    delay: int = 0
  ) : Future[seq[(discv5_protocol.Protocol, PrivateKey)]] {.async.} =

  debug "---- STARTING BOOSTRAPS ---"
  for i in 0..<nodecount:
    let privKey = PrivateKey.example(rng)
    let node = initDiscoveryNode(rng, privKey, localAddress(23302 + i), bootnodes)
    await node.start()
    result.add((node, privKey))
    if delay > 0:
      await sleepAsync(chronos.milliseconds(delay))


  #await allFutures(result.mapIt(it.bootstrap())) # this waits for bootstrap based on bootENode, which includes bonding with all its ping pongs

proc bootstrapNetwork(
    nodecount: int,
    rng = newRng(),
    delay: int = 0
  ) : Future[seq[(discv5_protocol.Protocol, PrivateKey)]] {.async.} =

  let
    bootNodeKey = PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
      .expect("Valid private key hex")
    bootNodeAddr = localAddress(25311)
    bootNode = initDiscoveryNode(rng, bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open

  #waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above

  var res = await bootstrapNodes(nodecount - 1,
                           @[bootNode.localNode.record],
                           rng,
                           delay)
  res.insert((bootNode, bootNodeKey), 0)
  return res


# suite "Providers Tests":
suite "Providers Tests: node alone":
  var
    rng: ref HmacDrbgContext
    nodes: seq[(discv5_protocol.Protocol, PrivateKey)]
    targetId: NodeId
    node0: discv5_protocol.Protocol
    privKey0: PrivateKey
    signedPeerRec0: SignedPeerRecord
    peerRec0: PeerRecord

  setupAll:
    rng = newRng()
    nodes = await bootstrapNetwork(nodecount=1)
    targetId = NodeId.example(rng)
    (node0, privKey0) = nodes[0]
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

  teardownAll:
    for (n, _) in nodes:
      await n.closeWait()
    await sleepAsync(chronos.seconds(3))


  test "Node in isolation should store":
    debug "---- ADDING PROVIDERS ---", nodes = nodes.len
    let addedTo = await node0.addProvider(targetId, signedPeerRec0)
    debug "Provider added to: ", addedTo

    debug "---- STARTING CHECKS ---"
    check (addedTo.len == 1)
    check (addedTo[0].id == node0.localNode.id)
    check ((await node0.getProvidersLocal(targetId))[0].data.peerId == peerRec0.peerId)

  test "Node in isolation should retrieve":

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providersRes = await node0.getProviders(targetId)

    debug "---- STARTING CHECKS ---"
    check providersRes.isOk
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len > 0 and providers[0].data.peerId == peerRec0.peerId)

  test "Should not retrieve bogus":

    let bogusId = NodeId.example(rng)

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providersRes = await node0.getProviders(bogusId)

    debug "---- STARTING CHECKS ---"
    check providersRes.isOk
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len == 0)

suite "Providers Tests: two nodes":

  var
    rng: ref HmacDrbgContext
    nodes: seq[(discv5_protocol.Protocol, PrivateKey)]
    targetId: NodeId
    node0: discv5_protocol.Protocol
    privKey0: PrivateKey
    signedPeerRec0: SignedPeerRecord
    peerRec0: PeerRecord

  setupAll:
    rng = newRng()
    nodes = await bootstrapNetwork(nodecount=3)
    targetId = NodeId.example(rng)
    (node0, privKey0) = nodes[0]
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

  teardownAll:
    for (n, _) in nodes:
      await n.closeWait()
    await sleepAsync(chronos.seconds(3))

  test "2 nodes, store and retrieve from same":

    debug "---- ADDING PROVIDERS ---"
    let addedTo = await node0.addProvider(targetId, signedPeerRec0)
    debug "Provider added to: ", addedTo

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providersRes = await node0.getProviders(targetId)

    debug "---- STARTING CHECKS ---"
    check providersRes.isOk
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

  test "2 nodes, retrieve from other":
    debug "---- STARTING PROVIDERS LOOKUP ---"
    let (node1, _) = nodes[1]
    let providersRes = await node1.getProviders(targetId)

    debug "---- STARTING CHECKS ---"
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

suite "Providers Tests: 20 nodes":

  var
    rng: ref HmacDrbgContext
    nodes: seq[(discv5_protocol.Protocol, PrivateKey)]
    targetId: NodeId
    node0: discv5_protocol.Protocol
    privKey0: PrivateKey
    signedPeerRec0: SignedPeerRecord
    peerRec0: PeerRecord

  setupAll:
    rng = newRng()
    nodes = await bootstrapNetwork(nodecount=20)
    targetId = NodeId.example(rng)
    (node0, privKey0) = nodes[0]
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

    await sleepAsync(chronos.seconds(15))

  teardownAll:
    for (n, _) in nodes: # if last test is enabled, we need nodes[1..^1] here
      await n.closeWait()

  test "20 nodes, store and retrieve from same":

    debug "---- ADDING PROVIDERS ---"
    let addedTo = await node0.addProvider(targetId, signedPeerRec0)
    debug "Provider added to: ", addedTo

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providersRes = await node0.getProviders(targetId)

    debug "---- STARTING CHECKS ---"
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

  test "20 nodes, retrieve from other":
    debug "---- STARTING PROVIDERS LOOKUP ---"
    let (node19, _) = nodes[^2]
    let providersRes = await node19.getProviders(targetId)

    debug "---- STARTING CHECKS ---"
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

  test "20 nodes, retrieve after bootnodes dies":
    debug "---- KILLING BOOTSTRAP NODE ---"
    let (node0, _) = nodes[0]
    let (node18, _) = nodes[^2]
    await node0.closeWait()
    nodes.del(0)

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providersRes = await node18.getProviders(targetId)

    debug "---- STARTING CHECKS ---"
    let providers = providersRes.get
    debug "Providers:", providers
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)
