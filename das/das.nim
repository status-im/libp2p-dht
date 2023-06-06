import
  std/[options, sequtils],
  asynctest,
  bearssl/rand,
  chronicles,
  chronos,
  nimcrypto,
  libp2p/crypto/[crypto, secp],
  libp2p/[multiaddress, multicodec, multihash, routing_record, signed_envelope],
  libp2pdht/dht,
  libp2pdht/discv5/crypto as dhtcrypto,
  libp2pdht/discv5/protocol as discv5_protocol,
  stew/byteutils,
  tests/dht/test_helper

logScope:
  topics = "DAS emulator"

proc bootstrapNodes(
    nodecount: int,
    bootnodes: seq[SignedPeerRecord],
    rng = newRng(),
    delay: int = 0
  ) : Future[seq[(discv5_protocol.Protocol, PrivateKey)]] {.async.} =

  debug "---- STARTING BOOSTRAPS ---"
  for i in 0..<nodecount:
    try:
      let privKey = PrivateKey.example(rng)
      let node = initDiscoveryNode(rng, privKey, localAddress(20302 + i), bootnodes)
      await node.start()
      result.add((node, privKey))
      if delay > 0:
        await sleepAsync(chronos.milliseconds(delay))
    except TransportOsError as e:
      echo "skipping node ",i ,":", e.msg

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
    bootNodeAddr = localAddress(20301)
    bootNode = initDiscoveryNode(rng, bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open

  #waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above

  var res = await bootstrapNodes(nodecount - 1,
                           @[bootnode.localNode.record],
                           rng,
                           delay)
  res.insert((bootNode, bootNodeKey), 0)
  return res

proc toNodeId(data: openArray[byte]): NodeId =
  readUintBE[256](keccak256.digest(data).data)

proc segmentData(s: int, segmentsize: int) : seq[byte] =
  result = newSeq[byte](segmentsize)
  result[0] = byte(s mod 256)

when isMainModule:
  proc main() {.async.} =
    let
      nodecount = 5
      delay_pernode = 10 # in millisec
      delay_init = 2*1000 # in millisec
      blocksize = 16
      segmentsize = 10
      samplesize = 3

    var
      rng: ref HmacDrbgContext
      nodes: seq[(discv5_protocol.Protocol, PrivateKey)]
      node0: discv5_protocol.Protocol
      privKey0: PrivateKey
      signedPeerRec0: SignedPeerRecord
      peerRec0: PeerRecord
      segmentIDs = newSeq[NodeId](blocksize)

    # start network
    rng = newRng()
    nodes = await bootstrapNetwork(nodecount=nodecount, delay=delay_pernode)
    (node0, privKey0) = nodes[0]
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

    # wait for network to settle
    await sleepAsync(chronos.milliseconds(delay_init))

    # generate block and push data
    for s in 0 ..< blocksize:
      let
        segment = segmentData(s, segmentsize)
        key = toNodeId(segment)

      segmentIDs[s] = key

      let addedTo = await node0.addValue(key, segment)
      debug "Value added to: ", addedTo

    # sample
    for n in 1 ..< nodecount:
      for s in 0 ..< blocksize:
        let startTime = Moment.now()
        let res = await nodes[n][0].getValue(segmentIDs[s])
        let pass = res.isOk()
        info "sample", pass, by = n, sample = s, time = Moment.now() - startTime

  waitfor main()

# proc teardownAll() =
#     for (n, _) in nodes: # if last test is enabled, we need nodes[1..^1] here
#       await n.closeWait()


