import
  bearssl/rand,
  chronos,
  libp2p/crypto/[crypto, secp],
  libp2p/multiaddress,
  codexdht/discv5/[node, routing_table, spr],
  codexdht/discv5/protocol as discv5_protocol

proc localAddress*(port: int): Address =
  Address(ip: parseIpAddress("127.0.0.1"), port: Port(port))

proc example*(T: type PrivateKey, rng: ref HmacDrbgContext): PrivateKey =
  PrivateKey.random(PKScheme.Secp256k1, rng[]).expect("Valid rng for private key")

proc example*(T: type NodeId, rng: ref HmacDrbgContext): NodeId =
  let
    privKey = PrivateKey.example(rng)
    pubKey = privKey.getPublicKey.expect("Valid private key for public key")
  pubKey.toNodeId().expect("Public key valid for node id")

proc initDiscoveryNode*(
    rng: ref HmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openArray[SignedPeerRecord] = [],
    localEnrFields: openArray[(string, seq[byte])] = [],
    previousRecord = none[SignedPeerRecord]()):
    discv5_protocol.Protocol =
  # set bucketIpLimit to allow bucket split
  let config = DiscoveryConfig.init(1000, 24, 5)

  let protocol = newProtocol(
    privKey,
    some(address.ip),
    some(address.port),
    some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    config = config,
    rng = rng)

  protocol.open()

  protocol

proc nodeIdInNodes*(id: NodeId, nodes: openArray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

proc generateNode*(privKey: PrivateKey, port: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): Node =

  let
    port = Port(port)
    spr = SignedPeerRecord.init(1, privKey, some(ip), some(port), some(port))
              .expect("Properly intialized private key")
  result = newNode(spr).expect("Properly initialized node")

proc generateNRandomNodes*(rng: ref HmacDrbgContext, n: int): seq[Node] =
  var res = newSeq[Node]()
  for i in 1..n:
    let
      privKey = PrivateKey.example(rng)
      node = privKey.generateNode(port = 20402 + 10*n)
    res.add(node)
  res

proc nodeAndPrivKeyAtDistance*(n: Node, rng: var HmacDrbgContext, d: uint32,
    ip: IpAddress = parseIpAddress("127.0.0.1")): (Node, PrivateKey) =
  while true:
    let
      privKey = PrivateKey.random(rng).expect("Valid rng for private key")
      node = privKey.generateNode(port = 21302 + 10*d.int, ip = ip)
    if logDistance(n.id, node.id) == d:
      return (node, privKey)

proc nodeAtDistance*(n: Node, rng: var HmacDrbgContext, d: uint32,
    ip: IpAddress = parseIpAddress("127.0.0.1")): Node =
  let (node, _) = n.nodeAndPrivKeyAtDistance(rng, d, ip)
  node

proc nodesAtDistance*(
    n: Node, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): seq[Node] =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, rng, d, ip))

proc nodesAtDistanceUniqueIp*(
    n: Node, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): seq[Node] =
  var ta = initTAddress(ip, Port(0))
  for i in 0..<amount:
    ta.inc()
    result.add(nodeAtDistance(n, rng, d, ta.address()))

proc addSeenNode*(d: discv5_protocol.Protocol, n: Node): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.registerSeen()
  d.addNode(n)

func udpExample*(_: type MultiAddress): MultiAddress =
  ## creates a new udp multiaddress on a random port
  Multiaddress.init("/ip4/0.0.0.0/udp/0")

func udpExamples*(_: type MultiAddress, count: int): seq[MultiAddress] =
  var res: seq[MultiAddress] = @[]
  for i in 1..count:
    res.add Multiaddress.init("/ip4/0.0.0.0/udp/" & $i).get
  return res

proc toSignedPeerRecord*(privKey: PrivateKey) : SignedPeerRecord =
  ## handle conversion between the two worlds

  let pr = PeerRecord.init(
    peerId = PeerId.init(privKey.getPublicKey.get).get,
    addresses = MultiAddress.udpExamples(3))
  return SignedPeerRecord.init(privKey, pr)
           .expect("Should init SignedPeerRecord with private key")

proc example*(T: type SignedPeerRecord): T =
  let
    rng = newRng()
    privKey = PrivateKey.example(rng)

  privKey.toSignedPeerRecord
