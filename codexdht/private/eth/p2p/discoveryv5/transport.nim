# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Everything below the handling of ordinary messages
import
  std/[tables, options, sets],
  bearssl/rand,
  chronos,
  chronicles,
  metrics,
  libp2p/crypto/crypto,
  stew/shims/net,
  "."/[node, encoding, sessions]

const
  handshakeTimeout* = 500.milliseconds ## timeout for the reply on the
  ## whoareyou message
  responseTimeout* = 1.seconds ## timeout for the response of a request-response
  ## call

logScope:
  topics = "discv5 transport"

declarePublicCounter dht_transport_tx_packets,
  "Discovery transport packets sent", labels = ["state"]
declarePublicCounter dht_transport_tx_bytes,
  "Discovery transport bytes sent", labels = ["state"]
declarePublicCounter dht_transport_rx_packets,
  "Discovery transport packets received", labels = ["state"]
declarePublicCounter dht_transport_rx_bytes,
  "Discovery transport bytes received", labels = ["state"]

type
  Transport* [Client] = ref object
    client: Client
    bindAddress: Address ## UDP binding address
    transp: DatagramTransport
    pendingRequests: Table[AESGCMNonce, (PendingRequest, Moment)]
    keyexchangeInProgress: HashSet[NodeId]
    pendingRequestsByNode: Table[NodeId, seq[seq[byte]]]
    codec*: Codec
    rng: ref HmacDrbgContext

  PendingRequest = object
    node: Node
    message: seq[byte]

proc sendToA(t: Transport, a: Address, msg: seq[byte]) =
  trace "Send packet", myport = t.bindAddress.port, address = a
  let ta = initTAddress(a.ip, a.port)
  let f = t.transp.sendTo(ta, msg)
  f.addCallback(
    proc(data: pointer) =
      if f.failed:
        # Could be `TransportUseClosedError` in case the transport is already
        # closed, or could be `TransportOsError` in case of a socket error.
        # In the latter case this would probably mostly occur if the network
        # interface underneath gets disconnected or similar.
        # TODO: Should this kind of error be propagated upwards? Probably, but
        # it should not stop the process as that would reset the discovery
        # progress in case there is even a small window of no connection.
        # One case that needs this error available upwards is when revalidating
        # nodes. Else the revalidation might end up clearing the routing tabl
        # because of ping failures due to own network connection failure.
        warn "Discovery send failed", msg = f.readError.msg
        dht_transport_tx_packets.inc(labelValues = ["failed"])
        dht_transport_tx_bytes.inc(msg.len.int64, labelValues = ["failed"])
  )
  dht_transport_tx_packets.inc()
  dht_transport_tx_bytes.inc(msg.len.int64)

proc send(t: Transport, n: Node, data: seq[byte]) =
  doAssert(n.address.isSome())
  t.sendToA(n.address.get(), data)

proc sendMessage*(t: Transport, toId: NodeId, toAddr: Address, message: seq[byte]) =
  let (data, _, _) = encodeMessagePacket(t.rng[], t.codec, toId, toAddr,
    message)
  t.sendToA(toAddr, data)

# TODO: This could be improved to do the clean-up immediatily in case a non
# whoareyou response does arrive, but we would need to store the AuthTag
# somewhere
proc registerRequest(t: Transport, n: Node, message: seq[byte],
    nonce: AESGCMNonce) =
  let request = PendingRequest(node: n, message: message)
  if not t.pendingRequests.hasKeyOrPut(nonce, (request, Moment.now())):
    sleepAsync(responseTimeout).addCallback() do(data: pointer):
      t.pendingRequests.del(nonce)

##Todo: remove dependence on message. This should be higher
proc sendMessage*(t: Transport, toNode: Node, message: seq[byte]) =
  doAssert(toNode.address.isSome())
  let address = toNode.address.get()
  let (data, nonce, haskey) = encodeMessagePacket(t.rng[], t.codec,
    toNode.id, address, message)

  if haskey:
    trace "Send message: has key", myport = t.bindAddress.port , dstId = toNode
    t.registerRequest(toNode, message, nonce)
    t.send(toNode, data)
  else:
    # we don't have an encryption key for this target, so we should initiate keyexchange
    if not (toNode.id in t.keyexchangeInProgress):
      trace "Send message: send random to trigger Whoareyou", myport = t.bindAddress.port , dstId = toNode
      t.registerRequest(toNode, message, nonce)
      t.send(toNode, data)
      t.keyexchangeInProgress.incl(toNode.id)
      trace "keyexchangeInProgress added", myport = t.bindAddress.port , dstId = toNode
      sleepAsync(handshakeTimeout).addCallback() do(data: pointer):
        t.keyexchangeInProgress.excl(toNode.id)
        trace "keyexchangeInProgress removed (timeout)", myport = t.bindAddress.port , dstId = toNode
    else:
      # delay sending this message until whoareyou is received and handshake is sent
      # have to reencode once keys are clear
      t.pendingRequestsByNode.mgetOrPut(toNode.id, newSeq[seq[byte]]()).add(message)
      trace "Send message: Node with this id already has ongoing keyexchage, delaying packet",
            myport = t.bindAddress.port , dstId = toNode, qlen=t.pendingRequestsByNode[toNode.id].len

proc sendWhoareyou(t: Transport, toId: NodeId, a: Address,
    requestNonce: AESGCMNonce, node: Option[Node]) =
  let key = HandshakeKey(nodeId: toId, address: a)
  if not t.codec.hasHandshake(key):
    let
      recordSeq = if node.isSome(): node.get().record.seqNum
                  else: 0
      pubkey = if node.isSome(): some(node.get().pubkey)
              else: none(PublicKey)

    let data = encodeWhoareyouPacket(t.rng[], t.codec, toId, a, requestNonce,
      recordSeq, pubkey)
    sleepAsync(handshakeTimeout).addCallback() do(data: pointer):
      # handshake key is popped in decodeHandshakePacket. if not yet popped by timeout:
      if t.codec.hasHandshake(key):
        debug "Handshake timeout", myport = t.bindAddress.port , dstId = toId, address = a
        t.codec.handshakes.del(key)

    trace "Send whoareyou", dstId = toId, address = a
    t.sendToA(a, data)
  else:
    # TODO: is this reasonable to drop it? Should we allow a mini-queue here?
    # Queue should be on sender side, as this is random encoded!
    debug "Node with this id already has ongoing handshake, queuing packet", myport = t.bindAddress.port , dstId = toId, address = a

proc sendPending(t:Transport, toNode: Node):
      Future[void] {.async.} =
  if t.pendingRequestsByNode.hasKey(toNode.id):
    trace "Found pending request", myport = t.bindAddress.port, src = toNode, len = t.pendingRequestsByNode[toNode.id].len
    for message in t.pendingRequestsByNode[toNode.id]:
      trace "Sending pending packet", myport = t.bindAddress.port, dstId = toNode.id
      let address = toNode.address.get()
      let (data, nonce, haskey) = encodeMessagePacket(t.rng[], t.codec, toNode.id, address, message)
      t.registerRequest(toNode, message, nonce)
      t.send(toNode, data)
    t.pendingRequestsByNode.del(toNode.id)

proc receive*(t: Transport, a: Address, packet: openArray[byte]) =
  dht_transport_rx_packets.inc()
  dht_transport_rx_bytes.inc(packet.len.int64)
  let decoded = t.codec.decodePacket(a, packet)
  if decoded.isOk:
    let packet = decoded[]
    case packet.flag
    of OrdinaryMessage:
      if packet.messageOpt.isSome():
        let message = packet.messageOpt.get()
        trace "Received message packet", myport = t.bindAddress.port, srcId = packet.srcId, address = a,
          kind = message.kind, p = $packet
        t.client.handleMessage(packet.srcId, a, message)
      else:
        trace "Not decryptable message packet received", myport = t.bindAddress.port,
          srcId = packet.srcId, address = a
        # If we already have a keyexchange in progress, we have a case of simultaneous cross-connect.
        # We could try to decide here which should go on, but since we are on top of UDP, a more robust
        # choice is to answer here and resolve conflicts in the next stage (reception of Whoareyou), or
        # even later (reception of Handshake).
        if packet.srcId in t.keyexchangeInProgress:
          trace "cross-connect detected, still sending Whoareyou"
        t.sendWhoareyou(packet.srcId, a, packet.requestNonce,
          t.client.getNode(packet.srcId))

    of Flag.Whoareyou:
      trace "Received whoareyou packet", myport = t.bindAddress.port, address = a
      var
        prt: (PendingRequest, Moment)
      if t.pendingRequests.take(packet.whoareyou.requestNonce, prt):
        let
          pr = prt[0]
          startTime = prt[1]
          toNode = pr.node
          rtt = Moment.now() - startTime
        # trace "whoareyou RTT:", rtt, node = toNode
        toNode.registerRtt(rtt)
        # This is a node we previously contacted and thus must have an address.
        doAssert(toNode.address.isSome())
        let address = toNode.address.get()
        let data = encodeHandshakePacket(
                    t.rng[],
                    t.codec,
                    toNode.id,
                    address,
                    pr.message,
                    packet.whoareyou,
                    toNode.pubkey
                  ).expect("Valid handshake packet to encode")

        trace "Send handshake message packet", myport = t.bindAddress.port, dstId = toNode.id, address
        t.send(toNode, data)
        # keyexchange ready, we can send queued packets
        t.keyexchangeInProgress.excl(toNode.id)
        trace "keyexchangeInProgress removed (finished)", myport = t.bindAddress.port, dstId = toNode.id, address
        discard t.sendPending(toNode)

      else:
        debug "Timed out or unrequested whoareyou packet", address = a
    of HandshakeMessage:
      trace "Received handshake message packet", myport = t.bindAddress.port, srcId = packet.srcIdHs,
        address = a, kind = packet.message.kind
      t.client.handleMessage(packet.srcIdHs, a, packet.message)
      # For a handshake message it is possible that we received an newer SPR.
      # In that case we can add/update it to the routing table.
      if packet.node.isSome():
        let node = packet.node.get()
        # Lets not add nodes without correct IP in the SPR to the routing table.
        # The SPR could contain bogus IPs and although they would get removed
        # on the next revalidation, one could spam these as the handshake
        # message occurs on (first) incoming messages.
        if node.address.isSome() and a == node.address.get():
          # TODO: maybe here we could verify that the address matches what we were
          # sending the 'whoareyou' message to. In that case, we can set 'seen'
          # TODO: verify how this works with restrictive NAT and firewall scenarios.
          node.registerSeen()
          if t.client.addNode(node):
            trace "Added new node to routing table after handshake", node, tablesize=t.client.nodesDiscovered()
          discard t.sendPending(node)
        else:
          trace "address mismatch, not adding seen flag", node, address = a, nodeAddress = node.address.get()
  else:
    dht_transport_rx_packets.inc(labelValues = ["failed_decode"])
    dht_transport_rx_bytes.inc(packet.len.int64, labelValues = ["failed_decode"])
    trace "Packet decoding error", myport = t.bindAddress.port, error = decoded.error, address = a

proc processClient[T](transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  let t = getUserData[Transport[T]](transp)

  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try:
    transp.getMessage()
  except TransportOsError as e:
    # This is likely to be local network connection issues.
    warn "Transport getMessage", exception = e.name, msg = e.msg
    return

  let ip = try: raddr.address()
           except ValueError as e:
             error "Not a valid IpAddress", exception = e.name, msg = e.msg
             return
  let a = Address(ip: ip, port: raddr.port)

  t.receive(a, buf)

proc open*[T](t: Transport[T]) {.raises: [Defect, CatchableError].} =
  info "Starting transport", bindAddress = t.bindAddress

  # TODO allow binding to specific IP / IPv6 / etc
  let ta = initTAddress(t.bindAddress.ip, t.bindAddress.port)
  t.transp = newDatagramTransport(processClient[T], udata = t, local = ta)

proc close*(t: Transport) =
  t.transp.close

proc closed*(t: Transport) : bool =
  t.transp.closed

proc closeWait*(t: Transport) {.async.} =
  await t.transp.closeWait

proc newTransport*[T](
  client: T,
  privKey: PrivateKey,
  localNode: Node,
  bindPort: Port,
  bindIp = IPv4_any(),
  rng = newRng()): Transport[T]=

  # TODO Consider whether this should be a Defect
  doAssert rng != nil, "RNG initialization failed"

  Transport[T](
    client: client,
    bindAddress: Address(ip: bindIp, port: bindPort),
    codec: Codec(
      localNode: localNode,
      privKey: privKey,
      sessions: Sessions.init(256)),
    rng: rng)
