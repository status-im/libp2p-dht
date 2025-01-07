# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Node Discovery Protocol v5
##
## Node discovery protocol implementation as per specification:
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
##
## This node discovery protocol implementation uses the same underlying
## implementation of routing table as is also used for the discovery v4
## implementation, which is the same or similar as the one described in the
## original Kademlia paper:
## https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf
##
## This might not be the most optimal implementation for the node discovery
## protocol v5. Why?
##
## The Kademlia paper describes an implementation that starts off from one
## k-bucket, and keeps splitting the bucket as more nodes are discovered and
## added. The bucket splits only on the part of the binary tree where our own
## node its id belongs too (same prefix). Resulting eventually in a k-bucket per
## logarithmic distance (log base2 distance). Well, not really, as nodes with
## ids in the closer distance ranges will never be found. And because of this an
## optimisation is done where buckets will also split sometimes even if the
## nodes own id does not have the same prefix (this is to avoid creating highly
## unbalanced branches which would require longer lookups).
##
## Now, some implementations take a more simplified approach. They just create
## directly a bucket for each possible logarithmic distance (e.g. here 1->256).
## Some implementations also don't create buckets with logarithmic distance
## lower than a certain value (e.g. only 1/15th of the highest buckets),
## because the closer to the node (the lower the distance), the less chance
## there is to still find nodes.
##
## The discovery protocol v4 its `FindNode` call will request the k closest
## nodes. As does original Kademlia. This effectively puts the work at the node
## that gets the request. This node will have to check its buckets and gather
## the closest. Some implementations go over all the nodes in all the buckets
## for this (e.g. go-ethereum discovery v4). However, in our bucket splitting
## approach, this search is improved.
##
## In the discovery protocol v5 the `FindNode` call is changed and now the
## logarithmic distance is passed as parameter instead of the NodeId. And only
## nodes that match that logarithmic distance are allowed to be returned.
## This change was made to not put the trust at the requested node for selecting
## the closest nodes. To counter a possible (mistaken) difference in
## implementation, but more importantly for security reasons. See also:
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-rationale.md#115-guard-against-kademlia-implementation-flaws
##
## The result is that in an implementation which just stores buckets per
## logarithmic distance, it simply needs to return the right bucket. In our
## split-bucket implementation, this cannot be done as such and thus the closest
## neighbors search is still done. And to do this, a reverse calculation of an
## id at given logarithmic distance is needed (which is why there is the
## `idAtDistance` proc). Next, nodes with invalid distances need to be filtered
## out to be compliant to the specification. This can most likely get further
## optimized, but it sounds likely better to switch away from the split-bucket
## approach. I believe that the main benefit it has is improved lookups
## (due to no unbalanced branches), and it looks like this will be negated by
## limiting the returned nodes to only the ones of the requested logarithmic
## distance for the `FindNode` call.

## This `FindNode` change in discovery v5 will also have an effect on the
## efficiency of the network. Work will be moved from the receiver of
## `FindNodes` to the requester. But this also means more network traffic,
## as less nodes will potentially be passed around per `FindNode` call, and thus
## more requests will be needed for a lookup (adding bandwidth and latency).
## This might be a concern for mobile devices.

{.push raises: [Defect].}

import
  std/[tables, sets, options, math, sequtils, algorithm, strutils],
  stew/shims/net as stewNet,
  json_serialization/std/net,
  stew/[base64, endians2, results],
  pkg/[chronicles, chronicles/chronos_tools],
  pkg/chronos,
  pkg/stint,
  pkg/bearssl/rand,
  pkg/metrics

import "."/[
  messages,
  messages_encoding,
  node,
  routing_table,
  spr,
  random2,
  ip_vote,
  nodes_verification,
  providers,
  transport]

import nimcrypto except toHex

export options, results, node, spr, providers

declareCounter dht_message_requests_outgoing,
  "Discovery protocol outgoing message requests", labels = ["response"]
declareCounter dht_message_requests_incoming,
  "Discovery protocol incoming message requests", labels = ["response"]
declareCounter dht_unsolicited_messages,
  "Discovery protocol unsolicited or timed-out messages"
declareCounter dht_enr_auto_update,
  "Amount of discovery IP:port address SPR auto updates"

logScope:
  topics = "discv5"

const
  Alpha = 3 ## Kademlia concurrency factor
  LookupRequestLimit = 3 ## Amount of distances requested in a single Findnode
  ## message for a lookup or query
  FindNodeResultLimit = 16 ## Maximum amount of SPRs in the total Nodes messages
  FindNodeFastResultLimit = 6 ## Maximum amount of SPRs in response to findNodeFast
  ## that will be processed
  MaxNodesPerMessage = 3 ## Maximum amount of SPRs per individual Nodes message
  RefreshInterval = 5.minutes ## Interval of launching a random query to
  ## refresh the routing table.
  RevalidateMin = 5000
  RevalidateMax = 10000 ## Revalidation of a peer is done between min and max milliseconds.
  ## value in milliseconds
  IpMajorityInterval = 5.minutes ## Interval for checking the latest IP:Port
  DebugPrintInterval = 5.minutes ## Interval to print neighborhood with stats
  ## majority and updating this when SPR auto update is set.
  InitialLookups = 1 ## Amount of lookups done when populating the routing table
  ResponseTimeout* = 1.seconds ## timeout for the response of a request-response
  MaxProvidersEntries* = 1_000_000 # one million records
  MaxProvidersPerEntry* = 20 # providers per entry
  ## call
  FindnodeSeenThreshold = 1.0 ## threshold used as findnode response filter
  LookupSeenThreshold = 0.0 ## threshold used for lookup nodeset selection
  QuerySeenThreshold = 0.0 ## threshold used for query nodeset selection
  NoreplyRemoveThreshold = 0.5 ## remove node on no reply if 'seen' is below this value

func shortLog*(record: SignedPeerRecord): string =
  ## Returns compact string representation of ``SignedPeerRecord``.
  ##

  result =
    "peerId: " & record.data.peerId.shortLog & ", " &
    "seqNo: " & $record.data.seqNo & ", " &
    "addresses: " & record.data.addresses.mapIt($it.address).join(", ")

func shortLog*(records: seq[SignedPeerRecord]): string =
  ## Returns compact string representation of a sequence of
  ## ``SignedPeerRecord``.
  ##

  for r in records:
    result &= "provider: " & r.shortLog

chronicles.formatIt(SignedPeerRecord): shortLog(it)
chronicles.formatIt(seq[SignedPeerRecord]): shortLog(it)

type
  DiscoveryConfig* = object
    tableIpLimits*: TableIpLimits
    bitsPerHop*: int

  Protocol* = ref object
    localNode*: Node
    privateKey: PrivateKey
    transport*: Transport[Protocol] # exported for tests
    routingTable*: RoutingTable
    awaitedMessages: Table[(NodeId, RequestId), Future[Option[Message]]]
    refreshLoop: Future[void]
    revalidateLoop: Future[void]
    ipMajorityLoop: Future[void]
    debugPrintLoop: Future[void]
    lastLookup: chronos.Moment
    bootstrapRecords*: seq[SignedPeerRecord]
    ipVote: IpVote
    enrAutoUpdate: bool
    talkProtocols*: Table[seq[byte], TalkProtocol] # TODO: Table is a bit of
    rng*: ref HmacDrbgContext
    providers: ProvidersManager

  TalkProtocolHandler* = proc(p: TalkProtocol, request: seq[byte], fromId: NodeId, fromUdpAddress: Address): seq[byte]
    {.gcsafe, raises: [Defect].}

  TalkProtocol* = ref object of RootObj
    protocolHandler*: TalkProtocolHandler

  DiscResult*[T] = Result[T, cstring]

func `$`*(p: Protocol): string =
  $p.localNode.id

const
  defaultDiscoveryConfig* = DiscoveryConfig(
    tableIpLimits: DefaultTableIpLimits,
    bitsPerHop: DefaultBitsPerHop)

proc addNode*(d: Protocol, node: Node): bool =
  ## Add `Node` to discovery routing table.
  ##
  ## Returns true only when `Node` was added as a new entry to a bucket in the
  ## routing table.
  if d.routingTable.addNode(node) == Added:
    return true
  else:
    return false

proc addNode*(d: Protocol, r: SignedPeerRecord): bool =
  ## Add `Node` from a `SignedPeerRecord` to discovery routing table.
  ##
  ## Returns false only if no valid `Node` can be created from the `SignedPeerRecord` or
  ## on the conditions of `addNode` from a `Node`.
  let node = newNode(r)
  if node.isOk():
    return d.addNode(node[])
  else:
    return false

proc addNode*(d: Protocol, spr: SprUri): bool =
  ## Add `Node` from a SPR URI to discovery routing table.
  ##
  ## Returns false if no valid SPR URI, or on the conditions of `addNode` from
  ## an `SignedPeerRecord`.
  try:
    var r: SignedPeerRecord
    let res = r.fromURI(spr)
    if res:
      return d.addNode(r)
  except Base64Error as e:
    error "Base64 error decoding SPR URI", error = e.msg
    return false

proc getNode*(d: Protocol, id: NodeId): Option[Node] =
  ## Get the node with id from the routing table.
  d.routingTable.getNode(id)

proc randomNodes*(d: Protocol, maxAmount: int): seq[Node] {.raises: Exception.} =
  ## Get a `maxAmount` of random nodes from the local routing table.
  d.routingTable.randomNodes(maxAmount)

proc randomNodes*(d: Protocol, maxAmount: int,
    pred: proc(x: Node): bool {.gcsafe, noSideEffect.}): seq[Node] {.raises: Exception.} =
  ## Get a `maxAmount` of random nodes from the local routing table with the
  ## `pred` predicate function applied as filter on the nodes selected.
  d.routingTable.randomNodes(maxAmount, pred)

proc randomNodes*(d: Protocol, maxAmount: int,
  enrField: (string, seq[byte])): seq[Node]  {.raises: Exception.} =
  ## Get a `maxAmount` of random nodes from the local routing table. The
  ## the nodes selected are filtered by provided `enrField`.
  d.randomNodes(maxAmount, proc(x: Node): bool = x.record.contains(enrField))

proc neighbours*(d: Protocol, id: NodeId, k: int = BUCKET_SIZE,
    seenThreshold = 0.0): seq[Node] =
  ## Return up to k neighbours (closest node ids) of the given node id.
  d.routingTable.neighbours(id, k, seenThreshold)

proc neighboursAtDistances*(d: Protocol, distances: seq[uint16],
    k: int = BUCKET_SIZE, seenThreshold = 0.0): seq[Node] =
  ## Return up to k neighbours (closest node ids) at given distances.
  d.routingTable.neighboursAtDistances(distances, k, seenThreshold)

proc nodesDiscovered*(d: Protocol): int = d.routingTable.len

func privKey*(d: Protocol): lent PrivateKey =
  d.privateKey

func getRecord*(d: Protocol): SignedPeerRecord =
  ## Get the SPR of the local node.
  d.localNode.record

proc updateRecord*(
  d: Protocol,
  spr: Option[SignedPeerRecord] = SignedPeerRecord.none): DiscResult[void] =
  ## Update the ENR of the local node with provided `enrFields` k:v pairs.
  ##

  if spr.isSome:
    let
      newSpr = spr.get()
      seqNo = d.localNode.record.seqNum

    info "Updated discovery SPR", uri = newSpr.toURI(), newSpr = newSpr.data

    d.localNode.record = newSpr
    d.localNode.record.data.seqNo = seqNo

  ? d.localNode.record.incSeqNo(d.privateKey)

  # TODO: Would it make sense to actively ping ("broadcast") to all the peers
  # we stored a handshake with in order to get that ENR updated?

  ok()

proc sendResponse(d: Protocol, dstId: NodeId, dstAddr: Address,
    message: SomeMessage, reqId: RequestId) =
  ## send Response using the specifid reqId
  d.transport.sendMessage(dstId, dstAddr, encodeMessage(message, reqId))

proc sendNodes(d: Protocol, toId: NodeId, toAddr: Address, reqId: RequestId,
    nodes: openArray[Node]) =
  proc sendNodes(d: Protocol, toId: NodeId, toAddr: Address,
      message: NodesMessage, reqId: RequestId) {.nimcall.} =
    trace "Respond message packet", dstId = toId, address = toAddr,
      kind = MessageKind.nodes
    d.sendResponse(toId, toAddr, message, reqId)

  if nodes.len == 0:
    # In case of 0 nodes, a reply is still needed
    d.sendNodes(toId, toAddr, NodesMessage(total: 1, sprs: @[]), reqId)
    return

  var message: NodesMessage
  # TODO: Do the total calculation based on the max UDP packet size we want to
  # send and the SPR size of all (max 16) nodes.
  # Which UDP packet size to take? 1280? 576?
  message.total = ceil(nodes.len / MaxNodesPerMessage).uint32

  for i in 0 ..< nodes.len:
    message.sprs.add(nodes[i].record)
    if message.sprs.len == MaxNodesPerMessage:
      d.sendNodes(toId, toAddr, message, reqId)
      message.sprs.setLen(0)

  if message.sprs.len != 0:
    d.sendNodes(toId, toAddr, message, reqId)

proc handlePing(d: Protocol, fromId: NodeId, fromAddr: Address,
    ping: PingMessage, reqId: RequestId) =
  let pong = PongMessage(sprSeq: d.localNode.record.seqNum, ip: fromAddr.ip,
    port: fromAddr.port.uint16)
  trace "Respond message packet", dstId = fromId, address = fromAddr,
    kind = MessageKind.pong
  d.sendResponse(fromId, fromAddr, pong, reqId)

proc handleFindNode(d: Protocol, fromId: NodeId, fromAddr: Address,
    fn: FindNodeMessage, reqId: RequestId) =
  if fn.distances.len == 0:
    d.sendNodes(fromId, fromAddr, reqId, [])
  elif fn.distances.contains(0):
    # A request for our own record.
    # It would be a weird request if there are more distances next to 0
    # requested, so in this case lets just pass only our own. TODO: OK?
    d.sendNodes(fromId, fromAddr, reqId, [d.localNode])
  else:
    # TODO: Still deduplicate also?
    if fn.distances.all(proc (x: uint16): bool = return x <= 256):
      d.sendNodes(fromId, fromAddr, reqId,
        d.routingTable.neighboursAtDistances(fn.distances, FindNodeResultLimit, FindnodeSeenThreshold))
    else:
      # At least one invalid distance, but the polite node we are, still respond
      # with empty nodes.
      d.sendNodes(fromId, fromAddr, reqId, [])

proc handleFindNodeFast(d: Protocol, fromId: NodeId, fromAddr: Address,
    fnf: FindNodeFastMessage, reqId: RequestId) =
  d.sendNodes(fromId, fromAddr, reqId,
    d.routingTable.neighbours(fnf.target, FindNodeFastResultLimit, FindnodeSeenThreshold))
  # TODO: if known, maybe we should add exact target even if not yet "seen"

proc handleTalkReq(d: Protocol, fromId: NodeId, fromAddr: Address,
    talkreq: TalkReqMessage, reqId: RequestId) =
  let talkProtocol = d.talkProtocols.getOrDefault(talkreq.protocol)

  let talkresp =
    if talkProtocol.isNil() or talkProtocol.protocolHandler.isNil():
      # Protocol identifier that is not registered and thus not supported. An
      # empty response is send as per specification.
      TalkRespMessage(response: @[])
    else:
      TalkRespMessage(response: talkProtocol.protocolHandler(talkProtocol,
        talkreq.request, fromId, fromAddr))

  trace "Respond message packet", dstId = fromId, address = fromAddr,
    kind = MessageKind.talkresp
  d.sendResponse(fromId, fromAddr, talkresp, reqId)

proc addProviderLocal(p: Protocol, cId: NodeId, prov: SignedPeerRecord) {.async.} =
  trace "adding provider to local db", n = p.localNode, cId, prov
  if (let res = (await p.providers.add(cId, prov)); res.isErr):
    trace "Unable to add provider", cid, peerId = prov.data.peerId

proc handleAddProvider(
  d: Protocol,
  fromId: NodeId,
  fromAddr: Address,
  addProvider: AddProviderMessage,
  reqId: RequestId) =
  asyncSpawn d.addProviderLocal(addProvider.cId, addProvider.prov)

proc handleGetProviders(
  d: Protocol,
  fromId: NodeId,
  fromAddr: Address,
  getProviders: GetProvidersMessage,
  reqId: RequestId) {.async.} =

  #TODO: add checks, add signed version
  let
    provs = await d.providers.get(getProviders.cId)

  if provs.isErr:
    trace "Unable to get providers", cid = getProviders.cId, err = provs.error.msg
    return

  ##TODO: handle multiple messages
  let response = ProvidersMessage(total: 1, provs: provs.get)
  d.sendResponse(fromId, fromAddr, response, reqId)

proc handleMessage(d: Protocol, srcId: NodeId, fromAddr: Address,
    message: Message) =
  case message.kind
  of ping:
    dht_message_requests_incoming.inc()
    d.handlePing(srcId, fromAddr, message.ping, message.reqId)
  of findNode:
    dht_message_requests_incoming.inc()
    d.handleFindNode(srcId, fromAddr, message.findNode, message.reqId)
  of findNodeFast:
    dht_message_requests_incoming.inc()
    d.handleFindNodeFast(srcId, fromAddr, message.findNodeFast, message.reqId)
  of talkReq:
    dht_message_requests_incoming.inc()
    d.handleTalkReq(srcId, fromAddr, message.talkReq, message.reqId)
  of addProvider:
    dht_message_requests_incoming.inc()
    dht_message_requests_incoming.inc(labelValues = ["no_response"])
    d.handleAddProvider(srcId, fromAddr, message.addProvider, message.reqId)
  of getProviders:
    dht_message_requests_incoming.inc()
    asyncSpawn d.handleGetProviders(srcId, fromAddr, message.getProviders, message.reqId)
  of regTopic, topicQuery:
    dht_message_requests_incoming.inc()
    dht_message_requests_incoming.inc(labelValues = ["no_response"])
    trace "Received unimplemented message kind", kind = message.kind,
      origin = fromAddr
  else:
    var waiter: Future[Option[Message]]
    if d.awaitedMessages.take((srcId, message.reqId), waiter):
      waiter.complete(some(message))
    else:
      dht_unsolicited_messages.inc()
      trace "Timed out or unrequested message", kind = message.kind,
        origin = fromAddr

proc registerTalkProtocol*(d: Protocol, protocolId: seq[byte],
    protocol: TalkProtocol): DiscResult[void] =
  # Currently allow only for one handler per talk protocol.
  if d.talkProtocols.hasKeyOrPut(protocolId, protocol):
    err("Protocol identifier already registered")
  else:
    ok()

proc replaceNode(d: Protocol, n: Node, forceRemoveBelow = 1.0) =
  if n.record notin d.bootstrapRecords:
    d.routingTable.replaceNode(n, forceRemoveBelow)
  else:
    # For now we never remove bootstrap nodes. It might make sense to actually
    # do so and to retry them only in case we drop to a really low amount of
    # peers in the routing table.
    debug "Message request to bootstrap node failed", src=d.localNode, dst=n

proc sendRequest*[T: SomeMessage](d: Protocol, toNode: Node, m: T,
    reqId: RequestId) =
  doAssert(toNode.address.isSome())
  let
    message = encodeMessage(m, reqId)

  trace "Send message packet", dstId = toNode.id,
    address = toNode.address, kind = messageKind(T)
  dht_message_requests_outgoing.inc()

  d.transport.sendMessage(toNode, message)

proc waitResponse*[T: SomeMessage](d: Protocol, node: Node, msg: T):
    Future[Option[Message]] =
  let reqId = RequestId.init(d.rng[])
  result = d.waitMessage(node, reqId)
  sendRequest(d, node, msg, reqId)

proc waitMessage(d: Protocol, fromNode: Node, reqId: RequestId, timeout = ResponseTimeout):
    Future[Option[Message]] =
  result = newFuture[Option[Message]]("waitMessage")
  let res = result
  let key = (fromNode.id, reqId)
  sleepAsync(timeout).addCallback() do(data: pointer):
    d.awaitedMessages.del(key)
    if not res.finished:
      res.complete(none(Message))
  d.awaitedMessages[key] = result

proc waitNodeResponses*[T: SomeMessage](d: Protocol, node: Node, msg: T):
    Future[DiscResult[seq[SignedPeerRecord]]] =
  let reqId = RequestId.init(d.rng[])
  result = d.waitNodes(node, reqId)
  sendRequest(d, node, msg, reqId)

proc waitNodes(d: Protocol, fromNode: Node, reqId: RequestId):
    Future[DiscResult[seq[SignedPeerRecord]]] {.async.} =
  ## Wait for one or more nodes replies.
  ##
  ## The first reply will hold the total number of replies expected, and based
  ## on that, more replies will be awaited.
  ## If one reply is lost here (timed out), others are ignored too.
  ## Same counts for out of order receival.
  let startTime = Moment.now()
  var op = await d.waitMessage(fromNode, reqId)
  if op.isSome:
    if op.get.kind == MessageKind.nodes:
      var res = op.get.nodes.sprs
      let
        total = op.get.nodes.total
        firstTime = Moment.now()
        rtt = firstTime - startTime
      # trace "nodes RTT:", rtt, node = fromNode
      fromNode.registerRtt(rtt)
      for i in 1 ..< total:
        op = await d.waitMessage(fromNode, reqId)
        if op.isSome and op.get.kind == MessageKind.nodes:
          res.add(op.get.nodes.sprs)
          # Estimate bandwidth based on UDP packet train received, assuming these were
          # released fast and spaced in time by bandwidth bottleneck. This is just a rough
          # packet-pair based estimate, far from being perfect.
          # TODO: get message size from lower layer for better bandwidth estimate
          # TODO: get better reception timestamp from lower layers
          let
            deltaT = Moment.now() - firstTime
            bwBps = 500.0 * 8.0 / (deltaT.nanoseconds.float / i.float / 1e9)
          # trace "bw estimate:", deltaT = deltaT, i, bw_mbps = bwBps / 1e6, node = fromNode
          fromNode.registerBw(bwBps)
        else:
          # No error on this as we received some nodes.
          break
      return ok(res)
    else:
      dht_message_requests_outgoing.inc(labelValues = ["invalid_response"])
      return err("Invalid response to find node message")
  else:
    dht_message_requests_outgoing.inc(labelValues = ["no_response"])
    return err("Nodes message not received in time")

proc ping*(d: Protocol, toNode: Node):
    Future[DiscResult[PongMessage]] {.async.} =
  ## Send a discovery ping message.
  ##
  ## Returns the received pong message or an error.
  let
    msg = PingMessage(sprSeq: d.localNode.record.seqNum)
    startTime = Moment.now()
    resp = await d.waitResponse(toNode, msg)
    rtt = Moment.now() - startTime
  # trace "ping RTT:", rtt, node = toNode
  toNode.registerRtt(rtt)

  d.routingTable.setJustSeen(toNode, resp.isSome())
  if resp.isSome():
    if resp.get().kind == pong:
      return ok(resp.get().pong)
    else:
      d.replaceNode(toNode)
      dht_message_requests_outgoing.inc(labelValues = ["invalid_response"])
      return err("Invalid response to ping message")
  else:
    # A ping (or the pong) was lost, what should we do? Previous implementation called 
    # d.replaceNode(toNode) immediately, which removed the node. This is too aggressive,
    # especially if we have a temporary network outage. Although bootstrap nodes are protected
    # from being removed, everything else would slowly be removed.
    d.replaceNode(toNode, NoreplyRemoveThreshold)
    dht_message_requests_outgoing.inc(labelValues = ["no_response"])
    return err("Pong message not received in time")

proc findNode*(d: Protocol, toNode: Node, distances: seq[uint16]):
    Future[DiscResult[seq[Node]]] {.async.} =
  ## Send a getNeighbours message.
  ##
  ## Returns the received nodes or an error.
  ## Received SPRs are already validated and converted to `Node`.
  let
    msg = FindNodeMessage(distances: distances)
    nodes = await d.waitNodeResponses(toNode, msg)

  d.routingTable.setJustSeen(toNode, nodes.isOk)
  if nodes.isOk:
    let res = verifyNodesRecords(nodes.get(), toNode, FindNodeResultLimit, distances)
    return ok(res)
  else:
    trace "findNode nodes not OK."
    d.replaceNode(toNode)
    return err(nodes.error)

proc findNodeFast*(d: Protocol, toNode: Node, target: NodeId):
    Future[DiscResult[seq[Node]]] {.async.} =
  ## Send a findNode message.
  ##
  ## Returns the received nodes or an error.
  ## Received SPRs are already validated and converted to `Node`.
  let
    msg = FindNodeFastMessage(target: target)
    nodes = await d.waitNodeResponses(toNode, msg)

  d.routingTable.setJustSeen(toNode, nodes.isOk)
  if nodes.isOk:
    let res = verifyNodesRecords(nodes.get(), toNode, FindNodeFastResultLimit)
    return ok(res)
  else:
    d.replaceNode(toNode)
    return err(nodes.error)


proc talkReq*(d: Protocol, toNode: Node, protocol, request: seq[byte]):
    Future[DiscResult[seq[byte]]] {.async.} =
  ## Send a discovery talkreq message.
  ##
  ## Returns the received talkresp message or an error.
  let
    msg = TalkReqMessage(protocol: protocol, request: request)
    startTime = Moment.now()
    resp = await d.waitResponse(toNode, msg)
    rtt = Moment.now() - startTime
  # trace "talk RTT:", rtt, node = toNode
  toNode.registerRtt(rtt)

  d.routingTable.setJustSeen(toNode, resp.isSome())
  if resp.isSome():
    if resp.get().kind == talkResp:
      return ok(resp.get().talkResp.response)
    else:
      d.replaceNode(toNode)
      dht_message_requests_outgoing.inc(labelValues = ["invalid_response"])
      return err("Invalid response to talk request message")
  else:
    # remove on loss only if there is a replacement
    d.replaceNode(toNode, NoreplyRemoveThreshold)
    dht_message_requests_outgoing.inc(labelValues = ["no_response"])
    return err("Talk response message not received in time")

proc lookupDistances*(target, dest: NodeId): seq[uint16] =
  let td = logDistance(target, dest)
  let tdAsInt = int(td)
  result.add(td)
  var i = 1
  while result.len < LookupRequestLimit:
    if tdAsInt + i < 256:
      result.add(td + uint16(i))
    if tdAsInt - i > 0:
      result.add(td - uint16(i))
    inc i

proc lookupWorker(d: Protocol, destNode: Node, target: NodeId, fast: bool):
    Future[seq[Node]] {.async.} =

  let r =
    if fast:
      await d.findNodeFast(destNode, target)
    else:
      # Instead of doing max `LookupRequestLimit` findNode requests, make use
      # of the discv5.1 functionality to request nodes for multiple distances.
      let dists = lookupDistances(target, destNode.id)
      await d.findNode(destNode, dists)

  if r.isOk:
    result.add(r[])

    # Attempt to add all nodes discovered
    for n in result:
      discard d.addNode(n)

proc lookup*(d: Protocol, target: NodeId, fast: bool = false): Future[seq[Node]] {.async.} =
  ## Perform a lookup for the given target, return the closest n nodes to the
  ## target. Maximum value for n is `BUCKET_SIZE`.
  # `closestNodes` holds the k closest nodes to target found, sorted by distance
  # Unvalidated nodes are used for requests as a form of validation.
  var closestNodes = d.routingTable.neighbours(target, BUCKET_SIZE,
    LookupSeenThreshold)

  var asked, seen = initHashSet[NodeId]()
  asked.incl(d.localNode.id) # No need to ask our own node
  seen.incl(d.localNode.id) # No need to discover our own node
  for node in closestNodes:
    seen.incl(node.id)

  var pendingQueries = newSeqOfCap[Future[seq[Node]]](Alpha)

  while true:
    var i = 0
    # Doing `Alpha` amount of requests at once as long as closer non queried
    # nodes are discovered.
    while i < closestNodes.len and pendingQueries.len < Alpha:
      let n = closestNodes[i]
      if not asked.containsOrIncl(n.id):
        pendingQueries.add(d.lookupWorker(n, target, fast))
      inc i

    trace "discv5 pending queries", total = pendingQueries.len

    if pendingQueries.len == 0:
      break

    let query = await one(pendingQueries)
    trace "Got discv5 lookup query response"

    let index = pendingQueries.find(query)
    if index != -1:
      pendingQueries.del(index)
    else:
      error "Resulting query should have been in the pending queries"

    let nodes = query.read
    # TODO: Remove node on timed-out query?
    for n in nodes:
      if not seen.containsOrIncl(n.id):
        # If it wasn't seen before, insert node while remaining sorted
        closestNodes.insert(n, closestNodes.lowerBound(n,
          proc(x: Node, n: Node): int =
            cmp(distance(x.id, target), distance(n.id, target))
        ))

        if closestNodes.len > BUCKET_SIZE:
          closestNodes.del(closestNodes.high())

  d.lastLookup = now(chronos.Moment)
  trace "Closest nodes", nodes = closestNodes.len
  return closestNodes

proc addProvider*(
    d: Protocol,
    cId: NodeId,
    pr: SignedPeerRecord): Future[seq[Node]] {.async.} =

  var res = await d.lookup(cId)
  # TODO: lookup is specified as not returning local, even if that is the closest. Is this OK?
  if res.len == 0:
      res.add(d.localNode)
  for toNode in res:
    if toNode != d.localNode:
      let reqId = RequestId.init(d.rng[])
      d.sendRequest(toNode, AddProviderMessage(cId: cId, prov: pr), reqId)
    else:
      asyncSpawn d.addProviderLocal(cId, pr)

  return res

proc sendGetProviders(d: Protocol, toNode: Node,
                       cId: NodeId): Future[DiscResult[ProvidersMessage]]
                       {.async.} =
  let msg = GetProvidersMessage(cId: cId)
  trace "sendGetProviders", toNode, msg

  let
    resp = await d.waitResponse(toNode, msg)

  d.routingTable.setJustSeen(toNode, resp.isSome())
  if resp.isSome():
    if resp.get().kind == MessageKind.providers:
      return ok(resp.get().provs)
    else:
      # TODO: do we need to do something when there is an invalid response?
      d.replaceNode(toNode)
      dht_message_requests_outgoing.inc(labelValues = ["invalid_response"])
      return err("Invalid response to GetProviders message")
  else:
    # remove on loss only if there is a replacement
    d.replaceNode(toNode, NoreplyRemoveThreshold)
    dht_message_requests_outgoing.inc(labelValues = ["no_response"])
    return err("GetProviders response message not received in time")

proc getProvidersLocal*(
    d: Protocol,
    cId: NodeId,
    maxitems: int = 5,
  ): Future[seq[SignedPeerRecord]] {.async.} =

  let provs = await d.providers.get(cId)
  if provs.isErr:
    trace "Unable to get local providers", cId, err = provs.error.msg

  return provs.get

proc removeProvidersLocal*(
    d: Protocol,
    peerId: PeerId) {.async.} =

  trace "Removing local provider", peerId
  if(
    let res = await d.providers.remove(peerId);
    res.isErr):
    trace "Error removing provider", err = res.error.msg

proc getProviders*(
    d: Protocol,
    cId: NodeId,
    maxitems: int = 5,
    timeout: Duration = 5000.milliseconds
  ): Future[DiscResult[seq[SignedPeerRecord]]] {.async.} =

  # What providers do we know about?
  var res = await d.getProvidersLocal(cId, maxitems)
  trace "local providers:", prov = res.mapIt(it)

  let nodesNearby = await d.lookup(cId)
  trace "nearby:", nodesNearby
  var providersFut: seq[Future[DiscResult[ProvidersMessage]]]
  for n in nodesNearby:
    if n != d.localNode:
      providersFut.add(d.sendGetProviders(n, cId))

  while providersFut.len > 0:
    let providersMsg = await one(providersFut)

    let index = providersFut.find(providersMsg)
    if index != -1:
      providersFut.del(index)

    let providersMsg2 = await providersMsg

    let providersMsgRes = providersMsg.read
    if providersMsgRes.isOk:
      let providers = providersMsgRes.get.provs
      res = res.concat(providers).deduplicate
    else:
      error "Sending of GetProviders message failed", error = providersMsgRes.error
      # TODO: should we consider this as an error result if all GetProviders
      # requests fail??

  trace "getProviders collected: ", res = res.mapIt(it.data)

  return ok res

proc query*(d: Protocol, target: NodeId, k = BUCKET_SIZE): Future[seq[Node]]
    {.async.} =
  ## Query k nodes for the given target, returns all nodes found, including the
  ## nodes queried.
  ##
  ## This will take k nodes from the routing table closest to target and
  ## query them for nodes closest to target. If there are less than k nodes in
  ## the routing table, nodes returned by the first queries will be used.
  var queryBuffer = d.routingTable.neighbours(target, k, QuerySeenThreshold)

  var asked, seen = initHashSet[NodeId]()
  asked.incl(d.localNode.id) # No need to ask our own node
  seen.incl(d.localNode.id) # No need to discover our own node
  for node in queryBuffer:
    seen.incl(node.id)

  var pendingQueries = newSeqOfCap[Future[seq[Node]]](Alpha)

  while true:
    var i = 0
    while i < min(queryBuffer.len, k) and pendingQueries.len < Alpha:
      let n = queryBuffer[i]
      if not asked.containsOrIncl(n.id):
        pendingQueries.add(d.lookupWorker(n, target, false))
      inc i

    trace "discv5 pending queries", total = pendingQueries.len

    if pendingQueries.len == 0:
      break

    let query = await one(pendingQueries)
    trace "Got discv5 lookup query response"

    let index = pendingQueries.find(query)
    if index != -1:
      pendingQueries.del(index)
    else:
      error "Resulting query should have been in the pending queries"

    let nodes = query.read
    # TODO: Remove node on timed-out query?
    for n in nodes:
      if not seen.containsOrIncl(n.id):
        queryBuffer.add(n)

  d.lastLookup = now(chronos.Moment)
  return queryBuffer

proc queryRandom*(d: Protocol): Future[seq[Node]] =
  ## Perform a query for a random target, return all nodes discovered.
  d.query(NodeId.random(d.rng[]))

proc queryRandom*(d: Protocol, enrField: (string, seq[byte])):
    Future[seq[Node]] {.async.} =
  ## Perform a query for a random target, return all nodes discovered which
  ## contain enrField.
  let nodes = await d.queryRandom()
  var filtered: seq[Node]
  for n in nodes:
    if n.record.contains(enrField):
      filtered.add(n)

  return filtered

proc resolve*(d: Protocol, id: NodeId): Future[Option[Node]] {.async.} =
  ## Resolve a `Node` based on provided `NodeId`.
  ##
  ## This will first look in the own routing table. If the node is known, it
  ## will try to contact if for newer information. If node is not known or it
  ## does not reply, a lookup is done to see if it can find a (newer) record of
  ## the node on the network.
  if id == d.localNode.id:
    return some(d.localNode)

  let node = d.getNode(id)
  if node.isSome():
    let request = await d.findNode(node.get(), @[0'u16])

    # TODO: Handle failures better. E.g. stop on different failures than timeout
    if request.isOk() and request[].len > 0:
      trace "resolve (with local node found) is returning:", r = (request[][0])
      return some(request[][0])

  let discovered = await d.lookup(id)
  for n in discovered:
    if n.id == id:
      if node.isSome() and node.get().record.seqNum >= n.record.seqNum:
        trace "resolve (lookup) found node, but local one has greater or equal seqNum"
        return node
      else:
        trace "resolve (lookup) found new node with equal or greater seqNum", n = n
        return some(n)

  return node

proc seedTable*(d: Protocol) =
  ## Seed the table with known nodes.
  for record in d.bootstrapRecords:
    if d.addNode(record):
      debug "Added bootstrap node", uri = toURI(record)
    else:
      debug "Bootstrap node could not be added", uri = toURI(record)

  # TODO:
  # Persistent stored nodes could be added to seed from here
  # See: https://github.com/status-im/nim-eth/issues/189

proc populateTable*(d: Protocol) {.async.} =
  ## Do a set of initial lookups to quickly populate the table.
  # start with a self target query (neighbour nodes)
  let selfQuery = await d.query(d.localNode.id)
  trace "Discovered nodes in self target query", nodes = selfQuery.len

  # `InitialLookups` random queries
  for i in 0..<InitialLookups:
    let randomQuery = await d.queryRandom()
    trace "Discovered nodes in random target query", nodes = randomQuery.len

  debug "Total nodes in routing table after populate",
    total = d.routingTable.len()

proc revalidateNode*(d: Protocol, n: Node) {.async.} =
  let pong = await d.ping(n)

  if pong.isOk():
    let res = pong.get()
    if res.sprSeq > n.record.seqNum:
      # Request new SPR
      let nodes = await d.findNode(n, @[0'u16])
      if nodes.isOk() and nodes[].len > 0:
        discard d.addNode(nodes[][0])

    # Get IP and port from pong message and add it to the ip votes
    trace "pong rx", n, myip = res.ip, myport = res.port
    let a = Address(ip: res.ip, port: Port(res.port))
    d.ipVote.insert(n.id, a)

proc revalidateLoop(d: Protocol) {.async.} =
  ## Loop which revalidates the nodes in the routing table by sending the ping
  ## message.
  try:
    while true:
      let revalidateTimeout = RevalidateMin + d.rng[].rand(RevalidateMax - RevalidateMin)
      await sleepAsync(milliseconds(revalidateTimeout))
      let n = d.routingTable.nodeToRevalidate()
      if not n.isNil:
        traceAsyncErrors d.revalidateNode(n)
  except CancelledError:
    trace "revalidateLoop canceled"
  trace "revalidator loop exited!"

proc refreshLoop(d: Protocol) {.async.} =
  ## Loop that refreshes the routing table by starting a random query in case
  ## no queries were done since `RefreshInterval` or more.
  ## It also refreshes the majority address voted for via pong responses.
  try:
    await d.populateTable()

    while true:
      let currentTime = now(chronos.Moment)
      if currentTime > (d.lastLookup + RefreshInterval):
        let randomQuery = await d.queryRandom()
        trace "Discovered nodes in random target query", nodes = randomQuery.len
        debug "Total nodes in discv5 routing table", total = d.routingTable.len()

      await sleepAsync(RefreshInterval)
  except CancelledError:
    trace "refreshLoop canceled"
  trace "refreshloop exited!"

proc ipMajorityLoop(d: Protocol) {.async.} =
  #TODO this should be handled by libp2p, not the DHT
  ## When `enrAutoUpdate` is enabled, the IP:port combination returned
  ## by the majority will be used to update the local SPR.
  ## This should be safe as long as the routing table is not overwhelmed by
  ## malicious nodes trying to provide invalid addresses.
  ## Why is that?
  ## - Only one vote per NodeId is counted, and they are removed over time.
  ## - IP:port values are provided through the pong message. The local node
  ## initiates this by first sending a ping message. Unsolicited pong messages
  ## are ignored.
  ## - At interval pings are send to the least recently contacted node (tail of
  ## bucket) from a random bucket from the routing table.
  ## - Only messages that our node initiates (ping, findnode, talkreq) and that
  ## successfully get a response move a node to the head of the bucket.
  ## Additionally, findNode requests have typically a randomness to it, as they
  ## usually come from a query for random NodeId.
  ## - Currently, when a peer fails the respond, it gets replaced. It doesn't
  ## remain at the tail of the bucket.
  ## - There are IP limits on the buckets and the whole routing table.
  try:
    while true:
      let majority = d.ipVote.majority()
      if majority.isSome():
        if d.localNode.address != majority:
          let address = majority.get()
          let previous = d.localNode.address
          if d.enrAutoUpdate:
            let res = d.localNode.update(d.privateKey,
              ip = some(address.ip), udpPort = some(address.port))
            if res.isErr:
              warn "Failed updating SPR with newly discovered external address",
                majority, previous, error = res.error
            else:
              dht_enr_auto_update.inc()
              info "Updated SPR with newly discovered external address",
                majority, previous, uri = toURI(d.localNode.record)
          else:
            warn "Discovered new external address but SPR auto update is off",
              majority, previous
        else:
          debug "Discovered external address matches current address", majority,
            current = d.localNode.address

      await sleepAsync(IpMajorityInterval)
  except CancelledError:
    trace "ipMajorityLoop canceled"
  trace "ipMajorityLoop exited!"

proc debugPrintLoop(d: Protocol) {.async.} =
  ## Loop which prints the neighborhood with stats
  while true:
    await sleepAsync(DebugPrintInterval)
    for b in d.routingTable.buckets:
      debug "bucket", depth = b.getDepth,
            len = b.nodes.len, standby = b.replacementLen
      for n in b.nodes:
        debug "node", n, rttMin = n.stats.rttMin.int, rttAvg = n.stats.rttAvg.int,
          reliability = n.seen.round(3)
        # bandwidth estimates are based on limited information, so not logging it yet to avoid confusion
        # trace "node", n, bwMaxMbps = (n.stats.bwMax / 1e6).round(3), bwAvgMbps = (n.stats.bwAvg / 1e6).round(3)

func init*(
    T: type DiscoveryConfig,
    tableIpLimit: uint,
    bucketIpLimit: uint,
    bitsPerHop: int): T =

  DiscoveryConfig(
    tableIpLimits: TableIpLimits(
      tableIpLimit: tableIpLimit,
      bucketIpLimit: bucketIpLimit),
    bitsPerHop: bitsPerHop
  )

proc newProtocol*(
    privKey: PrivateKey,
    enrIp: Option[IpAddress],
    enrTcpPort, enrUdpPort: Option[Port],
    localEnrFields: openArray[(string, seq[byte])] = [],
    bootstrapRecords: openArray[SignedPeerRecord] = [],
    previousRecord = none[SignedPeerRecord](),
    bindPort: Port,
    bindIp = IPv4_any(),
    enrAutoUpdate = false,
    config = defaultDiscoveryConfig,
    rng = newRng(),
    providers = ProvidersManager.new(
      SQLiteDatastore.new(Memory)
      .expect("Should not fail!"))
): Protocol =
  # TODO: Tried adding bindPort = udpPort as parameter but that gave
  # "Error: internal error: environment misses: udpPort" in nim-beacon-chain.
  # Anyhow, nim-beacon-chain would also require some changes to support port
  # remapping through NAT and this API is also subject to change once we
  # introduce support for ipv4 + ipv6 binding/listening.

  # TODO: Implement SignedPeerRecord custom fields?
  # let extraFields = mapIt(localEnrFields, toFieldPair(it[0], it[1]))

  # TODO:
  # - Defect as is now or return a result for spr errors?
  # - In case incorrect key, allow for new spr based on new key (new node id)?
  var record: SignedPeerRecord
  if previousRecord.isSome():
    record = previousRecord.get()
    record.update(privKey, enrIp, enrTcpPort, enrUdpPort)
            .expect("SignedPeerRecord within size limits and correct key")
  else:
    record = SignedPeerRecord.init(1, privKey, enrIp, enrTcpPort, enrUdpPort)
               .expect("SignedPeerRecord within size limits")

  info "SPR initialized", ip = enrIp, tcp = enrTcpPort, udp = enrUdpPort,
    seqNum = record.seqNum, uri = toURI(record)
  if enrIp.isNone():
    if enrAutoUpdate:
      notice "No external IP provided for the SPR, this node will not be " &
        "discoverable until the SPR is updated with the discovered external IP address"
    else:
      warn "No external IP provided for the SPR, this node will not be discoverable"

  let node = newNode(record).expect("Properly initialized record")

  # TODO Consider whether this should be a Defect
  doAssert rng != nil, "RNG initialization failed"

  let
    routingTable = RoutingTable.init(
      node,
      config.bitsPerHop,
      config.tableIpLimits,
      rng)

  result = Protocol(
    privateKey: privKey,
    localNode: node,
    bootstrapRecords: @bootstrapRecords,
    ipVote: IpVote.init(),
    enrAutoUpdate: enrAutoUpdate,
    routingTable: routingTable,
    rng: rng,
    providers: providers)

  result.transport = newTransport(result, privKey, node, bindPort, bindIp, rng)

proc newProtocol*(
    privKey: PrivateKey,
    bindPort: Port,
    record: SignedPeerRecord,
    bootstrapRecords: openArray[SignedPeerRecord] = [],
    bindIp = IPv4_any(),
    config = defaultDiscoveryConfig,
    rng = newRng(),
    providers = ProvidersManager.new(SQLiteDatastore.new(Memory)
                                .expect("Should not fail!"))
): Protocol =
  ## Initialize DHT protocol
  ##

  info "Discovery SPR initialized", seqNum = record.seqNum, uri = toURI(record)

  let
    node = newNode(
      bindIp,
      bindPort,
      privKey.getPublicKey.expect("Should get public key"),
      record).expect("Properly initialized record")

  # TODO Consider whether this should be a Defect
  doAssert rng != nil, "RNG initialization failed"

  result = Protocol(
    privateKey: privKey,
    localNode: node,
    bootstrapRecords: @bootstrapRecords,
    ipVote: IpVote.init(),
    enrAutoUpdate: false, #TODO this should be removed from nim-libp2p-dht
    routingTable: RoutingTable.init(
      node, config.bitsPerHop, config.tableIpLimits, rng),
    rng: rng,
    providers: providers)

  trace "newProtocol initiated."
  result.transport = newTransport(result, privKey, node, bindPort, bindIp, rng)

proc open*(d: Protocol) {.raises: [Defect, CatchableError].} =
  info "Starting discovery node", node = d.localNode

  d.transport.open()
  trace "Transport open."

  d.seedTable()
  trace "Routing table seeded."

proc start*(d: Protocol) {.async.} =
  trace "Protocol start..."
  d.refreshLoop = refreshLoop(d)
  d.revalidateLoop = revalidateLoop(d)
  d.ipMajorityLoop = ipMajorityLoop(d)
  d.debugPrintLoop = debugPrintLoop(d)

  await d.providers.start()

proc closeWait*(d: Protocol) {.async.} =
  doAssert(not d.transport.closed)

  debug "Closing discovery node", node = d.localNode
  if not d.revalidateLoop.isNil:
    await d.revalidateLoop.cancelAndWait()
  if not d.refreshLoop.isNil:
    await d.refreshLoop.cancelAndWait()
  if not d.ipMajorityLoop.isNil:
    await d.ipMajorityLoop.cancelAndWait()

  await d.transport.closeWait()
