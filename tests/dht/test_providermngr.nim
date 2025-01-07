
import std/sequtils

import pkg/chronos
import pkg/asynctest/chronos/unittest
import pkg/datastore
from pkg/libp2p import PeerId

import codexdht/private/eth/p2p/discoveryv5/spr
import codexdht/private/eth/p2p/discoveryv5/providers
import codexdht/discv5/node
import codexdht/private/eth/p2p/discoveryv5/lru
import ./test_helper

suite "Test Providers Manager simple":
  let
    ds = SQLiteDatastore.new(Memory).tryGet()
    manager = ProvidersManager.new(ds, disableCache = true)
    rng = newRng()
    privKey = PrivateKey.example(rng)
    provider = privKey.toSignedPeerRecord()
    nodeId = NodeId.example(rng)

  teardownAll:
    (await ds.close()).tryGet()

  test "Should add provider":
    (await manager.add(nodeId, provider)).tryGet

  test "Should get provider":
    let
      prov = (await manager.get(nodeId)).tryGet

    check prov[0] == provider

  test "Should check provider presence":
    check:
      (await manager.contains(nodeId))
      (await manager.contains(provider.data.peerId))
      (await manager.contains(nodeId, provider.data.peerId))

  test "Should update provider with newer seqno":
    var
      updated = provider

    updated.incSeqNo(privKey).tryGet
    (await manager.add(nodeId, updated)).tryGet
    let prov = (await manager.get(nodeId)).tryGet
    check prov[0] == updated

  test "Should remove single record by NodeId and PeerId":
    check:
      (await manager.contains(nodeId))
      (await manager.contains(provider.data.peerId))

    (await (manager.remove(nodeId, provider.data.peerId))).tryGet

    check:
      not (await manager.contains(nodeId, provider.data.peerId))

suite "Test Providers Manager multiple":
  let
    rng = newRng()
    privKeys = (0..<10).mapIt( PrivateKey.example(rng) )
    providers = privKeys.mapIt( it.toSignedPeerRecord() )
    nodeIds = (0..<100).mapIt( NodeId.example(rng) )

  var
    ds: SQLiteDatastore
    manager: ProvidersManager

  setup:
    ds = SQLiteDatastore.new(Memory).tryGet()
    manager = ProvidersManager.new(ds, disableCache = true)

    for id in nodeIds:
      for p in providers:
        (await manager.add(id, p)).tryGet

  teardown:
    (await ds.close()).tryGet()
    ds = nil
    manager = nil

  test "Should retrieve multiple records":
    for id in nodeIds:
      check: (await manager.get(id)).tryGet.len == 10

  test "Should retrieve multiple records with limit":
    for id in nodeIds:
      check: (await manager.get(id, 5)).tryGet.len == 5

  test "Should remove by NodeId":
    (await (manager.remove(nodeIds[0]))).tryGet
    (await (manager.remove(nodeIds[49]))).tryGet
    (await (manager.remove(nodeIds[99]))).tryGet

    check:
      not (await manager.contains(nodeIds[0]))
      not (await manager.contains(nodeIds[49]))
      not (await manager.contains(nodeIds[99]))

  test "Should remove by PeerId with associated keys":
    (await (manager.remove(providers[0].data.peerId, true))).tryGet
    (await (manager.remove(providers[5].data.peerId, true))).tryGet
    (await (manager.remove(providers[9].data.peerId, true))).tryGet

    for id in nodeIds:
      check:
        not (await manager.contains(id, providers[0].data.peerId))
        not (await manager.contains(id, providers[5].data.peerId))
        not (await manager.contains(id, providers[9].data.peerId))

    check:
      not (await manager.contains(providers[0].data.peerId))
      not (await manager.contains(providers[5].data.peerId))
      not (await manager.contains(providers[9].data.peerId))

  test "Should not return keys without provider":
    for id in nodeIds:
      check:
        (await manager.get(id)).tryGet.len == 10

    for provider in providers:
      (await (manager.remove(provider.data.peerId))).tryGet

    for id in nodeIds:
      check:
        (await manager.get(id)).tryGet.len == 0

    for provider in providers:
      check:
        not (await manager.contains(provider.data.peerId))

suite "Test providers with cache":
  let
    rng = newRng()
    privKeys = (0..<10).mapIt( PrivateKey.example(rng) )
    providers = privKeys.mapIt( it.toSignedPeerRecord() )
    nodeIds = (0..<100).mapIt( NodeId.example(rng) )

  var
    ds: SQLiteDatastore
    manager: ProvidersManager

  setup:
    ds = SQLiteDatastore.new(Memory).tryGet()
    manager = ProvidersManager.new(ds)

    for id in nodeIds:
      for p in providers:
        (await manager.add(id, p)).tryGet

  teardown:
    (await ds.close()).tryGet()
    ds = nil
    manager = nil

  test "Should retrieve multiple records":
    for id in nodeIds:
      check: (await manager.get(id)).tryGet.len == 10

  test "Should retrieve multiple records with limit":
    for id in nodeIds:
      check: (await manager.get(id, 5)).tryGet.len == 5

  test "Should remove by NodeId":
    (await (manager.remove(nodeIds[0]))).tryGet
    (await (manager.remove(nodeIds[49]))).tryGet
    (await (manager.remove(nodeIds[99]))).tryGet

    check:
      nodeIds[0] notin manager.cache.cache
      not (await manager.contains(nodeIds[0]))

      nodeIds[49] notin manager.cache.cache
      not (await manager.contains(nodeIds[49]))

      nodeIds[99] notin manager.cache.cache
      not (await manager.contains(nodeIds[99]))

  test "Should remove by PeerId":
    (await (manager.remove(providers[0].data.peerId, true))).tryGet
    (await (manager.remove(providers[5].data.peerId, true))).tryGet
    (await (manager.remove(providers[9].data.peerId, true))).tryGet

    for id in nodeIds:
      check:
        providers[0].data.peerId notin manager.cache.cache.get(id).get
        not (await manager.contains(id, providers[0].data.peerId))

        providers[5].data.peerId notin manager.cache.cache.get(id).get
        not (await manager.contains(id, providers[5].data.peerId))

        providers[9].data.peerId notin manager.cache.cache.get(id).get
        not (await manager.contains(id, providers[9].data.peerId))

    check:
      not (await manager.contains(providers[0].data.peerId))
      not (await manager.contains(providers[5].data.peerId))
      not (await manager.contains(providers[9].data.peerId))

suite "Test Provider Maintenance":
  let
    rng = newRng()
    privKeys = (0..<10).mapIt( PrivateKey.example(rng) )
    providers = privKeys.mapIt( it.toSignedPeerRecord() )
    nodeIds = (0..<100).mapIt( NodeId.example(rng) )

  var
    ds: SQLiteDatastore
    manager: ProvidersManager

  setupAll:
    ds = SQLiteDatastore.new(Memory).tryGet()
    manager = ProvidersManager.new(ds, disableCache = true)

    for id in nodeIds:
      for p in providers:
        (await manager.add(id, p, ttl = 1.millis)).tryGet

  teardownAll:
    (await ds.close()).tryGet()
    ds = nil
    manager = nil

  test "Should cleanup expired":
    for id in nodeIds:
      check: (await manager.get(id)).tryGet.len == 10

    await sleepAsync(500.millis)
    await manager.store.cleanupExpired()

    for id in nodeIds:
      check: (await manager.get(id)).tryGet.len == 0

  test "Should not cleanup unexpired":
    let
      unexpired = PrivateKey.example(rng).toSignedPeerRecord()

    (await manager.add(nodeIds[0], unexpired, ttl = 1.minutes)).tryGet

    await sleepAsync(500.millis)
    await manager.store.cleanupExpired()

    let
      unexpiredProvs = (await manager.get(nodeIds[0])).tryGet

    check:
      unexpiredProvs.len == 1
      await (unexpired.data.peerId in manager)

    (await manager.remove(nodeIds[0])).tryGet

  test "Should cleanup orphaned":
    for id in nodeIds:
      check: (await manager.get(id)).tryGet.len == 0

    await manager.store.cleanupOrphaned()

    for p in providers:
      check: not (await manager.contains(p.data.peerId))
