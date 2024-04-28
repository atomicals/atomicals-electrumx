# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''

import asyncio
import codecs
import datetime
import itertools
import math
import os
import ssl
import time
from collections import defaultdict
from functools import partial
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Optional, TYPE_CHECKING
import asyncio

import attr
import pylru
from aiohttp import web
from aiorpcx import (Event, JSONRPCAutoDetect, JSONRPCConnection,
                     ReplyAndDisconnect, Request, RPCError, RPCSession,
                     handler_invocation, serve_rs, serve_ws, sleep,
                     NewlineFramer, TaskTimeout, timeout_after, run_in_thread)

import electrumx
from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder
from electrumx.lib.script2addr import get_address_from_output_script
import electrumx.lib.util as util
from electrumx.lib.util import OldTaskGroup, unpack_le_uint64
from electrumx.lib.util_atomicals import (
    DFT_MINT_MAX_MAX_COUNT_DENSITY,
    format_name_type_candidates_to_rpc,
    SUBREALM_MINT_PATH,
    MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
    DMINT_PATH,
    convert_db_mint_info_to_rpc_mint_info_format,
    compact_to_location_id_bytes,
    location_id_bytes_to_compact,
    is_compact_atomical_id,
    format_name_type_candidates_to_rpc_for_subname,
    calculate_latest_state_from_mod_history,
    parse_protocols_operations_from_witness_array,
    validate_rules_data,
    AtomicalsValidationError,
    auto_encode_bytes_elements,
    validate_merkle_proof_dmint
)
from electrumx.lib.hash import (HASHX_LEN, Base58Error, hash_to_hex_str,
                                hex_str_to_hash, sha256, double_sha256)
from electrumx.lib.merkle import MerkleCache
from electrumx.lib.text import sessions_lines
from electrumx.server.daemon import DaemonError
from electrumx.server.history import TXNUM_LEN
from electrumx.server.http_middleware import rate_limiter, cors_middleware, error_middleware, request_middleware
from electrumx.server.http_session import HttpHandler
from electrumx.server.peers import PeerManager
from electrumx.lib.script import SCRIPTHASH_LEN

if TYPE_CHECKING:
    from electrumx.server.db import DB
    from electrumx.server.env import Env
    from electrumx.server.block_processor import BlockProcessor
    from electrumx.server.daemon import Daemon
    from electrumx.server.mempool import MemPool


BAD_REQUEST = 1
DAEMON_ERROR = 2
ATOMICALS_INVALID_TX = 800422

def scripthash_to_hashX(scripthash):
    try:
        bin_hash = hex_str_to_hash(scripthash)
        if len(bin_hash) == 32:
            return bin_hash[:HASHX_LEN]
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f'{scripthash} is not a valid script hash')

def non_negative_integer(value):
    '''Return param value it is or can be converted to a non-negative
    integer, otherwise raise an RPCError.'''
    try:
        value = int(value)
        if value >= 0:
            return value
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST,
                   f'{value} should be a non-negative integer')

def assert_boolean(value):
    '''Return param value it is boolean otherwise raise an RPCError.'''
    if value in (False, True):
        return value
    raise RPCError(BAD_REQUEST, f'{value} should be a boolean value')

def assert_tx_hash(value):
    '''Raise an RPCError if the value is not a valid hexadecimal transaction hash.

    If it is valid, return it as 32-byte binary hash.
    '''
    try:
        raw_hash = hex_str_to_hash(value)
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f'{value} should be a transaction hash')

def assert_atomical_id(value):
    '''Raise an RPCError if the value is not a valid atomical id
    If it is valid, return it as 32-byte binary hash.
    '''
    try:
        if value == None or value == "":
            raise RPCError(BAD_REQUEST, f'atomical_id required')
        index_of_i = value.find("i")
        if index_of_i != 64:
            raise RPCError(BAD_REQUEST, f'{value} should be an atomical_id')
        raw_hash = hex_str_to_hash(value[ : 64])
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass

    raise RPCError(BAD_REQUEST, f'{value} should be an atomical_id')

@attr.s(slots=True)
class SessionGroup:
    name = attr.ib()
    weight = attr.ib()
    sessions = attr.ib()
    retained_cost = attr.ib()

    def session_cost(self):
        return sum(session.cost for session in self.sessions)

    def cost(self):
        return self.retained_cost + self.session_cost()


@attr.s(slots=True)
class SessionReferences:
    # All attributes are sets but groups is a list
    sessions = attr.ib()
    groups = attr.ib()
    specials = attr.ib()    # Lower-case strings
    unknown = attr.ib()     # Strings


class SessionManager:
    '''Holds global state about all sessions.'''

    def __init__(
            self,
            env: 'Env',
            db: 'DB',
            bp: 'BlockProcessor',
            daemon: 'Daemon',
            mempool: 'MemPool',
            shutdown_event: asyncio.Event,
    ):
        env.max_send = max(350000, env.max_send)
        self.env = env
        self.db = db
        self.bp = bp
        self.daemon = daemon
        self.mempool = mempool
        self.peer_mgr = PeerManager(env, db)
        self.shutdown_event = shutdown_event
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.servers = {}           # service->server
        self.sessions = {}          # session->iterable of its SessionGroups
        self.session_groups = {}    # group name->SessionGroup instance
        self.txs_sent = 0
        # Would use monotonic time, but aiorpcx sessions use Unix time:
        self.start_time = time.time()
        self._method_counts = defaultdict(int)
        self._reorg_count = 0
        self._history_cache = pylru.lrucache(1000)
        self._history_lookups = 0
        self._history_hits = 0
        self._history_op_cache = pylru.lrucache(1000)
        self._tx_num_op_cache = pylru.lrucache(10000000)
        self._tx_hashes_cache = pylru.lrucache(1000)
        self._tx_hashes_lookups = 0
        self._tx_hashes_hits = 0
        # Really a MerkleCache cache
        self._merkle_cache = pylru.lrucache(1000)
        self._merkle_lookups = 0
        self._merkle_hits = 0
        self.estimatefee_cache = pylru.lrucache(1000)
        self._tx_detail_cache = pylru.lrucache(1000000)
        self.notified_height = None
        self.hsub_results = None
        self._task_group = OldTaskGroup()
        self._sslc = None
        # Event triggered when electrumx is listening for incoming requests.
        self.server_listening = Event()
        self.session_event = Event()
        self.op_list = {
            "mint-dft": 1, "mint-ft": 2, "mint-nft": 3, "mint-nft-realm": 4,
            "mint-nft-subrealm": 5, "mint-nft-container": 6, "mint-nft-dmitem": 7,
            "dft": 20, "dat": 21, "split": 22, "splat": 23,
            "seal": 24, "evt": 25, "mod": 26,
            "transfer": 30,
            "payment-subrealm": 40, "payment-dmitem": 41,
            "mint-dft-failed": 51, "mint-ft-failed": 52, "mint-nft-failed": 53, "mint-nft-realm-failed": 54,
            "mint-nft-subrealm-failed": 55, "mint-nft-container-failed": 56, "mint-nft-dmitem-failed": 57,
            "invalid-mint": 59,
            "burn": 70,
        }

        # Set up the RPC request handlers
        cmds = ('add_peer daemon_url disconnect getinfo groups log peers '
                'query reorg sessions stop debug_memusage_list_all_objects '
                'debug_memusage_get_random_backref_chain'.split())
        LocalRPC.request_handlers = {cmd: getattr(self, 'rpc_' + cmd)
                                     for cmd in cmds}

    def _ssl_context(self):
        if self._sslc is None:
            self._sslc = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self._sslc.load_cert_chain(self.env.ssl_certfile, keyfile=self.env.ssl_keyfile)
        return self._sslc

    async def _start_servers(self, services):
        for service in services:
            kind = service.protocol.upper()
            if service.protocol == 'http':
                host = None if service.host == 'all_interfaces' else str(service.host)
                try:
                    app = web.Application(middlewares=[
                        cors_middleware(self),
                        error_middleware(self),
                        request_middleware(self),
                    ])
                    handler = HttpHandler(self, self.db, self.mempool, self.peer_mgr, kind)
                    # GET
                    app.router.add_get('/proxy', handler.proxy)
                    app.router.add_get('/proxy/health', handler.health)
                    app.router.add_get('/proxy/blockchain.block.header', handler.block_header)
                    app.router.add_get('/proxy/blockchain.block.headers', handler.block_headers)
                    app.router.add_get('/proxy/blockchain.estimatefee', handler.estimatefee)
                    # app.router.add_get('/proxy/headers.subscribe', handler.headers_subscribe)
                    # app.router.add_get('/proxy/relayfee', handler.relayfee)
                    app.router.add_get('/proxy/blockchain.scripthash.get_balance', handler.scripthash_get_balance)
                    app.router.add_get('/proxy/blockchain.scripthash.get_history', handler.scripthash_get_history)
                    app.router.add_get('/proxy/blockchain.scripthash.get_mempool', handler.scripthash_get_mempool)
                    app.router.add_get('/proxy/blockchain.scripthash.listunspent', handler.scripthash_listunspent)
                    app.router.add_get('/proxy/blockchain.scripthash.subscribe', handler.scripthash_subscribe)
                    app.router.add_get('/proxy/blockchain.transaction.broadcast', handler.transaction_broadcast)
                    app.router.add_get('/proxy/blockchain.transaction.get', handler.transaction_get)
                    app.router.add_get('/proxy/blockchain.transaction.get_merkle', handler.transaction_merkle)
                    app.router.add_get('/proxy/blockchain.transaction.id_from_pos', handler.transaction_id_from_pos)
                    # app.router.add_get('/proxy/server.add_peer', handler.add_peer)
                    # app.router.add_get('/proxy/server.banner', handler.banner)
                    app.router.add_get('/proxy/server.donation_address', handler.donation_address)
                    app.router.add_get('/proxy/server.features', handler.server_features_async)
                    app.router.add_get('/proxy/server.peers.subscribe', handler.peers_subscribe)
                    app.router.add_get('/proxy/server.ping', handler.ping)
                    # app.router.add_get('/proxy/server.version', handler.server_version)
                    app.router.add_get('/proxy/blockchain.atomicals.validate', handler.transaction_broadcast_validate)
                    app.router.add_get('/proxy/blockchain.atomicals.get_ft_balances_scripthash', handler.atomicals_get_ft_balances)
                    app.router.add_get('/proxy/blockchain.atomicals.get_nft_balances_scripthash', handler.atomicals_get_nft_balances)
                    app.router.add_get('/proxy/blockchain.atomicals.listscripthash', handler.atomicals_listscripthash)
                    app.router.add_get('/proxy/blockchain.atomicals.list', handler.atomicals_list)
                    app.router.add_get('/proxy/blockchain.atomicals.get_numbers', handler.atomicals_num_to_id)
                    app.router.add_get('/proxy/blockchain.atomicals.get_block_hash', handler.atomicals_block_hash)
                    app.router.add_get('/proxy/blockchain.atomicals.get_block_txs', handler.atomicals_block_txs)
                    app.router.add_get('/proxy/blockchain.atomicals.dump', handler.atomicals_dump)
                    app.router.add_get('/proxy/blockchain.atomicals.at_location', handler.atomicals_at_location)
                    app.router.add_get('/proxy/blockchain.atomicals.get_location', handler.atomicals_get_location)
                    app.router.add_get('/proxy/blockchain.atomicals.get', handler.atomicals_get)
                    app.router.add_get('/proxy/blockchain.atomicals.get_global', handler.atomicals_get_global)
                    app.router.add_get('/proxy/blockchain.atomicals.get_state', handler.atomical_get_state)
                    app.router.add_get('/proxy/blockchain.atomicals.get_state_history', handler.atomical_get_state_history)
                    app.router.add_get('/proxy/blockchain.atomicals.get_events', handler.atomical_get_events)
                    app.router.add_get('/proxy/blockchain.atomicals.get_tx_history', handler.atomicals_get_tx_history)
                    app.router.add_get('/proxy/blockchain.atomicals.get_realm_info', handler.atomicals_get_realm_info)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_realm', handler.atomicals_get_by_realm)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_subrealm', handler.atomicals_get_by_subrealm)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_dmitem', handler.atomicals_get_by_dmitem)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_ticker', handler.atomicals_get_by_ticker)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_container', handler.atomicals_get_by_container)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_container_item', handler.atomicals_get_by_container_item)
                    app.router.add_get('/proxy/blockchain.atomicals.get_by_container_item_validate', handler.atomicals_get_by_container_item_validation)
                    app.router.add_get('/proxy/blockchain.atomicals.get_container_items', handler.atomicals_get_container_items)
                    app.router.add_get('/proxy/blockchain.atomicals.get_ft_info', handler.atomicals_get_ft_info)
                    app.router.add_get('/proxy/blockchain.atomicals.get_dft_mints', handler.atomicals_get_dft_mints)
                    app.router.add_get('/proxy/blockchain.atomicals.find_tickers', handler.atomicals_search_tickers)
                    app.router.add_get('/proxy/blockchain.atomicals.find_realms', handler.atomicals_search_realms)
                    app.router.add_get('/proxy/blockchain.atomicals.find_subrealms', handler.atomicals_search_subrealms)
                    app.router.add_get('/proxy/blockchain.atomicals.find_containers', handler.atomicals_search_containers)
                    app.router.add_get('/proxy/blockchain.atomicals.get_holders', handler.atomicals_get_holders)
                    app.router.add_get('/proxy/blockchain.atomicals.transaction', handler.atomicals_transaction)
                    app.router.add_get('/proxy/blockchain.atomicals.transaction_by_height', handler.transaction_by_height)
                    app.router.add_get('/proxy/blockchain.atomicals.transaction_by_atomical_id', handler.transaction_by_atomical_id)
                    app.router.add_get('/proxy/blockchain.atomicals.transaction_by_scripthash', handler.transaction_by_scripthash)
                    app.router.add_get('/proxy/blockchain.atomicals.transaction_global', handler.transaction_global)
                    # POST
                    app.router.add_post('/proxy', handler.proxy)
                    app.router.add_post('/proxy/blockchain.block.header', handler.block_header)
                    app.router.add_post('/proxy/blockchain.block.headers', handler.block_headers)
                    app.router.add_post('/proxy/blockchain.estimatefee', handler.estimatefee)
                    # app.router.add_post('/proxy/headers.subscribe', handler.headers_subscribe)
                    # app.router.add_post('/proxy/relayfee', handler.relayfee)
                    app.router.add_post('/proxy/blockchain.scripthash.get_balance', handler.scripthash_get_balance)
                    app.router.add_post('/proxy/blockchain.scripthash.get_history', handler.scripthash_get_history)
                    app.router.add_post('/proxy/blockchain.scripthash.get_mempool', handler.scripthash_get_mempool)
                    app.router.add_post('/proxy/blockchain.scripthash.listunspent', handler.scripthash_listunspent)
                    app.router.add_post('/proxy/blockchain.scripthash.subscribe', handler.scripthash_subscribe)
                    app.router.add_post('/proxy/blockchain.transaction.broadcast', handler.transaction_broadcast)
                    app.router.add_post('/proxy/blockchain.transaction.get', handler.transaction_get)
                    app.router.add_post('/proxy/blockchain.transaction.get_merkle', handler.transaction_merkle)
                    app.router.add_post('/proxy/blockchain.transaction.id_from_pos', handler.transaction_id_from_pos)
                    # app.router.add_post('/proxy/server.add_peer', handler.add_peer)
                    # app.router.add_post('/proxy/server.banner', handler.banner)
                    app.router.add_post('/proxy/server.donation_address', handler.donation_address)
                    app.router.add_post('/proxy/server.features', handler.server_features_async)
                    app.router.add_post('/proxy/server.peers.subscribe', handler.peers_subscribe)
                    app.router.add_post('/proxy/server.ping', handler.ping)
                    # app.router.add_post('/proxy/server.version', handler.server_version)
                    app.router.add_post('/proxy/blockchain.atomicals.validate', handler.transaction_broadcast_validate)
                    app.router.add_post('/proxy/blockchain.atomicals.get_ft_balances_scripthash', handler.atomicals_get_ft_balances)
                    app.router.add_post('/proxy/blockchain.atomicals.get_nft_balances_scripthash', handler.atomicals_get_nft_balances)
                    app.router.add_post('/proxy/blockchain.atomicals.listscripthash', handler.atomicals_listscripthash)
                    app.router.add_post('/proxy/blockchain.atomicals.list', handler.atomicals_list)
                    app.router.add_post('/proxy/blockchain.atomicals.get_numbers', handler.atomicals_num_to_id)
                    app.router.add_post('/proxy/blockchain.atomicals.get_block_hash', handler.atomicals_block_hash)
                    app.router.add_post('/proxy/blockchain.atomicals.get_block_txs', handler.atomicals_block_txs)
                    app.router.add_post('/proxy/blockchain.atomicals.dump', handler.atomicals_dump)
                    app.router.add_post('/proxy/blockchain.atomicals.at_location', handler.atomicals_at_location)
                    app.router.add_post('/proxy/blockchain.atomicals.get_location', handler.atomicals_get_location)
                    app.router.add_post('/proxy/blockchain.atomicals.get', handler.atomicals_get)
                    app.router.add_post('/proxy/blockchain.atomicals.get_global', handler.atomicals_get_global)
                    app.router.add_post('/proxy/blockchain.atomicals.get_state', handler.atomical_get_state)
                    app.router.add_post('/proxy/blockchain.atomicals.get_state_history', handler.atomical_get_state_history)
                    app.router.add_post('/proxy/blockchain.atomicals.get_events', handler.atomical_get_events)
                    app.router.add_post('/proxy/blockchain.atomicals.get_tx_history', handler.atomicals_get_tx_history)
                    app.router.add_post('/proxy/blockchain.atomicals.get_realm_info', handler.atomicals_get_realm_info)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_realm', handler.atomicals_get_by_realm)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_subrealm', handler.atomicals_get_by_subrealm)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_dmitem', handler.atomicals_get_by_dmitem)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_ticker', handler.atomicals_get_by_ticker)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_container', handler.atomicals_get_by_container)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_container_item', handler.atomicals_get_by_container_item)
                    app.router.add_post('/proxy/blockchain.atomicals.get_by_container_item_validate', handler.atomicals_get_by_container_item_validation)
                    app.router.add_post('/proxy/blockchain.atomicals.get_container_items', handler.atomicals_get_container_items)
                    app.router.add_post('/proxy/blockchain.atomicals.get_ft_info', handler.atomicals_get_ft_info)
                    app.router.add_post('/proxy/blockchain.atomicals.get_dft_mints', handler.atomicals_get_dft_mints)
                    app.router.add_post('/proxy/blockchain.atomicals.find_tickers', handler.atomicals_search_tickers)
                    app.router.add_post('/proxy/blockchain.atomicals.find_realms', handler.atomicals_search_realms)
                    app.router.add_post('/proxy/blockchain.atomicals.find_subrealms', handler.atomicals_search_subrealms)
                    app.router.add_post('/proxy/blockchain.atomicals.find_containers', handler.atomicals_search_containers)
                    app.router.add_post('/proxy/blockchain.atomicals.get_holders', handler.atomicals_get_holders)
                    app.router.add_post('/proxy/blockchain.atomicals.transaction', handler.atomicals_transaction)
                    app.router.add_post('/proxy/blockchain.atomicals.transaction_by_height', handler.transaction_by_height)
                    app.router.add_post('/proxy/blockchain.atomicals.transaction_by_atomical_id', handler.transaction_by_atomical_id)
                    app.router.add_post('/proxy/blockchain.atomicals.transaction_by_scripthash', handler.transaction_by_scripthash)
                    app.router.add_post('/proxy/blockchain.atomicals.transaction_global', handler.transaction_global)
                    # common proxy
                    app.router.add_get('/proxy/{method}', handler.handle_get_method)
                    app.router.add_post('/proxy/{method}', handler.handle_post_method)
                    app['rate_limiter'] = rate_limiter
                    runner = web.AppRunner(app)
                    await runner.setup()
                    site = web.TCPSite(runner, host, service.port)
                    await site.start()
                except Exception as e:
                    self.logger.error(f'{kind} server failed to listen on {service.address}: {e}')
                else:
                    self.logger.info(f'{kind} server listening on {service.address}')
            else:
                if service.protocol in self.env.SSL_PROTOCOLS:
                    sslc = self._ssl_context()
                else:
                    sslc = None
                if service.protocol == 'rpc':
                    session_class = LocalRPC
                else:
                    session_class = self.env.coin.SESSIONCLS
                if service.protocol in ('ws', 'wss'):
                    serve = serve_ws
                else:
                    serve = serve_rs
                # FIXME: pass the service not the kind
                session_factory = partial(session_class, self, self.db, self.mempool,
                                        self.peer_mgr, kind)
                host = None if service.host == 'all_interfaces' else str(service.host)
                try:
                    self.servers[service] = await serve(session_factory, host,
                                                        service.port, ssl=sslc)
                except OSError as e:    # don't suppress CancelledError
                    self.logger.error(f'{kind} server failed to listen on {service.address}: {e}')
                else:
                    self.logger.info(f'{kind} server listening on {service.address}')


    async def _start_external_servers(self):
        '''Start listening on TCP and SSL ports, but only if the respective
        port was given in the environment.
        '''
        await self._start_servers(service for service in self.env.services
                                  if service.protocol != 'rpc')
        self.server_listening.set()

    async def _stop_servers(self, services):
        '''Stop the servers of the given protocols.'''
        server_map = {service: self.servers.pop(service)
                      for service in set(services).intersection(self.servers)}
        # Close all before waiting
        for service, server in server_map.items():
            self.logger.info(f'closing down server for {service}')
            server.close()
        # No value in doing these concurrently
        for server in server_map.values():
            await server.wait_closed()

    async def _manage_servers(self):
        paused = False
        max_sessions = self.env.max_sessions
        low_watermark = max_sessions * 19 // 20
        while True:
            await self.session_event.wait()
            self.session_event.clear()
            if not paused and len(self.sessions) >= max_sessions:
                self.logger.info(f'maximum sessions {max_sessions:,d} '
                                 f'reached, stopping new connections until '
                                 f'count drops to {low_watermark:,d}')
                await self._stop_servers(service for service in self.servers
                                         if service.protocol != 'rpc')
                paused = True
            # Start listening for incoming connections if paused and
            # session count has fallen
            if paused and len(self.sessions) <= low_watermark:
                self.logger.info('resuming listening for incoming connections')
                await self._start_external_servers()
                paused = False

    async def _log_sessions(self):
        '''Periodically log sessions.'''
        log_interval = self.env.log_sessions
        if log_interval:
            while True:
                await sleep(log_interval)
                data = self._session_data(for_log=True)
                for line in sessions_lines(data):
                    self.logger.info(line)
                self.logger.info(util.json_serialize(self._get_info()))

    async def _disconnect_sessions(self, sessions, reason, *, force_after=1.0):
        if sessions:
            session_ids = ', '.join(str(session.session_id) for session in sessions)
            self.logger.info(f'{reason} session ids {session_ids}')
            for session in sessions:
                await self._task_group.spawn(session.close(force_after=force_after))

    async def _clear_stale_sessions(self):
        '''Cut off sessions that haven't done anything for 10 minutes.'''
        while True:
            await sleep(60)
            stale_cutoff = time.time() - self.env.session_timeout
            stale_sessions = [session for session in self.sessions
                              if session.last_recv < stale_cutoff]
            await self._disconnect_sessions(stale_sessions, 'closing stale')
            del stale_sessions

    async def _handle_chain_reorgs(self):
        '''Clear certain caches on chain reorgs.'''
        while True:
            await self.bp.backed_up_event.wait()
            self.logger.info(f'reorg signalled; clearing tx_hashes and merkle caches')
            self._reorg_count += 1
            self._tx_hashes_cache.clear()
            self._merkle_cache.clear()

    async def _recalc_concurrency(self):
        '''Periodically recalculate session concurrency.'''
        session_class = self.env.coin.SESSIONCLS
        period = 300
        while True:
            await sleep(period)
            hard_limit = session_class.cost_hard_limit

            # Reduce retained group cost
            refund = period * hard_limit / 5000
            dead_groups = []
            for group in self.session_groups.values():
                group.retained_cost = max(0.0, group.retained_cost - refund)
                if group.retained_cost == 0 and not group.sessions:
                    dead_groups.append(group)
            # Remove dead groups
            for group in dead_groups:
                self.session_groups.pop(group.name)

            # Recalc concurrency for sessions where cost is changing gradually, and update
            # cost_decay_per_sec.
            for session in self.sessions:
                # Subs have an on-going cost so decay more slowly with more subs
                session.cost_decay_per_sec = hard_limit / (10000 + 5 * session.sub_count())
                session.recalc_concurrency()

    def _get_info(self):
        '''A summary of server state.'''
        cache_fmt = '{:,d} lookups {:,d} hits {:,d} entries'
        sessions = self.sessions
        return {
            'coin': self.env.coin.__name__,
            'daemon': self.daemon.logged_url(),
            'daemon height': self.daemon.cached_height(),
            'db height': self.db.db_height,
            'db_flush_count': self.db.history.flush_count,
            'groups': len(self.session_groups),
            'history cache': cache_fmt.format(
                self._history_lookups, self._history_hits, len(self._history_cache)),
            'merkle cache': cache_fmt.format(
                self._merkle_lookups, self._merkle_hits, len(self._merkle_cache)),
            'pid': os.getpid(),
            'peers': self.peer_mgr.info(),
            'request counts': self._method_counts,
            'request total': sum(self._method_counts.values()),
            'sessions': {
                'count': len(sessions),
                'count with subs': sum(len(getattr(s, 'hashX_subs', ())) > 0 for s in sessions),
                'errors': sum(s.errors for s in sessions),
                'logged': len([s for s in sessions if s.log_me]),
                'pending requests': sum(s.unanswered_request_count() for s in sessions),
                'subs': sum(s.sub_count() for s in sessions),
            },
            'tx hashes cache': cache_fmt.format(
                self._tx_hashes_lookups, self._tx_hashes_hits, len(self._tx_hashes_cache)),
            'txs sent': self.txs_sent,
            'uptime': util.formatted_time(time.time() - self.start_time),
            'version': electrumx.version,
        }

    def _session_data(self, for_log):
        '''Returned to the RPC 'sessions' call.'''
        now = time.time()
        sessions = sorted(self.sessions, key=lambda s: s.start_time)
        return [(session.session_id,
                 session.flags(),
                 session.remote_address_string(for_log=for_log),
                 session.client,
                 session.protocol_version_string(),
                 session.cost,
                 session.extra_cost(),
                 session.unanswered_request_count(),
                 session.txs_sent,
                 session.sub_count(),
                 session.recv_count, session.recv_size,
                 session.send_count, session.send_size,
                 now - session.start_time)
                for session in sessions]

    def _group_data(self):
        '''Returned to the RPC 'groups' call.'''
        result = []
        for name, group in self.session_groups.items():
            sessions = group.sessions
            result.append([name,
                           len(sessions),
                           group.session_cost(),
                           group.retained_cost,
                           sum(s.unanswered_request_count() for s in sessions),
                           sum(s.txs_sent for s in sessions),
                           sum(s.sub_count() for s in sessions),
                           sum(s.recv_count for s in sessions),
                           sum(s.recv_size for s in sessions),
                           sum(s.send_count for s in sessions),
                           sum(s.send_size for s in sessions),
                           ])
        return result

    async def _refresh_hsub_results(self, height):
        '''Refresh the cached header subscription responses to be for height,
        and record that as notified_height.
        '''
        # Paranoia: a reorg could race and leave db_height lower
        height = min(height, self.db.db_height)
        raw = await self.raw_header(height)
        self.hsub_results = {'hex': raw.hex(), 'height': height}
        self.notified_height = height

    def _session_references(self, items, special_strings):
        '''Return a SessionReferences object.'''
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise RPCError(BAD_REQUEST, 'expected a list of session IDs')

        sessions_by_id = {session.session_id: session for session in self.sessions}
        groups_by_name = self.session_groups

        sessions = set()
        groups = set()     # Names as groups are not hashable
        specials = set()
        unknown = set()

        for item in items:
            if item.isdigit():
                session = sessions_by_id.get(int(item))
                if session:
                    sessions.add(session)
                else:
                    unknown.add(item)
            else:
                lc_item = item.lower()
                if lc_item in special_strings:
                    specials.add(lc_item)
                else:
                    if lc_item in groups_by_name:
                        groups.add(lc_item)
                    else:
                        unknown.add(item)

        groups = [groups_by_name[group] for group in groups]
        return SessionReferences(sessions, groups, specials, unknown)

    # --- LocalRPC command handlers

    async def rpc_add_peer(self, real_name):
        '''Add a peer.

        real_name: "bch.electrumx.cash t50001 s50002" for example
        '''
        await self.peer_mgr.add_localRPC_peer(real_name)
        return f"peer '{real_name}' added"

    async def rpc_disconnect(self, session_ids):
        '''Disconnect sesssions.

        session_ids: array of session IDs
        '''
        refs = self._session_references(session_ids, {'all'})
        result = []

        if 'all' in refs.specials:
            sessions = self.sessions
            result.append('disconnecting all sessions')
        else:
            sessions = refs.sessions
            result.extend(f'disconnecting session {session.session_id}' for session in sessions)
            for group in refs.groups:
                result.append(f'disconnecting group {group.name}')
                sessions.update(group.sessions)
        result.extend(f'unknown: {item}' for item in refs.unknown)

        await self._disconnect_sessions(sessions, 'local RPC request to disconnect')
        return result

    async def rpc_log(self, session_ids):
        '''Toggle logging of sesssions.

        session_ids: array of session or group IDs, or 'all', 'none', 'new'
        '''
        refs = self._session_references(session_ids, {'all', 'none', 'new'})
        result = []

        def add_result(text, value):
            result.append(f'logging {text}' if value else f'not logging {text}')

        if 'all' in refs.specials:
            for session in self.sessions:
                session.log_me = True
            SessionBase.log_new = True
            result.append('logging all sessions')
        if 'none' in refs.specials:
            for session in self.sessions:
                session.log_me = False
            SessionBase.log_new = False
            result.append('logging no sessions')
        if 'new' in refs.specials:
            SessionBase.log_new = not SessionBase.log_new
            add_result('new sessions', SessionBase.log_new)

        sessions = refs.sessions
        for session in sessions:
            session.log_me = not session.log_me
            add_result(f'session {session.session_id}', session.log_me)
        for group in refs.groups:
            for session in group.sessions.difference(sessions):
                sessions.add(session)
                session.log_me = not session.log_me
                add_result(f'session {session.session_id}', session.log_me)

        result.extend(f'unknown: {item}' for item in refs.unknown)
        return result

    async def rpc_daemon_url(self, daemon_url):
        '''Replace the daemon URL.'''
        daemon_url = daemon_url or self.env.daemon_url
        try:
            self.daemon.set_url(daemon_url)
        except Exception as e:
            raise RPCError(BAD_REQUEST, f'an error occurred: {e!r}')
        return f'now using daemon at {self.daemon.logged_url()}'

    async def rpc_stop(self):
        '''Shut down the server cleanly.'''
        self.shutdown_event.set()
        return 'stopping'

    async def rpc_getinfo(self):
        '''Return summary information about the server process.'''
        return self._get_info()

    async def rpc_groups(self):
        '''Return statistics about the session groups.'''
        return self._group_data()

    async def rpc_peers(self):
        '''Return a list of data about server peers.'''
        return self.peer_mgr.rpc_data()

    async def rpc_query(self, items, limit):
        '''Returns data about a script, address or name.'''
        coin = self.env.coin
        db = self.db
        lines = []

        def arg_to_hashX(arg):
            try:
                script = bytes.fromhex(arg)
                lines.append(f'Script: {arg}')
                return coin.hashX_from_script(script)
            except ValueError:
                pass

            try:
                hashX = coin.address_to_hashX(arg)
                lines.append(f'Address: {arg}')
                return hashX
            except Base58Error:
                pass

            try:
                script = coin.build_name_index_script(arg.encode("ascii"))
                hashX = coin.name_hashX_from_script(script)
                lines.append(f'Name: {arg}')
                return hashX
            except (AttributeError, UnicodeEncodeError):
                pass

            return None

        for arg in items:
            hashX = arg_to_hashX(arg)
            if not hashX:
                continue
            n = None
            history = await db.limited_history(hashX, limit=limit)
            for n, (tx_hash, height) in enumerate(history):
                lines.append(f'History #{n:,d}: height {height:,d} '
                             f'tx_hash {hash_to_hex_str(tx_hash)}')
            if n is None:
                lines.append('No history found')
            n = None
            utxos = await db.all_utxos(hashX)
            for n, utxo in enumerate(utxos, start=1):
                lines.append(f'UTXO #{n:,d}: tx_hash '
                             f'{hash_to_hex_str(utxo.tx_hash)} '
                             f'tx_pos {utxo.tx_pos:,d} height '
                             f'{utxo.height:,d} value {utxo.value:,d}')
                if n == limit:
                    break
            if n is None:
                lines.append('No UTXOs found')

            balance = sum(utxo.value for utxo in utxos)
            lines.append(f'Balance: {coin.decimal_value(balance):,f} '
                         f'{coin.SHORTNAME}')

        return lines

    async def rpc_sessions(self):
        '''Return statistics about connected sessions.'''
        return self._session_data(for_log=False)

    async def rpc_reorg(self, count):
        '''Force a reorg of the given number of blocks.

        count: number of blocks to reorg
        '''
        count = non_negative_integer(count)
        if not self.bp.force_chain_reorg(count):
            raise RPCError(BAD_REQUEST, 'still catching up with daemon')
        return f'scheduled a reorg of {count:,d} blocks'

    async def rpc_debug_memusage_list_all_objects(self, limit: int) -> str:
        """Return a string listing the most common types in memory."""
        import objgraph  # optional dependency
        import io
        with io.StringIO() as fd:
            objgraph.show_most_common_types(
                limit=limit,
                shortnames=False,
                file=fd)
            return fd.getvalue()

    async def rpc_debug_memusage_get_random_backref_chain(self, objtype: str) -> str:
        """Return a dotfile as text containing the backref chain
        for a randomly selected object of type objtype.

        Warning: very slow! and it blocks the server.

        To convert to image:
        $ dot -Tps filename.dot -o outfile.ps
        """
        import objgraph  # optional dependency
        import random
        import io
        with io.StringIO() as fd:
            await run_in_thread(
                lambda:
                objgraph.show_chain(
                    objgraph.find_backref_chain(
                        random.choice(objgraph.by_type(objtype)),
                        objgraph.is_proper_module),
                    output=fd))
            return fd.getvalue()

    # --- External Interface

    async def serve(self, notifications, event):
        '''Start the RPC server if enabled.  When the event is triggered,
        start TCP and SSL servers.'''
        try:
            await self._start_servers(service for service in self.env.services
                                      if service.protocol == 'rpc')
            await event.wait()

            session_class = self.env.coin.SESSIONCLS
            session_class.cost_soft_limit = self.env.cost_soft_limit
            session_class.cost_hard_limit = self.env.cost_hard_limit
            session_class.cost_decay_per_sec = session_class.cost_hard_limit / 10000
            session_class.bw_cost_per_byte = 1.0 / self.env.bw_unit_cost
            session_class.cost_sleep = self.env.request_sleep / 1000
            session_class.initial_concurrent = self.env.initial_concurrent
            session_class.processing_timeout = self.env.request_timeout

            self.logger.info(f'max session count: {self.env.max_sessions:,d}')
            self.logger.info(f'session timeout: {self.env.session_timeout:,d} seconds')
            self.logger.info(f'session cost hard limit {self.env.cost_hard_limit:,d}')
            self.logger.info(f'session cost soft limit {self.env.cost_soft_limit:,d}')
            self.logger.info(f'bandwidth unit cost {self.env.bw_unit_cost:,d}')
            self.logger.info(f'request sleep {self.env.request_sleep:,d}ms')
            self.logger.info(f'request timeout {self.env.request_timeout:,d}s')
            self.logger.info(f'initial concurrent {self.env.initial_concurrent:,d}')

            self.logger.info(f'max response size {self.env.max_send:,d} bytes')
            if self.env.drop_client is not None:
                self.logger.info(
                    f'drop clients matching: {self.env.drop_client.pattern}'
                )
            for service in self.env.report_services:
                self.logger.info(f'advertising service {service}')
            # Start notifications; initialize hsub_results
            await notifications.start(self.db.db_height, self._notify_sessions)
            await self._start_external_servers()
            # Peer discovery should start after the external servers
            # because we connect to ourself
            async with self._task_group as group:
                await group.spawn(self.peer_mgr.discover_peers())
                await group.spawn(self._clear_stale_sessions())
                await group.spawn(self._handle_chain_reorgs())
                await group.spawn(self._recalc_concurrency())
                await group.spawn(self._log_sessions())
                await group.spawn(self._manage_servers())
        finally:
            # Close servers then sessions
            await self._stop_servers(self.servers.keys())
            async with OldTaskGroup() as group:
                for session in list(self.sessions):
                    await group.spawn(session.close(force_after=1))

    def extra_cost(self, session):
        # Note there is no guarantee that session is still in self.sessions.  Example traceback:
        # notify_sessions->notify->address_status->bump_cost->recalc_concurrency->extra_cost
        # during which there are many places the sesssion could be removed
        groups = self.sessions.get(session)
        if groups is None:
            return 0
        return sum((group.cost() - session.cost) * group.weight for group in groups)

    async def _merkle_branch(self, height, tx_hashes, tx_pos):
        tx_hash_count = len(tx_hashes)
        cost = tx_hash_count

        if tx_hash_count >= 200:
            self._merkle_lookups += 1
            merkle_cache = self._merkle_cache.get(height)
            if merkle_cache:
                self._merkle_hits += 1
                cost = 10 * math.sqrt(tx_hash_count)
            else:
                async def tx_hashes_func(start, count):
                    return tx_hashes[start: start + count]
                merkle_cache = MerkleCache(self.db.merkle, tx_hashes_func)
                self._merkle_cache[height] = merkle_cache
                await merkle_cache.initialize(len(tx_hashes))
            branch, _root = await merkle_cache.branch_and_root(tx_hash_count, tx_pos)
        else:
            branch, _root = self.db.merkle.branch_and_root(tx_hashes, tx_pos)

        branch = [hash_to_hex_str(hash) for hash in branch]
        return branch, cost / 2500

    async def merkle_branch_for_tx_hash(self, height, tx_hash):
        '''Return a triple (branch, tx_pos, cost).'''
        tx_hashes, tx_hashes_cost = await self.tx_hashes_at_blockheight(height)
        try:
            tx_pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError(BAD_REQUEST,
                           f'tx {hash_to_hex_str(tx_hash)} not in block at height {height:,d}')
        branch, merkle_cost = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, tx_pos, tx_hashes_cost + merkle_cost

    async def merkle_branch_for_tx_pos(self, height, tx_pos):
        '''Return a triple (branch, tx_hash_hex, cost).'''
        tx_hashes, tx_hashes_cost = await self.tx_hashes_at_blockheight(height)
        try:
            tx_hash = tx_hashes[tx_pos]
        except IndexError:
            raise RPCError(BAD_REQUEST,
                           f'no tx at position {tx_pos:,d} in block at height {height:,d}')
        branch, merkle_cost = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, hash_to_hex_str(tx_hash), tx_hashes_cost + merkle_cost

    async def tx_hashes_at_blockheight(self, height):
        '''Returns a pair (tx_hashes, cost).

        tx_hashes is an ordered list of binary hashes, cost is an estimated cost of
        getting the hashes; cheaper if in-cache.  Raises RPCError.
        '''
        self._tx_hashes_lookups += 1
        tx_hashes = self._tx_hashes_cache.get(height)
        if tx_hashes:
            self._tx_hashes_hits += 1
            return tx_hashes, 0.1

        # Ensure the tx_hashes are fresh before placing in the cache
        while True:
            reorg_count = self._reorg_count
            try:
                tx_hashes = await self.db.tx_hashes_at_blockheight(height)
            except self.db.DBError as e:
                raise RPCError(BAD_REQUEST, f'db error: {e!r}')
            if reorg_count == self._reorg_count:
                break

        self._tx_hashes_cache[height] = tx_hashes

        return tx_hashes, 0.25 + len(tx_hashes) * 0.0001

    def session_count(self):
        '''The number of connections that we've sent something to.'''
        return len(self.sessions)

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError(DAEMON_ERROR, f'daemon error: {e!r}') from None

    async def raw_header(self, height):
        '''Return the binary header at the given height.'''
        try:
            return await self.db.raw_header(height)
        except IndexError:
            raise RPCError(BAD_REQUEST, f'height {height:,d} '
                           'out of range') from None

    async def broadcast_transaction(self, raw_tx):
        hex_hash = await self.daemon.broadcast_transaction(raw_tx)
        self.txs_sent += 1
        return hex_hash

    async def broadcast_transaction_validated(self, raw_tx, live_run):
        self.bp.validate_ft_rules_raw_tx(raw_tx)
        if live_run:
            hex_hash = await self.daemon.broadcast_transaction(raw_tx)
            self.txs_sent += 1
            return hex_hash
        else:
            tx, tx_hash = self.env.coin.DESERIALIZER(bytes.fromhex(raw_tx), 0).read_tx_and_hash()
            return hash_to_hex_str(tx_hash)

    async def limited_history(self, hashX):
        '''Returns a pair (history, cost).

        History is a sorted list of (tx_hash, height) tuples, or an RPCError.'''
        # History DoS limit.  Each element of history is about 99 bytes when encoded
        # as JSON.
        limit = self.env.max_send // 99
        cost = 0.1
        self._history_lookups += 1
        result = self._history_cache.get(hashX)
        if result:
            self._history_hits += 1
        else:
            result = await self.db.limited_history(hashX, limit=limit)
            cost += 0.1 + len(result) * 0.001
            if len(result) >= limit:
                result = RPCError(BAD_REQUEST, f'history too large', cost=cost)
            self._history_cache[hashX] = result

        if isinstance(result, Exception):
            raise result
        return result, cost

    async def get_history_op(self, hashX, limit=10, offset=0, op=None, reverse=True):
        history_data = self._history_op_cache.get(hashX, [])
        if not history_data:
            history_data = []
            txnum_padding = bytes(8-TXNUM_LEN)
            for _key, hist in self.db.history.db.iterator(prefix=hashX, reverse=reverse):
                for tx_numb in util.chunks(hist, TXNUM_LEN):
                    tx_num, = util.unpack_le_uint64(tx_numb + txnum_padding)
                    op_data = self._tx_num_op_cache.get(tx_num)
                    if not op_data:
                        op_prefix_key = b'op' + util.pack_le_uint64(tx_num)
                        tx_op = self.db.utxo_db.get(op_prefix_key)
                        if tx_op:
                            op_data, = util.unpack_le_uint32(tx_op)
                            self._tx_num_op_cache[tx_num] = op_data
                    history_data.append({"tx_num": tx_num, "op": op_data})
            self._history_op_cache[hashX] = history_data
        if reverse:
            history_data.sort(key=lambda x: x['tx_num'], reverse=reverse)
        if op:
            history_data = list(filter(lambda x: x["op"] == op, history_data))
        else:
            history_data = list(filter(lambda x: x["op"], history_data))
        return history_data[offset:limit+offset], len(history_data)

    async def _notify_sessions(self, height, touched):
        '''Notify sessions about height changes and touched addresses.'''
        height_changed = height != self.notified_height
        if height_changed:
            await self._refresh_hsub_results(height)
            # Invalidate all history caches since they rely on block heights
            self._history_cache.clear()
            # Invalidate our op cache for touched hashXs
            op_cache = self._history_op_cache
            for hashX in set(op_cache).intersection(touched):
                op_cache.pop(hashX, None)
                self.logger.info(f"refresh op cache {self.notified_height}")
                time.sleep(2)
                background_task = asyncio.create_task(self.get_history_op(hashX, 10, 0, None, True))
                await background_task

        for session in self.sessions:
            if self._task_group.joined:  # this can happen during shutdown
                self.logger.warning(f"task group already terminated. not notifying sessions.")
                return
            await self._task_group.spawn(session.notify, touched, height_changed)

    def _ip_addr_group_name(self, session) -> Optional[str]:
        host = session.remote_address().host
        if isinstance(host, (IPv4Address, IPv6Address)):
            if host.is_private:  # exempt private addresses
                return None
            if isinstance(host, IPv4Address):
                subnet_size = self.env.session_group_by_subnet_ipv4
                subnet = IPv4Network(host).supernet(prefixlen_diff=32 - subnet_size)
                return str(subnet)
            elif isinstance(host, IPv6Address):
                subnet_size = self.env.session_group_by_subnet_ipv6
                subnet = IPv6Network(host).supernet(prefixlen_diff=128 - subnet_size)
                return str(subnet)
        return 'unknown_addr'

    def _session_group(self, name: Optional[str], weight: float) -> Optional[SessionGroup]:
        if name is None:
            return None
        group = self.session_groups.get(name)
        if not group:
            group = SessionGroup(name, weight, set(), 0)
            self.session_groups[name] = group
        return group

    def add_session(self, session):
        self.session_event.set()
        # Return the session groups
        groups = (
            self._session_group(self._ip_addr_group_name(session), 1.0),
        )
        groups = tuple(group for group in groups if group is not None)
        self.sessions[session] = groups
        for group in groups:
            group.sessions.add(session)

    def remove_session(self, session):
        '''Remove a session from our sessions list if there.'''
        self.session_event.set()
        groups = self.sessions.pop(session)
        for group in groups:
            group.retained_cost += session.cost
            group.sessions.remove(session)


class SessionBase(RPCSession):
    '''Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    '''

    MAX_CHUNK_SIZE = 2016
    session_counter = itertools.count()
    log_new = False

    def __init__(
            self,
            session_mgr: 'SessionManager',
            db: 'DB',
            mempool: 'MemPool',
            peer_mgr: 'PeerManager',
            kind: str,
            transport,
    ):
        connection = JSONRPCConnection(JSONRPCAutoDetect)
        super().__init__(transport, connection=connection)
        self.session_mgr = session_mgr
        self.db = db
        self.mempool = mempool
        self.peer_mgr = peer_mgr
        self.kind = kind  # 'RPC', 'TCP' etc.
        self.env = session_mgr.env
        self.coin = self.env.coin
        self.client = 'unknown'
        self.anon_logs = self.env.anon_logs
        self.txs_sent = 0
        self.log_me = SessionBase.log_new
        self.session_id = None
        self.daemon_request = self.session_mgr.daemon_request
        self.session_id = next(self.session_counter)
        context = {'conn_id': f'{self.session_id}'}
        logger = util.class_logger(__name__, self.__class__.__name__)
        self.logger = util.ConnectionLogger(logger, context)
        self.logger.info(f'{self.kind} {self.remote_address_string()}, '
                         f'{self.session_mgr.session_count():,d} total')
        self.session_mgr.add_session(self)
        self.recalc_concurrency()  # must be called after session_mgr.add_session

    async def notify(self, touched, height_changed):
        pass

    def default_framer(self):
        return NewlineFramer(max_size=self.env.max_recv)

    def remote_address_string(self, *, for_log=True):
        '''Returns the peer's IP address and port as a human-readable
        string, respecting anon logs if the output is for a log.'''
        if for_log and self.anon_logs:
            return 'xx.xx.xx.xx:xx'
        return str(self.remote_address())

    def flags(self):
        '''Status flags.'''
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self._incoming_concurrency.max_concurrent)
        return status

    async def connection_lost(self):
        '''Handle client disconnection.'''
        await super().connection_lost()
        self.session_mgr.remove_session(self)
        msg = ''
        if self._incoming_concurrency.max_concurrent < self.initial_concurrent * 0.8:
            msg += ' whilst throttled'
        if self.send_size >= 1_000_000:
            msg += f'.  Sent {self.send_size:,d} bytes in {self.send_count:,d} messages'
        if msg:
            msg = 'disconnected' + msg
            self.logger.info(msg)

    def sub_count(self):
        return 0

    async def handle_request(self, request):
        '''Handle an incoming request.  ElectrumX doesn't receive
        notifications from client sessions.
        '''
        if isinstance(request, Request):
            handler = self.request_handlers.get(request.method)
        else:
            handler = None
        method = 'invalid method' if handler is None else request.method

        # If DROP_CLIENT_UNKNOWN is enabled, check if the client identified
        # by calling server.version previously. If not, disconnect the session
        if self.env.drop_client_unknown and method != 'server.version' and self.client == 'unknown':
            self.logger.info(f'disconnecting because client is unknown')
            raise ReplyAndDisconnect(
                BAD_REQUEST, f'use server.version to identify client')

        self.session_mgr._method_counts[method] += 1
        coro = handler_invocation(handler, request)()
        return await coro


class ElectrumX(SessionBase):
    '''A TCP server that handles incoming Electrum connections.'''

    PROTOCOL_MIN = (1, 4)
    PROTOCOL_MAX = (1, 4, 3)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.connection.max_response_size = self.env.max_send
        self.hashX_subs = {}
        self.sv_seen = False
        self.mempool_statuses = {}
        self.set_request_handlers(self.PROTOCOL_MIN)
        self.is_peer = False
        self.cost = 5.0   # Connection cost

    @classmethod
    def protocol_min_max_strings(cls):
        return [util.version_string(ver)
                for ver in (cls.PROTOCOL_MIN, cls.PROTOCOL_MAX)]

    @classmethod
    def server_features(cls, env):
        '''Return the server features dictionary.'''
        hosts_dict = {}
        for service in env.report_services:
            port_dict = hosts_dict.setdefault(str(service.host), {})
            if service.protocol not in port_dict:
                port_dict[f'{service.protocol}_port'] = service.port

        min_str, max_str = cls.protocol_min_max_strings()
        return {
            'hosts': hosts_dict,
            'pruning': None,
            'server_version': electrumx.version,
            'protocol_min': min_str,
            'protocol_max': max_str,
            'genesis_hash': env.coin.GENESIS_HASH,
            'hash_function': 'sha256',
            'services': [str(service) for service in env.report_services],
        }

    async def server_features_async(self):
        self.bump_cost(0.2)
        return self.server_features(self.env)

    @classmethod
    def server_version_args(cls):
        '''The arguments to a server.version RPC call to a peer.'''
        return [electrumx.version, cls.protocol_min_max_strings()]

    def protocol_version_string(self):
        return util.version_string(self.protocol_tuple)

    def extra_cost(self):
        return self.session_mgr.extra_cost(self)

    def on_disconnect_due_to_excessive_session_cost(self):
        remote_addr = self.remote_address()
        ip_addr = remote_addr.host if remote_addr else None
        groups = self.session_mgr.sessions[self]
        group_names = [group.name for group in groups]
        self.logger.info(f"closing session over res usage. ip: {ip_addr}. groups: {group_names}")

    def sub_count(self):
        return len(self.hashX_subs)

    def unsubscribe_hashX(self, hashX):
        self.mempool_statuses.pop(hashX, None)
        return self.hashX_subs.pop(hashX, None)

    async def notify(self, touched, height_changed):
        '''Wrap _notify_inner; websockets raises exceptions for unclear reasons.'''
        try:
            async with timeout_after(30):
                await self._notify_inner(touched, height_changed)
        except TaskTimeout:
            self.logger.warning('timeout notifying client, closing...')
            await self.close(force_after=1.0)
        except Exception:
            self.logger.exception('unexpected exception notifying client')

    async def _notify_inner(self, touched, height_changed):
        '''Notify the client about changes to touched addresses (from mempool
        updates or new blocks) and height.
        '''
        if height_changed and self.subscribe_headers:
            args = (await self.subscribe_headers_result(), )
            await self.send_notification('blockchain.headers.subscribe', args)

        touched = touched.intersection(self.hashX_subs)
        if touched or (height_changed and self.mempool_statuses):
            changed = {}

            for hashX in touched:
                alias = self.hashX_subs.get(hashX)
                if alias:
                    status = await self.subscription_address_status(hashX)
                    changed[alias] = status

            # Check mempool hashXs - the status is a function of the confirmed state of
            # other transactions.
            mempool_statuses = self.mempool_statuses.copy()
            for hashX, old_status in mempool_statuses.items():
                alias = self.hashX_subs.get(hashX)
                if alias:
                    status = await self.subscription_address_status(hashX)
                    if status != old_status:
                        changed[alias] = status

            method = 'blockchain.scripthash.subscribe'
            for alias, status in changed.items():
                await self.send_notification(method, (alias, status))

            if changed:
                es = '' if len(changed) == 1 else 'es'
                self.logger.info(f'notified of {len(changed):,d} address{es}')

    async def subscribe_headers_result(self):
        '''The result of a header subscription or notification.'''
        return self.session_mgr.hsub_results

    async def headers_subscribe(self):
        '''Subscribe to get raw headers of new blocks.'''
        if not self.subscribe_headers:
            self.subscribe_headers = True
            self.bump_cost(0.25)
        return await self.subscribe_headers_result()

    async def add_peer(self, features):
        '''Add a peer (but only if the peer resolves to the source).'''
        self.is_peer = True
        self.bump_cost(100.0)
        return await self.peer_mgr.on_add_peer(features, self.remote_address())

    async def peers_subscribe(self):
        '''Return the server peers as a list of (ip, host, details) tuples.'''
        self.bump_cost(1.0)
        return self.peer_mgr.on_peers_subscribe(self.is_tor())

    async def address_status(self, hashX):
        '''Returns an address status.

        Status is a hex string, but must be None if there is no history.
        '''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if it has unconfirmed inputs, otherwise 0
        db_history, cost = await self.session_mgr.limited_history(hashX)
        mempool = await self.mempool.transaction_summaries(hashX)

        status = ''.join(f'{hash_to_hex_str(tx_hash)}:'
                         f'{height:d}:'
                         for tx_hash, height in db_history)
        status += ''.join(f'{hash_to_hex_str(tx.hash)}:'
                          f'{-tx.has_unconfirmed_inputs:d}:'
                          for tx in mempool)

        # Add status hashing cost
        self.bump_cost(cost + 0.1 + len(status) * 0.00002)

        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None

        if mempool:
            self.mempool_statuses[hashX] = status
        else:
            self.mempool_statuses.pop(hashX, None)

        return status

    async def subscription_address_status(self, hashX):
        '''As for address_status, but if it can't be calculated the subscription is
        discarded.'''
        try:
            return await self.address_status(hashX)
        except RPCError:
            self.unsubscribe_hashX(hashX)
            return None

    async def hashX_listunspent(self, hashX):
        '''Return the list of UTXOs of a script hash, including mempool
        effects.'''
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = await self.mempool.potential_spends(hashX)
        returned_utxos = []
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = []
            for atomical_id in atomicals:
                # This call is efficient in that it's cached underneath
                # For now we only show the atomical id because it can always be fetched separately and it will be more efficient
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                # Todo need to combine mempool atomicals
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_basic_infos.append(atomical_id_compact)

            returned_utxos.append({
                'txid': hash_to_hex_str(utxo.tx_hash),
                'tx_hash': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'tx_pos': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'atomicals': atomicals_basic_infos
            })
        return returned_utxos

    # Get atomical_id from an atomical inscription number
    def get_atomical_id_by_atomical_number(self, atomical_number):
        return self.db.get_atomical_id_by_atomical_number(atomical_number)

    # Get atomicals base information from db or placeholder information if mint is still in the mempool and unconfirmed
    async def atomical_id_get(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
        if atomical:
            return atomical
        # Check mempool
        atomical_in_mempool = await self.mempool.get_atomical_mint(atomical_id)
        if atomical_in_mempool == None:
            raise RPCError(BAD_REQUEST, f'"{compact_atomical_id}" is not found')
        return atomical_in_mempool

    async def atomical_id_get_ft_info(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
        if atomical['subtype'] == 'decentralized':
            atomical = await self.session_mgr.bp.get_dft_mint_info_rpc_format_by_atomical_id(atomical_id)
        elif atomical['subtype'] == 'direct':
            atomical = await self.session_mgr.bp.get_ft_mint_info_rpc_format_by_atomical_id(atomical_id)
        else:
            raise RPCError(BAD_REQUEST, f'"{compact_atomical_id}" is not a fungible token (FT)')

        if atomical:
            return atomical
        # Check mempool
        atomical_in_mempool = await self.mempool.get_atomical_mint(atomical_id)
        if atomical_in_mempool == None:
            raise RPCError(BAD_REQUEST, f'"{compact_atomical_id}" is not found')
        return atomical_in_mempool

    async def atomical_id_get_state(self, compact_atomical_id, Verbose=False):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.atomical_id_get(compact_atomical_id)
        height = self.session_mgr.bp.height
        self.db.populate_extended_mod_state_latest_atomical_info(atomical_id, atomical, height)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def atomical_id_get_state_history(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.atomical_id_get(compact_atomical_id)
        height = self.session_mgr.bp.height
        self.db.populate_extended_mod_state_history_atomical_info(atomical_id, atomical, height)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def atomical_id_get_events(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.atomical_id_get(compact_atomical_id)
        height = self.session_mgr.bp.height
        self.db.populate_extended_events_atomical_info(atomical_id, atomical, height)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def atomical_id_get_tx_history(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.atomical_id_get(compact_atomical_id)
        history = await self.scripthash_get_history(hash_to_hex_str(double_sha256(atomical_id)))
        history.sort(key=lambda x: x['height'], reverse=True)

        atomical['tx'] = {
            'history': history
        }
        return atomical

    async def atomical_id_get_location(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.atomical_id_get(compact_atomical_id)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def get_summary_info(self, atomical_hash_count=10):

        if atomical_hash_count and atomical_hash_count > 100000:
                atomical_hash_count = 100000

        db_height = self.db.db_height
        last_block_hash = self.db.get_atomicals_block_hash(db_height)
        ret = {
            'coin': self.env.coin.__name__,
            'network': self.coin.NET,
            'height': db_height,
            'block_tip': hash_to_hex_str(self.db.db_tip),
            'server_time': datetime.datetime.now().isoformat(),
            'atomicals_block_tip': last_block_hash,
            'atomical_count': self.db.db_atomical_count
        }

        list_hashes = {}
        ret['atomicals_block_hashes'] = {}
        # ret['atomicals_block_hashes'][db_height] = last_block_hash
        for i in range(atomical_hash_count):
            next_db_height = db_height - i
            nextblockhash = self.db.get_atomicals_block_hash(next_db_height)
            ret['atomicals_block_hashes'][next_db_height] = nextblockhash
        return ret

    async def atomicals_list_get(self, limit, offset, asc):
        atomicals = await self.db.get_atomicals_list(limit, offset, asc)
        atomicals_populated = []
        for atomical_id in atomicals:
            atomical = await self.atomical_id_get(location_id_bytes_to_compact(atomical_id))
            atomicals_populated.append(atomical)
        return {'global': await self.get_summary_info(), 'result': atomicals_populated }

    async def atomicals_num_to_id(self, limit, offset, asc):
        atomicals_num_to_id_map = await self.db.get_num_to_id(limit, offset, asc)
        atomicals_num_to_id_map_reformatted = {}
        for num, id in atomicals_num_to_id_map.items():
            atomicals_num_to_id_map_reformatted[num] = location_id_bytes_to_compact(id)
        return {'global': await self.get_summary_info(), 'result': atomicals_num_to_id_map_reformatted }

    async def atomicals_block_hash(self, height):
        if not height:
            height = self.session_mgr.bp.height
        block_hash = self.db.get_atomicals_block_hash(height)
        return {'result': block_hash}

    async def atomicals_block_txs(self, height):
        tx_list = self.session_mgr.bp.get_atomicals_block_txs(height)
        return {'global': await self.get_summary_info(), 'result': tx_list }

    async def hashX_subscribe(self, hashX, alias):
        # Store the subscription only after address_status succeeds
        result = await self.address_status(hashX)
        self.hashX_subs[hashX] = alias
        return result

    async def get_balance(self, hashX):
        utxos = await self.db.all_utxos(hashX)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = await self.mempool.balance_delta(hashX)
        self.bump_cost(1.0 + len(utxos) / 50)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def scripthash_get_balance(self, scripthash):
        '''Return the confirmed and unconfirmed balance of a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.get_balance(hashX)

    async def unconfirmed_history(self, hashX):
        # Note unconfirmed history is unordered in electrum-server
        # height is -1 if it has unconfirmed inputs, otherwise 0
        result = [{'tx_hash': hash_to_hex_str(tx.hash),
                   'height': -tx.has_unconfirmed_inputs,
                   'fee': tx.fee}
                  for tx in await self.mempool.transaction_summaries(hashX)]
        self.bump_cost(0.25 + len(result) / 50)
        return result

    async def confirmed_and_unconfirmed_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history, cost = await self.session_mgr.limited_history(hashX)
        self.bump_cost(cost)
        conf = [{'tx_hash': hash_to_hex_str(tx_hash), 'height': height}
                for tx_hash, height in history]
        return conf + await self.unconfirmed_history(hashX)

    async def atomicals_listscripthash(self, scripthash, Verbose=False):
        '''Return the list of Atomical UTXOs for an address'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_listscripthash_atomicals(hashX, Verbose)

    async def atomicals_list(self, offset, limit, asc):
        '''Return the list of atomicals order by reverse atomical number'''
        return await self.atomicals_list_get(offset, limit, asc)

    async def atomicals_get(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get(compact_atomical_id)}

    async def atomicals_dump(self):
        if True:
            self.db.dump()
            return {'result': True}
        else:
            return {'result': False}

    async def atomicals_get_dft_mints(self, compact_atomical_id, limit=100, offset=0):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        entries = self.session_mgr.bp.get_distmints_by_atomical_id(atomical_id, limit, offset)
        return {'global': await self.get_summary_info(), 'result': entries}

    async def atomicals_get_ft_info(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_ft_info(compact_atomical_id)}

    async def atomicals_get_global(self, hashes=10):
        return {'global': await self.get_summary_info(hashes)}

    async def atomicals_get_location(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_location(compact_atomical_id)}

    async def atomical_get_state(self, compact_atomical_id_or_atomical_number, Verbose=False):
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_state(compact_atomical_id, Verbose)}

    async def atomical_get_state_history(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_state_history(compact_atomical_id)}

    async def atomical_get_events(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_events(compact_atomical_id)}

    def atomical_resolve_id(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = compact_atomical_id_or_atomical_number
        if not isinstance(compact_atomical_id_or_atomical_number, int) and is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            found_atomical_id = self.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number)
            if not found_atomical_id:
                raise RPCError(BAD_REQUEST, f'not found atomical: {compact_atomical_id_or_atomical_number}')
            compact_atomical_id = location_id_bytes_to_compact(found_atomical_id)
        return compact_atomical_id

    async def atomicals_get_tx_history(self, compact_atomical_id_or_atomical_number):
        '''Return the history of an Atomical```
        atomical_id: the mint transaction hash + 'i'<index> of the atomical id
        verbose: to determine whether to print extended information
        '''
        compact_atomical_id = compact_atomical_id_or_atomical_number
        if isinstance(compact_atomical_id_or_atomical_number, int) != True and is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            compact_atomical_id = location_id_bytes_to_compact(self.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number))
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_tx_history(compact_atomical_id)}

    async def atomicals_get_by_ticker(self, ticker):
        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_ticker(ticker, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'ticker'
        }
        return {
            'result': return_result
        }
    async def atomicals_get_by_container(self, container):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, f'empty container')
        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_container(container, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'container'
        }
        return {
            'result': return_result
        }

    def auto_populate_container_regular_items_fields(self, items):
        if not items or not isinstance(items, dict):
            return {}
        for item, value in items.items():
            provided_id = value.get('id')
            value['status'] = 'verified'
            if provided_id and isinstance(provided_id, bytes) and len(provided_id) == 36:
                value['$id'] = location_id_bytes_to_compact(provided_id)
        return auto_encode_bytes_elements(items)

    def auto_populate_container_dmint_items_fields(self, items):
        if not items or not isinstance(items, dict):
            return {}
        for item, value in items.items():
            provided_id = value.get('id')
            if provided_id and isinstance(provided_id, bytes) and len(provided_id) == 36:
                value['$id'] = location_id_bytes_to_compact(provided_id)
        return auto_encode_bytes_elements(items)

    async def atomicals_get_container_items(self, container, limit, offset):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, f'empty container')
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_container(container, self.session_mgr.bp.height)
        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id
        else:
            raise RPCError(BAD_REQUEST, f'Container not found')

        compact_atomical_id = location_id_bytes_to_compact(found_atomical_id)
        container_info = await self.atomical_id_get(compact_atomical_id)
        # If it is a dmint container then there is no items field, instead construct it from the dmitems
        container_dmint_status = container_info.get('$container_dmint_status')
        items = []
        if container_dmint_status:
            if limit > 100:
                limit = 100
            if offset < 0:
                offset = 0
            height = self.session_mgr.bp.height
            items = await self.session_mgr.bp.get_effective_dmitems_paginated(found_atomical_id, limit, offset, height)
            return {
                'result': {
                    'container': container_info,
                    'item_data': {
                        'limit': limit,
                        'offset': offset,
                        'type': 'dmint',
                        'items': self.auto_populate_container_dmint_items_fields(items)
                    }
                }
            }
        else:
            container_mod_history = self.session_mgr.bp.get_mod_history(found_atomical_id, self.session_mgr.bp.height)
            current_height_latest_state = calculate_latest_state_from_mod_history(container_mod_history)
            items = current_height_latest_state.get('items', [])
            return {
                'result': {
                    'container': container_info,
                    'item_data': {
                        'limit': limit,
                        'offset': offset,
                        'type': 'regular',
                        'items': self.auto_populate_container_regular_items_fields(items)
                    }
                }
            }

    async def atomicals_get_by_container_item(self, container, item_name):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, f'empty container')
        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_container(container, height)
        found_atomical_id = None
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))
        if status == 'verified':
            found_atomical_id = candidate_atomical_id
        else:
            self.logger.info(f'formatted_entries {formatted_entries}')
            raise RPCError(BAD_REQUEST, f'Container does not exist')
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_dmitem(found_atomical_id, item_name, height)
        found_item_atomical_id = None
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        if status == 'verified':
            found_item_atomical_id = candidate_atomical_id
        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_item_atomical_id,
            'candidates': formatted_entries,
            'type': 'item'
        }
        return {
            'result': return_result
        }

    async def atomicals_get_by_container_item_validation(self, container, item_name, bitworkc, bitworkr, main_name, main_hash, proof, check_without_sealed):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, f'empty container')
        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_container(container, height)
        found_parent_atomical_id = None
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))
        if status == 'verified':
            found_parent_atomical_id = candidate_atomical_id
        else:
            raise RPCError(BAD_REQUEST, f'Container does not exist')
        compact_atomical_id = location_id_bytes_to_compact(found_parent_atomical_id)
        container_info = await self.atomical_id_get(compact_atomical_id)
        # If it is a dmint container then there is no items field, instead construct it from the dmitems
        container_dmint_status = container_info.get('$container_dmint_status')
        errors = container_dmint_status.get('errors')
        if not container_dmint_status:
            raise RPCError(BAD_REQUEST, f'Container dmint status not exist')
        if container_dmint_status.get('status') != 'valid':
            errors = container_dmint_status.get('errors')
            if check_without_sealed and errors and len(errors) == 1 and errors[0] == 'container not sealed':
                pass
            else:
                raise RPCError(BAD_REQUEST, f'Container dmint status is invalid')

        dmint = container_dmint_status.get('dmint')
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_dmitem(found_parent_atomical_id, item_name, height)
        found_item_atomical_id = None
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        if status == 'verified':
            found_item_atomical_id = candidate_atomical_id

        # validate the proof data nonetheless
        if not proof or not isinstance(proof, list) or len(proof) == 0:
            raise RPCError(BAD_REQUEST, f'Proof must be provided')

        applicable_rule, state_at_height = self.session_mgr.bp.get_applicable_rule_by_height(found_parent_atomical_id, item_name, height - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS, DMINT_PATH)
        proof_valid, target_vector, target_hash = validate_merkle_proof_dmint(dmint['merkle'], item_name, bitworkc, bitworkr, main_name, main_hash, proof)
        if applicable_rule and applicable_rule.get('matched_rule'):
            applicable_rule = applicable_rule.get('matched_rule')

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_item_atomical_id,
            'candidates': formatted_entries,
            'type': 'item',
            'applicable_rule': applicable_rule,
            'proof_valid': proof_valid,
            'target_vector': target_vector,
            'target_hash': target_hash,
            'dmint': state_at_height.get('dmint')
        }
        return {
            'result': return_result
        }

    async def atomicals_get_by_realm(self, name):
        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_realm(name, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'realm'
        }
        return {
            'result': return_result
        }

    async def atomicals_get_by_subrealm(self, parent_compact_atomical_id_or_atomical_number, name):
        height = self.session_mgr.bp.height
        compact_atomical_id_parent = self.atomical_resolve_id(parent_compact_atomical_id_or_atomical_number)
        atomical_id_parent = compact_to_location_id_bytes(compact_atomical_id_parent)
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_subrealm(atomical_id_parent, name, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'subrealm'
        }
        return {
            'result': return_result
        }

    async def atomicals_get_by_dmitem(self, parent_compact_atomical_id_or_atomical_number, name):
        height = self.session_mgr.bp.height
        compact_atomical_id_parent = self.atomical_resolve_id(parent_compact_atomical_id_or_atomical_number)
        atomical_id_parent = compact_to_location_id_bytes(compact_atomical_id_parent)
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_dmitem(atomical_id_parent, name, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'dmitem'
        }
        return {
            'result': return_result
        }

    # Get a summary view of a realm and if it's allowing mints and what parts already existed of a subrealm
    async def atomicals_get_realm_info(self, full_name, Verbose=False):
        if not full_name or not isinstance(full_name, str):
            raise RPCError(BAD_REQUEST, f'invalid input full_name: {full_name}')
        full_name = full_name.lower()
        split_names = full_name.split('.')
        total_name_parts = len(split_names)
        level = 0
        last_found_realm_atomical_id = None
        last_found_realm = None
        realms_path = []
        latest_all_entries_candidates = []
        height = self.session_mgr.bp.height
        for name_part in split_names:
            if level == 0:
                realm_status, last_found_realm, latest_all_entries_candidates = self.session_mgr.bp.get_effective_realm(name_part, height)
            else:
                self.logger.info(f'atomicals_get_realm_info {last_found_realm} {name_part}')
                realm_status, last_found_realm, latest_all_entries_candidates = self.session_mgr.bp.get_effective_subrealm(last_found_realm, name_part, height)
            # stops when it does not found the realm component
            if realm_status != 'verified':
                break
            # Save the latest realm (could be the top level realm, or the parent of a subrealm, or even the subrealm itself)
            last_found_realm_atomical_id = last_found_realm
            # Add it to the list of paths
            realms_path.append({
                'atomical_id': location_id_bytes_to_compact(last_found_realm),
                'name_part': name_part,
                'candidates': latest_all_entries_candidates
            })
            level += 1

        joined_name = ''
        is_first_name_part = True
        for name_element in realms_path:
            if is_first_name_part:
                is_first_name_part = False
            else:
                joined_name += '.'
            joined_name +=  name_element['name_part']
        # Nothing was found
        realms_path_len = len(realms_path)
        if realms_path_len == 0:
            return {'result': {
                    'atomical_id': None,
                    'top_level_realm_atomical_id': None,
                    'top_level_realm_name': None,
                    'nearest_parent_realm_atomical_id': None,
                    'nearest_parent_realm_name': None,
                    'request_full_realm_name': full_name,
                    'found_full_realm_name': None,
                    'missing_name_parts': full_name,
                    'candidates': format_name_type_candidates_to_rpc(latest_all_entries_candidates, self.session_mgr.bp.build_atomical_id_to_candidate_map(latest_all_entries_candidates)) }
                }
        # Populate the subrealm minting rules for a parent atomical
        that = self
        def populate_rules_response_struct(parent_atomical_id, struct_to_populate, Verbose):
            current_height = that.session_mgr.bp.height
            subrealm_mint_mod_history = that.session_mgr.bp.get_mod_history(parent_atomical_id, current_height)
            current_height_latest_state = calculate_latest_state_from_mod_history(subrealm_mint_mod_history)
            current_height_rules_list = validate_rules_data(current_height_latest_state.get(SUBREALM_MINT_PATH, None))
            nearest_parent_realm_subrealm_mint_allowed = False
            struct_to_populate['nearest_parent_realm_subrealm_mint_rules'] = {
                'nearest_parent_realm_atomical_id': location_id_bytes_to_compact(parent_atomical_id),
                'current_height': current_height,
                'current_height_rules': current_height_rules_list
            }
            if current_height_rules_list and len(current_height_rules_list) > 0:
                nearest_parent_realm_subrealm_mint_allowed = True
            struct_to_populate['nearest_parent_realm_subrealm_mint_allowed'] = nearest_parent_realm_subrealm_mint_allowed
        #
        #
        #
        # At least the top level realm was found if we got this far
        #
        #
        # The number of realms returned and name components is equal, therefore the subrealm was found correctly
        if realms_path_len == total_name_parts:
            nearest_parent_realm_atomical_id = None
            nearest_parent_realm_name = None
            top_level_realm = realms_path[0]['atomical_id']
            top_level_realm_name = realms_path[0]['name_part']
            if realms_path_len >= 2:
                nearest_parent_realm_atomical_id = realms_path[-2]['atomical_id']
                nearest_parent_realm_name = realms_path[-2]['name_part']
            elif realms_path_len == 1:
                nearest_parent_realm_atomical_id = top_level_realm
                nearest_parent_realm_name = top_level_realm_name
            final_subrealm_name = split_names[-1]
            applicable_rule_map = self.session_mgr.bp.build_applicable_rule_map(latest_all_entries_candidates, compact_to_location_id_bytes(nearest_parent_realm_atomical_id), final_subrealm_name)
            return_struct = {
                'atomical_id': realms_path[-1]['atomical_id'],
                'top_level_realm_atomical_id': top_level_realm,
                'top_level_realm_name': top_level_realm_name,
                'nearest_parent_realm_atomical_id': nearest_parent_realm_atomical_id,
                'nearest_parent_realm_name': nearest_parent_realm_name,
                'request_full_realm_name': full_name,
                'found_full_realm_name': joined_name,
                'missing_name_parts': None,
                'candidates': format_name_type_candidates_to_rpc(latest_all_entries_candidates, self.session_mgr.bp.build_atomical_id_to_candidate_map(latest_all_entries_candidates))
            }
            populate_rules_response_struct(compact_to_location_id_bytes(nearest_parent_realm_atomical_id), return_struct, Verbose)
            return {'result': return_struct}

        # The number of realms and components do not match, that is because at least the top level realm or intermediate subrealm was found
        # But the final subrealm does not exist yet
        # if realms_path_len < total_name_parts:
        # It is known if we got this far that realms_path_len < total_name_parts
        nearest_parent_realm_atomical_id = None
        nearest_parent_realm_name = None
        top_level_realm = realms_path[0]['atomical_id']
        top_level_realm_name = realms_path[0]['name_part']
        if realms_path_len >= 2:
            nearest_parent_realm_atomical_id = realms_path[-1]['atomical_id']
            nearest_parent_realm_name = realms_path[-1]['name_part']
        elif realms_path_len == 1:
            nearest_parent_realm_atomical_id = top_level_realm
            nearest_parent_realm_name = top_level_realm_name

        missing_name_parts = '.'.join(split_names[ len(realms_path):])
        final_subrealm_name = split_names[-1]
        applicable_rule_map = self.session_mgr.bp.build_applicable_rule_map(latest_all_entries_candidates, compact_to_location_id_bytes(nearest_parent_realm_atomical_id), final_subrealm_name)
        return_struct = {
            'atomical_id': None,
            'top_level_realm_atomical_id': top_level_realm,
            'top_level_realm_name': top_level_realm_name,
            'nearest_parent_realm_atomical_id': nearest_parent_realm_atomical_id,
            'nearest_parent_realm_name': nearest_parent_realm_name,
            'request_full_realm_name': full_name,
            'found_full_realm_name': joined_name,
            'missing_name_parts': missing_name_parts,
            'final_subrealm_name': final_subrealm_name,
            'candidates': format_name_type_candidates_to_rpc_for_subname(latest_all_entries_candidates, self.session_mgr.bp.build_atomical_id_to_candidate_map(latest_all_entries_candidates))
        }
        if Verbose:
            populate_rules_response_struct(compact_to_location_id_bytes(nearest_parent_realm_atomical_id), return_struct, Verbose)
        return {'result': return_struct}

    # Perform a search for tickers, containers, and realms
    def atomicals_search_name_template(self, db_prefix, name_type_str, parent_prefix=None, prefix=None, Reverse=False, Limit=1000, Offset=0, is_verified_only=False):
        db_entries = self.db.get_name_entries_template_limited(db_prefix, parent_prefix, prefix, Reverse, Limit, Offset)
        formatted_results = []
        for item in db_entries:
            if name_type_str == "ticker":
                status, _, _ = self.session_mgr.bp.get_effective_name_template(b'tick', item['name'], self.session_mgr.bp.height, self.session_mgr.bp.ticker_data_cache)
            elif name_type_str == "realm":
                status, _, _ = self.session_mgr.bp.get_effective_name_template(b'rlm', item['name'], self.session_mgr.bp.height, self.session_mgr.bp.realm_data_cache)
            elif name_type_str == "collection":
                status, _, _ = self.session_mgr.bp.get_effective_name_template(b'co', item['name'], self.session_mgr.bp.height, self.session_mgr.bp.container_data_cache)
            elif name_type_str == "subrealm":
                status, _, _ = self.session_mgr.bp.get_effective_subrealm(parent_prefix, item['name'], self.session_mgr.bp.height)
            obj = {
                'atomical_id': location_id_bytes_to_compact(item['atomical_id']),
                'tx_num': item['tx_num']
            }
            obj[name_type_str + '_hex'] = item['name_hex']
            obj[name_type_str] = item['name']
            obj['status'] = status
            if is_verified_only and status == "verified":
                formatted_results.append(obj)
            elif not is_verified_only:
                formatted_results.append(obj)
        return {'result': formatted_results}

    async def atomicals_search_tickers(self, prefix=None, Reverse=False, Limit=100, Offset=0, is_verified_only=False):
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self.atomicals_search_name_template(b'tick', 'ticker', None, prefix, Reverse, Limit, Offset, is_verified_only)

    async def atomicals_search_realms(self, prefix=None, Reverse=False, Limit=100, Offset=0, is_verified_only=False):
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self.atomicals_search_name_template(b'rlm', 'realm', None, prefix, Reverse, Limit, Offset, is_verified_only)

    async def atomicals_search_subrealms(self, parent_realm_id_compact, prefix=None, Reverse=False, Limit=100, Offset=0, is_verified_only=False):
        parent_realm_id_long_form = compact_to_location_id_bytes(parent_realm_id_compact)
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self.atomicals_search_name_template(b'srlm', 'subrealm', parent_realm_id_long_form, prefix, Reverse, Limit, Offset, is_verified_only)

    async def atomicals_search_containers(self, prefix=None, Reverse=False, Limit=100, Offset=0, is_verified_only=False):
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self.atomicals_search_name_template(b'co', 'collection', None, prefix, Reverse, Limit, Offset, is_verified_only)

    async def atomicals_at_location(self, compact_location_id):
        '''Return the Atomicals at a specific location id```
        '''
        atomical_basic_infos = []
        atomicals_found_at_location = self.db.get_atomicals_by_location_extended_info_long_form(compact_to_location_id_bytes(compact_location_id))
        for atomical_id in atomicals_found_at_location['atomicals']:
            atomical_basic_info = self.session_mgr.bp.get_atomicals_id_mint_info_basic_struct(atomical_id)
            atomical_basic_infos.append(atomical_basic_info)
        return {
            'location_info': atomicals_found_at_location['location_info'],
            'atomicals': atomical_basic_infos
        }

    async def atomicals_get_ft_balances(self, scripthash):
        '''Return the FT balances for a scripthash address'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_ft_balances_atomicals(hashX)

    async def atomicals_get_nft_balances(self, scripthash):
        '''Return the NFT balances for a scripthash address'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_nft_balances_atomicals(hashX)

    async def atomicals_get_holders(self, compact_atomical_id, limit=50, offset=0):
        '''Return the holder by a specific location id```
        '''
        formatted_results = []
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.atomical_id_get(compact_atomical_id)
        atomical = await self.db.populate_extended_atomical_holder_info(atomical_id, atomical)
        if atomical["type"] == "FT":
            if atomical.get("$mint_mode", "fixed") == "fixed":
                max_supply = atomical.get('$max_supply', 0)
            else:
                max_supply = atomical.get('$max_supply', -1)
                if max_supply < 0:
                    mint_amount = atomical.get("mint_info", {}).get("args", {}).get("mint_amount")
                    max_supply = DFT_MINT_MAX_MAX_COUNT_DENSITY * mint_amount
            for holder in atomical.get("holders", [])[offset:offset+limit]:
                percent = holder['holding'] / max_supply
                formatted_results.append({
                    "percent": percent,
                    "address": get_address_from_output_script(bytes.fromhex(holder['script'])),
                    "holding": holder["holding"]
                })
        elif atomical["type"] == "NFT":
            for holder in atomical.get("holders", [])[offset:offset+limit]:
                formatted_results.append({
                    "address": get_address_from_output_script(bytes.fromhex(holder['script'])),
                    "holding": holder["holding"]
                })
        return formatted_results

    async def hashX_ft_balances_atomicals(self, hashX):
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = [] # await self.mempool.potential_spends(hashX)
        returned_utxos = []
        atomicals_id_map = {}
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = []
            for atomical_id in atomicals:
                # This call is efficient in that it's cached underneath
                # For now we only show the atomical id because it can always be fetched separately and it will be more efficient
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = atomical_basic_info
                atomicals_basic_infos.append(atomical_id_compact)
            if len(atomicals) > 0:
                returned_utxos.append({'txid': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'atomicals': atomicals_basic_infos})
        # Aggregate balances
        return_struct = {
            'balances': {}
        }
        for returned_utxo in returned_utxos:
            for atomical_id_entry_compact in returned_utxo['atomicals']:
                atomical_id_basic_info = atomicals_id_map[atomical_id_entry_compact]
                atomical_id_compact = atomical_id_basic_info['atomical_id']
                assert(atomical_id_compact == atomical_id_entry_compact)
                if atomical_id_basic_info.get('type') == 'FT':
                    if return_struct['balances'].get(atomical_id_compact) == None:
                        return_struct['balances'][atomical_id_compact] = {}
                        return_struct['balances'][atomical_id_compact]['id'] = atomical_id_compact
                        return_struct['balances'][atomical_id_compact]['ticker'] = atomical_id_basic_info.get('$ticker')
                        return_struct['balances'][atomical_id_compact]['confirmed'] = 0
                    if returned_utxo['height'] > 0:
                        return_struct['balances'][atomical_id_compact]['confirmed'] += returned_utxo['value']
        return return_struct

    async def hashX_nft_balances_atomicals(self, hashX):
        Verbose = False
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = [] # await self.mempool.potential_spends(hashX)
        returned_utxos = []
        atomicals_id_map = {}
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = []
            for atomical_id in atomicals:
                # This call is efficient in that it's cached underneath
                # For now we only show the atomical id because it can always be fetched separately and it will be more efficient
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = atomical_basic_info
                atomicals_basic_infos.append(atomical_id_compact)
            if len(atomicals) > 0:
                returned_utxos.append({'txid': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'atomicals': atomicals_basic_infos})
        # Aggregate balances
        return_struct = {
            'balances': {}
        }
        for returned_utxo in returned_utxos:
            for atomical_id_entry_compact in returned_utxo['atomicals']:
                atomical_id_basic_info = atomicals_id_map[atomical_id_entry_compact]
                atomical_id_compact = atomical_id_basic_info['atomical_id']
                assert(atomical_id_compact == atomical_id_entry_compact)
                if atomical_id_basic_info.get('type') == 'NFT':
                    if return_struct['balances'].get(atomical_id_compact) == None:
                        return_struct['balances'][atomical_id_compact] = {}
                        return_struct['balances'][atomical_id_compact]['id'] = atomical_id_compact
                        return_struct['balances'][atomical_id_compact]['confirmed'] = 0
                    if atomical_id_basic_info.get('subtype'):
                        return_struct['balances'][atomical_id_compact]['subtype'] = atomical_id_basic_info.get('subtype')
                    if atomical_id_basic_info.get('$request_container'):
                        return_struct['balances'][atomical_id_compact]['request_container'] = atomical_id_basic_info.get('$request_container')
                    if atomical_id_basic_info.get('$container'):
                        return_struct['balances'][atomical_id_compact]['container'] = atomical_id_basic_info.get('$container')
                    if atomical_id_basic_info.get('$dmitem'):
                        return_struct['balances'][atomical_id_compact]['dmitem'] = atomical_id_basic_info.get('$dmitem')
                    if atomical_id_basic_info.get('$request_dmitem'):
                        return_struct['balances'][atomical_id_compact]['request_dmitem'] = atomical_id_basic_info.get('$request_dmitem')
                    if atomical_id_basic_info.get('$realm'):
                        return_struct['balances'][atomical_id_compact]['realm'] = atomical_id_basic_info.get('$realm')
                    if atomical_id_basic_info.get('$request_realm'):
                        return_struct['balances'][atomical_id_compact]['request_realm'] = atomical_id_basic_info.get('$request_realm')
                    if atomical_id_basic_info.get('$subrealm'):
                        return_struct['balances'][atomical_id_compact]['subrealm'] = atomical_id_basic_info.get('$subrealm')
                    if atomical_id_basic_info.get('$request_subrealm'):
                        return_struct['balances'][atomical_id_compact]['request_subrealm'] = atomical_id_basic_info.get('$request_subrealm')
                    if atomical_id_basic_info.get('$full_realm_name'):
                        return_struct['balances'][atomical_id_compact]['full_realm_name'] = atomical_id_basic_info.get('$full_realm_name')
                    if atomical_id_basic_info.get('$parent_container'):
                        return_struct['balances'][atomical_id_compact]['parent_container'] = atomical_id_basic_info.get('$parent_container')
                    if atomical_id_basic_info.get('$parent_realm'):
                        return_struct['balances'][atomical_id_compact]['parent_realm'] = atomical_id_basic_info.get('$parent_realm')
                    if atomical_id_basic_info.get('$parent_container_name'):
                        return_struct['balances'][atomical_id_compact]['parent_container_name'] = atomical_id_basic_info.get('$parent_container_name')
                    if atomical_id_basic_info.get('$bitwork'):
                        return_struct['balances'][atomical_id_compact]['bitwork'] = atomical_id_basic_info.get('$bitwork')
                    if atomical_id_basic_info.get('$parents'):
                        return_struct['balances'][atomical_id_compact]['parents'] = atomical_id_basic_info.get('$parents')
                    if returned_utxo['height'] > 0:
                        return_struct['balances'][atomical_id_compact]['confirmed'] += returned_utxo['value']
        return return_struct

    async def hashX_listscripthash_atomicals(self, hashX, Verbose=False):
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = [] # await self.mempool.potential_spends(hashX)
        returned_utxos = []
        atomicals_id_map = {}
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = []
            for atomical_id in atomicals:
                # This call is efficient in that it's cached underneath
                # For now we only show the atomical id because it can always be fetched separately and it will be more efficient
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = atomical_basic_info
                atomicals_basic_infos.append(atomical_id_compact)
            if Verbose or len(atomicals) > 0:
                returned_utxos.append({'txid': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'atomicals': atomicals_basic_infos})

        # Aggregate balances
        return_struct = {
            'global': await self.get_summary_info(),
            'atomicals': {},
            'utxos': returned_utxos
        }

        for returned_utxo in returned_utxos:
            for atomical_id_entry_compact in returned_utxo['atomicals']:
                atomical_id_basic_info = atomicals_id_map[atomical_id_entry_compact]
                atomical_id_ref = atomical_id_basic_info['atomical_id']
                if return_struct['atomicals'].get(atomical_id_ref) == None:
                    return_struct['atomicals'][atomical_id_ref] = {
                        'atomical_id': atomical_id_ref,
                        'atomical_number': atomical_id_basic_info['atomical_number'],
                        'type': atomical_id_basic_info['type'],
                        'confirmed': 0,
                        # 'subtype': atomical_id_basic_info.get('subtype'),
                        'data': atomical_id_basic_info
                    }
                    if atomical_id_basic_info.get('$realm'):
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['request_realm_status'] = atomical_id_basic_info.get('$request_realm_status')
                        return_struct['atomicals'][atomical_id_ref]['request_realm'] = atomical_id_basic_info.get('$request_realm')
                        return_struct['atomicals'][atomical_id_ref]['realm'] = atomical_id_basic_info.get('$realm')
                        return_struct['atomicals'][atomical_id_ref]['full_realm_name'] = atomical_id_basic_info.get('$full_realm_name')
                    elif atomical_id_basic_info.get('$subrealm'):
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['request_subrealm_status'] = atomical_id_basic_info.get('$request_subrealm_status')
                        return_struct['atomicals'][atomical_id_ref]['request_subrealm'] = atomical_id_basic_info.get('$request_subrealm')
                        return_struct['atomicals'][atomical_id_ref]['parent_realm'] = atomical_id_basic_info.get('$parent_realm')
                        return_struct['atomicals'][atomical_id_ref]['subrealm'] = atomical_id_basic_info.get('$subrealm')
                        return_struct['atomicals'][atomical_id_ref]['full_realm_name'] = atomical_id_basic_info.get('$full_realm_name')
                    elif atomical_id_basic_info.get('$dmitem'):
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['request_dmitem_status'] = atomical_id_basic_info.get('$request_dmitem_status')
                        return_struct['atomicals'][atomical_id_ref]['request_dmitem'] = atomical_id_basic_info.get('$request_dmitem')
                        return_struct['atomicals'][atomical_id_ref]['parent_container'] = atomical_id_basic_info.get('$parent_container')
                        return_struct['atomicals'][atomical_id_ref]['dmitem'] = atomical_id_basic_info.get('$dmitem')
                    elif atomical_id_basic_info.get('$ticker'):
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['ticker_candidates'] = atomical_id_basic_info.get('$ticker_candidates')
                        return_struct['atomicals'][atomical_id_ref]['request_ticker_status'] =  atomical_id_basic_info.get('$request_ticker_status')
                        return_struct['atomicals'][atomical_id_ref]['request_ticker'] = atomical_id_basic_info.get('$request_ticker')
                        return_struct['atomicals'][atomical_id_ref]['ticker'] = atomical_id_basic_info.get('$ticker')
                    elif atomical_id_basic_info.get('$container'):
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['request_container_status'] = atomical_id_basic_info.get('$request_container_status')
                        return_struct['atomicals'][atomical_id_ref]['container'] = atomical_id_basic_info.get('$container')
                        return_struct['atomicals'][atomical_id_ref]['request_container'] = atomical_id_basic_info.get('$request_container')
                    # Label them as candidates if they were candidates
                    elif atomical_id_basic_info.get('subtype') == 'request_realm':
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['request_realm_status'] = atomical_id_basic_info.get('$request_realm_status')
                        return_struct['atomicals'][atomical_id_ref]['request_realm'] = atomical_id_basic_info.get('$request_realm')
                        return_struct['atomicals'][atomical_id_ref]['realm_candidates'] = atomical_id_basic_info.get('$realm_candidates')
                    elif atomical_id_basic_info.get('subtype') == 'request_subrealm':
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['subrealm_candidates'] = atomical_id_basic_info.get('$subrealm_candidates')
                        return_struct['atomicals'][atomical_id_ref]['request_subrealm_status'] = atomical_id_basic_info.get('$request_subrealm_status')
                        return_struct['atomicals'][atomical_id_ref]['request_full_realm_name'] = atomical_id_basic_info.get('$request_full_realm_name')
                        return_struct['atomicals'][atomical_id_ref]['request_subrealm'] = atomical_id_basic_info.get('$request_subrealm')
                        return_struct['atomicals'][atomical_id_ref]['parent_realm'] = atomical_id_basic_info.get('$parent_realm')
                    elif atomical_id_basic_info.get('subtype') == 'request_dmitem':
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['dmitem_candidates'] = atomical_id_basic_info.get('$dmitem_candidates')
                        return_struct['atomicals'][atomical_id_ref]['request_dmitem_status'] = atomical_id_basic_info.get('$request_dmitem_status')
                        return_struct['atomicals'][atomical_id_ref]['request_dmitem'] = atomical_id_basic_info.get('$request_dmitem')
                        return_struct['atomicals'][atomical_id_ref]['parent_container'] = atomical_id_basic_info.get('$parent_container')
                    elif atomical_id_basic_info.get('subtype') == 'request_container':
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['container_candidates'] = atomical_id_basic_info.get('$container_candidates')
                        return_struct['atomicals'][atomical_id_ref]['request_container_status'] = atomical_id_basic_info.get('$request_container_status')
                        return_struct['atomicals'][atomical_id_ref]['request_container'] = atomical_id_basic_info.get('$request_container')
                    elif atomical_id_basic_info.get('$request_ticker_status'):
                        return_struct['atomicals'][atomical_id_ref]['subtype'] = atomical_id_basic_info.get('subtype')
                        return_struct['atomicals'][atomical_id_ref]['ticker_candidates'] = atomical_id_basic_info.get('$ticker_candidates')
                        return_struct['atomicals'][atomical_id_ref]['request_ticker_status'] =  atomical_id_basic_info.get('$request_ticker_status')
                        return_struct['atomicals'][atomical_id_ref]['request_ticker'] = atomical_id_basic_info.get('$request_ticker')

                if returned_utxo['height'] <= 0:
                    return_struct['atomicals'][atomical_id_ref]['unconfirmed'] += returned_utxo['value']
                else:
                    return_struct['atomicals'][atomical_id_ref]['confirmed'] += returned_utxo['value']

        return return_struct

    async def atomicals_get_tx(self, txids):
        return await self.atomical_get_tx(txids)

    async def scripthash_get_history(self, scripthash):
        '''Return the confirmed and unconfirmed history of a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def scripthash_get_mempool(self, scripthash):
        '''Return the mempool transactions touching a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.unconfirmed_history(hashX)

    async def scripthash_listunspent(self, scripthash):
        '''Return the list of UTXOs of a scripthash.'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_listunspent(hashX)

    async def scripthash_subscribe(self, scripthash):
        '''Subscribe to a script hash.

        scripthash: the SHA256 hash of the script to subscribe to'''
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)

    async def scripthash_unsubscribe(self, scripthash):
        '''Unsubscribe from a script hash.'''
        self.bump_cost(0.1)
        hashX = scripthash_to_hashX(scripthash)
        return self.unsubscribe_hashX(hashX) is not None

    async def _merkle_proof(self, cp_height, height):
        max_height = self.db.db_height
        if not height <= cp_height <= max_height:
            raise RPCError(BAD_REQUEST,
                           f'require header height {height:,d} <= '
                           f'cp_height {cp_height:,d} <= '
                           f'chain height {max_height:,d}')
        branch, root = await self.db.header_branch_and_root(cp_height + 1,
                                                            height)
        return {
            'branch': [hash_to_hex_str(elt) for elt in branch],
            'root': hash_to_hex_str(root),
        }

    async def block_header(self, height, cp_height=0):
        '''Return a raw block header as a hexadecimal string, or as a
        dictionary with a merkle proof.'''
        height = non_negative_integer(height)
        cp_height = non_negative_integer(cp_height)
        raw_header_hex = (await self.session_mgr.raw_header(height)).hex()
        self.bump_cost(1.25 - (cp_height == 0))
        if cp_height == 0:
            return raw_header_hex
        result = {'header': raw_header_hex}
        result.update(await self._merkle_proof(cp_height, height))
        return result

    async def block_headers(self, start_height, count, cp_height=0):
        '''Return count concatenated block headers as hex for the main chain;
        starting at start_height.

        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        '''
        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)
        cp_height = non_negative_integer(cp_height)
        cost = count / 50

        max_size = self.MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.db.read_headers(start_height, count)
        result = {'hex': headers.hex(), 'count': count, 'max': max_size}
        if count and cp_height:
            cost += 1.0
            last_height = start_height + count - 1
            result.update(await self._merkle_proof(cp_height, last_height))
        self.bump_cost(cost)
        return result

    def is_tor(self):
        '''Try to detect if the connection is to a tor hidden service we are
        running.'''
        proxy_address = self.peer_mgr.proxy_address()
        if not proxy_address:
            return False
        remote_addr = self.remote_address()
        if not remote_addr:
            return False
        return remote_addr.host == proxy_address.host

    async def replaced_banner(self, banner):
        network_info = await self.daemon_request('getnetworkinfo')
        ni_version = network_info['version']
        major, minor = divmod(ni_version, 1000000)
        minor, revision = divmod(minor, 10000)
        revision //= 100
        daemon_version = f'{major:d}.{minor:d}.{revision:d}'
        for pair in [
                ('$SERVER_VERSION', electrumx.version_short),
                ('$SERVER_SUBVERSION', electrumx.version),
                ('$DAEMON_VERSION', daemon_version),
                ('$DAEMON_SUBVERSION', network_info['subversion']),
                ('$DONATION_ADDRESS', self.env.donation_address),
        ]:
            banner = banner.replace(*pair)
        return banner

    async def donation_address(self):
        '''Return the donation address as a string, empty if there is none.'''
        self.bump_cost(0.1)
        return self.env.donation_address

    async def banner(self):
        '''Return the server banner text.'''
        banner = f'You are connected to an {electrumx.version} server.'
        self.bump_cost(0.5)

        if self.is_tor():
            banner_file = self.env.tor_banner_file
        else:
            banner_file = self.env.banner_file
        if banner_file:
            try:
                with codecs.open(banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except (OSError, UnicodeDecodeError) as e:
                self.logger.error(f'reading banner file {banner_file}: {e!r}')
            else:
                banner = await self.replaced_banner(banner)

        return banner

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        self.bump_cost(1.0)
        return await self.daemon_request('relayfee')

    async def estimatefee(self, number, mode=None):
        '''The estimated transaction fee per kilobyte to be paid for a
        transaction to be included within a certain number of blocks.

        number: the number of blocks
        mode: CONSERVATIVE or ECONOMICAL estimation mode
        '''
        number = non_negative_integer(number)
        # use whitelist for mode, otherwise it would be easy to force a cache miss:
        if mode not in self.coin.ESTIMATEFEE_MODES:
            raise RPCError(BAD_REQUEST, f'unknown estimatefee mode: {mode}')
        self.bump_cost(0.1)

        number = self.coin.bucket_estimatefee_block_target(number)
        cache = self.session_mgr.estimatefee_cache

        cache_item = cache.get((number, mode))
        if cache_item is not None:
            blockhash, feerate, lock = cache_item
            if blockhash and blockhash == self.session_mgr.bp.tip:
                return feerate
        else:
            # create lock now, store it, and only then await on it
            lock = asyncio.Lock()
            cache[(number, mode)] = (None, None, lock)
        async with lock:
            cache_item = cache.get((number, mode))
            if cache_item is not None:
                blockhash, feerate, lock = cache_item
                if blockhash == self.session_mgr.bp.tip:
                    return feerate
            self.bump_cost(2.0)  # cache miss incurs extra cost
            blockhash = self.session_mgr.bp.tip
            if mode:
                feerate = await self.daemon_request('estimatefee', number, mode)
            else:
                feerate = await self.daemon_request('estimatefee', number)
            assert feerate is not None
            assert blockhash is not None
            cache[(number, mode)] = (blockhash, feerate, lock)
            return feerate

    async def ping(self):
        '''Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        '''
        self.bump_cost(0.1)
        return None

    async def server_version(self, client_name='', protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        self.bump_cost(0.5)
        if self.sv_seen:
            raise RPCError(BAD_REQUEST, f'server.version already sent')
        self.sv_seen = True

        if client_name:
            client_name = str(client_name)
            if self.env.drop_client is not None and \
                    self.env.drop_client.match(client_name):
                raise ReplyAndDisconnect(RPCError(
                    BAD_REQUEST, f'unsupported client: {client_name}'))
            self.client = client_name[:17]

        # Find the highest common protocol version.  Disconnect if
        # that protocol version in unsupported.
        ptuple, client_min = util.protocol_version(
            protocol_version, self.PROTOCOL_MIN, self.PROTOCOL_MAX)

        await self.crash_old_client(ptuple, self.env.coin.CRASH_CLIENT_VER)

        if ptuple is None:
            if client_min > self.PROTOCOL_MIN:
                self.logger.info(f'client requested future protocol version '
                                 f'{util.version_string(client_min)} '
                                 f'- is your software out of date?')
            raise ReplyAndDisconnect(RPCError(
                BAD_REQUEST, f'unsupported protocol version: {protocol_version}'))
        self.set_request_handlers(ptuple)

        return electrumx.version, self.protocol_version_string()

    async def crash_old_client(self, ptuple, crash_client_ver):
        if crash_client_ver:
            client_ver = util.protocol_tuple(self.client)
            is_old_protocol = ptuple is None or ptuple <= (1, 2)
            is_old_client = client_ver != (0,) and client_ver <= crash_client_ver
            if is_old_protocol and is_old_client:
                self.logger.info(f'attempting to crash old client with version {self.client}')
                # this can crash electrum client 2.6 <= v < 3.1.2
                await self.send_notification('blockchain.relayfee', ())
                # this can crash electrum client (v < 2.8.2) UNION (3.0.0 <= v < 3.3.0)
                await self.send_notification('blockchain.estimatefee', ())

    async def transaction_broadcast_validate(self, raw_tx):
        '''Simulate a Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string to validate for Atomicals FT rules'''
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        # This returns errors as JSON RPC errors, as is natural
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, False)
            return hex_hash
        except AtomicalsValidationError as e:
            self.logger.info(f'error validating atomicals transaction: {e}')
            raise RPCError(ATOMICALS_INVALID_TX, 'the transaction was rejected by '
                           f'atomicals rules.\n\n{e}\n[{raw_tx}]')

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        # This returns errors as JSON RPC errors, as is natural
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, True)
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'error sending transaction: {message}')
            raise RPCError(BAD_REQUEST, 'the transaction was rejected by '
                           f'network rules.\n\n{message}\n[{raw_tx}]')
        except AtomicalsValidationError as e:
            self.logger.info(f'error validating atomicals transaction: {e}')
            raise RPCError(ATOMICALS_INVALID_TX, 'the transaction was rejected by '
                           f'atomicals rules.\n\n{e}\n[{raw_tx}]')

        else:
            self.txs_sent += 1
            client_ver = util.protocol_tuple(self.client)
            if client_ver != (0, ):
                msg = self.coin.warn_old_client_on_tx_broadcast(client_ver)
                if msg:
                    self.logger.info(f'sent tx: {hex_hash}. and warned user to upgrade their '
                                     f'client from {self.client}')
                    return msg

            self.logger.info(f'sent tx: {hex_hash}')
            return hex_hash

    async def transaction_broadcast_force(self, raw_tx):
        '''Broadcast a raw transaction to the network. Force even if invalid FT transfer
        raw_tx: the raw transaction as a hexadecimal string'''
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        # This returns errors as JSON RPC errors, as is natural
        try:
            hex_hash = await self.session_mgr.broadcast_transaction(raw_tx)
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'error sending transaction: {message}')
            raise RPCError(BAD_REQUEST, 'the transaction was rejected by '
                           f'network rules.\n\n{message}\n[{raw_tx}]')
        else:
            self.txs_sent += 1
            client_ver = util.protocol_tuple(self.client)
            if client_ver != (0, ):
                msg = self.coin.warn_old_client_on_tx_broadcast(client_ver)
                if msg:
                    self.logger.info(f'sent tx: {hex_hash}. and warned user to upgrade their '
                                     f'client from {self.client}')
                    return msg

            self.logger.info(f'sent tx: {hex_hash}')
            return hex_hash


    async def transaction_get(self, tx_hash, verbose=False):
        '''Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        '''
        assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, '"verbose" must be a boolean')

        self.bump_cost(1.0)
        return await self.daemon_request('getrawtransaction', tx_hash, verbose)

    async def transaction_merkle(self, tx_hash, height):
        '''Return the merkle branch to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        '''
        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos, cost = await self.session_mgr.merkle_branch_for_tx_hash(
            height, tx_hash)
        self.bump_cost(cost)

        return {"block_height": height, "merkle": branch, "pos": tx_pos}

    async def transaction_id_from_pos(self, height, tx_pos, merkle=False):
        '''Return the txid and optionally a merkle proof, given
        a block height and position in the block.
        '''
        tx_pos = non_negative_integer(tx_pos)
        height = non_negative_integer(height)
        if merkle not in (True, False):
            raise RPCError(BAD_REQUEST, '"merkle" must be a boolean')

        if merkle:
            branch, tx_hash, cost = await self.session_mgr.merkle_branch_for_tx_pos(
                height, tx_pos)
            self.bump_cost(cost)
            return {"tx_hash": tx_hash, "merkle": branch}
        else:
            tx_hashes, cost = await self.session_mgr.tx_hashes_at_blockheight(height)
            try:
                tx_hash = tx_hashes[tx_pos]
            except IndexError:
                raise RPCError(BAD_REQUEST,
                               f'no tx at position {tx_pos:,d} in block at height {height:,d}')
            self.bump_cost(cost)
            return hash_to_hex_str(tx_hash)

    async def compact_fee_histogram(self):
        self.bump_cost(1.0)
        return await self.mempool.compact_fee_histogram()

    async def get_transaction_detail(self, txid, height=None, tx_num=-1):
        tx_hash = hex_str_to_hash(txid)
        res = self.session_mgr._tx_detail_cache.get(tx_hash)
        if res:
            # txid maybe the same, this key should add height add key prefix
            self.logger.debug(f"read transation detail from cache {txid}")
            return res
        if not height:
            tx_num, height = self.db.get_tx_num_height_from_tx_hash(tx_hash)

        raw_tx = self.db.get_raw_tx_by_tx_hash(tx_hash)
        if not raw_tx:
            raw_tx = await self.daemon_request('getrawtransaction', txid, False)
            raw_tx = bytes.fromhex(raw_tx)
        tx, _tx_hash = self.coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
        assert tx_hash == _tx_hash

        operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
        atomicals_spent_at_inputs = self.session_mgr.bp.build_atomicals_spent_at_inputs_for_validation_only(tx)
        atomicals_receive_at_outputs = self.session_mgr.bp.build_atomicals_receive_at_ouutput_for_validation_only(tx, tx_hash)
        blueprint_builder = AtomicalsTransferBlueprintBuilder(self.logger, atomicals_spent_at_inputs, operation_found_at_inputs, tx_hash, tx, self.session_mgr.bp.get_atomicals_id_mint_info, True)
        is_burned = blueprint_builder.are_fts_burned
        is_cleanly_assigned = blueprint_builder.cleanly_assigned
        # format burned_fts
        raw_burned_fts = blueprint_builder.get_fts_burned()
        burned_fts = {}
        for ft_key, ft_value in raw_burned_fts.items():
            burned_fts[location_id_bytes_to_compact(ft_key)] = ft_value

        res = {
            "op": "",
            "txid": txid,
            "height": height,
            "tx_num": tx_num,
            "info": {},
            "transfers": {
                "inputs": {},
                "outputs": {},
                "is_burned": is_burned,
                "burned_fts": burned_fts,
                "is_cleanly_assigned": is_cleanly_assigned
            }
        }
        if operation_found_at_inputs:
            res["info"]["payload"] = operation_found_at_inputs.get("payload", {})
        if blueprint_builder.is_mint and operation_found_at_inputs and operation_found_at_inputs["op"] in ["dmt", "ft"]:
            if operation_found_at_inputs["op"] == "dmt":
                res["op"] = "mint-dft"
            if operation_found_at_inputs["op"] == "ft":
                res["op"] = "mint-ft"
            expected_output_index = 0
            txout = tx.outputs[expected_output_index]
            location = tx_hash + util.pack_le_uint32(expected_output_index)
            # if save into the db, it means mint success
            has_atomicals = self.db.get_atomicals_by_location_long_form(location)
            if len(has_atomicals):
                ticker_name = operation_found_at_inputs.get("payload", {}).get("args", {}).get("mint_ticker", "")
                status, candidate_atomical_id, _ = self.session_mgr.bp.get_effective_ticker(ticker_name, self.session_mgr.bp.height)
                if status:
                    atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
                    res["info"] = {
                        "atomical_id": atomical_id,
                        "location_id": location_id_bytes_to_compact(location),
                        "payload": operation_found_at_inputs.get("payload"),
                        "outputs": {
                            expected_output_index: [{
                                "address": get_address_from_output_script(txout.pk_script),
                                "atomical_id": atomical_id,
                                "type": "FT",
                                "index": expected_output_index,
                                "value": txout.value
                            }]
                        }
                    }
            else:
                res["op"] = f"{res['op']}-failed"
        elif operation_found_at_inputs and operation_found_at_inputs and operation_found_at_inputs["op"] == "nft":
            mint_info = operation_found_at_inputs.get("payload", {}).get("args", {})
            if mint_info.get('request_realm'):
                res["op"] = "mint-nft-realm"
            elif mint_info.get('request_subrealm'):
                res["op"] = "mint-nft-subrealm"
            elif mint_info.get('request_container'):
                res["op"] = "mint-nft-container"
            elif mint_info.get('request_dmitem'):
                res["op"] = "mint-nft-dmitem"
            else:
                res["op"] = "mint-nft"
            if atomicals_receive_at_outputs:
                expected_output_index = 0
                location = tx_hash + util.pack_le_uint32(expected_output_index)
                txout = tx.outputs[expected_output_index]
                atomical_id = location_id_bytes_to_compact(atomicals_receive_at_outputs[expected_output_index][-1]["atomical_id"])
                res["info"] = {
                    "atomical_id": atomical_id,
                    "location_id": location_id_bytes_to_compact(location),
                    "payload": operation_found_at_inputs.get("payload"),
                    "outputs": {
                        expected_output_index: [{
                            "address": get_address_from_output_script(txout.pk_script),
                            "atomical_id": atomical_id,
                            "type": "NFT",
                            "index": expected_output_index,
                            "value": txout.value
                        }]
                    }
                }
            else:
                res["op"] = f"{res['op']}-failed"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "dft":
            res["op"] = "dft"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "sl":
            res["op"] = "seal"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "x":
            res["op"] = "splat"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "y":
            res["op"] = "split"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "evt":
            res["op"] = "evt"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "mod":
            res["op"] = "mod"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "dat":
            res["op"] = "dat"
        # no operation_found_at_inputs, it will be transfer.
        if blueprint_builder.ft_atomicals and atomicals_spent_at_inputs:
            if not operation_found_at_inputs:
                res["op"] = "transfer"
            for atomical_id, input_ft in blueprint_builder.ft_atomicals.items():
                compact_atomical_id = location_id_bytes_to_compact(atomical_id)
                for i in input_ft.input_indexes:
                    prev_txid = hash_to_hex_str(tx.inputs[i.txin_index].prev_hash)
                    prev_raw_tx = self.db.get_raw_tx_by_tx_hash(hex_str_to_hash(prev_txid))
                    if not prev_raw_tx:
                        prev_raw_tx = await self.daemon_request('getrawtransaction', prev_txid, False)
                        prev_raw_tx = bytes.fromhex(prev_raw_tx)
                        self.session_mgr.bp.general_data_cache[b'rtx' + hex_str_to_hash(prev_txid)] = prev_raw_tx
                    prev_tx, _ = self.coin.DESERIALIZER(prev_raw_tx, 0).read_tx_and_hash()
                    ft_data = {
                        "address": get_address_from_output_script(prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].pk_script),
                        "atomical_id": compact_atomical_id,
                        "type": "FT",
                        "index": i.txin_index,
                        "value": prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].value
                    }
                    if i.txin_index not in res["transfers"]["inputs"]:
                        res["transfers"]["inputs"][i.txin_index] = [ft_data]
                    else:
                        res["transfers"]["inputs"][i.txin_index].append(ft_data)
            for k, v in blueprint_builder.ft_output_blueprint.outputs.items():
                for atomical_id, output_ft in v['atomicals'].items():
                    compact_atomical_id = location_id_bytes_to_compact(atomical_id)
                    ft_data = {
                        "address": get_address_from_output_script(tx.outputs[k].pk_script),
                        "atomical_id": compact_atomical_id,
                        "type": "FT",
                        "index": k,
                        "value": output_ft.satvalue
                    }
                    if k not in res["transfers"]["outputs"]:
                        res["transfers"]["outputs"][k] = [ft_data]
                    else:
                        res["transfers"]["outputs"][k].append(ft_data)
        if blueprint_builder.nft_atomicals and atomicals_spent_at_inputs:
            if not operation_found_at_inputs:
                res["op"] = "transfer"
            for atomical_id, input_nft in blueprint_builder.nft_atomicals.items():
                compact_atomical_id = location_id_bytes_to_compact(atomical_id)
                for i in input_nft.input_indexes:
                    prev_txid = hash_to_hex_str(tx.inputs[i.txin_index].prev_hash)
                    prev_raw_tx = self.db.get_raw_tx_by_tx_hash(hex_str_to_hash(prev_txid))
                    if not prev_raw_tx:
                        prev_raw_tx = await self.daemon_request('getrawtransaction', prev_txid, False)
                        prev_raw_tx = bytes.fromhex(prev_raw_tx)
                        self.session_mgr.bp.general_data_cache[b'rtx' + hex_str_to_hash(prev_txid)] = prev_raw_tx
                    prev_tx, _ = self.coin.DESERIALIZER(prev_raw_tx, 0).read_tx_and_hash()
                    nft_data = {
                        "address": get_address_from_output_script(prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].pk_script),
                        "atomical_id": compact_atomical_id,
                        "type": "NFT",
                        "index": i.txin_index,
                        "value": prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].value
                    }
                    if i.txin_index not in res["transfers"]["inputs"]:
                        res["transfers"]["inputs"][i.txin_index] = [nft_data]
                    else:
                        res["transfers"]["inputs"][i.txin_index].append(nft_data)
            for k, v in blueprint_builder.nft_output_blueprint.outputs.items():
                for atomical_id, output_nft in v['atomicals'].items():
                    compact_atomical_id = location_id_bytes_to_compact(atomical_id)
                    nft_data = {
                        "address": get_address_from_output_script(tx.outputs[k].pk_script),
                        "atomical_id": compact_atomical_id,
                        "type": output_nft.type,
                        "index": k,
                        "value": output_nft.total_satsvalue
                    }
                    if k not in res["transfers"]["outputs"]:
                        res["transfers"]["outputs"][k] = [nft_data]
                    else:
                        res["transfers"]["outputs"][k].append(nft_data)

        atomical_id_for_payment, payment_marker_idx, entity_type = AtomicalsTransferBlueprintBuilder.get_atomical_id_for_payment_marker_if_found(tx)
        if atomical_id_for_payment:
            res["info"]["payment"] = {
                "atomical_id": location_id_bytes_to_compact(atomical_id_for_payment),
                "payment_marker_idx": payment_marker_idx
            }
            if entity_type == 'subrealm':
                res["op"] = "payment-subrealm"
            if entity_type == 'dmitem':
                res["op"] = "payment-dmitem"

        if res.get("op"):
            self.session_mgr._tx_detail_cache[tx_hash] = res

        # Recursively encode the result.
        return auto_encode_bytes_elements(res)

    async def atomicals_transaction(self, txid):
        return await self.get_transaction_detail(txid)

    async def get_transaction_detail_by_height(self, height, limit, offset, op_type, reverse=True):
        res = []
        txs_list = []
        txs = self.db.get_atomicals_block_txs(height)
        for tx in txs:
            # get operation by db method
            tx_num, _ = self.db.get_tx_num_height_from_tx_hash(hex_str_to_hash(tx))
            txs_list.append({
                "tx_num": tx_num,
                "tx_hash": tx,
                "height": height
            })

        txs_list.sort(key=lambda x: x['tx_num'], reverse=reverse)
        for tx in txs_list:
            data = await self.get_transaction_detail(tx["tx_hash"], height, tx["tx_num"])
            if (op_type and op_type == data["op"]) or (not op_type and data["op"]):
                res.append(data)
        total = len(res)
        return res[offset:offset+limit], total

    # get the whole transaction by block height
    # return transaction detail
    async def transaction_by_height(self, height, limit=10, offset=0, op_type=None, reverse=True):
        res, total = await self.get_transaction_detail_by_height(height, limit, offset, op_type, reverse)
        return {"result": res, "total": total, "limit": limit, "offset": offset}

    # get transaction by atomical id
    async def transaction_by_atomical_id(self, compact_atomical_id_or_atomical_number, limit=10, offset=0, op_type=None, reverse=True):
        res = []
        compact_atomical_id = compact_atomical_id_or_atomical_number
        if isinstance(compact_atomical_id_or_atomical_number, int) != True and is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            compact_atomical_id = location_id_bytes_to_compact(self.db.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number))
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        hashX = double_sha256(atomical_id)

        res = []
        if op_type:
            op = self.session_mgr.bp.op_list.get(op_type, None)
            history_data, total = await self.session_mgr.get_history_op(hashX, limit, offset, op, reverse)
        else:
            history_data, total = await self.session_mgr.get_history_op(hashX, limit, offset, None, reverse)
        for history in history_data:
            tx_hash, tx_height = self.db.fs_tx_hash(history["tx_num"])
            data = await self.get_transaction_detail(hash_to_hex_str(tx_hash), tx_height, history["tx_num"])
            if data and data["op"]:
                if (op_type and data["op"] == op_type) or not op_type:
                    res.append(data)
        return {"result": res, "total": total, "limit": limit, "offset": offset}

    # get transaction by scripthash
    async def transaction_by_scripthash(self, scripthash, limit=10, offset=0, op_type=None, reverse=True):
        hashX = scripthash_to_hashX(scripthash)
        res = []
        if op_type:
            op = self.session_mgr.bp.op_list.get(op_type, None)
            history_data, total = await self.session_mgr.get_history_op(hashX, limit, offset, op, reverse)
        else:
            history_data, total = await self.session_mgr.get_history_op(hashX, limit, offset, None, reverse)

        for history in history_data:
            tx_hash, tx_height = self.db.fs_tx_hash(history["tx_num"])
            data = await self.get_transaction_detail(hash_to_hex_str(tx_hash), tx_height, history["tx_num"])
            if data and data["op"]:
                if data["op"] and (data["op"] == op_type or not op_type):
                    res.append(data)
        return {"result": res, "total": total, "limit": limit, "offset": offset}

    def set_request_handlers(self, ptuple):
        self.protocol_tuple = ptuple
        handlers = {
            'blockchain.block.header': self.block_header,
            'blockchain.block.headers': self.block_headers,
            'blockchain.estimatefee': self.estimatefee,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.relayfee': self.relayfee,
            'blockchain.scripthash.get_balance': self.scripthash_get_balance,
            'blockchain.scripthash.get_history': self.scripthash_get_history,
            'blockchain.scripthash.get_mempool': self.scripthash_get_mempool,
            'blockchain.scripthash.listunspent': self.scripthash_listunspent,
            'blockchain.scripthash.subscribe': self.scripthash_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
            'blockchain.transaction.broadcast_force': self.transaction_broadcast_force,
            'blockchain.transaction.get': self.transaction_get,
            'blockchain.transaction.get_merkle': self.transaction_merkle,
            'blockchain.transaction.id_from_pos': self.transaction_id_from_pos,
            'mempool.get_fee_histogram': self.compact_fee_histogram,
            'server.add_peer': self.add_peer,
            'server.banner': self.banner,
            'server.donation_address': self.donation_address,
            'server.features': self.server_features_async,
            'server.peers.subscribe': self.peers_subscribe,
            'server.ping': self.ping,
            'server.version': self.server_version,
            # The Atomicals era has begun #
            'blockchain.atomicals.validate': self.transaction_broadcast_validate,
            'blockchain.atomicals.get_ft_balances_scripthash': self.atomicals_get_ft_balances,
            'blockchain.atomicals.get_nft_balances_scripthash': self.atomicals_get_nft_balances,
            'blockchain.atomicals.listscripthash': self.atomicals_listscripthash,
            'blockchain.atomicals.list': self.atomicals_list,
            'blockchain.atomicals.get_numbers': self.atomicals_num_to_id,
            'blockchain.atomicals.get_block_hash': self.atomicals_block_hash,
            'blockchain.atomicals.get_block_txs': self.atomicals_block_txs,
            'blockchain.atomicals.dump': self.atomicals_dump,
            'blockchain.atomicals.at_location': self.atomicals_at_location,
            'blockchain.atomicals.get_location': self.atomicals_get_location,
            'blockchain.atomicals.get': self.atomicals_get,
            'blockchain.atomicals.get_global': self.atomicals_get_global,
            'blockchain.atomicals.get_state': self.atomical_get_state,
            'blockchain.atomicals.get_state_history': self.atomical_get_state_history,
            'blockchain.atomicals.get_events': self.atomical_get_events,
            'blockchain.atomicals.get_tx_history': self.atomicals_get_tx_history,
            'blockchain.atomicals.get_realm_info': self.atomicals_get_realm_info,
            'blockchain.atomicals.get_by_realm': self.atomicals_get_by_realm,
            'blockchain.atomicals.get_by_subrealm': self.atomicals_get_by_subrealm,
            'blockchain.atomicals.get_by_dmitem': self.atomicals_get_by_dmitem,
            'blockchain.atomicals.get_by_ticker': self.atomicals_get_by_ticker,
            'blockchain.atomicals.get_by_container': self.atomicals_get_by_container,
            'blockchain.atomicals.get_by_container_item': self.atomicals_get_by_container_item,
            'blockchain.atomicals.get_by_container_item_validate': self.atomicals_get_by_container_item_validation,
            'blockchain.atomicals.get_container_items': self.atomicals_get_container_items,
            'blockchain.atomicals.get_ft_info': self.atomicals_get_ft_info,
            'blockchain.atomicals.get_dft_mints': self.atomicals_get_dft_mints,
            'blockchain.atomicals.find_tickers': self.atomicals_search_tickers,
            'blockchain.atomicals.find_realms': self.atomicals_search_realms,
            'blockchain.atomicals.find_subrealms': self.atomicals_search_subrealms,
            'blockchain.atomicals.find_containers': self.atomicals_search_containers,
            'blockchain.atomicals.get_holders': self.atomicals_get_holders,
            'blockchain.atomicals.transaction': self.atomicals_transaction,
            'blockchain.atomicals.transaction_by_height': self.transaction_by_height,
            'blockchain.atomicals.transaction_by_atomical_id': self.transaction_by_atomical_id,
            'blockchain.atomicals.transaction_by_scripthash': self.transaction_by_scripthash,
        }
        if ptuple >= (1, 4, 2):
            handlers['blockchain.scripthash.unsubscribe'] = self.scripthash_unsubscribe
        self.request_handlers = handlers

class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    processing_timeout = 10**9  # disable timeouts

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.connection.max_response_size = 0

    def protocol_version_string(self):
        return 'RPC'


class DashElectrumX(ElectrumX):
    '''A TCP server that handles incoming Electrum Dash connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mns = set()
        self.mn_cache_height = 0
        self.mn_cache = []

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update({
            'masternode.announce.broadcast':
            self.masternode_announce_broadcast,
            'masternode.subscribe': self.masternode_subscribe,
            'masternode.list': self.masternode_list,
            'protx.diff': self.protx_diff,
            'protx.info': self.protx_info,
        })

    async def _notify_inner(self, touched, height_changed):
        '''Notify the client about changes in masternode list.'''
        await super()._notify_inner(touched, height_changed)
        for mn in self.mns.copy():
            status = await self.daemon_request('masternode_list',
                                               ('status', mn))
            await self.send_notification('masternode.subscribe',
                                         (mn, status.get(mn)))

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.

        signmnb: signed masternode broadcast message.'''
        try:
            return await self.daemon_request('masternode_broadcast',
                                             ('relay', signmnb))
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'masternode_broadcast: {message}')
            raise RPCError(BAD_REQUEST, 'the masternode broadcast was '
                           f'rejected.\n\n{message}\n[{signmnb}]')

    async def masternode_subscribe(self, collateral):
        '''Returns the status of masternode.

        collateral: masternode collateral.
        '''
        result = await self.daemon_request('masternode_list',
                                           ('status', collateral))
        if result is not None:
            self.mns.add(collateral)
            return result.get(collateral)
        return None

    async def masternode_list(self, payees):
        '''
        Returns the list of masternodes.

        payees: a list of masternode payee addresses.
        '''
        if not isinstance(payees, list):
            raise RPCError(BAD_REQUEST, 'expected a list of payees')

        def get_masternode_payment_queue(mns):
            '''Returns the calculated position in the payment queue for all the
            valid masterernodes in the given mns list.

            mns: a list of masternodes information.
            '''
            now = int(datetime.datetime.utcnow().strftime("%s"))
            mn_queue = []

            # Only ENABLED masternodes are considered for the list.
            for line in mns:
                mnstat = mns[line].split()
                if mnstat[0] == 'ENABLED':
                    # if last paid time == 0
                    if int(mnstat[5]) == 0:
                        # use active seconds
                        mnstat.append(int(mnstat[4]))
                    else:
                        # now minus last paid
                        delta = now - int(mnstat[5])
                        # if > active seconds, use active seconds
                        if delta >= int(mnstat[4]):
                            mnstat.append(int(mnstat[4]))
                        # use active seconds
                        else:
                            mnstat.append(delta)
                    mn_queue.append(mnstat)
            mn_queue = sorted(mn_queue, key=lambda x: x[8], reverse=True)
            return mn_queue

        def get_payment_position(payment_queue, address):
            '''
            Returns the position of the payment list for the given address.

            payment_queue: position in the payment queue for the masternode.
            address: masternode payee address.
            '''
            position = -1
            for pos, mn in enumerate(payment_queue, start=1):
                if mn[2] == address:
                    position = pos
                    break
            return position

        # Accordingly with the masternode payment queue, a custom list
        # with the masternode information including the payment
        # position is returned.
        cache = self.session_mgr.mn_cache
        if not cache or self.session_mgr.mn_cache_height != self.db.db_height:
            full_mn_list = await self.daemon_request('masternode_list',
                                                     ('full',))
            mn_payment_queue = get_masternode_payment_queue(full_mn_list)
            mn_payment_count = len(mn_payment_queue)
            mn_list = []
            for key, value in full_mn_list.items():
                mn_data = value.split()
                mn_info = {
                    'vin': key,
                    'status': mn_data[0],
                    'protocol': mn_data[1],
                    'payee': mn_data[2],
                    'lastseen': mn_data[3],
                    'activeseconds': mn_data[4],
                    'lastpaidtime': mn_data[5],
                    'lastpaidblock': mn_data[6],
                    'ip': mn_data[7]
                }
                mn_info['paymentposition'] = get_payment_position(
                    mn_payment_queue, mn_info['payee']
                )
                mn_info['inselection'] = (
                    mn_info['paymentposition'] < mn_payment_count // 10
                )
                hashX = self.coin.address_to_hashX(mn_info['payee'])
                balance = await self.get_balance(hashX)
                mn_info['balance'] = (sum(balance.values())
                                      / self.coin.VALUE_PER_COIN)
                mn_list.append(mn_info)
            cache.clear()
            cache.extend(mn_list)
            self.session_mgr.mn_cache_height = self.db.db_height

        # If payees is an empty list the whole masternode list is returned
        if payees:
            return [mn for mn in cache if mn['payee'] in payees]
        else:
            return cache

    async def protx_diff(self, base_height, height):
        '''
        Calculates a diff between two deterministic masternode lists.
        The result also contains proof data.

        base_height: The starting block height (starting from 1).
        height: The ending block height.
        '''
        if not isinstance(base_height, int) or not isinstance(height, int):
            raise RPCError(BAD_REQUEST, 'expected a int block heights')

        max_height = self.db.db_height
        if (not 1 <= base_height <= max_height or
                not base_height <= height <= max_height):
            raise RPCError(BAD_REQUEST,
                           f'require 1 <= base_height {base_height:,d} <= '
                           f'height {height:,d} <= '
                           f'chain height {max_height:,d}')

        return await self.daemon_request('protx',
                                         ('diff', base_height, height))

    async def protx_info(self, protx_hash):
        '''
        Returns detailed information about a deterministic masternode.

        protx_hash: The hash of the initial ProRegTx
        '''
        if not isinstance(protx_hash, str):
            raise RPCError(BAD_REQUEST, 'expected protx hash string')

        res = await self.daemon_request('protx', ('info', protx_hash))
        if 'wallet' in res:
            del res['wallet']
        return res


class SmartCashElectrumX(DashElectrumX):
    '''A TCP server that handles incoming Electrum-SMART connections.'''

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update({
            'smartrewards.current': self.smartrewards_current,
            'smartrewards.check': self.smartrewards_check
        })

    async def smartrewards_current(self):
        '''Returns the current smartrewards info.'''
        result = await self.daemon_request('smartrewards', ('current',))
        if result is not None:
            return result
        return None

    async def smartrewards_check(self, addr):
        '''
        Returns the status of an address

        addr: a single smartcash address
        '''
        result = await self.daemon_request('smartrewards', ('check', addr))
        if result is not None:
            return result
        return None


class AuxPoWElectrumX(ElectrumX):
    async def block_header(self, height, cp_height=0):
        result = await super().block_header(height, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result['header'] = self.truncate_auxpow(result['header'], height)
        return result

    async def block_headers(self, start_height, count, cp_height=0):
        result = await super().block_headers(start_height, count, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result['hex'] = self.truncate_auxpow(result['hex'], start_height)
        return result

    def truncate_auxpow(self, headers_full_hex, start_height):
        height = start_height
        headers_full = util.hex_to_bytes(headers_full_hex)
        cursor = 0
        headers = bytearray()

        while cursor < len(headers_full):
            headers += headers_full[cursor:cursor+self.coin.TRUNCATED_HEADER_SIZE]
            cursor += self.db.dynamic_header_len(height)
            height += 1

        return headers.hex()


class NameIndexElectrumX(ElectrumX):
    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)

        if ptuple >= (1, 4, 3):
            self.request_handlers['blockchain.name.get_value_proof'] = self.name_get_value_proof

    async def name_get_value_proof(self, scripthash, cp_height=0):
        history = await self.scripthash_get_history(scripthash)

        trimmed_history = []
        prev_height = None

        for update in history[::-1]:
            txid = update['tx_hash']
            height = update['height']

            if (self.coin.NAME_EXPIRATION is not None
                    and prev_height is not None
                    and height < prev_height - self.coin.NAME_EXPIRATION):
                break

            tx = await(self.transaction_get(txid))
            update['tx'] = tx
            del update['tx_hash']

            tx_merkle = await self.transaction_merkle(txid, height)
            del tx_merkle['block_height']
            update['tx_merkle'] = tx_merkle

            if height <= cp_height:
                header = await self.block_header(height, cp_height)
                update['header'] = header

            trimmed_history.append(update)

            if height <= cp_height:
                break

            prev_height = height

        return {scripthash: trimmed_history}


class NameIndexAuxPoWElectrumX(NameIndexElectrumX, AuxPoWElectrumX):
    pass
