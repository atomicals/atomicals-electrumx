import asyncio
import math
import os
import ssl
import time
from asyncio import Event, sleep
from collections import defaultdict
from functools import partial
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING, Dict, List, Optional

import attr
import pylru
from aiohttp import web
from aiorpcx import RPCError, run_in_thread, serve_rs, serve_ws

from electrumx.lib import util
from electrumx.lib.atomicals_blueprint_builder import (
    AtomicalColoredOutput,
    AtomicalsTransferBlueprintBuilder,
    AtomicalsValidation,
    AtomicalsValidationError,
)
from electrumx.lib.hash import Base58Error, hash_to_hex_str, hex_str_to_hash
from electrumx.lib.merkle import MerkleCache
from electrumx.lib.script2addr import get_address_from_output_script
from electrumx.lib.text import sessions_lines
from electrumx.lib.util_atomicals import (
    auto_encode_bytes_elements,
    auto_encode_bytes_items,
    compact_to_location_id_bytes,
    encode_atomical_ids_hex,
    location_id_bytes_to_compact,
    parse_atomicals_operations_from_tap_leafs,
    parse_protocols_operations_from_witness_array,
)
from electrumx.server.daemon import Daemon, DaemonError
from electrumx.server.history import TXNUM_LEN
from electrumx.server.http_middleware import (
    cors_middleware,
    error_middleware,
    rate_limiter,
    request_middleware,
)
from electrumx.server.mempool import MemPool
from electrumx.server.peers import PeerManager
from electrumx.server.session import BAD_REQUEST, DAEMON_ERROR
from electrumx.server.session.http_session import HttpSession
from electrumx.server.session.rpc_session import LocalRPC
from electrumx.server.session.util import SESSION_PROTOCOL_MAX, non_negative_integer
from electrumx.version import electrumx_version

if TYPE_CHECKING:
    from electrumx.server.block_processor import BlockProcessor
    from electrumx.server.db import DB
    from electrumx.server.env import Env


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
    specials = attr.ib()  # Lower-case strings
    unknown = attr.ib()  # Strings


class SessionManager:
    """Holds global state about all sessions."""

    def __init__(
        self,
        env: "Env",
        db: "DB",
        bp: "BlockProcessor",
        daemon: "Daemon",
        mempool: "MemPool",
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
        self.servers = {}  # service->server
        self.sessions = {}  # session->iterable of its SessionGroups
        self.session_groups = {}  # group name->SessionGroup instance
        self.txs_sent = 0
        # Would use monotonic time, but aiorpcx sessions use Unix time:
        self.start_time = time.time()
        self.method_counts = defaultdict(int)
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
        self._tx_decode_cache = pylru.lrucache(1000)
        self.notified_height = None
        self.hsub_results = None
        self._task_group = util.OldTaskGroup()
        self._sslc = None
        # Event triggered when electrumx is listening for incoming requests.
        self.server_listening = Event()
        self.session_event = Event()

        # Set up the RPC request handlers
        # cmds = ('add_peer daemon_url disconnect getinfo groups log peers '
        #         'query reorg sessions stop debug_memusage_list_all_objects '
        #         'debug_memusage_get_random_backref_chain'.split())
        # LocalRPC.request_handlers = {cmd: getattr(self, 'rpc_' + cmd) for cmd in cmds}

    def _ssl_context(self):
        if self._sslc is None:
            self._sslc = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self._sslc.load_cert_chain(self.env.ssl_certfile, keyfile=self.env.ssl_keyfile)
        return self._sslc

    async def _start_servers(self, services):
        for service in services:
            kind = service.protocol.upper()
            if service.protocol == "http":
                host = None if service.host == "all_interfaces" else str(service.host)
                try:
                    app = web.Application(
                        middlewares=[
                            cors_middleware(self),
                            error_middleware(self),
                            request_middleware(self),
                        ],
                        client_max_size=self.env.session_max_size_http
                    )
                    handler = HttpSession(self, self.db, self.mempool, self.peer_mgr, kind)
                    await handler.add_endpoints(app.router, SESSION_PROTOCOL_MAX)
                    app["rate_limiter"] = rate_limiter
                    runner = web.AppRunner(app)
                    await runner.setup()
                    site = web.TCPSite(runner, host, service.port)
                    await site.start()
                except Exception as e:
                    self.logger.error(f"{kind} server failed to listen on {service.address}: {e}")
                else:
                    self.logger.info(f"{kind} server listening on {service.address}")
            else:
                if service.protocol in self.env.SSL_PROTOCOLS:
                    sslc = self._ssl_context()
                else:
                    sslc = None
                if service.protocol == "rpc":
                    session_class = LocalRPC
                else:
                    session_class = self.env.coin.SESSIONCLS
                if service.protocol in ("ws", "wss"):
                    serve = serve_ws
                else:
                    serve = serve_rs
                # FIXME: pass the service not the kind
                session_factory = partial(session_class, self, self.db, self.mempool, self.peer_mgr, kind)
                host = None if service.host == "all_interfaces" else str(service.host)
                try:
                    if service.protocol in ("ws", "wss"):
                        self.servers[service] = await serve(
                            session_factory, host, service.port, ssl=sslc, max_size=self.env.session_max_size_ws
                        )
                    else:
                        self.servers[service] = await serve(session_factory, host, service.port, ssl=sslc)
                except OSError as e:  # don't suppress CancelledError
                    self.logger.error(f"{kind} server failed to listen on {service.address}: {e}")
                else:
                    self.logger.info(f"{kind} server listening on {service.address}")

    async def _start_external_servers(self):
        """Start listening on TCP and SSL ports, but only if the respective
        port was given in the environment.
        """
        await self._start_servers(service for service in self.env.services if service.protocol != "rpc")
        self.server_listening.set()

    async def _stop_servers(self, services):
        """Stop the servers of the given protocols."""
        server_map = {service: self.servers.pop(service) for service in set(services).intersection(self.servers)}
        # Close all before waiting
        for service, server in server_map.items():
            self.logger.info(f"closing down server for {service}")
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
                self.logger.info(
                    f"maximum sessions {max_sessions:,d} "
                    f"reached, stopping new connections until "
                    f"count drops to {low_watermark:,d}"
                )
                await self._stop_servers(service for service in self.servers if service.protocol != "rpc")
                paused = True
            # Start listening for incoming connections if paused and
            # session count has fallen
            if paused and len(self.sessions) <= low_watermark:
                self.logger.info("resuming listening for incoming connections")
                await self._start_external_servers()
                paused = False

    async def _log_sessions(self):
        """Periodically log sessions."""
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
            session_ids = ", ".join(str(session.session_id) for session in sessions)
            self.logger.info(f"{reason} session ids {session_ids}")
            for session in sessions:
                await self._task_group.spawn(session.close(force_after=force_after))

    async def _clear_stale_sessions(self):
        """Cut off sessions that haven't done anything for 10 minutes."""
        while True:
            await sleep(60)
            stale_cutoff = time.time() - self.env.session_timeout
            stale_sessions = [session for session in self.sessions if session.last_recv < stale_cutoff]
            await self._disconnect_sessions(stale_sessions, "closing stale")
            del stale_sessions

    async def _handle_chain_reorgs(self):
        """Clear certain caches on chain reorgs."""
        while True:
            await self.bp.backed_up_event.wait()
            self.logger.info("reorg signalled; clearing tx_hashes and merkle caches")
            self._reorg_count += 1
            self._tx_hashes_cache.clear()
            self._merkle_cache.clear()

    async def _recalc_concurrency(self):
        """Periodically recalculate session concurrency."""
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
        """A summary of server state."""
        cache_fmt = "{:,d} lookups {:,d} hits {:,d} entries"
        sessions = self.sessions
        return {
            "coin": self.env.coin.__name__,
            "daemon": self.daemon.logged_url(),
            "daemon height": self.daemon.cached_height(),
            "db height": self.db.db_height,
            "db_flush_count": self.db.history.flush_count,
            "groups": len(self.session_groups),
            "history cache": cache_fmt.format(self._history_lookups, self._history_hits, len(self._history_cache)),
            "merkle cache": cache_fmt.format(self._merkle_lookups, self._merkle_hits, len(self._merkle_cache)),
            "pid": os.getpid(),
            "peers": self.peer_mgr.info(),
            "request counts": self.method_counts,
            "request total": sum(self.method_counts.values()),
            "sessions": {
                "count": len(sessions),
                "count with subs": sum(len(getattr(s, "hashX_subs", ())) > 0 for s in sessions),
                "errors": sum(s.errors for s in sessions),
                "logged": len([s for s in sessions if s.log_me]),
                "pending requests": sum(s.unanswered_request_count() for s in sessions),
                "subs": sum(s.sub_count() for s in sessions),
            },
            "tx hashes cache": cache_fmt.format(
                self._tx_hashes_lookups,
                self._tx_hashes_hits,
                len(self._tx_hashes_cache),
            ),
            "txs sent": self.txs_sent,
            "uptime": util.formatted_time(time.time() - self.start_time),
            "version": electrumx_version,
        }

    def _session_data(self, for_log):
        """Returned to the RPC 'sessions' call."""
        now = time.time()
        sessions = sorted(self.sessions, key=lambda s: s.start_time)
        return [
            (
                session.session_id,
                session.flags(),
                session.remote_address_string(for_log=for_log),
                session.client,
                session.protocol_version_string(),
                session.cost,
                session.extra_cost(),
                session.unanswered_request_count(),
                session.txs_sent,
                session.sub_count(),
                session.recv_count,
                session.recv_size,
                session.send_count,
                session.send_size,
                now - session.start_time,
            )
            for session in sessions
        ]

    def _group_data(self):
        """Returned to the RPC 'groups' call."""
        result = []
        for name, group in self.session_groups.items():
            sessions = group.sessions
            result.append(
                [
                    name,
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
                ]
            )
        return result

    async def _refresh_hsub_results(self, height):
        """Refresh the cached header subscription responses to be for height,
        and record that as notified_height.
        """
        # Paranoia: a reorg could race and leave db_height lower
        height = min(height, self.db.db_height)
        raw = await self.raw_header(height)
        self.hsub_results = {"hex": raw.hex(), "height": height}
        self.notified_height = height

    def _session_references(self, items, special_strings):
        """Return a SessionReferences object."""
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise RPCError(BAD_REQUEST, "expected a list of session IDs")

        sessions_by_id = {session.session_id: session for session in self.sessions}
        groups_by_name = self.session_groups

        sessions = set()
        groups = set()  # Names as groups are not hashable
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
        """Add a peer.

        real_name: "bch.electrumx.cash t50001 s50002" for example
        """
        await self.peer_mgr.add_localRPC_peer(real_name)
        return f"peer '{real_name}' added"

    async def rpc_disconnect(self, session_ids):
        """Disconnect sesssions.

        session_ids: array of session IDs
        """
        refs = self._session_references(session_ids, {"all"})
        result = []

        if "all" in refs.specials:
            sessions = self.sessions
            result.append("disconnecting all sessions")
        else:
            sessions = refs.sessions
            result.extend(f"disconnecting session {session.session_id}" for session in sessions)
            for group in refs.groups:
                result.append(f"disconnecting group {group.name}")
                sessions.update(group.sessions)
        result.extend(f"unknown: {item}" for item in refs.unknown)

        await self._disconnect_sessions(sessions, "local RPC request to disconnect")
        return result

    async def rpc_daemon_url(self, daemon_url):
        """Replace the daemon URL."""
        daemon_url = daemon_url or self.env.daemon_url
        try:
            self.daemon.set_url(daemon_url)
        except Exception as e:
            raise RPCError(BAD_REQUEST, f"an error occurred: {e!r}")
        return f"now using daemon at {self.daemon.logged_url()}"

    async def rpc_stop(self):
        """Shut down the server cleanly."""
        self.shutdown_event.set()
        return "stopping"

    async def rpc_getinfo(self):
        """Return summary information about the server process."""
        return self._get_info()

    async def rpc_groups(self):
        """Return statistics about the session groups."""
        return self._group_data()

    async def rpc_peers(self):
        """Return a list of data about server peers."""
        return self.peer_mgr.rpc_data()

    async def rpc_query(self, items, limit):
        """Returns data about a script, address or name."""
        coin = self.env.coin
        db = self.db
        lines = []

        def arg_to_hashX(arg):
            try:
                script = bytes.fromhex(arg)
                lines.append(f"Script: {arg}")
                return coin.hashX_from_script(script)
            except ValueError:
                pass

            try:
                hashX = coin.address_to_hashX(arg)
                lines.append(f"Address: {arg}")
                return hashX
            except Base58Error:
                pass

            try:
                script = coin.build_name_index_script(arg.encode("ascii"))
                hashX = coin.name_hashX_from_script(script)
                lines.append(f"Name: {arg}")
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
                lines.append(f"History #{n:,d}: height {height:,d} " f"tx_hash {hash_to_hex_str(tx_hash)}")
            if n is None:
                lines.append("No history found")
            n = None
            utxos = await db.all_utxos(hashX)
            for n, utxo in enumerate(utxos, start=1):
                lines.append(
                    f"UTXO #{n:,d}: tx_hash "
                    f"{hash_to_hex_str(utxo.tx_hash)} "
                    f"tx_pos {utxo.tx_pos:,d} height "
                    f"{utxo.height:,d} value {utxo.value:,d}"
                )
                if n == limit:
                    break
            if n is None:
                lines.append("No UTXOs found")

            balance = sum(utxo.value for utxo in utxos)
            lines.append(f"Balance: {coin.decimal_value(balance):,f} " f"{coin.SHORTNAME}")

        return lines

    async def rpc_sessions(self):
        """Return statistics about connected sessions."""
        return self._session_data(for_log=False)

    async def rpc_reorg(self, count):
        """Force a reorg of the given number of blocks.

        count: number of blocks to reorg
        """
        count = non_negative_integer(count)
        if not self.bp.force_chain_reorg(count):
            raise RPCError(BAD_REQUEST, "still catching up with daemon")
        return f"scheduled a reorg of {count:,d} blocks"

    async def rpc_debug_memusage_list_all_objects(self, limit: int) -> str:
        """Return a string listing the most common types in memory."""
        import io

        import objgraph  # optional dependency

        with io.StringIO() as fd:
            objgraph.show_most_common_types(limit=limit, shortnames=False, file=fd)
            return fd.getvalue()

    async def rpc_debug_memusage_get_random_backref_chain(self, objtype: str) -> str:
        """Return a dotfile as text containing the backref chain
        for a randomly selected object of type objtype.

        Warning: very slow! and it blocks the server.

        To convert to image:
        $ dot -Tps filename.dot -o outfile.ps
        """
        import io
        import random

        import objgraph  # optional dependency

        with io.StringIO() as fd:
            await run_in_thread(
                lambda: objgraph.show_chain(
                    objgraph.find_backref_chain(
                        random.choice(objgraph.by_type(objtype)),
                        objgraph.is_proper_module,
                    ),
                    output=fd,
                )
            )
            return fd.getvalue()

    # --- External Interface

    async def serve(self, notifications, event):
        """Start the RPC server if enabled.  When the event is triggered,
        start TCP and SSL servers."""
        try:
            await self._start_servers(service for service in self.env.services if service.protocol == "rpc")
            await event.wait()

            session_class = self.env.coin.SESSIONCLS
            session_class.cost_soft_limit = self.env.cost_soft_limit
            session_class.cost_hard_limit = self.env.cost_hard_limit
            session_class.cost_decay_per_sec = session_class.cost_hard_limit / 10000
            session_class.bw_cost_per_byte = 1.0 / self.env.bw_unit_cost
            session_class.cost_sleep = self.env.request_sleep / 1000
            session_class.initial_concurrent = self.env.initial_concurrent
            session_class.processing_timeout = self.env.request_timeout

            self.logger.info(f"max session count: {self.env.max_sessions:,d}")
            self.logger.info(f"session timeout: {self.env.session_timeout:,d} seconds")
            self.logger.info(f"session cost hard limit {self.env.cost_hard_limit:,d}")
            self.logger.info(f"session cost soft limit {self.env.cost_soft_limit:,d}")
            self.logger.info(f"bandwidth unit cost {self.env.bw_unit_cost:,d}")
            self.logger.info(f"request sleep {self.env.request_sleep:,d}ms")
            self.logger.info(f"request timeout {self.env.request_timeout:,d}s")
            self.logger.info(f"initial concurrent {self.env.initial_concurrent:,d}")

            self.logger.info(f"max response size {self.env.max_send:,d} bytes")
            if self.env.drop_client is not None:
                self.logger.info(f"drop clients matching: {self.env.drop_client.pattern}")
            for service in self.env.report_services:
                self.logger.info(f"advertising service {service}")
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
            async with util.OldTaskGroup() as group:
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
                    return tx_hashes[start : start + count]

                merkle_cache = MerkleCache(self.db.merkle, tx_hashes_func)
                self._merkle_cache[height] = merkle_cache
                await merkle_cache.initialize(len(tx_hashes))
            branch, _root = await merkle_cache.branch_and_root(tx_hash_count, tx_pos)
        else:
            branch, _root = self.db.merkle.branch_and_root(tx_hashes, tx_pos)

        branch = [hash_to_hex_str(hash) for hash in branch]
        return branch, cost / 2500

    async def merkle_branch_for_tx_hash(self, height, tx_hash):
        """Return a triple (branch, tx_pos, cost)."""
        tx_hashes, tx_hashes_cost = await self.tx_hashes_at_blockheight(height)
        try:
            tx_pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError(
                BAD_REQUEST,
                f"tx {hash_to_hex_str(tx_hash)} not in block at height {height:,d}",
            )
        branch, merkle_cost = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, tx_pos, tx_hashes_cost + merkle_cost

    async def merkle_branch_for_tx_pos(self, height, tx_pos):
        """Return a triple (branch, tx_hash_hex, cost)."""
        tx_hashes, tx_hashes_cost = await self.tx_hashes_at_blockheight(height)
        try:
            tx_hash = tx_hashes[tx_pos]
        except IndexError:
            raise RPCError(
                BAD_REQUEST,
                f"no tx at position {tx_pos:,d} in block at height {height:,d}",
            )
        branch, merkle_cost = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, hash_to_hex_str(tx_hash), tx_hashes_cost + merkle_cost

    async def tx_hashes_at_blockheight(self, height):
        """Returns a pair (tx_hashes, cost).

        tx_hashes is an ordered list of binary hashes, cost is an estimated cost of
        getting the hashes; cheaper if in-cache.  Raises RPCError.
        """
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
                raise RPCError(BAD_REQUEST, f"db error: {e!r}")
            if reorg_count == self._reorg_count:
                break

        self._tx_hashes_cache[height] = tx_hashes

        return tx_hashes, 0.25 + len(tx_hashes) * 0.0001

    def session_count(self):
        """The number of connections that we've sent something to."""
        return len(self.sessions)

    async def daemon_request(self, method, *args):
        """Catch a DaemonError and convert it to an RPCError."""
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError(DAEMON_ERROR, f"daemon error: {e!r}") from None

    async def raw_header(self, height):
        """Return the binary header at the given height."""
        try:
            return await self.db.raw_header(height)
        except IndexError:
            raise RPCError(BAD_REQUEST, f"height {height:,d} " "out of range") from None

    async def broadcast_transaction(self, raw_tx):
        hex_hash = await self.daemon.broadcast_transaction(raw_tx)
        self.txs_sent += 1
        return hex_hash

    async def broadcast_transaction_validated(self, raw_tx: str, live_run: bool):
        self.validate_raw_tx_blueprint(raw_tx)
        if live_run:
            hex_hash = await self.daemon.broadcast_transaction(raw_tx)
            self.txs_sent += 1
            return hex_hash
        else:
            tx, tx_hash = self.env.coin.DESERIALIZER(bytes.fromhex(raw_tx), 0).read_tx_and_hash()
            return hash_to_hex_str(tx_hash)

    async def limited_history(self, hashX):
        """Returns a pair (history, cost).

        History is a sorted list of (tx_hash, height) tuples, or an RPCError."""
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
                result = RPCError(BAD_REQUEST, "history too large", cost=cost)
            self._history_cache[hashX] = result

        if isinstance(result, Exception):
            raise result
        return result, cost

    async def get_history_op(self, hashX, limit=10, offset=0, op=None, reverse=True):
        history_data = self._history_op_cache.get(hashX, [])
        if not history_data:
            history_data = []
            txnum_padding = bytes(8 - TXNUM_LEN)
            for _key, hist in self.db.history.db.iterator(prefix=hashX, reverse=reverse):
                for tx_numb in util.chunks(hist, TXNUM_LEN):
                    (tx_num,) = util.unpack_le_uint64(tx_numb + txnum_padding)
                    op_data = self._tx_num_op_cache.get(tx_num)
                    if not op_data:
                        op_prefix_key = b"op" + util.pack_le_uint64(tx_num)
                        tx_op = self.db.utxo_db.get(op_prefix_key)
                        if tx_op:
                            (op_data,) = util.unpack_le_uint32(tx_op)
                            self._tx_num_op_cache[tx_num] = op_data
                    history_data.append({"tx_num": tx_num, "op": op_data})
            self._history_op_cache[hashX] = history_data
        if reverse:
            history_data.sort(key=lambda x: x["tx_num"], reverse=reverse)
        if op:
            history_data = list(filter(lambda x: x["op"] == op, history_data))
        else:
            history_data = list(filter(lambda x: x["op"], history_data))
        return history_data[offset : limit + offset], len(history_data)

    # Helper method to validate if the transaction correctly cleanly assigns all Atomicals.
    # This method simulates coloring according to split and regular rules.
    # Note: This does not apply to mempool but only prevout utxos that are confirmed.
    def validate_raw_tx_blueprint(self, raw_tx, raise_if_burned=True) -> AtomicalsValidation:
        # Deserialize the transaction
        tx, tx_hash = self.env.coin.DESERIALIZER(bytes.fromhex(raw_tx), 0).read_tx_and_hash()
        # Determine if there are any other operations at the transfer
        operations_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
        # Build the map of the atomicals potential spent at the tx
        atomicals_spent_at_inputs = self.bp.build_atomicals_spent_at_inputs_for_validation_only(tx)
        # Build a structure of organizing into NFT and FTs
        # Note: We do not validate anything with NFTs, just FTs
        # Build the "blueprint" for how to assign all atomicals
        blueprint_builder = AtomicalsTransferBlueprintBuilder(
            self.logger,
            atomicals_spent_at_inputs,
            operations_found_at_inputs,
            tx_hash,
            tx,
            self.bp.get_atomicals_id_mint_info,
            True,
            self.bp.is_custom_coloring_activated(self.bp.height),
        )
        encoded_atomicals_spent_at_inputs = encode_atomical_ids_hex(atomicals_spent_at_inputs)
        ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
        nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
        encoded_ft_output_blueprint = auto_encode_bytes_items(encode_atomical_ids_hex(dict(ft_output_blueprint)))
        encoded_nft_output_blueprint = auto_encode_bytes_items(encode_atomical_ids_hex(dict(nft_output_blueprint)))
        # Log that there were tokens burned due to not being cleanly assigned
        if blueprint_builder.get_are_fts_burned() and raise_if_burned:
            ft_outputs = encoded_ft_output_blueprint["outputs"]
            fts_burned = encoded_ft_output_blueprint["fts_burned"]
            nft_outputs = encoded_nft_output_blueprint["outputs"]
            nft_burned = encoded_nft_output_blueprint["nfts_burned"]
            raise AtomicalsValidationError(
                f"Invalid FT token inputs/outputs:\n"
                f"tx_hash={hash_to_hex_str(tx_hash)}\n"
                f"operations_found_at_inputs={operations_found_at_inputs}\n"
                f"atomicals_spent_at_inputs={encoded_atomicals_spent_at_inputs}\n"
                f"ft_output_blueprint.outputs={ft_outputs}\n"
                f"ft_output_blueprint.fts_burned={fts_burned}\n"
                f"nft_output_blueprint.outputs={nft_outputs}\n"
                f"nft_output_blueprint.nfts_burned={nft_burned}"
            )
        return AtomicalsValidation(
            tx_hash,
            operations_found_at_inputs,
            encoded_atomicals_spent_at_inputs,
            encoded_ft_output_blueprint,
            encoded_nft_output_blueprint,
        )

    # Helper method to decode the transaction and returns formatted structure.
    async def transaction_decode_raw_tx_blueprint(
        self,
        raw_tx: bytes,
        tap_leafs: Optional[List[bytes]],
    ) -> dict:
        # Deserialize the transaction
        tx, tx_hash = self.env.coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
        cache_res = self._tx_decode_cache.get(tx_hash)
        if cache_res:
            # txid maybe the same, this key should add height add key prefix
            tx_id = hash_to_hex_str(tx_hash)
            self.logger.debug(f"read transaction detail from cache {tx_id}")
            return cache_res

        # Determine if there are any other operations at the transfer
        if tap_leafs:
            found_operations = parse_atomicals_operations_from_tap_leafs(tap_leafs, True)
        else:
            found_operations = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
        # Build the map of the atomicals potential spent at the tx
        atomicals_spent_at_inputs: Dict[int:List] = self.bp.build_atomicals_spent_at_inputs_for_validation_only(tx)
        # Build a structure of organizing into NFT and FTs
        # Note: We do not validate anything with NFTs, just FTs
        # Build the "blueprint" for how to assign all atomicals
        blueprint_builder = AtomicalsTransferBlueprintBuilder(
            self.logger,
            atomicals_spent_at_inputs,
            found_operations,
            tx_hash,
            tx,
            self.bp.get_atomicals_id_mint_info,
            True,
            self.bp.is_custom_coloring_activated(self.bp.height),
        )
        ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
        nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
        # Log that there were tokens burned due to not being cleanly assigned
        encoded_spent_at_inputs = encode_atomical_ids_hex(atomicals_spent_at_inputs)
        encoded_ft_output_blueprint: Dict[str, Dict] = encode_atomical_ids_hex(dict(ft_output_blueprint))
        encoded_nft_output_blueprint: Dict[str, Dict] = encode_atomical_ids_hex(dict(nft_output_blueprint))
        op = found_operations.get("op") or "transfer"
        burned = auto_encode_bytes_items(
            {
                **encoded_ft_output_blueprint["fts_burned"],
                **encoded_nft_output_blueprint["nfts_burned"],
            }
        )
        ret = {
            "op": [op],
            "burned": dict(sorted(burned.items())),
        }
        payload = found_operations.get("payload")
        if payload:
            ret["op_payload"] = payload
        atomicals = []
        inputs = {}
        outputs = {}
        for k1, v1 in encoded_spent_at_inputs.items():
            for item1 in v1:
                id1 = item1["atomical_id"]
                if id1 not in atomicals:
                    atomicals.append(id1)
                if not inputs.get(k1):
                    inputs[k1] = {}
                inputs[k1][id1] = item1["data_value"]["atomical_value"]
        ft_outputs: dict = encoded_ft_output_blueprint["outputs"]
        for k2, v2 in ft_outputs.items():
            for id2, item2 in v2["atomicals"].items():
                if not outputs.get(k2):
                    outputs[k2] = {}
                outputs[k2][id2] = item2.atomical_value
        for k3, v3 in encoded_nft_output_blueprint["outputs"].items():
            for id3, item3 in v3["atomicals"].items():
                if not outputs.get(k3):
                    outputs[k3] = {}
                outputs[k3][id3] = item3.atomical_value
        mint_info: Optional[Dict] = None
        if blueprint_builder.is_mint:
            if op in ["dmt", "ft"]:
                tx_out = tx.outputs[0]
                ticker_name = payload.get("args", {}).get("mint_ticker", "")
                status, candidate_atomical_id, _ = self.bp.get_effective_ticker(ticker_name, self.bp.height)
                atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
                mint_info = {
                    "atomical_id": atomical_id,
                    "outputs": {
                        "index": 0,
                        "value": tx_out.value,
                    },
                }
            elif op == "nft":
                _receive_at_outputs = self.bp.build_atomicals_receive_at_ouutput_for_validation_only(tx, tx_hash)
                tx_out = tx.outputs[0]
                atomical_id = location_id_bytes_to_compact(_receive_at_outputs[0][-1]["atomical_id"])
                mint_info = {
                    "atomical_id": atomical_id,
                    "outputs": {
                        "index": 0,
                        "value": tx_out.value,
                    },
                }
        if mint_info:
            atomical_id = mint_info["atomical_id"]
            index = mint_info["outputs"]["index"]
            value = mint_info["outputs"]["value"]
            if not outputs.get(index):
                outputs[index] = {}
            outputs[index][atomical_id] = value
        payment_info: Optional[Dict] = None
        (
            payment_id,
            payment_idx,
            _,
        ) = AtomicalsTransferBlueprintBuilder.get_atomical_id_for_payment_marker_if_found(tx)
        if payment_id:
            payment_info = {
                "atomical_id": location_id_bytes_to_compact(payment_id),
                "payment_marker_idx": payment_idx,
            }
        ret["atomicals"] = [await self.atomical_id_get(atomical_id) for atomical_id in atomicals]
        ret["inputs"] = dict(sorted(inputs.items()))
        ret["outputs"] = dict(sorted(outputs.items()))
        ret["payment"] = payment_info
        self._tx_decode_cache[tx_hash] = ret
        return ret

    # Analysis the transaction detail by txid.
    # See BlockProcessor.op_list for the complete op list.
    async def get_transaction_detail(self, tx_id: str, height=None, tx_num=-1):
        tx_hash = hex_str_to_hash(tx_id)
        res = self._tx_detail_cache.get(tx_hash)
        if res:
            # txid maybe the same, this key should add height add key prefix
            self.logger.debug(f"read transaction detail from cache {tx_id}")
            return res
        if not height:
            tx_num, height = self.db.get_tx_num_height_from_tx_hash(tx_hash)

        raw_tx = self.db.get_raw_tx_by_tx_hash(tx_hash)
        if not raw_tx:
            raw_tx = await self.daemon_request("getrawtransaction", tx_id, False)
            raw_tx = bytes.fromhex(raw_tx)
        tx, _tx_hash = self.env.coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
        assert tx_hash == _tx_hash
        ops = self.db.get_op_by_tx_num(tx_num)
        op_raw = self.bp.op_list_vk[ops[0]] if ops else ""

        operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
        atomicals_spent_at_inputs = self.bp.build_atomicals_spent_at_inputs_for_validation_only(tx)
        atomicals_receive_at_outputs = self.bp.build_atomicals_receive_at_ouutput_for_validation_only(tx, tx_hash)
        blueprint_builder = AtomicalsTransferBlueprintBuilder(
            self.logger,
            atomicals_spent_at_inputs,
            operation_found_at_inputs,
            tx_hash,
            tx,
            self.bp.get_atomicals_id_mint_info,
            self.bp.is_dmint_activated(height),
            self.bp.is_custom_coloring_activated(height),
        )
        is_burned = blueprint_builder.are_fts_burned
        is_cleanly_assigned = blueprint_builder.cleanly_assigned
        # format burned_fts
        raw_burned_fts = blueprint_builder.get_fts_burned()
        burned_fts = {}
        for ft_key, ft_value in raw_burned_fts.items():
            burned_fts[location_id_bytes_to_compact(ft_key)] = ft_value

        res = {
            "txid": tx_id,
            "height": height,
            "tx_num": tx_num,
            "info": {},
            "transfers": {
                "inputs": {},
                "outputs": {},
                "is_burned": is_burned,
                "burned_fts": burned_fts,
                "is_cleanly_assigned": is_cleanly_assigned,
            },
        }
        operation_type = operation_found_at_inputs.get("op", "") if operation_found_at_inputs else ""
        if operation_found_at_inputs:
            payload = operation_found_at_inputs.get("payload")
            payload_not_none = payload or {}
            res["info"]["payload"] = payload_not_none
            if blueprint_builder.is_mint and operation_type in ["dmt", "ft"]:
                expected_output_index = 0
                tx_out = tx.outputs[expected_output_index]
                location = tx_hash + util.pack_le_uint32(expected_output_index)
                # if save into the db, it means mint success
                has_atomicals = self.db.get_atomicals_by_location_long_form(location)
                if len(has_atomicals):
                    ticker_name = payload_not_none.get("args", {}).get("mint_ticker", "")
                    status, candidate_atomical_id, _ = self.bp.get_effective_ticker(ticker_name, self.bp.height)
                    if status:
                        atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
                        res["info"] = {
                            "atomical_id": atomical_id,
                            "location_id": location_id_bytes_to_compact(location),
                            "payload": payload,
                            "outputs": {
                                expected_output_index: [
                                    {
                                        "address": get_address_from_output_script(tx_out.pk_script),
                                        "atomical_id": atomical_id,
                                        "type": "FT",
                                        "index": expected_output_index,
                                        "value": tx_out.value,
                                    }
                                ]
                            },
                        }
            elif operation_type == "nft":
                if atomicals_receive_at_outputs:
                    expected_output_index = 0
                    location = tx_hash + util.pack_le_uint32(expected_output_index)
                    tx_out = tx.outputs[expected_output_index]
                    atomical_id = location_id_bytes_to_compact(
                        atomicals_receive_at_outputs[expected_output_index][-1]["atomical_id"]
                    )
                    res["info"] = {
                        "atomical_id": atomical_id,
                        "location_id": location_id_bytes_to_compact(location),
                        "payload": payload,
                        "outputs": {
                            expected_output_index: [
                                {
                                    "address": get_address_from_output_script(tx_out.pk_script),
                                    "atomical_id": atomical_id,
                                    "type": "NFT",
                                    "index": expected_output_index,
                                    "value": tx_out.value,
                                }
                            ]
                        },
                    }

        async def make_transfer_inputs(result, inputs_atomicals, tx_inputs, make_type) -> Dict[int, List[Dict]]:
            for atomical_id, input_data in inputs_atomicals.items():
                compact_atomical_id = location_id_bytes_to_compact(atomical_id)
                for _i in input_data.input_indexes:
                    _prev_txid = hash_to_hex_str(tx_inputs[_i.txin_index].prev_hash)
                    _prev_raw_tx = self.db.get_raw_tx_by_tx_hash(hex_str_to_hash(_prev_txid))
                    if not _prev_raw_tx:
                        _prev_raw_tx = await self.daemon_request("getrawtransaction", _prev_txid, False)
                        _prev_raw_tx = bytes.fromhex(_prev_raw_tx)
                        self.bp.general_data_cache[b"rtx" + hex_str_to_hash(_prev_txid)] = _prev_raw_tx
                    _prev_tx, _ = self.env.coin.DESERIALIZER(_prev_raw_tx, 0).read_tx_and_hash()
                    _data = {
                        "address": get_address_from_output_script(
                            _prev_tx.outputs[tx_inputs[_i.txin_index].prev_idx].pk_script
                        ),
                        "atomical_id": compact_atomical_id,
                        "type": make_type,
                        "index": _i.txin_index,
                        "value": _i.atomical_value,
                    }
                    if not result.get(_i.txin_index):
                        result[_i.txin_index] = [_data]
                    else:
                        result[_i.txin_index].append(_data)
            return result

        def make_transfer_outputs(
            result: Dict[int, List[Dict]],
            outputs: Dict[int, Dict[str, Dict[bytes, AtomicalColoredOutput]]],
        ) -> Dict[int, List[Dict]]:
            for k, v in outputs.items():
                for _atomical_id, _output in v["atomicals"].items():
                    _compact_atomical_id = location_id_bytes_to_compact(_atomical_id)
                    _data = {
                        "address": get_address_from_output_script(tx.outputs[k].pk_script),
                        "atomical_id": _compact_atomical_id,
                        "type": _output.type,
                        "index": k,
                        "value": _output.atomical_value,
                    }
                    if not result.get(k):
                        result[k] = [_data]
                    else:
                        result[k].append(_data)
            return result

        # no operation_found_at_inputs, it will be transfer.
        if blueprint_builder.ft_atomicals and atomicals_spent_at_inputs:
            if not operation_type and not op_raw:
                op_raw = "transfer"
            await make_transfer_inputs(res["transfers"]["inputs"], blueprint_builder.ft_atomicals, tx.inputs, "FT")
            make_transfer_outputs(res["transfers"]["outputs"], blueprint_builder.ft_output_blueprint.outputs)
        if blueprint_builder.nft_atomicals and atomicals_spent_at_inputs:
            if not operation_type and not op_raw:
                op_raw = "transfer"
            await make_transfer_inputs(res["transfers"]["inputs"], blueprint_builder.nft_atomicals, tx.inputs, "NFT")
            make_transfer_outputs(res["transfers"]["outputs"], blueprint_builder.nft_output_blueprint.outputs)

        (
            payment_id,
            payment_marker_idx,
            _,
        ) = AtomicalsTransferBlueprintBuilder.get_atomical_id_for_payment_marker_if_found(tx)
        if payment_id:
            res["info"]["payment"] = {
                "atomical_id": location_id_bytes_to_compact(payment_id),
                "payment_marker_idx": payment_marker_idx,
            }

        if op_raw and height:
            self._tx_detail_cache[tx_hash] = res
        res["op"] = op_raw

        # Recursively encode the result.
        return auto_encode_bytes_elements(res)

    async def get_transaction_detail_batch(self, tx_ids: str):
        tasks = [self.get_transaction_detail(txid) for txid in tx_ids.split(',')]
        details = await asyncio.gather(*tasks)
        return details

    async def transaction_global(
        self,
        limit: int = 10,
        offset: int = 0,
        op_type: Optional[str] = None,
        reverse: bool = True,
    ):
        height = self.bp.height
        res = []
        count = 0
        history_list = []
        for current_height in range(height, self.env.coin.ATOMICALS_ACTIVATION_HEIGHT, -1):
            txs = self.db.get_atomicals_block_txs(current_height)
            for tx in txs:
                tx_num, _ = self.db.get_tx_num_height_from_tx_hash(hex_str_to_hash(tx))
                history_list.append({"tx_num": tx_num, "tx_hash": tx, "height": current_height})
                count += 1
            if count >= offset + limit:
                break
        history_list.sort(key=lambda x: x["tx_num"], reverse=reverse)

        for history in history_list:
            data = await self.get_transaction_detail(history["tx_hash"], history["height"], history["tx_num"])
            if (op_type and op_type == data["op"]) or (not op_type and data["op"]):
                res.append(data)
        total = len(res)
        return {
            "result": res[offset : offset + limit],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    # Get atomicals base information from db or placeholder information if mint is still in the mempool and unconfirmed
    async def atomical_id_get(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
        if atomical:
            return atomical
        # Check mempool
        atomical_in_mempool = await self.mempool.get_atomical_mint(atomical_id)
        if atomical_in_mempool is None:
            raise RPCError(BAD_REQUEST, f'"{compact_atomical_id}" is not found')
        return atomical_in_mempool

    async def _notify_sessions(self, height, touched):
        """Notify sessions about height changes and touched addresses."""
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
                self.logger.warning("task group already terminated. not notifying sessions.")
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
        return "unknown_addr"

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
        groups = (self._session_group(self._ip_addr_group_name(session), 1.0),)
        groups = tuple(group for group in groups if group is not None)
        self.sessions[session] = groups
        for group in groups:
            group.sessions.add(session)

    def remove_session(self, session):
        """Remove a session from our sessions list if there."""
        self.session_event.set()
        groups = self.sessions.pop(session)
        for group in groups:
            group.retained_cost += session.cost
            group.sessions.remove(session)
