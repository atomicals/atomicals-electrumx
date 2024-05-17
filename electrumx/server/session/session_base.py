from typing import Optional, Tuple, Callable, Dict

import electrumx.lib.util as util
import itertools

from aiorpcx import Request, RPCSession, JSONRPCConnection, JSONRPCAutoDetect, NewlineFramer, ReplyAndDisconnect, \
    handler_invocation, RPCError

from electrumx.lib.hash import hex_str_to_hash, HASHX_LEN
from electrumx.server.db import DB
from electrumx.server.mempool import MemPool
from electrumx.server.peers import PeerManager
from electrumx.server.session import BAD_REQUEST
from electrumx.server.session.shared_session import SharedSession


def scripthash_to_hashX(scripthash):
    try:
        bin_hash = hex_str_to_hash(scripthash)
        if len(bin_hash) == 32:
            return bin_hash[:HASHX_LEN]
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f'{scripthash} is not a valid script hash')


def non_negative_integer(value):
    """Return param value it is or can be converted to a non-negative
    integer, otherwise raise an RPCError."""
    try:
        value = int(value)
        if value >= 0:
            return value
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f'{value} should be a non-negative integer')


def assert_tx_hash(value):
    """Raise an RPCError if the value is not a valid hexadecimal transaction hash.

    If it is valid, return it as 32-byte binary hash."""
    try:
        raw_hash = hex_str_to_hash(value)
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f'{value} should be a transaction hash')


def assert_atomical_id(value):
    """Raise an RPCError if the value is not a valid atomical id
    If it is valid, return it as 32-byte binary hash."""
    try:
        if value is None or value == "":
            raise RPCError(BAD_REQUEST, f'atomical_id required')
        index_of_i = value.find("i")
        if index_of_i != 64:
            raise RPCError(BAD_REQUEST, f'{value} should be an atomical_id')
        raw_hash = hex_str_to_hash(value[: 64])
        if len(raw_hash) == 32:
            return raw_hash
    except (ValueError, TypeError):
        pass

    raise RPCError(BAD_REQUEST, f'{value} should be an atomical_id')


class SessionBase(RPCSession):
    """Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    """

    MAX_CHUNK_SIZE = 2016
    session_counter = itertools.count()
    log_new = False

    def __init__(
            self,
            session_mgr,
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
        self.protocol_tuple: Optional[Tuple[int, ...]] = None
        self.request_handlers: Optional[Dict[str, Callable]] = None
        # Use the sharing session to manage handlers.
        self.ss = SharedSession(self.session_mgr, self.logger)

    async def notify(self, touched, height_changed):
        pass

    def default_framer(self):
        return NewlineFramer(max_size=self.env.max_recv)

    def remote_address_string(self, *, for_log=True):
        """Returns the peer's IP address and port as a human-readable
        string, respecting anon logs if the output is for a log."""
        if for_log and self.anon_logs:
            return 'xx.xx.xx.xx:xx'
        return str(self.remote_address())

    def flags(self):
        """Status flags."""
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self._incoming_concurrency.max_concurrent)
        return status

    async def connection_lost(self):
        """Handle client disconnection."""
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
        """Handle an incoming request.  ElectrumX doesn't receive
        notifications from client sessions.
        """
        if isinstance(request, Request):
            handler = self.request_handlers.get(request.method)
            method = request.method
            args = request.args
        else:
            handler = None
            method = 'invalid method'
            args = None
        self.logger.debug(f'Session request handling: [method] {method}, [args] {args}')

        # If DROP_CLIENT_UNKNOWN is enabled, check if the client identified
        # by calling server.version previously. If not, disconnect the session
        if self.env.drop_client_unknown and method != 'server.version' and self.client == 'unknown':
            self.logger.info(f'disconnecting because client is unknown')
            raise ReplyAndDisconnect(BAD_REQUEST, f'use server.version to identify client')

        self.session_mgr.method_counts[method] += 1
        coro = handler_invocation(handler, request)()
        return await coro


class LocalRPC(SessionBase):
    """A local TCP RPC server session."""

    processing_timeout = 10**9  # disable timeouts

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.connection.max_response_size = 0

    def protocol_version_string(self):
        return 'RPC'
