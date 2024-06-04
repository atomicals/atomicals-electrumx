import itertools
from typing import TYPE_CHECKING, Awaitable, Dict, Optional, Tuple

from aiorpcx import (
    JSONRPCAutoDetect,
    JSONRPCConnection,
    NewlineFramer,
    ReplyAndDisconnect,
    Request,
    RPCSession,
    handler_invocation,
)

import electrumx.lib.util as util
from electrumx.server.session import BAD_REQUEST
from electrumx.server.session.shared_session import SharedSession

if TYPE_CHECKING:
    from electrumx.server.db import DB
    from electrumx.server.mempool import MemPool
    from electrumx.server.peers import PeerManager


class SessionBase(RPCSession):
    """Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    """

    session_counter = itertools.count()

    def __init__(
        self,
        session_mgr,
        db: "DB",
        mempool: "MemPool",
        peer_mgr: "PeerManager",
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
        self.client = "unknown"
        self.anon_logs = self.env.anon_logs
        self.txs_sent = 0
        self.log_me = False
        self.session_id = None
        self.daemon_request = self.session_mgr.daemon_request
        self.session_id = next(self.session_counter)
        context = {"conn_id": f"{self.session_id}"}
        logger = util.class_logger(__name__, self.__class__.__name__)
        self.logger = util.ConnectionLogger(logger, context)
        self.logger.info(f"{self.kind} {self.remote_address_string()}, " f"{self.session_mgr.session_count():,d} total")
        self.session_mgr.add_session(self)
        self.recalc_concurrency()  # must be called after session_mgr.add_session
        self.protocol_tuple: Optional[Tuple[int, ...]] = None
        self.request_handlers: Optional[Dict[str, Awaitable]] = None
        # Use the sharing session to manage handlers.
        self.ss = SharedSession(
            self.logger,
            self.coin,
            self.session_mgr,
            self.peer_mgr,
            self.client,
            maybe_bump_cost=self.bump_cost,
        )

    async def notify(self, touched, height_changed):
        pass

    def default_framer(self):
        return NewlineFramer(max_size=self.env.max_recv)

    def remote_address_string(self, *, for_log=True):
        """Returns the peer's IP address and port as a human-readable
        string, respecting anon logs if the output is for a log."""
        if for_log and self.anon_logs:
            return "xx.xx.xx.xx:xx"
        return str(self.remote_address())

    def flags(self):
        """Status flags."""
        status = self.kind[0]
        if self.is_closing():
            status += "C"
        if self.log_me:
            status += "L"
        status += str(self._incoming_concurrency.max_concurrent)
        return status

    async def connection_lost(self):
        """Handle client disconnection."""
        await super().connection_lost()
        self.session_mgr.remove_session(self)
        msg = ""
        if self._incoming_concurrency.max_concurrent < self.initial_concurrent * 0.8:
            msg += " whilst throttled"
        if self.send_size >= 1_000_000:
            msg += f".  Sent {self.send_size:,d} bytes in {self.send_count:,d} messages"
        if msg:
            msg = "disconnected" + msg
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
            method = "invalid method"
            args = None
        self.logger.debug(f"Session request handling: [method] {method}, [args] {args}")

        # If DROP_CLIENT_UNKNOWN is enabled, check if the client identified
        # by calling server.version previously. If not, disconnect the session
        if self.env.drop_client_unknown and method != "server.version" and self.client == "unknown":
            self.logger.info(f"disconnecting because client is unknown")
            raise ReplyAndDisconnect(BAD_REQUEST, f"use server.version to identify client")

        self.session_mgr.method_counts[method] += 1
        coro = handler_invocation(handler, request)()
        if isinstance(coro, Awaitable):
            return await coro
        else:
            return coro


class LocalRPC(SessionBase):
    """A local TCP RPC server session."""

    processing_timeout = 10**9  # disable timeouts

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = "RPC"
        self.connection.max_response_size = 0

    def protocol_version_string(self):
        return "RPC"
