from electrumx.server.session.session_base import SessionBase


class LocalRPC(SessionBase):
    """A local TCP RPC server session."""

    processing_timeout = 10**9  # disable timeouts

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = "RPC"
        self.connection.max_response_size = 0
        self.request_handlers = {
            "getinfo": self.session_mgr.rpc_getinfo,
            "groups": self.session_mgr.rpc_groups,
            "peers": self.session_mgr.rpc_peers,
            "sessions": self.session_mgr.rpc_sessions,
            "stop": self.session_mgr.rpc_stop,
            "disconnect": self.session_mgr.rpc_disconnect,
            "add_peer": self.session_mgr.rpc_add_peer,
            "daemon_url": self.session_mgr.rpc_daemon_url,
            "query": self.session_mgr.rpc_query,
            "reorg": self.session_mgr.rpc_reorg,
            "debug_memusage_list_all_objects": self.session_mgr.rpc_debug_memusage_list_all_objects,
            "debug_memusage_get_random_backref_chain": self.session_mgr.rpc_debug_memusage_get_random_backref_chain,
        }

    def protocol_version_string(self):
        return "RPC"
