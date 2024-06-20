# -*- coding: utf-8 -*-

import json
import traceback
from decimal import Decimal
from typing import Awaitable

import aiorpcx
from aiohttp import web

import electrumx.lib.util as util
from electrumx.server.http_middleware import error_resp, success_resp
from electrumx.server.session.shared_session import SharedSession
from electrumx.server.session.util import SESSION_PROTOCOL_MAX, SESSION_PROTOCOL_MIN
from electrumx.version import electrumx_version, get_server_info


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)


class HttpSession(object):
    def __init__(self, session_mgr, db, mempool, peer_mgr, kind):
        # self.transport = transport
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.session_mgr = session_mgr
        self.subscribe_headers = False
        self.db = db
        self.mempool = mempool
        self.peer_mgr = peer_mgr
        self.kind = kind
        self.env = session_mgr.env
        self.coin = self.env.coin
        self.client = "unknown"
        self.anon_logs = self.env.anon_logs
        self.log_me = False
        self.daemon_request = self.session_mgr.daemon_request
        self.mempool_statuses = {}
        self.sv_seen = False
        self.MAX_CHUNK_SIZE = 2016
        self.hashX_subs = {}
        # Use the sharing session to manage handlers.
        self.ss = SharedSession(
            self.logger,
            self.coin,
            self.session_mgr,
            self.peer_mgr,
            self.client,
        )

    async def formatted_request(self, request: web.Request, call):
        method = request.path
        params: list
        if request.method == "GET":
            params = json.loads(request.query.get("params", "[]"))
        elif request.content_length:
            json_data = await request.json()
            params = json_data.get("params", [])
        else:
            params = []
        self.logger.debug(f"HTTP request handling: [method] {method}, [params]: {params}")
        try:
            result = call(*params)
            if isinstance(result, Awaitable):
                result = await result
            return success_resp(result)
        except Exception as e:
            method = request.method
            path = request.url
            s = traceback.format_exc()
            self.logger.error(f"Exception during formatting request: {method} {path}, " f"exception: {e}, stack: {s}")
            return error_resp(500, e)

    async def add_endpoints(self, router, protocols):
        handlers = {
            "health": self.health,
            # 'server.banner': self.ss.banner,
            "server.donation_address": self.ss.donation_address,
            "server.features": self.server_features_async,
            "server.info": get_server_info,
            # 'server.peers.subscribe': self.ss.peers_subscribe,
            # 'server.ping': self.ss.ping,
            # 'server.version': self.server_version,
            "blockchain.headers.subscribe": self.ss.headers_subscribe,
            "blockchain.block.header": self.ss.block_header,
            "blockchain.block.headers": self.ss.block_headers,
            "blockchain.estimatefee": self.ss.estimate_fee,
            "blockchain.relayfee": self.ss.relay_fee,
            "blockchain.scripthash.get_balance": self.ss.scripthash_get_balance,
            "blockchain.scripthash.get_history": self.ss.scripthash_get_history,
            "blockchain.scripthash.get_mempool": self.ss.scripthash_get_mempool,
            "blockchain.scripthash.listunspent": self.ss.scripthash_list_unspent,
            "blockchain.scripthash.subscribe": self.ss.scripthash_subscribe,
            "blockchain.transaction.broadcast": self.ss.transaction_broadcast,
            "blockchain.transaction.broadcast_force": self.ss.transaction_broadcast_force,
            "blockchain.transaction.get": self.ss.transaction_get,
            "blockchain.transaction.get_merkle": self.ss.transaction_merkle,
            "blockchain.transaction.id_from_pos": self.ss.transaction_id_from_pos,
            "mempool.get_fee_histogram": self.ss.compact_fee_histogram,
            # The Atomicals era has begun #
            "blockchain.atomicals.validate": self.ss.transaction_broadcast_validate,
            "blockchain.atomicals.validate_psbt_blueprint": self.ss.transaction_validate_psbt_blueprint,
            "blockchain.atomicals.validate_tx_blueprint": self.ss.transaction_validate_tx_blueprint,
            "blockchain.atomicals.decode_psbt": self.ss.transaction_decode_psbt,
            "blockchain.atomicals.decode_tx": self.ss.transaction_decode_tx,
            "blockchain.atomicals.get_ft_balances_scripthash": self.ss.atomicals_get_ft_balances,
            "blockchain.atomicals.get_nft_balances_scripthash": self.ss.atomicals_get_nft_balances,
            "blockchain.atomicals.listscripthash": self.ss.atomicals_list_scripthash,
            "blockchain.atomicals.list": self.ss.atomicals_list,
            "blockchain.atomicals.get_numbers": self.ss.atomicals_num_to_id,
            "blockchain.atomicals.get_block_hash": self.ss.atomicals_block_hash,
            "blockchain.atomicals.get_block_txs": self.ss.atomicals_block_txs,
            # 'blockchain.atomicals.dump': self.ss.atomicals_dump,
            "blockchain.atomicals.at_location": self.ss.atomicals_at_location,
            "blockchain.atomicals.get_location": self.ss.atomicals_get_location,
            "blockchain.atomicals.get": self.ss.atomicals_get,
            "blockchain.atomicals.get_global": self.ss.atomicals_get_global,
            "blockchain.atomicals.get_state": self.ss.atomical_get_state,
            "blockchain.atomicals.get_state_history": self.ss.atomical_get_state_history,
            "blockchain.atomicals.get_events": self.ss.atomical_get_events,
            "blockchain.atomicals.get_tx_history": self.ss.atomicals_get_tx_history,
            "blockchain.atomicals.get_ft_info": self.ss.atomicals_get_ft_info,
            "blockchain.atomicals.get_dft_mints": self.ss.atomicals_get_dft_mints,
            "blockchain.atomicals.get_realm_info": self.ss.atomicals_get_realm_info,
            "blockchain.atomicals.get_by_realm": self.ss.atomicals_get_by_realm,
            "blockchain.atomicals.get_by_subrealm": self.ss.atomicals_get_by_subrealm,
            "blockchain.atomicals.get_by_dmitem": self.ss.atomicals_get_by_dmitem,
            "blockchain.atomicals.get_by_ticker": self.ss.atomicals_get_by_ticker,
            "blockchain.atomicals.get_by_container": self.ss.atomicals_get_by_container,
            "blockchain.atomicals.get_by_container_item": self.ss.atomicals_get_by_container_item,
            "blockchain.atomicals.get_by_container_item_validate": self.ss.atomicals_get_by_container_item_validation,
            "blockchain.atomicals.get_container_items": self.ss.atomicals_get_container_items,
            "blockchain.atomicals.find_tickers": self.ss.atomicals_search_tickers,
            "blockchain.atomicals.find_realms": self.ss.atomicals_search_realms,
            "blockchain.atomicals.find_subrealms": self.ss.atomicals_search_subrealms,
            "blockchain.atomicals.find_containers": self.ss.atomicals_search_containers,
            "blockchain.atomicals.get_holders": self.ss.atomicals_get_holders,
            "blockchain.atomicals.transaction": self.session_mgr.get_transaction_detail,
            "blockchain.atomicals.transaction_by_height": self.ss.transaction_by_height,
            "blockchain.atomicals.transaction_by_atomical_id": self.ss.transaction_by_atomical_id,
            "blockchain.atomicals.transaction_by_scripthash": self.ss.transaction_by_scripthash,
            "blockchain.atomicals.transaction_global": self.session_mgr.transaction_global,
        }

        if protocols >= (1, 4, 2):
            handlers["blockchain.scripthash.unsubscribe"] = self.ss.scripthash_unsubscribe

        router.add_get("/proxy", self.proxy)
        router.add_post("/proxy", self.proxy)

        for m, h in handlers.items():
            method = f"/proxy/{m}"
            router.add_get(method, lambda r, handler=h: self.formatted_request(r, handler))
            router.add_post(method, lambda r, handler=h: self.formatted_request(r, handler))

        # Fallback proxy recognition
        router.add_get("/proxy/{method}", self.handle_get_method)
        router.add_post("/proxy/{method}", self.handle_post_method)

    async def get_rpc_server(self):
        for service in self.env.services:
            if service.protocol == "tcp":
                return service

    @classmethod
    def protocol_min_max_strings(cls):
        return [util.version_string(ver) for ver in (SESSION_PROTOCOL_MIN, SESSION_PROTOCOL_MAX)]

    @classmethod
    def server_features(cls, env):
        """Return the server features dictionary."""
        hosts_dict = {}
        for service in env.report_services:
            port_dict = hosts_dict.setdefault(str(service.host), {})
            if service.protocol not in port_dict:
                port_dict[f"{service.protocol}_port"] = service.port

        min_str, max_str = cls.protocol_min_max_strings()
        return {
            "hosts": hosts_dict,
            "pruning": None,
            "server_version": electrumx_version,
            "protocol_min": min_str,
            "protocol_max": max_str,
            "genesis_hash": env.coin.GENESIS_HASH,
            "hash_function": "sha256",
            "services": [str(service) for service in env.report_services],
        }

    async def handle_get_method(self, request):
        method = request.match_info.get("method", None)
        params = json.loads(request.query.get("params", "[]"))

        rpc_service = await self.get_rpc_server()
        async with aiorpcx.connect_rs(str(rpc_service.address.host), int(rpc_service.address.port)) as session:
            result = await session.send_request(method, params)
            await session.close()

        return result

    async def handle_post_method(self, request):
        json_data = await request.json()
        method = request.match_info.get("method", None)
        params = json_data.get("params", "[]")
        rpc_service = await self.get_rpc_server()
        async with aiorpcx.connect_rs(str(rpc_service.address.host), int(rpc_service.address.port)) as session:
            result = await session.send_request(method, params)
            await session.close()

        return result

    async def proxy(self, request):
        result = {
            "success": True,
            "info": {
                "note": "Atomicals ElectrumX Digital Object Proxy Online",
                "usageInfo": {
                    "note": "The service offers both POST and GET requests for proxying requests to ElectrumX. "
                    "To handle larger broadcast transaction payloads use the POST method instead of GET.",
                    "POST": "POST /proxy/:method with string encoded array "
                    'in the field \\"params\\" in the request body. ',
                    "GET": 'GET /proxy/:method?params=[\\"value1\\"] with string encoded array '
                    'in the query argument \\"params\\" in the URL.',
                },
                "healthCheck": "GET /proxy/health",
                "github": "https://github.com/atomicals/electrumx-proxy",
                "license": "MIT",
            },
        }
        return result

    async def health(self):
        result = {"success": True, "health": True}
        return result

    async def donation_address(self):
        """Return the donation address as a string, empty if there is none."""
        return self.env.donation_address

    async def server_features_async(self):
        return self.server_features(self.env)

    async def peers_subscribe(self):
        """Return the server peers as a list of (ip, host, details) tuples."""
        return self.peer_mgr.on_peers_subscribe(False)

    # async def ping(self, request):
    #     """Serves as a connection keep-alive mechanism and for the client to
    #     confirm the server is still responding.
    #     """
    #     return None
