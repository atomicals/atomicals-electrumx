import codecs
import datetime
from typing import Tuple

from aiorpcx import ReplyAndDisconnect, TaskTimeout, timeout_after

from electrumx.lib import util
from electrumx.server.daemon import DaemonError
from electrumx.server.session.session_base import SessionBase
from electrumx.server.session.util import *
from electrumx.version import (
    electrumx_version,
    electrumx_version_short,
    get_server_info,
)


class ElectrumX(SessionBase):
    """A TCP server that handles incoming Electrum connections."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.connection.max_response_size = self.env.max_send
        self.hashX_subs = {}
        self.sv_seen = False
        self.mempool_statuses = {}
        self.set_request_handlers(SESSION_PROTOCOL_MAX)
        self.cost = 5.0  # Connection cost

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

    async def server_features_async(self):
        return self.server_features(self.env)

    @classmethod
    def server_version_args(cls):
        """The arguments to a server.version RPC call to a peer."""
        return [electrumx_version, cls.protocol_min_max_strings()]

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

    async def notify(self, touched, height_changed):
        """Wrap _notify_inner; websockets raises exceptions for unclear reasons."""
        try:
            async with timeout_after(30):
                await self._notify_inner(touched, height_changed)
        except TaskTimeout:
            self.logger.warning("timeout notifying client, closing...")
            await self.close(force_after=1.0)
        except Exception as e:
            self.logger.exception(f"Unexpected exception notifying client: {e}")

    async def _notify_inner(self, touched, height_changed):
        """Notify the client about changes to touched addresses (from mempool
        updates or new blocks) and height.
        """
        if height_changed and self.subscribe_headers:
            args = (await self.ss.subscribe_headers_result(),)
            await self.send_notification("blockchain.headers.subscribe", args)

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

            method = "blockchain.scripthash.subscribe"
            for alias, status in changed.items():
                await self.send_notification(method, (alias, status))

            if changed:
                es = "" if len(changed) == 1 else "es"
                self.logger.info(f"notified of {len(changed):,d} address{es}")

    def set_request_handlers(self, protocols):
        self.protocol_tuple: Tuple[int, ...] = protocols
        handlers = {
            # 'server.banner': self.banner,
            "server.donation_address": self.ss.donation_address,
            "server.features": self.server_features_async,
            "server.info": get_server_info,
            # 'server.peers.subscribe': self.peers_subscribe,
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
        self.request_handlers = handlers

    async def banner(self):
        """Return the server banner text."""
        banner = f"You are connected to an {electrumx_version} server."
        self.bump_cost(0.5)
        if self.is_tor():
            banner_file = self.env.tor_banner_file
        else:
            banner_file = self.env.banner_file
        if banner_file:
            try:
                with codecs.open(banner_file, "r", "utf-8") as f:
                    banner = f.read()
            except (OSError, UnicodeDecodeError) as e:
                self.logger.error(f"reading banner file {banner_file}: {e!r}")
            else:
                banner = await self.replaced_banner(banner)
        return banner

    async def peers_subscribe(self):
        """Return the server peers as a list of (ip, host, details) tuples."""
        self.bump_cost(1.0)
        return self.peer_mgr.on_peers_subscribe(self.is_tor())

    async def subscription_address_status(self, hash_x):
        """As for address_status, but if it can't be calculated the subscription is
        discarded."""
        try:
            return await self.ss.address_status(hash_x)
        except RPCError:
            self.ss.unsubscribe_hash_x(hash_x)
            return None

    def is_tor(self):
        """Try to detect if the connection is to a tor hidden service we are
        running."""
        proxy_address = self.peer_mgr.proxy_address()
        if not proxy_address:
            return False
        remote_addr = self.remote_address()
        if not remote_addr:
            return False
        return remote_addr.host == proxy_address.host

    async def replaced_banner(self, banner):
        network_info = await self.daemon_request("getnetworkinfo")
        ni_version = network_info["version"]
        major, minor = divmod(ni_version, 1000000)
        minor, revision = divmod(minor, 10000)
        revision //= 100
        daemon_version = f"{major:d}.{minor:d}.{revision:d}"
        for pair in [
            ("$SERVER_VERSION", electrumx_version_short),
            ("$SERVER_SUBVERSION", electrumx_version),
            ("$DAEMON_VERSION", daemon_version),
            ("$DAEMON_SUBVERSION", network_info["subversion"]),
            ("$DONATION_ADDRESS", self.env.donation_address),
        ]:
            banner = banner.replace(*pair)
        return banner

    async def server_version(self, client_name="", protocol_version=None):
        """Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        """
        self.bump_cost(0.5)
        if self.sv_seen:
            raise RPCError(BAD_REQUEST, f"server.version already sent")
        self.sv_seen = True

        if client_name:
            client_name = str(client_name)
            if self.env.drop_client is not None and self.env.drop_client.match(client_name):
                raise ReplyAndDisconnect(RPCError(BAD_REQUEST, f"unsupported client: {client_name}"))
            self.client = client_name[:17]

        # Find the highest common protocol version.  Disconnect if
        # that protocol version in unsupported.
        ptuple, client_min = util.protocol_version(protocol_version, SESSION_PROTOCOL_MIN, SESSION_PROTOCOL_MAX)
        await self.crash_old_client(ptuple, self.env.coin.CRASH_CLIENT_VER)
        if ptuple is None:
            if client_min > SESSION_PROTOCOL_MIN:
                self.logger.info(
                    f"client requested future protocol version "
                    f"{util.version_string(client_min)} "
                    f"- is your software out of date?"
                )
            raise ReplyAndDisconnect(RPCError(BAD_REQUEST, f"unsupported protocol version: {protocol_version}"))

        self.set_request_handlers(ptuple)
        return electrumx_version, self.protocol_version_string()

    async def crash_old_client(self, ptuple, crash_client_ver):
        if crash_client_ver:
            client_ver = util.protocol_tuple(self.client)
            is_old_protocol = ptuple is None or ptuple <= (1, 2)
            is_old_client = client_ver != (0,) and client_ver <= crash_client_ver
            if is_old_protocol and is_old_client:
                self.logger.info(f"attempting to crash old client with version {self.client}")
                # this can crash electrum client 2.6 <= v < 3.1.2
                await self.send_notification("blockchain.relayfee", ())
                # this can crash electrum client (v < 2.8.2) UNION (3.0.0 <= v < 3.3.0)
                await self.send_notification("blockchain.estimatefee", ())


class DashElectrumX(ElectrumX):
    """A TCP server that handles incoming Electrum Dash connections."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mns = set()
        self.mn_cache_height = 0
        self.mn_cache = []

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update(
            {
                "masternode.announce.broadcast": self.masternode_announce_broadcast,
                "masternode.subscribe": self.masternode_subscribe,
                "masternode.list": self.masternode_list,
                "protx.diff": self.protx_diff,
                "protx.info": self.protx_info,
            }
        )

    async def _notify_inner(self, touched, height_changed):
        """Notify the client about changes in masternode list."""
        await super()._notify_inner(touched, height_changed)
        for mn in self.mns.copy():
            status = await self.daemon_request("masternode_list", ("status", mn))
            await self.send_notification("masternode.subscribe", (mn, status.get(mn)))

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        """Pass through the masternode announce message to be broadcast
        by the daemon.

        signmnb: signed masternode broadcast message."""
        try:
            return await self.daemon_request("masternode_broadcast", ("relay", signmnb))
        except DaemonError as e:
            (error,) = e.args
            message = error["message"]
            self.logger.info(f"masternode_broadcast: {message}")
            raise RPCError(
                BAD_REQUEST,
                "the masternode broadcast was " f"rejected.\n\n{message}\n[{signmnb}]",
            )

    async def masternode_subscribe(self, collateral):
        """Returns the status of masternode.

        collateral: masternode collateral.
        """
        result = await self.daemon_request("masternode_list", ("status", collateral))
        if result is not None:
            self.mns.add(collateral)
            return result.get(collateral)
        return None

    async def masternode_list(self, payees):
        """
        Returns the list of masternodes.

        payees: a list of masternode payee addresses.
        """
        if not isinstance(payees, list):
            raise RPCError(BAD_REQUEST, "expected a list of payees")

        def get_masternode_payment_queue(mns):
            """Returns the calculated position in the payment queue for all the
            valid masterernodes in the given mns list.

            mns: a list of masternodes information.
            """
            now = int(datetime.datetime.now(datetime.UTC).strftime("%s"))
            mn_queue = []

            # Only ENABLED masternodes are considered for the list.
            for line in mns:
                mnstat = mns[line].split()
                if mnstat[0] == "ENABLED":
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
            """
            Returns the position of the payment list for the given address.

            payment_queue: position in the payment queue for the masternode.
            address: masternode payee address.
            """
            position = -1
            for pos, mn in enumerate(payment_queue, start=1):
                if mn[2] == address:
                    position = pos
                    break
            return position

        # Accordingly with the masternode payment queue, a custom list
        # with the masternode information including the payment
        # position is returned.
        cache = self.mn_cache
        if not cache or self.session_mgr.mn_cache_height != self.db.db_height:
            full_mn_list = await self.daemon_request("masternode_list", ("full",))
            mn_payment_queue = get_masternode_payment_queue(full_mn_list)
            mn_payment_count = len(mn_payment_queue)
            mn_list = []
            for key, value in full_mn_list.items():
                mn_data = value.split()
                mn_info = {
                    "vin": key,
                    "status": mn_data[0],
                    "protocol": mn_data[1],
                    "payee": mn_data[2],
                    "lastseen": mn_data[3],
                    "activeseconds": mn_data[4],
                    "lastpaidtime": mn_data[5],
                    "lastpaidblock": mn_data[6],
                    "ip": mn_data[7],
                }
                mn_info["paymentposition"] = get_payment_position(mn_payment_queue, mn_info["payee"])
                mn_info["inselection"] = mn_info["paymentposition"] < mn_payment_count // 10
                hash_x = self.coin.address_to_hashX(mn_info["payee"])
                balance = await self.ss.get_balance(hash_x)
                mn_info["balance"] = sum(balance.values()) / self.coin.VALUE_PER_COIN
                mn_list.append(mn_info)
            cache.clear()
            cache.extend(mn_list)
            self.session_mgr.mn_cache_height = self.db.db_height

        # If payees is an empty list the whole masternode list is returned
        if payees:
            return [mn for mn in cache if mn["payee"] in payees]
        else:
            return cache

    async def protx_diff(self, base_height, height):
        """
        Calculates a diff between two deterministic masternode lists.
        The result also contains proof data.

        base_height: The starting block height (starting from 1).
        height: The ending block height.
        """
        if not isinstance(base_height, int) or not isinstance(height, int):
            raise RPCError(BAD_REQUEST, "expected a int block heights")

        max_height = self.db.db_height
        if not 1 <= base_height <= max_height or not base_height <= height <= max_height:
            raise RPCError(
                BAD_REQUEST,
                f"require 1 <= base_height {base_height:,d} <= "
                f"height {height:,d} <= "
                f"chain height {max_height:,d}",
            )

        return await self.daemon_request("protx", ("diff", base_height, height))

    async def protx_info(self, protx_hash):
        """
        Returns detailed information about a deterministic masternode.

        protx_hash: The hash of the initial ProRegTx
        """
        if not isinstance(protx_hash, str):
            raise RPCError(BAD_REQUEST, "expected protx hash string")

        res = await self.daemon_request("protx", ("info", protx_hash))
        if "wallet" in res:
            del res["wallet"]
        return res


class SmartCashElectrumX(DashElectrumX):
    """A TCP server that handles incoming Electrum-SMART connections."""

    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)
        self.request_handlers.update(
            {
                "smartrewards.current": self.smartrewards_current,
                "smartrewards.check": self.smartrewards_check,
            }
        )

    async def smartrewards_current(self):
        """Returns the current smartrewards info."""
        result = await self.daemon_request("smartrewards", ("current",))
        if result is not None:
            return result
        return None

    async def smartrewards_check(self, addr):
        """
        Returns the status of an address

        addr: a single smartcash address
        """
        result = await self.daemon_request("smartrewards", ("check", addr))
        if result is not None:
            return result
        return None


class AuxPoWElectrumX(ElectrumX):
    async def block_header(self, height, cp_height=0):
        result = await super().ss.block_header(height, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result["header"] = self.truncate_auxpow(result["header"], height)
        return result

    async def block_headers(self, start_height, count, cp_height=0):
        result = await super().ss.block_headers(start_height, count, cp_height)

        # Older protocol versions don't truncate AuxPoW
        if self.protocol_tuple < (1, 4, 1):
            return result

        # Not covered by a checkpoint; return full AuxPoW data
        if cp_height == 0:
            return result

        # Covered by a checkpoint; truncate AuxPoW data
        result["hex"] = self.truncate_auxpow(result["hex"], start_height)
        return result

    def truncate_auxpow(self, headers_full_hex, start_height):
        height = start_height
        headers_full = util.hex_to_bytes(headers_full_hex)
        cursor = 0
        headers = bytearray()

        while cursor < len(headers_full):
            headers += headers_full[cursor : cursor + self.coin.TRUNCATED_HEADER_SIZE]
            cursor += self.db.dynamic_header_len(height)
            height += 1

        return headers.hex()


class NameIndexElectrumX(ElectrumX):
    def set_request_handlers(self, ptuple):
        super().set_request_handlers(ptuple)

        if ptuple >= SESSION_PROTOCOL_MAX:
            self.request_handlers["blockchain.name.get_value_proof"] = self.name_get_value_proof

    async def name_get_value_proof(self, scripthash, cp_height=0):
        history = await self.ss.scripthash_get_history(scripthash)

        trimmed_history = []
        prev_height = None

        for update in history[::-1]:
            txid = update["tx_hash"]
            height = update["height"]

            if (
                self.coin.NAME_EXPIRATION is not None
                and prev_height is not None
                and height < prev_height - self.coin.NAME_EXPIRATION
            ):
                break

            tx = await self.ss.transaction_get(txid)
            update["tx"] = tx
            del update["tx_hash"]

            tx_merkle = await self.ss.transaction_merkle(txid, height)
            del tx_merkle["block_height"]
            update["tx_merkle"] = tx_merkle

            if height <= cp_height:
                header = await self.ss.block_header(height, cp_height)
                update["header"] = header

            trimmed_history.append(update)

            if height <= cp_height:
                break

            prev_height = height

        return {scripthash: trimmed_history}


class NameIndexAuxPoWElectrumX(NameIndexElectrumX, AuxPoWElectrumX):
    pass
