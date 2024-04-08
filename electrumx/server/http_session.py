# -*- coding: utf-8 -*-

import asyncio
import codecs
import datetime
import json
import time
import aiorpcx
from aiohttp import request, web
from aiorpcx import RPCError, ReplyAndDisconnect
from functools import reduce
from decimal import Decimal
import electrumx
from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder
from electrumx.lib.hash import HASHX_LEN, double_sha256, hash_to_hex_str, hex_str_to_hash, sha256
import electrumx.lib.util as util
from electrumx.lib.script2addr import get_address_from_output_script
from electrumx.lib.util_atomicals import DFT_MINT_MAX_MAX_COUNT_DENSITY, DMINT_PATH, MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS, SUBREALM_MINT_PATH, AtomicalsValidationError, auto_encode_bytes_elements, calculate_latest_state_from_mod_history, compact_to_location_id_bytes, expand_spend_utxo_data, format_name_type_candidates_to_rpc, format_name_type_candidates_to_rpc_for_subname, is_compact_atomical_id, location_id_bytes_to_compact, parse_protocols_operations_from_witness_array, validate_merkle_proof_dmint, validate_rules_data
from electrumx.server.daemon import DaemonError


BAD_REQUEST = 1
DAEMON_ERROR = 2
MAX_TX_QUERY = 50
ATOMICALS_INVALID_TX = 800422

def scripthash_to_hashX(scripthash):
    try:
        bin_hash = hex_str_to_hash(scripthash)
        if len(bin_hash) == 32:
            return bin_hash[:HASHX_LEN]
    except (ValueError, TypeError):
        pass
    raise RPCError(BAD_REQUEST, f'{scripthash} is not a valid script hash')
    

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


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)


class HttpHandler(object):

    PROTOCOL_MIN = (1, 4)
    PROTOCOL_MAX = (1, 4, 3)

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
        self.client = 'unknown'
        self.anon_logs = self.env.anon_logs
        self.txs_sent = 0
        self.log_me = False
        self.daemon_request = self.session_mgr.daemon_request
        self.mempool_statuses = {}
        self.sv_seen = False
        self.MAX_CHUNK_SIZE = 2016
        self.hashX_subs = {}

    async def format_params(self, request):
        if request.method == "GET":
            params = json.loads(request.query.get("params", "[]"))
        else:
            json_data = await request.json()
            params = json_data.get("params", [])
        return dict(zip(range(len(params)), params))
    
    async def get_rpc_server(self):
        for service in self.env.services:
            if service.protocol == 'tcp':
                return service
            
    def remote_address(self):
        '''Returns a NetAddress or None if not connected.'''
        return self.transport.remote_address()
    
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
    
    async def address_listunspent(self, request):
        '''Return the list of UTXOs of an address.'''
        addrs = request.match_info.get('addrs', '')
        if not addrs:
            return web.Response(status=404)
        list_addr = list(dict.fromkeys(addrs.split(',')))
        list_tx = list()
        for address in list_addr:
            hashX = self.address_to_hashX(address)
            list_utxo = await self.hashX_listunspent(hashX)
            for utxo in list_utxo:
                tx_detail = await self.transaction_get(utxo["tx_hash"])
                list_tx.append(await self.wallet_unspent(address, utxo, tx_detail))
        return web.json_response(list_tx)

    async def address(self, request):
        addr = request.match_info.get('addr', '')
        if not addr:
            return web.Response(status=404)
        addr_balance = await self.address_get_balance(addr)
        confirmed_sat = addr_balance["confirmed"]
        unconfirmed_sat = addr_balance["unconfirmed"]
        res = {"addrStr": addr,
               "balance": float(self.coin.decimal_value(confirmed_sat)),
               "balanceSat": confirmed_sat,
               "unconfirmedBalance": float(self.coin.decimal_value(unconfirmed_sat)),
               "unconfirmedBalanceSat": addr_balance["unconfirmed"]}
        return web.json_response(res)

    async def history(self, request):
        '''Query parameters check.'''
        addrs = request.match_info.get('addrs', '')
        query_str = request.rel_url.query
        query_from = util.parse_int(query_str['from'], 0) if 'from' in query_str else 0
        query_to = util.parse_int(query_str['to'], MAX_TX_QUERY) if 'to' in query_str else MAX_TX_QUERY
        if query_from < 0:
            return web.Response(status=400, text=f'Invalid state: "from" ({query_from}) is expected to be greater '
            f'than or equal to 0')

        if query_to < 0:
            return web.Response(status=400, text=f'Invalid state: "to" ({query_to}) is expected to be greater '
            f'than or equal to 0')

        if query_from > query_to:
            return web.Response(status=400, text=f'Invalid state: "from" ({query_from}) is '
            f'expected to be less than "to" ({query_to})')

        if not addrs:
            return web.Response(status=404)

        query_to = query_to if query_to - query_from < MAX_TX_QUERY else query_from + MAX_TX_QUERY

        list_addr = list(dict.fromkeys(addrs.split(',')))
        items = list()
        list_history = []
        for address in list_addr:
            list_history = list_history + await self.address_get_history(address)
        for i in range(len(list_history)):
            if i < query_from or i >= query_to:
                continue
            item = list_history[i]
            blockheight = item["height"]
            tx_detail = await self.transaction_get(item["tx_hash"], True)
            items.append(await self.wallet_history(blockheight, tx_detail))
        res = {"totalItems": len(list_history),
               "from": query_from,
               "to": query_to,
               "items": items}
        jsonStr = json.dumps(res, cls=DecimalEncoder)
        return web.json_response(json.loads(jsonStr))

    async def wallet_history(self, blockheight, tx_detail):
        txid = tx_detail["txid"]
        confirmations = tx_detail["confirmations"] if 'confirmations' in tx_detail else 0
        if 'time' in tx_detail:
            time = tx_detail["time"]
        else:
            # This is unconfirmed transaction, so get the time from memory pool
            # The time the transaction entered the memory pool, Unix epoch time format
            mempool = await self.mempool_get(True)
            tx = mempool.get(txid)
            if tx is not None:
                time = tx["time"] if 'time' in tx else None
            else:
                time = None
        if time is None:
            raise RPCError(BAD_REQUEST, f'cannot get the transaction\'s time')
        list_vin = tx_detail["vin"]
        list_vout = tx_detail["vout"]
        list_final_vin = [await self.vin_factory(item) for item in list_vin]
        value_in = Decimal(str(reduce(lambda prev, x: prev + x["value"], list_final_vin, 0)))
        value_out = Decimal(str(reduce(lambda prev, x: prev + x["value"], list_vout, 0)))
        value_in_places = value_in.as_tuple().exponent
        value_out_places = value_out.as_tuple().exponent
        min_places = min(value_in_places, value_out_places)
        if min_places < 0:
            pos = abs(min_places)
        else:
            pos = 0
        if value_in > 0:
            fees = round(value_in - value_out, pos)
        else:
            '''from Block Reward'''
            fees = 0

        return {"txid": txid,
                "blockheight": blockheight,
                "vin": list_final_vin,
                "vout": list_vout,
                "valueOut": value_out,
                "valueIn": value_in,
                "fees": fees,
                "confirmations": confirmations,
                "time": time}

    async def vin_factory(self, obj):
        if 'txid' in obj:
            txid = obj["txid"]
            vout = obj["vout"]
            tx_detail = await self.transaction_get(txid, True)
            list_vout = tx_detail["vout"]
            prev_vout = list_vout[vout]
            value = prev_vout["value"]
            addr = prev_vout["scriptPubKey"]["addresses"][0]
            return {
                "txid": txid,
                "addr": addr,
                "valueSat": value * self.coin.VALUE_PER_COIN,
                "value": value
            }
        else:
            '''from Block Reward'''
            obj["value"] = 0
            return obj

    async def wallet_unspent(self, address, utxo, tx_detail):
        height = utxo["height"]
        satoshis = utxo["value"]
        vout = utxo["tx_pos"]
        confirmations = tx_detail["confirmations"] if 'confirmations' in tx_detail else 0
        list_vout = tx_detail["vout"]
        list_pick = []
        for item in list_vout:
            '''In case some vout will contain OP_RETURN and no addresses key'''
            addr = item["scriptPubKey"]["addresses"][0] if 'addresses' in item["scriptPubKey"] else ""
            n = item["n"] if 'n' in item else ""
            if addr == address or (addr == "" and n == vout):
                list_pick.append(item)

        if len(list_pick) > 0:
            obj = list_pick[0]
            amount = obj["value"]
            script_pub_key = obj["scriptPubKey"]["hex"]
        else:
            raise Exception(f'cannot get the transaction\'s list of outputs from address:{address}')
        return {"address": address,
                "txid": tx_detail["txid"],
                "vout": vout,
                "scriptPubKey": script_pub_key,
                "amount": amount,
                "satoshis": satoshis,
                "height": height,
                "confirmations": confirmations}
    
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
        # self.bump_cost(cost + 0.1 + len(status) * 0.00002)

        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None

        if mempool:
            self.mempool_statuses[hashX] = status
        else:
            self.mempool_statuses.pop(hashX, None)

        return status

    async def hashX_subscribe(self, hashX, alias):
        # Store the subscription only after address_status succeeds
        result = await self.address_status(hashX)
        self.hashX_subs[hashX] = alias
        return result

    def address_to_hashX(self, address):
        try:
            return self.coin.address_to_hashX(address)
        except Exception:
            pass
        raise RPCError(BAD_REQUEST, f'{address} is not a valid address')

    async def address_get_balance(self, address):
        '''Return the confirmed and unconfirmed balance of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.get_balance(hashX)

    async def address_get_history(self, address):
        '''Return the confirmed and unconfirmed history of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def get_balance(self, hashX):
        utxos = await self.db.all_utxos(hashX)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = await self.mempool.balance_delta(hashX)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def unconfirmed_history(self, hashX):
        # Note unconfirmed history is unordered in electrum-server
        # height is -1 if it has unconfirmed inputs, otherwise 0
        return [{'tx_hash': hash_to_hex_str(tx.hash),
                 'height': -tx.has_unconfirmed_inputs,
                 'fee': tx.fee}
                for tx in await self.mempool.transaction_summaries(hashX)]
    
    async def confirmed_history(self, hashX):
        # Note history is ordered
        history, cost = await self.session_mgr.limited_history(hashX)
        conf = [{'tx_hash': hash_to_hex_str(tx_hash), 'height': height}
                for tx_hash, height in history]
        return conf

    async def confirmed_and_unconfirmed_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history, cost = await self.session_mgr.limited_history(hashX)
        conf = [{'tx_hash': hash_to_hex_str(tx_hash), 'height': height}
                for tx_hash, height in history]
        return conf + await self.unconfirmed_history(hashX)
    
    async def mempool_get(self, verbose=False):
        '''Returns all transaction ids in memory pool as a json array of string transaction ids

        verbose: True for a json object, false for array of transaction ids
        '''
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, f'"verbose" must be a boolean')

        return await self.daemon_request('getrawmempool', verbose)

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
    

    async def atomicals_list_get(self, limit, offset, asc):
        atomicals = await self.db.get_atomicals_list(limit, offset, asc)
        atomicals_populated = []
        for atomical_id in atomicals:
            atomical = await self.atomical_id_get(location_id_bytes_to_compact(atomical_id))
            atomicals_populated.append(atomical)
        return {'global': await self.get_summary_info(), 'result': atomicals_populated }
    

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
    
    # Perform a search for tickers, containers, realms, subrealms 
    def atomicals_search_name_template(self, db_prefix, name_type_str, parent_prefix=None, prefix=None, Reverse=False, Limit=100, Offset=0, is_verified_only=False):
        search_prefix = b''
        if prefix:
            search_prefix = prefix.encode()

        db_entries = self.db.get_name_entries_template_limited(db_prefix, parent_prefix, search_prefix, Reverse, Limit, Offset)
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
            obj[name_type_str] = item['name']
            obj[name_type_str + '_hex'] = item.get('name_hex')
            obj['status'] = status
            if is_verified_only and status == "verified":
                formatted_results.append(obj)
            elif not is_verified_only:
                formatted_results.append(obj)
        return {'result': formatted_results}
    
    def auto_populate_container_dmint_items_fields(self, items):
        if not items or not isinstance(items, dict):
            return {}
        for item, value in items.items():
            provided_id = value.get('id')
            if provided_id and isinstance(provided_id, bytes) and len(provided_id) == 36:
                value['$id'] = location_id_bytes_to_compact(provided_id)
        return auto_encode_bytes_elements(items)

    async def search_token(self, db_prefix, name_type_str, prefix=None, Reverse=False, Limit=100, Offset=0):
        search_prefix = b''
        if prefix:
            search_prefix = prefix.encode()
        db_entries = self.db.get_name_entries_template_limited(db_prefix, None, search_prefix, Reverse, Limit, Offset)
        formatted_results = []
        for item in db_entries:
            atomical_id = location_id_bytes_to_compact(item['atomical_id'])
            atomical_data = await self.atomical_id_get_ft_info(atomical_id)
            obj = {
                'atomical_id': (atomical_id),
                'tx_num': item['tx_num'],
                'atomical_data': atomical_data,
            }
            obj[name_type_str] = item['name']
            formatted_results.append(obj)
        return {'result': formatted_results}

    async def hashX_listunspent(self, hashX):
        '''Return the list of UTXOs of a script hash, including mempool
        effects.'''
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        # self.bump_cost(1.0 + len(utxos) / 50)
        spends = await self.mempool.potential_spends(hashX)
        returned_utxos = []
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = {}
            for atomical_id in atomicals:
                # This call is efficient in that it's cached underneath.
                # Now we only show the atomical id and its corresponding value
                # because it can always be fetched separately which is more efficient.
                # Todo need to combine mempool atomicals
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[atomical_id_compact] = self.db.get_uxto_atomicals_value(location, atomical_id)
            returned_utxos.append({
                'txid': hash_to_hex_str(utxo.tx_hash),
                'tx_hash': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'tx_pos': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'sat_value': utxo.value,
                'atomicals': atomicals_basic_infos
            })
        return returned_utxos
    
    async def hashX_ft_balances_atomicals(self, hashX):
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        spends = [] # await self.mempool.potential_spends(hashX)
        returned_utxos = []
        atomicals_id_map = {}
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = {}
            for atomical_id in atomicals: 
                # This call is efficient in that it's cached underneath
                # For now we only show the atomical id because it can always be fetched separately and it will be more efficient
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id) 
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = atomical_basic_info
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[atomical_id_compact] = self.db.get_uxto_atomicals_value(location, atomical_id)
            if len(atomicals) > 0:
                returned_utxos.append({'txid': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'sat_value': utxo.value,
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
                        return_struct['balances'][atomical_id_compact]['confirmed'] += returned_utxo['atomicals'][atomical_id_compact]
        return return_struct

    async def hashX_nft_balances_atomicals(self, hashX):
        Verbose = False
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        spends = [] # await self.mempool.potential_spends(hashX)
        returned_utxos = []
        atomicals_id_map = {}
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = {}
            for atomical_id in atomicals: 
                # This call is efficient in that it's cached underneath
                # For now we only show the atomical id because it can always be fetched separately and it will be more efficient
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id) 
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = atomical_basic_info
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[atomical_id_compact] = self.db.get_uxto_atomicals_value(location, atomical_id)
            if len(atomicals) > 0:
                returned_utxos.append({'txid': hash_to_hex_str(utxo.tx_hash),
                'index': utxo.tx_pos,
                'vout': utxo.tx_pos,
                'height': utxo.height,
                'value': utxo.value,
                'sat_value': utxo.value,
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
                        return_struct['balances'][atomical_id_compact]['confirmed'] += returned_utxo['atomicals'][atomical_id_compact]
        return return_struct
    
    def atomical_resolve_id(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = compact_atomical_id_or_atomical_number
        if not isinstance(compact_atomical_id_or_atomical_number, int) and is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            found_atomical_id = self.db.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number)
            if not found_atomical_id:
                raise RPCError(BAD_REQUEST, f'not found atomical: {compact_atomical_id_or_atomical_number}')
            compact_atomical_id = location_id_bytes_to_compact(found_atomical_id)
        return compact_atomical_id
    
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
    
    async def hashX_listscripthash_atomicals(self, hashX, Verbose=False):
        utxos = await self.db.all_utxos(hashX)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        spends = []  # await self.mempool.potential_spends(hashX)
        returned_utxos = []
        atomicals_id_map = {}
        for utxo in utxos:
            if (utxo.tx_hash, utxo.tx_pos) in spends:
                continue
            atomicals = self.db.get_atomicals_by_utxo(utxo, True)
            atomicals_basic_infos = {}
            for atomical_id in atomicals:
                # This call is efficient in that it's cached underneath.
                # Now we only show the atomical id and its corresponding value
                # because it can always be fetched separately which is more efficient.
                atomical_basic_info = await self.session_mgr.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = atomical_basic_info
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[atomical_id_compact] = self.db.get_uxto_atomicals_value(location, atomical_id)
            if Verbose or len(atomicals) > 0:
                returned_utxos.append({
                    'txid': hash_to_hex_str(utxo.tx_hash),
                    'index': utxo.tx_pos,
                    'vout': utxo.tx_pos,
                    'height': utxo.height,
                    'value': utxo.value,
                    'atomicals': atomicals_basic_infos
                })

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
                if return_struct['atomicals'].get(atomical_id_ref) is None:
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
                    return_struct['atomicals'][atomical_id_ref]['unconfirmed'] += returned_utxo["atomicals"][atomical_id_ref]
                else:
                    return_struct['atomicals'][atomical_id_ref]['confirmed'] += returned_utxo["atomicals"][atomical_id_ref]

        return return_struct
    
    ############################################
    #  get method
    ############################################
    async def handle_get_method(self, request):
        method = request.match_info.get('method', None)
        params = json.loads(request.query.get("params", "[]"))

        rpc_service = await self.get_rpc_server()
        async with aiorpcx.connect_rs(str(rpc_service.address.host), int(rpc_service.address.port)) as session:
            result = await session.send_request(method, params)
            await session.close()

        return result
    
    ############################################
    #  post method
    ############################################
    async def handle_post_method(self, request):
        json_data = await request.json()
        method = request.match_info.get('method', None)
        params = json_data.get("params", "[]")
        rpc_service = await self.get_rpc_server()
        async with aiorpcx.connect_rs(str(rpc_service.address.host), int(rpc_service.address.port)) as session:
            result = await session.send_request(method, params)
            await session.close()

        return result

    ############################################
    #  http method
    ############################################  

    # verified
    async def proxy(self, request):
        result = {"success":True,"info":{"note":"Atomicals ElectrumX Digital Object Proxy Online","usageInfo":{"note":"The service offers both POST and GET requests for proxying requests to ElectrumX. To handle larger broadcast transaction payloads use the POST method instead of GET.","POST":"POST /proxy/:method with string encoded array in the field \\\"params\\\" in the request body. ","GET":"GET /proxy/:method?params=[\\\"value1\\\"] with string encoded array in the query argument \\\"params\\\" in the URL."},"healthCheck":"GET /proxy/health","github":"https://github.com/atomicals/electrumx-proxy","license":"MIT"}}
        return web.json_response(data=result)

    # verified
    async def health(self, request):
        result = {"success": True,"health": True}
        return web.json_response(data=result)
    
    # verified
    async def atomicals_list(self, request):
        params = await self.format_params(request)
        offset = params.get(0, 100)
        limit = params.get(1, 0)
        asc = params.get(2, True)

        '''Return the list of atomicals order by reverse atomical number'''
        formatted_results = await self.atomicals_list_get(offset, limit, asc)
        return formatted_results
    
    # verified
    async def atomicals_get(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")

        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get(compact_atomical_id)}
    
    # verified
    async def scripthash_listunspent(self, request):
        '''Return the list of UTXOs of a scripthash.'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")

        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_listunspent(hashX)
    
    # need verify
    async def transaction_broadcast(self, request):
        '''Broadcast a raw transaction to the network.
        raw_tx: the raw transaction as a hexadecimal string'''
        params = await self.format_params(request)
        raw_tx = params.get(0, "")

        # self.bump_cost(0.25 + len(raw_tx) / 5000)
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
    
    # verified
    async def scripthash_get_history(self, request):
        '''Return the confirmed and unconfirmed history of a scripthash.'''
        try:
            params = await self.format_params(request)
            scripthash = params.get(0, "")
        except Exception as e:
            scripthash = request

        hashX = scripthash_to_hashX(scripthash)
        return await self.confirmed_and_unconfirmed_history(hashX)
    
    # verified
    async def transaction_get(self, request):
        '''Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        '''
        params = await self.format_params(request)
        tx_hash = params.get(0, "")
        verbose = params.get(1, False)

        assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, '"verbose" must be a boolean')
        
        return await self.daemon_request('getrawtransaction', tx_hash, verbose)
    
    # verified
    async def atomical_get_state(self, request):
        # async def atomical_get_state(self, compact_atomical_id_or_atomical_number, Verbose=False):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")
        Verbose = params.get(0, False)

        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_state(compact_atomical_id, Verbose)}
    
    # verified
    async def scripthash_get_balance(self, request):
        '''Return the confirmed and unconfirmed balance of a scripthash.'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")

        hashX = scripthash_to_hashX(scripthash)
        return await self.get_balance(hashX)
    
    # verified
    async def atomicals_get_location(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_location(compact_atomical_id)}
    
    # verified
    async def atomicals_listscripthash(self, request):
        '''Return the list of Atomical UTXOs for an address'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")
        Verbose = params.get(1, False)

        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_listscripthash_atomicals(hashX, Verbose)
    
    # verified
    async def atomicals_get_global(self, request):
        params = await self.format_params(request)
        hashes = params.get(0, 10)
        return {'global': await self.get_summary_info(hashes)}
    
    async def block_header(self, request):
        '''Return a raw block header as a hexadecimal string, or as a
        dictionary with a merkle proof.'''
        params = await self.format_params(request)
        height = params.get(0, 0)
        cp_height = params.get(1, 0)
        height = non_negative_integer(height)
        cp_height = non_negative_integer(cp_height)
        raw_header_hex = (await self.session_mgr.raw_header(height)).hex()
        if cp_height == 0:
            return raw_header_hex
        result = {'header': raw_header_hex}
        result.update(await self._merkle_proof(cp_height, height))
        return result

    async def block_headers(self, request):
        '''Return count concatenated block headers as hex for the main chain;
        starting at start_height.

        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        '''
        params = await self.format_params(request)
        start_height = params.get(0, 0)
        count = params.get(1, 0)
        cp_height = params.get(2, 0)

        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)
        cp_height = non_negative_integer(cp_height)

        max_size = self.MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.db.read_headers(start_height, count)
        result = {'hex': headers.hex(), 'count': count, 'max': max_size}
        if count and cp_height:
            last_height = start_height + count - 1
            result.update(await self._merkle_proof(cp_height, last_height))
        return result
    
    async def estimatefee(self, request):
        '''The estimated transaction fee per kilobyte to be paid for a
        transaction to be included within a certain number of blocks.

        number: the number of blocks
        mode: CONSERVATIVE or ECONOMICAL estimation mode
        '''
        params = await self.format_params(request)
        number = params.get(0, 0)
        mode = params.get(1, None)

        number = non_negative_integer(number)
        # use whitelist for mode, otherwise it would be easy to force a cache miss:
        if mode not in self.coin.ESTIMATEFEE_MODES:
            raise RPCError(BAD_REQUEST, f'unknown estimatefee mode: {mode}')

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
            blockhash = self.session_mgr.bp.tip
            if mode:
                feerate = await self.daemon_request('estimatefee', number, mode)
            else:
                feerate = await self.daemon_request('estimatefee', number)
            assert feerate is not None
            assert blockhash is not None
            cache[(number, mode)] = (blockhash, feerate, lock)
            return feerate
        
    async def headers_subscribe(self, request):
        '''Subscribe to get raw headers of new blocks.'''
        self.subscribe_headers = True
        return self.session_mgr.hsub_results
    
    async def relayfee(self, request):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        return await self.daemon_request('relayfee')
    
    async def scripthash_get_mempool(self, request):
        '''Return the mempool transactions touching a scripthash.'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")

        hashX = scripthash_to_hashX(scripthash)
        return await self.unconfirmed_history(hashX)
    
    async def scripthash_subscribe(self, request):
        '''Subscribe to a script hash.

        scripthash: the SHA256 hash of the script to subscribe to'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)
    
    async def transaction_merkle(self, request):
        '''Return the merkle branch to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        '''
        params = await self.format_params(request)
        tx_hash = params.get(0, "")
        height = params.get(1, "")

        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos, cost = await self.session_mgr.merkle_branch_for_tx_hash(
            height, tx_hash)

        res = {"block_height": height, "merkle": branch, "pos": tx_pos}
        return res
    
    async def transaction_id_from_pos(self, request):
        '''Return the txid and optionally a merkle proof, given
        a block height and position in the block.
        '''
        params = await self.format_params(request)
        height = params.get(0, 0)
        tx_pos = params.get(1, 0)
        merkle = params.get(2, False)

        tx_pos = non_negative_integer(tx_pos)
        height = non_negative_integer(height)
        if merkle not in (True, False):
            raise RPCError(BAD_REQUEST, '"merkle" must be a boolean')

        if merkle:
            branch, tx_hash, cost = await self.session_mgr.merkle_branch_for_tx_pos(
                height, tx_pos)
            return {"tx_hash": tx_hash, "merkle": branch}
        else:
            tx_hashes, cost = await self.session_mgr.tx_hashes_at_blockheight(height)
            try:
                tx_hash = tx_hashes[tx_pos]
            except IndexError:
                raise RPCError(BAD_REQUEST,
                               f'no tx at position {tx_pos:,d} in block at height {height:,d}')
            return hash_to_hex_str(tx_hash)
        
    async def compact_fee_histogram(self, request):
        return await self.mempool.compact_fee_histogram()
    
    async def rpc_add_peer(self, request):
        '''Add a peer.

        real_name: "bch.electrumx.cash t50001 s50002" for example
        '''
        params = await self.format_params(request)
        real_name = params.get(0, "")
        await self.peer_mgr.add_localRPC_peer(real_name)
        
        res = f"peer '{real_name}' added"
        return res

    async def add_peer(self, request):
        '''Add a peer (but only if the peer resolves to the source).'''
        params = await self.format_params(request)
        features = params.get(0, None)
        self.is_peer = True
        return await self.peer_mgr.on_add_peer(features, self.remote_address())
    
    async def banner(self, request):
        '''Return the server banner text.'''
        banner = f'You are connected to an {electrumx.version} server.'
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
    
    async def donation_address(self, request):
        '''Return the donation address as a string, empty if there is none.'''
        return self.env.donation_address
    
    async def server_features_async(self, request):
        return self.server_features(self.env)
    
    async def peers_subscribe(self, request):
        '''Return the server peers as a list of (ip, host, details) tuples.'''
        return self.peer_mgr.on_peers_subscribe(self.is_tor())
    
    async def ping(self, request):
        '''Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        '''
        return None
    
    async def server_version(self, request):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        params = await self.format_params(request)
        client_name = params.get(0, "")
        protocol_version = params.get(1, None)

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
    
    async def transaction_broadcast_validate(self, request):
        '''Simulate a Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string to validate for Atomicals FT rules'''
        params = await self.format_params(request)
        raw_tx = params.get(0, "")
        # This returns errors as JSON RPC errors, as is natural
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, False)
            return hex_hash
        except AtomicalsValidationError as e:
            self.logger.info(f'error validating atomicals transaction: {e}')
            raise RPCError(ATOMICALS_INVALID_TX, 'the transaction was rejected by '
                           f'atomicals rules.\n\n{e}\n[{raw_tx}]')
        
    async def atomicals_get_ft_balances(self, request):
        '''Return the FT balances for a scripthash address'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_ft_balances_atomicals(hashX)

    async def atomicals_get_nft_balances(self, request):
        '''Return the NFT balances for a scripthash address'''
        params = await self.format_params(request)
        scripthash = params.get(0, "")
        hashX = scripthash_to_hashX(scripthash)
        return await self.hashX_nft_balances_atomicals(hashX)
    
    async def atomicals_num_to_id(self, request):
        params = await self.format_params(request)
        limit = params.get(0, 10)
        offset = params.get(1, 0)
        asc = params.get(2, False)

        atomicals_num_to_id_map = await self.db.get_num_to_id(limit, offset, asc)
        atomicals_num_to_id_map_reformatted = {}
        for num, id in atomicals_num_to_id_map.items():
            atomicals_num_to_id_map_reformatted[num] = location_id_bytes_to_compact(id)
        return {'global': await self.get_summary_info(), 'result': atomicals_num_to_id_map_reformatted }
    
    async def atomicals_block_txs(self, request):
        params = await self.format_params(request)
        height = params.get(0, "")
        tx_list = self.session_mgr.bp.get_atomicals_block_txs(height)
        return {'global': await self.get_summary_info(), 'result': tx_list }
    
    async def atomicals_dump(self, request):
        self.db.dump()
        return {'result': True}

    async def atomicals_at_location(self, request):
        '''Return the Atomicals at a specific location id```
        '''
        params = await self.format_params(request)
        compact_location_id = params.get(0, "")

        atomical_basic_infos = []
        atomicals_found_at_location = self.db.get_atomicals_by_location_extended_info_long_form(compact_to_location_id_bytes(compact_location_id))
        # atomicals_found_at_location['atomicals']
        # atomicals_found_at_location['atomicals'].sort(key=lambda x: x['atomical_number'])
        for atomical_id in atomicals_found_at_location['atomicals']:
            atomical_basic_info = self.session_mgr.bp.get_atomicals_id_mint_info_basic_struct(atomical_id)
            atomical_basic_infos.append(atomical_basic_info)
        return {
            'location_info': atomicals_found_at_location['location_info'],
            'atomicals': atomical_basic_infos
        }

    async def atomical_get_state_history(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")

        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_state_history(compact_atomical_id)}
    
    async def atomical_get_events(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")

        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_events(compact_atomical_id)}    

    async def atomicals_get_tx_history(self, request):
        '''Return the history of an Atomical```
        atomical_id: the mint transaction hash + 'i'<index> of the atomical id
        verbose: to determine whether to print extended information
        '''
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")

        compact_atomical_id = compact_atomical_id_or_atomical_number
        if isinstance(compact_atomical_id_or_atomical_number, int) != True and is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            compact_atomical_id = location_id_bytes_to_compact(self.db.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number))
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_tx_history(compact_atomical_id)}

    # Get a summary view of a realm and if it's allowing mints and what parts already existed of a subrealm
    async def atomicals_get_realm_info(self, request):
        params = await self.format_params(request)
        full_name = params.get(0, "")
        Verbose = params.get(1, False)

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
    
    async def atomicals_get_by_realm(self, request):
        params = await self.format_params(request)
        name = params.get(0, "")

        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_realm(name, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id
        if status is None:
            formatted_entries = []

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'realm'
        }
        res = {
            'result': return_result
        }
        return res
    
    async def atomicals_get_by_subrealm(self, request):
        params = await self.format_params(request)
        parent_compact_atomical_id_or_atomical_number = params.get(0, "")
        name = params.get(1, "")

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
        if status is None:
            formatted_entries = []

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'subrealm'
        }
        res = {
            'result': return_result
        }
        return res
    
    async def atomicals_get_by_dmitem(self, request):
        params = await self.format_params(request)
        parent_compact_atomical_id_or_atomical_number = params.get(0, "")
        name = params.get(1, "")

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
        if status is None:
            formatted_entries = []

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'dmitem'
        }
        res = {
            'result': return_result
        }
        return res
    
    # verified
    async def atomicals_get_by_ticker(self, request):
        params = await self.format_params(request)
        ticker = params.get(0, "")

        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_ticker(ticker, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id
        if status is None:
            formatted_entries = []

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
    
    async def atomicals_get_by_container(self, request):
        params = await self.format_params(request)
        container = params.get(0, "")

        height = self.session_mgr.bp.height
        status, candidate_atomical_id, all_entries = self.session_mgr.bp.get_effective_container(container, height)
        formatted_entries = format_name_type_candidates_to_rpc(all_entries, self.session_mgr.bp.build_atomical_id_to_candidate_map(all_entries))

        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)

        found_atomical_id = None
        if status == 'verified':
            found_atomical_id = candidate_atomical_id
        if status is None:
            formatted_entries = []

        return_result = {
            'status': status,
            'candidate_atomical_id': candidate_atomical_id,
            'atomical_id': found_atomical_id,
            'candidates': formatted_entries,
            'type': 'container'
        }
        res = {
            'result': return_result
        }
        return res
    
    async def atomicals_get_by_container_item(self, request):
        params = await self.format_params(request)
        container = params.get(0, "")
        item_name = params.get(1, "")

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
        if status is None:
            formatted_entries = []

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

    async def atomicals_get_by_container_item_validation(self, request):
        params = await self.format_params(request)
        container = params.get(0, "")
        item_name = params.get(1, "")
        bitworkc = params.get(2, "")
        bitworkr = params.get(3, "")
        main_name = params.get(4, "")
        main_hash = params.get(5, "")
        proof = params.get(6, "")
        check_without_sealed = params.get(7, "")

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
        if not container_dmint_status or container_dmint_status.get('status') != 'valid':
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
        res = {
            'result': return_result
        }
        return res
    
    def auto_populate_container_regular_items_fields(self, items):
        if not items or not isinstance(items, dict):
            return {}
        for item, value in items.items():
            provided_id = value.get('id') 
            value['status'] = 'verified'
            if provided_id and isinstance(provided_id, bytes) and len(provided_id) == 36:
                value['$id'] = location_id_bytes_to_compact(provided_id)
        return auto_encode_bytes_elements(items)

    async def atomicals_get_container_items(self, request):
        params = await self.format_params(request)
        container = params.get(0, "")
        limit = params.get(1, 10)
        offset = params.get(2, 0)

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
            res = {
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
            res = {
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
        return res
    
    async def atomicals_get_ft_info(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")
        compact_atomical_id = self.atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {'global': await self.get_summary_info(), 'result': await self.atomical_id_get_ft_info(compact_atomical_id)}
    
    async def atomicals_get_dft_mints(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")
        atomical_id = compact_to_location_id_bytes(compact_atomical_id_or_atomical_number)
        Limit = params.get(1, 100)
        Offset = params.get(2, 0)
        return {'global': await self.get_summary_info(), 'result': self.session_mgr.bp.get_distmints_by_atomical_id(atomical_id, Limit, Offset)} 
    
    # verified
    async def atomicals_search_tickers(self, request):
        params = await self.format_params(request)
        prefix = params.get(0, None)
        Reverse = params.get(1, False)
        Limit = params.get(2, 100)
        Offset = params.get(3, 0)
        is_verified_only = params.get(4, True)
        return self.atomicals_search_name_template(b'tick', 'ticker', None, prefix, Reverse, Limit, Offset, is_verified_only)
    
    async def atomicals_search_realms(self, request):
        params = await self.format_params(request)
        prefix = params.get(0, None)
        Reverse = params.get(1, False)
        Limit = params.get(2, 100)
        Offset = params.get(3, 0)
        is_verified_only = params.get(4, True)
        return self.atomicals_search_name_template(b'rlm', 'realm', None, prefix, Reverse, Limit, Offset, is_verified_only)

    async def atomicals_search_subrealms(self, request):
        params = await self.format_params(request)
        parent_realm_id_compact = params.get(0, "")
        prefix = params.get(1, None)
        Reverse = params.get(2, False)
        Limit = params.get(3, 100)
        Offset = params.get(4, 0)
        is_verified_only = params.get(5, True)
        parent_realm_id_long_form = compact_to_location_id_bytes(parent_realm_id_compact)
        return self.atomicals_search_name_template(b'srlm', 'subrealm', parent_realm_id_long_form, prefix, Reverse, Limit, Offset, is_verified_only)

    async def atomicals_search_containers(self, request):
        params = await self.format_params(request)
        prefix = params.get(0, None)
        Reverse = params.get(1, False)
        Limit = params.get(2, 100)
        Offset = params.get(3, 0)
        is_verified_only = params.get(4, True)
        return self.atomicals_search_name_template(b'co', 'collection', None, prefix, Reverse, Limit, Offset, is_verified_only)
    
    async def atomicals_get_holders(self, request):
        '''Return the holder by a specific location id```
        '''
        params = await self.format_params(request)
        compact_atomical_id = params.get(0, "")
        limit = params.get(1, 50)
        offset = params.get(2, 0)

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
    
    # analysis the transaction detail by txid
    # might be mint-dft, dmint, transfer, burn...
    async def get_transaction_detail(self, txid, height=None, tx_num=-1):
        tx_hash = hex_str_to_hash(txid)
        res = self.session_mgr._tx_detail_cache.get(tx_hash)
        if res:
            # txid maybe the same, this key should add height add key prefix
            self.logger.debug(f"read transation detail from cache {txid}")
            return res
        if not height:
            tx_num, height = self.db.get_tx_num_height_from_tx_hash(tx_hash)
            if not tx_num:
                height = 0
                tx_num = -1

        res = {}
        raw_tx = self.db.get_raw_tx_by_tx_hash(tx_hash)
        if not raw_tx:
            raw_tx = await self.daemon_request('getrawtransaction', txid, False)
            raw_tx = bytes.fromhex(raw_tx)
        tx, _tx_hash = self.coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
        assert(tx_hash == _tx_hash)

        operation_found_at_inputs = parse_protocols_operations_from_witness_array(tx, tx_hash, True)
        atomicals_spent_at_inputs = self.session_mgr.bp.build_atomicals_spent_at_inputs_for_validation_only(tx)
        atomicals_receive_at_outputs = self.session_mgr.bp.build_atomicals_receive_at_ouutput_for_validation_only(tx, tx_hash)
        blueprint_builder = AtomicalsTransferBlueprintBuilder(self.logger, atomicals_spent_at_inputs, operation_found_at_inputs, tx_hash, tx, self.session_mgr.bp.get_atomicals_id_mint_info, True, self.session_mgr.bp.is_split_activated(height))
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
            "transfers":{
                "inputs": {},
                "outputs": {},
                "is_burned": is_burned,
                "burned_fts": burned_fts,
                "is_cleanly_assigned": is_cleanly_assigned
            }
        }
        if operation_found_at_inputs:
            res["info"]["payload"] = operation_found_at_inputs.get("payload", {})
        if blueprint_builder.is_mint and operation_found_at_inputs["op"] in ["dmt", "ft"]:
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
                                "value": txout.value,
                                "sat_value": txout.value,
                                "atomical_value": txout.value
                            }]
                        }
                    }
            else:
                res["op"] = f"{res['op']}-failed"
        elif operation_found_at_inputs and operation_found_at_inputs["op"] == "nft":
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
                atomical_id = location_id_bytes_to_compact(atomicals_receive_at_outputs[expected_output_index][0]["atomical_id"])
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
                            "value": txout.value,
                            "sat_value": txout.value,
                            "atomical_value": txout.value
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
                    prev_tx, prev_tx_hash = self.coin.DESERIALIZER(prev_raw_tx, 0).read_tx_and_hash()
                    location = prev_tx_hash + util.pack_le_uint32(tx.inputs[i.txin_index].prev_idx)
                    sat_value = prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].value
                    atomical_value = self.db.get_uxto_atomicals_value(location, atomical_id)
                    ft_data = {
                        "address": get_address_from_output_script(prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].pk_script),
                        "atomical_id": compact_atomical_id,
                        "type": "FT",
                        "index": i.txin_index,
                        "value": sat_value,
                        "sat_value": sat_value,
                        "atomical_value": atomical_value,
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
                        "value": output_ft.sat_value,
                        "sat_value": output_ft.sat_value,
                        "atomical_value": output_ft.atomical_value
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
                    prev_tx, prev_tx_hash = self.coin.DESERIALIZER(prev_raw_tx, 0).read_tx_and_hash()
                    location = prev_tx_hash + util.pack_le_uint32(tx.inputs[i.txin_index].prev_idx)
                    sat_value = prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].value
                    atomical_value = self.db.get_uxto_atomicals_value(location, atomical_id)
                    nft_data = {
                        "address": get_address_from_output_script(prev_tx.outputs[tx.inputs[i.txin_index].prev_idx].pk_script),
                        "atomical_id": compact_atomical_id,
                        "type": "NFT",
                        "index": i.txin_index,
                        "value": sat_value,
                        "sat_value": sat_value,
                        "atomical_value": atomical_value
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
                        "value": output_nft.total_sat_value,
                        "sat_value": output_nft.total_sat_value,
                        "atomical_value": output_nft.total_sat_value
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

        if res.get("op") and height > 0:
            self.session_mgr._tx_detail_cache[tx_hash] = res

        # Recursively encode the result.
        return auto_encode_bytes_elements(res)

    async def atomicals_transaction(self, request):
        params = await self.format_params(request)
        txid = params.get(0, "")
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
    async def transaction_by_height(self, request):
        params = await self.format_params(request)
        height = params.get(0, "")
        limit = params.get(1, 10)
        offset = params.get(2, 0)
        op_type = params.get(3, None)
        reverse = params.get(4, True)

        res, total = await self.get_transaction_detail_by_height(height, limit, offset, op_type, reverse)
        return {"result": res, "total": total, "limit": limit, "offset": offset}
    
    # get transaction by atomical id
    async def transaction_by_atomical_id(self, request):
        params = await self.format_params(request)
        compact_atomical_id_or_atomical_number = params.get(0, "")
        limit = params.get(1, 10)
        offset = params.get(2, 0)
        op_type = params.get(3, None)
        reverse = params.get(4, True)

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
    async def transaction_by_scripthash(self, request):
        params = await self.format_params(request)
        scripthash = params.get(0, "")
        limit = params.get(1, 10)
        offset = params.get(2, 0)
        op_type = params.get(3, None)
        reverse = params.get(4, True)

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
    
    # searh for global
    async def transaction_global(self, request):
        params = await self.format_params(request)
        limit = params.get(0, 10)
        offset = params.get(1, 0)
        op_type = params.get(2, None)
        reverse = params.get(3, True)
        height = self.session_mgr.bp.height
        
        res = []
        count = 0
        history_list = []
        for current_height in range(height, self.coin.ATOMICALS_ACTIVATION_HEIGHT, -1):
            txs = self.db.get_atomicals_block_txs(current_height)
            for tx in txs:
                tx_num, _ = self.db.get_tx_num_height_from_tx_hash(hex_str_to_hash(tx))
                history_list.append({
                    "tx_num": tx_num, 
                    "tx_hash": tx,
                    "height": current_height
                })
                count += 1
            if count >= offset + limit:
                break
        history_list.sort(key=lambda x: x['tx_num'], reverse=reverse)
        
        for history in history_list:
            data = await self.get_transaction_detail(history["tx_hash"], history["height"], history["tx_num"])
            if (op_type and op_type == data["op"]) or (not op_type and data["op"]):
                res.append(data)
        total = len(res)
        return {"result": res[offset:offset+limit], "total": total, "limit": limit, "offset": offset}
