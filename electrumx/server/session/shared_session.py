import asyncio
import datetime
from logging import LoggerAdapter
from typing import TYPE_CHECKING, Callable, Optional, Union

from aiorpcx import RPCError

from electrumx.lib import util
from electrumx.lib.atomicals_blueprint_builder import AtomicalsValidationError
from electrumx.lib.hash import double_sha256, hash_to_hex_str, hex_str_to_hash, sha256
from electrumx.lib.psbt import parse_psbt_hex_and_operations
from electrumx.lib.script2addr import get_address_from_output_script
from electrumx.lib.util_atomicals import (
    DFT_MINT_MAX_MAX_COUNT_DENSITY,
    DMINT_PATH,
    MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
    SUBREALM_MINT_PATH,
    auto_encode_bytes_elements,
    calculate_latest_state_from_mod_history,
    compact_to_location_id_bytes,
    format_name_type_candidates_to_rpc,
    format_name_type_candidates_to_rpc_for_subname,
    is_compact_atomical_id,
    location_id_bytes_to_compact,
    validate_merkle_proof_dmint,
    validate_rules_data,
)
from electrumx.server.daemon import DaemonError
from electrumx.server.session import ATOMICALS_INVALID_TX, BAD_REQUEST
from electrumx.server.session.util import (
    SESSION_BASE_MAX_CHUNK_SIZE,
    assert_atomical_id,
    assert_tx_hash,
    non_negative_integer,
    scripthash_to_hash_x,
)

if TYPE_CHECKING:
    from electrumx.lib.coins import AtomicalsCoinMixin, Coin
    from electrumx.server.peers import PeerManager
    from electrumx.server.session.session_manager import SessionManager


class SharedSession(object):
    def __init__(
        self,
        logger: LoggerAdapter,
        coin: Union["Coin", "AtomicalsCoinMixin"],
        session_mgr: "SessionManager",
        peer_mgr: "PeerManager",
        client: str,
        maybe_bump_cost: Optional[Callable[[float], None]] = None,
    ):
        self.client: str = client
        self.coin = coin
        self.logger = logger
        self.session_mgr = session_mgr
        self.peer_mgr = peer_mgr
        self.maybe_bump_cost = maybe_bump_cost

        self.bp = session_mgr.bp
        self.daemon_request = session_mgr.daemon_request
        self.db = session_mgr.db
        self.env = session_mgr.env
        self.mempool = session_mgr.mempool
        self.subscribe_headers = False
        self.mempool_status = {}
        self.hash_x_subs = {}
        self.txs_sent: int = 0
        self.is_peer = False

    def bump_cost(self, amount: float):
        if self.maybe_bump_cost:
            self.maybe_bump_cost(amount)

    ################################################################################################################

    async def donation_address(self):
        """Return the donation address as a string, empty if there is none."""
        self.bump_cost(0.1)
        return self.env.donation_address

    async def ping(self):
        """Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        """
        self.bump_cost(0.1)
        return None

    async def block_header(self, height, cp_height=0):
        """Return a raw block header as a hexadecimal string, or as a
        dictionary with a merkle proof."""
        height = non_negative_integer(height)
        cp_height = non_negative_integer(cp_height)
        raw_header_hex = (await self.session_mgr.raw_header(height)).hex()
        self.bump_cost(1.25 - (cp_height == 0))
        if cp_height == 0:
            return raw_header_hex
        result = {"header": raw_header_hex}
        result.update(await self._merkle_proof(cp_height, height))
        return result

    async def block_headers(self, start_height, count, cp_height=0):
        """Return count concatenated block headers as hex for the main chain;
        starting at start_height.

        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        """
        start_height = non_negative_integer(start_height)
        count = non_negative_integer(count)
        cp_height = non_negative_integer(cp_height)
        cost = count / 50

        max_size = SESSION_BASE_MAX_CHUNK_SIZE
        count = min(count, max_size)
        headers, count = await self.db.read_headers(start_height, count)
        result = {"hex": headers.hex(), "count": count, "max": max_size}
        if count and cp_height:
            cost += 1.0
            last_height = start_height + count - 1
            result.update(await self._merkle_proof(cp_height, last_height))
        self.bump_cost(cost)
        return result

    def headers_subscribe(self):
        """Subscribe to get raw headers of new blocks."""
        if not self.subscribe_headers:
            self.subscribe_headers = True
            self.bump_cost(0.25)
        return self.subscribe_headers_result()

    def subscribe_headers_result(self):
        """The result of a header subscription or notification."""
        return self.session_mgr.hsub_results

    async def estimate_fee(self, number, mode=None):
        """The estimated transaction fee per kilobyte to be paid for a
        transaction to be included within a certain number of blocks.

        number: the number of blocks
        mode: CONSERVATIVE or ECONOMICAL estimation mode
        """
        number = non_negative_integer(number)
        # use whitelist for mode, otherwise it would be easy to force a cache miss:
        if mode not in self.coin.ESTIMATEFEE_MODES:
            raise RPCError(BAD_REQUEST, f"unknown estimatefee mode: {mode}")
        self.bump_cost(0.1)

        number = self.coin.bucket_estimatefee_block_target(number)
        cache = self.session_mgr.estimatefee_cache

        cache_item = cache.get((number, mode))
        if cache_item is not None:
            blockhash, fee_rate, lock = cache_item
            if blockhash and blockhash == self.bp.tip:
                return fee_rate
        else:
            # create lock now, store it, and only then await on it
            lock = asyncio.Lock()
            cache[(number, mode)] = (None, None, lock)
        async with lock:
            cache_item = cache.get((number, mode))
            if cache_item is not None:
                blockhash, fee_rate, lock = cache_item
                if blockhash == self.bp.tip:
                    return fee_rate
            self.bump_cost(2.0)  # cache miss incurs extra cost
            blockhash = self.bp.tip
            if mode:
                fee_rate = await self.daemon_request("estimatefee", number, mode)
            else:
                fee_rate = await self.daemon_request("estimatefee", number)
            assert fee_rate is not None
            assert blockhash is not None
            cache[(number, mode)] = (blockhash, fee_rate, lock)
            return fee_rate

    async def relay_fee(self):
        """The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool."""
        self.bump_cost(1.0)
        return await self.daemon_request("relayfee")

    async def scripthash_get_balance(self, scripthash):
        """Return the confirmed and unconfirmed balance of a scripthash."""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self.get_balance(hash_x)

    async def scripthash_get_history(self, scripthash):
        """Return the confirmed and unconfirmed history of a scripthash."""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._confirmed_and_unconfirmed_history(hash_x)

    async def scripthash_get_mempool(self, scripthash):
        """Return the mempool transactions touching a scripthash."""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._unconfirmed_history(hash_x)

    async def scripthash_list_unspent(self, scripthash):
        """Return the list of UTXOs of a scripthash."""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._hash_x_list_unspent(hash_x)

    async def scripthash_subscribe(self, scripthash):
        """Subscribe to a script hash.

        scripthash: the SHA256 hash of the script to subscribe to"""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._hash_x_subscribe(hash_x, scripthash)

    async def scripthash_unsubscribe(self, scripthash):
        """Unsubscribe from a script hash."""
        self.bump_cost(0.1)
        hash_x = scripthash_to_hash_x(scripthash)
        return self.unsubscribe_hash_x(hash_x) is not None

    async def compact_fee_histogram(self):
        self.bump_cost(1.0)
        return await self.mempool.compact_fee_histogram()

    async def atomicals_get_ft_balances(self, scripthash):
        """Return the FT balances for a scripthash address"""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._hash_x_ft_balances_atomicals(hash_x)

    async def atomicals_get_nft_balances(self, scripthash):
        """Return the NFT balances for a scripthash address"""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._hash_x_nft_balances_atomicals(hash_x)

    async def atomicals_list_scripthash(self, scripthash, verbose=False):
        """Return the list of Atomical UTXOs for an address"""
        hash_x = scripthash_to_hash_x(scripthash)
        return await self._hash_x_list_scripthash_atomicals(hash_x, verbose)

    async def atomicals_list(self, limit, offset, asc):
        atomicals = await self.db.get_atomicals_list(limit, offset, asc)
        atomicals_populated = []
        for atomical_id in atomicals:
            atomical = await self._atomical_id_get(location_id_bytes_to_compact(atomical_id))
            atomicals_populated.append(atomical)
        return {"global": await self._get_summary_info(), "result": atomicals_populated}

    async def atomicals_num_to_id(self, limit, offset, asc):
        atomicals_num_to_id_map = await self.db.get_num_to_id(limit, offset, asc)
        atomicals_num_to_id_map_reformatted = {}
        for num, atomical_id in atomicals_num_to_id_map.items():
            atomicals_num_to_id_map_reformatted[num] = location_id_bytes_to_compact(atomical_id)
        return {
            "global": await self._get_summary_info(),
            "result": atomicals_num_to_id_map_reformatted,
        }

    async def atomicals_block_hash(self, height):
        if not height:
            height = self.bp.height
        block_hash = self.db.get_atomicals_block_hash(height)
        return {"result": block_hash}

    async def atomicals_block_txs(self, height):
        tx_list = self.bp.get_atomicals_block_txs(height)
        return {"global": await self._get_summary_info(), "result": tx_list}

    async def atomicals_dump(self):
        self.db.dump()
        return {"result": True}

    async def atomicals_at_location(self, compact_location_id):
        """Return the Atomicals at a specific location id```"""
        atomical_basic_infos = []
        atomicals_found_at_location = self.db.get_atomicals_by_location_extended_info_long_form(
            compact_to_location_id_bytes(compact_location_id)
        )
        for atomical_id in atomicals_found_at_location["atomicals"]:
            basic_info = self.bp.get_atomicals_id_mint_info_basic_struct(atomical_id)
            basic_info["value"] = self.db.get_uxto_atomicals_value(
                compact_to_location_id_bytes(compact_location_id), atomical_id
            )
            atomical_basic_infos.append(basic_info)
        return {
            "location_info": atomicals_found_at_location["location_info"],
            "atomicals": atomical_basic_infos,
        }

    async def atomicals_get_location(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self._atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get_location(compact_atomical_id),
        }

    async def atomicals_get(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self._atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get(compact_atomical_id),
        }

    async def atomicals_get_global(self, hashes: int = 10):
        return {"global": await self._get_summary_info(hashes)}

    async def atomical_get_state(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self._atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get_state(compact_atomical_id),
        }

    async def atomical_get_state_history(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self._atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get_state_history(compact_atomical_id),
        }

    async def atomical_get_events(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self._atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get_events(compact_atomical_id),
        }

    async def atomicals_get_tx_history(self, compact_atomical_id_or_atomical_number):
        """Return the history of an Atomical```
        atomical_id: the mint transaction hash + 'i'<index> of the atomical id
        verbose: to determine whether to print extended information
        """
        compact_atomical_id = compact_atomical_id_or_atomical_number
        if is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            compact_atomical_id = location_id_bytes_to_compact(
                self.db.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number)
            )
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get_tx_history(compact_atomical_id),
        }

    async def atomicals_get_ft_info(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = self._atomical_resolve_id(compact_atomical_id_or_atomical_number)
        return {
            "global": await self._get_summary_info(),
            "result": await self._atomical_id_get_ft_info(compact_atomical_id),
        }

    async def atomicals_get_dft_mints(self, compact_atomical_id, limit=100, offset=0):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        entries = self.bp.get_distmints_by_atomical_id(atomical_id, limit, offset)
        return {"global": await self._get_summary_info(), "result": entries}

    # Get a summary view of a realm and if it's allowing mints and what parts already existed of a subrealm
    async def atomicals_get_realm_info(self, full_name, verbose=False):
        if not full_name or not isinstance(full_name, str):
            raise RPCError(BAD_REQUEST, f"invalid input full_name: {full_name}")
        full_name = full_name.lower()
        split_names = full_name.split(".")
        total_name_parts = len(split_names)
        level = 0
        last_found = None
        realms_path = []
        candidates = []
        height = self.bp.height
        for name_part in split_names:
            if level == 0:
                status, last_found, candidates = self.bp.get_effective_realm(name_part, height)
            else:
                self.logger.info(f"atomicals_get_realm_info {last_found} {name_part}")
                status, last_found, candidates = self.bp.get_effective_subrealm(last_found, name_part, height)
            # stops when it does not found the realm component
            if status != "verified":
                break
            # Save the latest realm
            # (could be the top level realm, or the parent of a subrealm, or even the subrealm itself)
            last_found_realm_atomical_id = last_found
            # Add it to the list of paths
            realms_path.append(
                {
                    "atomical_id": location_id_bytes_to_compact(last_found_realm_atomical_id),
                    "name_part": name_part,
                    "candidates": candidates,
                }
            )
            level += 1

        joined_name = ""
        is_first_name_part = True
        for name_element in realms_path:
            if is_first_name_part:
                is_first_name_part = False
            else:
                joined_name += "."
            joined_name += name_element["name_part"]
        # Nothing was found
        realms_path_len = len(realms_path)
        if realms_path_len == 0:
            return {
                "result": {
                    "atomical_id": None,
                    "top_level_realm_atomical_id": None,
                    "top_level_realm_name": None,
                    "nearest_parent_realm_atomical_id": None,
                    "nearest_parent_realm_name": None,
                    "request_full_realm_name": full_name,
                    "found_full_realm_name": None,
                    "missing_name_parts": full_name,
                    "candidates": format_name_type_candidates_to_rpc(
                        candidates,
                        self.bp.build_atomical_id_to_candidate_map(candidates),
                    ),
                }
            }
        # Populate the subrealm minting rules for a parent atomical
        that = self

        def populate_rules_response_struct(parent_atomical_id, struct_to_populate):
            current_height = that.bp.height
            subrealm_mint_mod_history = that.bp.get_mod_history(parent_atomical_id, current_height)
            current_height_latest_state = calculate_latest_state_from_mod_history(subrealm_mint_mod_history)
            current_height_rules_list = validate_rules_data(current_height_latest_state.get(SUBREALM_MINT_PATH, None))
            nearest_parent_mint_allowed = False
            struct_to_populate["nearest_parent_realm_subrealm_mint_rules"] = {
                "nearest_parent_realm_atomical_id": location_id_bytes_to_compact(parent_atomical_id),
                "current_height": current_height,
                "current_height_rules": current_height_rules_list,
            }
            if current_height_rules_list and len(current_height_rules_list) > 0:
                nearest_parent_mint_allowed = True
            struct_to_populate["nearest_parent_realm_subrealm_mint_allowed"] = nearest_parent_mint_allowed

        # At least the top level realm was found if we got this far.
        # The number of realms returned and name components is equal, therefore the subrealm was found correctly.
        if realms_path_len == total_name_parts:
            nearest_parent_realm_atomical_id = None
            nearest_parent_realm_name = None
            top_level_realm = realms_path[0]["atomical_id"]
            top_level_realm_name = realms_path[0]["name_part"]
            if realms_path_len >= 2:
                nearest_parent_realm_atomical_id = realms_path[-2]["atomical_id"]
                nearest_parent_realm_name = realms_path[-2]["name_part"]
            elif realms_path_len == 1:
                nearest_parent_realm_atomical_id = top_level_realm
                nearest_parent_realm_name = top_level_realm_name
            # final_subrealm_name = split_names[-1]
            # applicable_rule_map = self.bp.build_applicable_rule_map(
            #     candidates,
            #     compact_to_location_id_bytes(nearest_parent_realm_atomical_id),
            #     final_subrealm_name
            # )
            return_struct = {
                "atomical_id": realms_path[-1]["atomical_id"],
                "top_level_realm_atomical_id": top_level_realm,
                "top_level_realm_name": top_level_realm_name,
                "nearest_parent_realm_atomical_id": nearest_parent_realm_atomical_id,
                "nearest_parent_realm_name": nearest_parent_realm_name,
                "request_full_realm_name": full_name,
                "found_full_realm_name": joined_name,
                "missing_name_parts": None,
                "candidates": format_name_type_candidates_to_rpc(
                    candidates, self.bp.build_atomical_id_to_candidate_map(candidates)
                ),
            }
            populate_rules_response_struct(
                compact_to_location_id_bytes(nearest_parent_realm_atomical_id),
                return_struct,
            )
            return {"result": return_struct}

        # The number of realms and components do not match, that is because at least the top level realm
        # or intermediate subrealm was found.
        # But the final subrealm does not exist yet
        # if realms_path_len < total_name_parts:
        # It is known if we got this far that realms_path_len < total_name_parts
        nearest_parent_realm_atomical_id = None
        nearest_parent_realm_name = None
        top_level_realm = realms_path[0]["atomical_id"]
        top_level_realm_name = realms_path[0]["name_part"]
        if realms_path_len >= 2:
            nearest_parent_realm_atomical_id = realms_path[-1]["atomical_id"]
            nearest_parent_realm_name = realms_path[-1]["name_part"]
        elif realms_path_len == 1:
            nearest_parent_realm_atomical_id = top_level_realm
            nearest_parent_realm_name = top_level_realm_name

        missing_name_parts = ".".join(split_names[len(realms_path) :])
        final_subrealm_name = split_names[-1]
        # applicable_rule_map = self.bp.build_applicable_rule_map(
        #     candidates,
        #     compact_to_location_id_bytes(nearest_parent_realm_atomical_id),
        #     final_subrealm_name
        # )
        return_struct = {
            "atomical_id": None,
            "top_level_realm_atomical_id": top_level_realm,
            "top_level_realm_name": top_level_realm_name,
            "nearest_parent_realm_atomical_id": nearest_parent_realm_atomical_id,
            "nearest_parent_realm_name": nearest_parent_realm_name,
            "request_full_realm_name": full_name,
            "found_full_realm_name": joined_name,
            "missing_name_parts": missing_name_parts,
            "final_subrealm_name": final_subrealm_name,
            "candidates": format_name_type_candidates_to_rpc_for_subname(
                candidates, self.bp.build_atomical_id_to_candidate_map(candidates)
            ),
        }
        if verbose:
            populate_rules_response_struct(
                compact_to_location_id_bytes(nearest_parent_realm_atomical_id),
                return_struct,
            )
        return {"result": return_struct}

    async def atomicals_get_by_realm(self, name):
        height = self.bp.height
        status, candidate_atomical_id, all_entries = self.bp.get_effective_realm(name, height)
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries,
            self.bp.build_atomical_id_to_candidate_map(all_entries),
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        found_atomical_id = None
        if status == "verified":
            found_atomical_id = candidate_atomical_id
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_atomical_id,
            "candidates": formatted_entries,
            "type": "realm",
        }
        return {"result": return_result}

    async def atomicals_get_by_subrealm(self, parent_compact_atomical_id_or_atomical_number, name):
        height = self.bp.height
        compact_atomical_id_parent = self._atomical_resolve_id(parent_compact_atomical_id_or_atomical_number)
        parent_id = compact_to_location_id_bytes(compact_atomical_id_parent)
        status, candidate_atomical_id, all_entries = self.bp.get_effective_subrealm(parent_id, name, height)
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        found_atomical_id = None
        if status == "verified":
            found_atomical_id = candidate_atomical_id
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_atomical_id,
            "candidates": formatted_entries,
            "type": "subrealm",
        }
        return {"result": return_result}

    async def atomicals_get_by_dmitem(self, parent_compact_atomical_id_or_atomical_number, name):
        height = self.bp.height
        compact_atomical_id_parent = self._atomical_resolve_id(parent_compact_atomical_id_or_atomical_number)
        parent_id = compact_to_location_id_bytes(compact_atomical_id_parent)
        status, candidate_atomical_id, all_entries = self.bp.get_effective_dmitem(parent_id, name, height)
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        found_atomical_id = None
        if status == "verified":
            found_atomical_id = candidate_atomical_id
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_atomical_id,
            "candidates": formatted_entries,
            "type": "dmitem",
        }
        return {"result": return_result}

    async def atomicals_get_by_ticker(self, ticker):
        height = self.bp.height
        status, candidate_atomical_id, all_entries = self.bp.get_effective_ticker(ticker, height)
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        found_atomical_id = None
        if status == "verified":
            found_atomical_id = candidate_atomical_id
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_atomical_id,
            "candidates": formatted_entries,
            "type": "ticker",
        }
        return {"result": return_result}

    async def atomicals_get_by_container(self, container):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, "empty container")
        height = self.bp.height
        status, candidate_atomical_id, all_entries = self.bp.get_effective_container(container, height)
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        found_atomical_id = None
        if status == "verified":
            found_atomical_id = candidate_atomical_id
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_atomical_id,
            "candidates": formatted_entries,
            "type": "container",
        }
        return {"result": return_result}

    async def atomicals_get_by_container_item(self, container, item_name):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, "empty container")
        height = self.bp.height
        status, candidate_atomical_id, all_entries = self.bp.get_effective_container(container, height)
        if status != "verified":
            formatted_entries = format_name_type_candidates_to_rpc(
                all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
            )
            self.logger.info(f"formatted_entries {formatted_entries}")
            raise RPCError(BAD_REQUEST, "Container does not exist")
        found_atomical_id = candidate_atomical_id
        status, candidate_atomical_id, all_entries = self.bp.get_effective_dmitem(found_atomical_id, item_name, height)
        found_item_atomical_id = None
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        if status == "verified":
            found_item_atomical_id = candidate_atomical_id
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_item_atomical_id,
            "candidates": formatted_entries,
            "type": "item",
        }
        return {"result": return_result}

    async def atomicals_get_by_container_item_validation(
        self,
        container,
        item_name,
        bitworkc,
        bitworkr,
        main_name,
        main_hash,
        proof,
        check_without_sealed,
    ):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, "empty container")
        height = self.bp.height
        status, candidate_atomical_id, all_entries = self.bp.get_effective_container(container, height)
        if status != "verified":
            formatted_entries = format_name_type_candidates_to_rpc(
                all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
            )
            self.logger.info(f"formatted_entries {formatted_entries}")
            raise RPCError(BAD_REQUEST, "Container does not exist")
        found_parent = candidate_atomical_id
        compact_atomical_id = location_id_bytes_to_compact(found_parent)
        container_info = await self._atomical_id_get(compact_atomical_id)
        # If it is a dmint container then there is no items field, instead construct it from the dmitems
        container_dmint_status = container_info.get("$container_dmint_status")
        errors = container_dmint_status.get("errors")
        if not container_dmint_status:
            raise RPCError(BAD_REQUEST, "Container dmint status not exist")
        if container_dmint_status.get("status") != "valid":
            errors = container_dmint_status.get("errors")
            if check_without_sealed and errors and len(errors) == 1 and errors[0] == "container not sealed":
                pass
            else:
                raise RPCError(BAD_REQUEST, f"Container dmint status is invalid: {errors}")

        dmint = container_dmint_status.get("dmint")
        status, candidate_atomical_id, all_entries = self.bp.get_effective_dmitem(found_parent, item_name, height)
        found_item_atomical_id = None
        formatted_entries = format_name_type_candidates_to_rpc(
            all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
        )
        if candidate_atomical_id:
            candidate_atomical_id = location_id_bytes_to_compact(candidate_atomical_id)
        if status == "verified":
            found_item_atomical_id = candidate_atomical_id

        # validate the proof data nonetheless
        if not proof or not isinstance(proof, list) or len(proof) == 0:
            raise RPCError(BAD_REQUEST, "Proof must be provided")

        applicable_rule, state_at_height = self.bp.get_applicable_rule_by_height(
            found_parent,
            item_name,
            height - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
            DMINT_PATH,
        )
        proof_valid, target_vector, target_hash = validate_merkle_proof_dmint(
            dmint["merkle"], item_name, bitworkc, bitworkr, main_name, main_hash, proof
        )
        if applicable_rule and applicable_rule.get("matched_rule"):
            applicable_rule = applicable_rule.get("matched_rule")
        return_result = {
            "status": status,
            "candidate_atomical_id": candidate_atomical_id,
            "atomical_id": found_item_atomical_id,
            "candidates": formatted_entries,
            "type": "item",
            "applicable_rule": applicable_rule,
            "proof_valid": proof_valid,
            "target_vector": target_vector,
            "target_hash": target_hash,
            "dmint": state_at_height.get("dmint"),
        }
        return {"result": return_result}

    async def atomicals_get_container_items(self, container, limit, offset):
        if not isinstance(container, str):
            raise RPCError(BAD_REQUEST, "empty container")
        status, candidate_atomical_id, all_entries = self.bp.get_effective_container(container, self.bp.height)
        if status != "verified":
            formatted_entries = format_name_type_candidates_to_rpc(
                all_entries, self.bp.build_atomical_id_to_candidate_map(all_entries)
            )
            self.logger.info(f"formatted_entries {formatted_entries}")
            raise RPCError(BAD_REQUEST, "Container does not exist")
        found_atomical_id = candidate_atomical_id
        compact_atomical_id = location_id_bytes_to_compact(found_atomical_id)
        container_info = await self._atomical_id_get(compact_atomical_id)
        # If it is a dmint container then there is no items field, instead construct it from the dmitems
        container_dmint_status = container_info.get("$container_dmint_status")
        if container_dmint_status:
            if limit > 100:
                limit = 100
            if offset < 0:
                offset = 0
            height = self.bp.height
            items = await self.bp.get_effective_dmitems_paginated(found_atomical_id, limit, offset, height)
            return {
                "result": {
                    "container": container_info,
                    "item_data": {
                        "limit": limit,
                        "offset": offset,
                        "type": "dmint",
                        "items": _auto_populate_container_dmint_items_fields(items),
                    },
                }
            }
        container_mod_history = self.bp.get_mod_history(found_atomical_id, self.bp.height)
        current_height_latest_state = calculate_latest_state_from_mod_history(container_mod_history)
        items = current_height_latest_state.get("items", [])
        return {
            "result": {
                "container": container_info,
                "item_data": {
                    "limit": limit,
                    "offset": offset,
                    "type": "regular",
                    "items": _auto_populate_container_regular_items_fields(items),
                },
            }
        }

    async def atomicals_search_tickers(self, prefix=None, reverse=False, limit=100, offset=0, is_verified_only=False):
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self._atomicals_search_name_template(
            b"tick", "ticker", None, prefix, reverse, limit, offset, is_verified_only
        )

    async def atomicals_search_realms(self, prefix=None, reverse=False, limit=100, offset=0, is_verified_only=False):
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self._atomicals_search_name_template(
            b"rlm", "realm", None, prefix, reverse, limit, offset, is_verified_only
        )

    async def atomicals_search_subrealms(
        self,
        parent,
        prefix=None,
        reverse=False,
        limit=100,
        offset=0,
        is_verified_only=False,
    ):
        parent_realm_id_long_form = compact_to_location_id_bytes(parent)
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self._atomicals_search_name_template(
            b"srlm",
            "subrealm",
            parent_realm_id_long_form,
            prefix,
            reverse,
            limit,
            offset,
            is_verified_only,
        )

    async def atomicals_search_containers(
        self, prefix=None, reverse=False, limit=100, offset=0, is_verified_only=False
    ):
        if isinstance(prefix, str):
            prefix = prefix.encode()
        return self._atomicals_search_name_template(
            b"co", "collection", None, prefix, reverse, limit, offset, is_verified_only
        )

    async def atomicals_get_holders(self, compact_atomical_id, limit=50, offset=0):
        """Return the holder by a specific location id```"""
        formatted_results = []
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self._atomical_id_get(compact_atomical_id)
        atomical = await self.db.populate_extended_atomical_holder_info(atomical_id, atomical)
        if atomical["type"] == "FT":
            if atomical.get("$mint_mode", "fixed") == "fixed":
                max_supply = atomical.get("$max_supply", 0)
            else:
                max_supply = atomical.get("$max_supply", -1)
                if max_supply < 0:
                    mint_amount = atomical.get("mint_info", {}).get("args", {}).get("mint_amount")
                    max_supply = DFT_MINT_MAX_MAX_COUNT_DENSITY * mint_amount
            for holder in atomical.get("holders", [])[offset : offset + limit]:
                percent = holder["holding"] / max_supply
                formatted_results.append(
                    {
                        "percent": percent,
                        "address": get_address_from_output_script(bytes.fromhex(holder["script"])),
                        "holding": holder["holding"],
                    }
                )
        elif atomical["type"] == "NFT":
            for holder in atomical.get("holders", [])[offset : offset + limit]:
                formatted_results.append(
                    {
                        "address": get_address_from_output_script(bytes.fromhex(holder["script"])),
                        "holding": holder["holding"],
                    }
                )
        return formatted_results

    # get the whole transaction by block height
    # return transaction detail
    async def transaction_by_height(self, height, limit=10, offset=0, op_type=None, reverse=True):
        res, total = await self.get_transaction_detail_by_height(height, limit, offset, op_type, reverse)
        return {"result": res, "total": total, "limit": limit, "offset": offset}

    # get transaction by atomical id
    async def transaction_by_atomical_id(self, compact_id_or_number, limit=10, offset=0, op_type=None, reverse=True):
        compact_atomical_id = compact_id_or_number
        if is_compact_atomical_id(compact_id_or_number):
            assert_atomical_id(compact_atomical_id)
        else:
            compact_atomical_id = location_id_bytes_to_compact(
                self.db.get_atomical_id_by_atomical_number(compact_id_or_number)
            )
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        hash_x = double_sha256(atomical_id)
        if op_type:
            op = self.session_mgr.bp.op_list.get(op_type, None)
            history_data, total = await self.session_mgr.get_history_op(hash_x, limit, offset, op, reverse)
        else:
            history_data, total = await self.session_mgr.get_history_op(hash_x, limit, offset, None, reverse)
        res = []
        for history in history_data:
            tx_hash, tx_height = self.db.fs_tx_hash(history["tx_num"])
            data = await self.session_mgr.get_transaction_detail(hash_to_hex_str(tx_hash), tx_height, history["tx_num"])
            if data and data["op"]:
                if (op_type and data["op"] == op_type) or not op_type:
                    res.append(data)
        return {"result": res, "total": total, "limit": limit, "offset": offset}

    # get transaction by scripthash
    async def transaction_by_scripthash(self, scripthash, limit=10, offset=0, op_type=None, reverse=True):
        hash_x = scripthash_to_hash_x(scripthash)
        res = []
        if op_type:
            op = self.session_mgr.bp.op_list.get(op_type, None)
            history_data, total = await self.session_mgr.get_history_op(hash_x, limit, offset, op, reverse)
        else:
            history_data, total = await self.session_mgr.get_history_op(hash_x, limit, offset, None, reverse)

        for history in history_data:
            tx_hash, tx_height = self.db.fs_tx_hash(history["tx_num"])
            data = await self.session_mgr.get_transaction_detail(hash_to_hex_str(tx_hash), tx_height, history["tx_num"])
            if data and data["op"]:
                if data["op"] and (data["op"] == op_type or not op_type):
                    res.append(data)
        return {"result": res, "total": total, "limit": limit, "offset": offset}

    async def transaction_broadcast_validate(self, raw_tx: str = ""):
        """Simulate a Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string to validate for Atomicals FT rules
        """
        # This returns errors as JSON RPC errors, as is natural
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, False)
            return hex_hash
        except AtomicalsValidationError as e:
            self.logger.info(f"error validating atomicals transaction: {e}")
            raise RPCError(
                ATOMICALS_INVALID_TX,
                f"the transaction was rejected by atomicals rules.\n\n{e}\n[{raw_tx}]",
            )

    async def transaction_broadcast(self, raw_tx):
        """Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string"""
        # This returns errors as JSON RPC errors, as is natural.
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, True)
        except DaemonError as e:
            (error,) = e.args
            message = error["message"]
            self.logger.info(f"error sending transaction: {message}")
            raise RPCError(
                BAD_REQUEST,
                f"the transaction was rejected by network rules.\n\n{message}\n[{raw_tx}]",
            )
        except AtomicalsValidationError as e:
            self.logger.info(f"error validating atomicals transaction: {e}")
            raise RPCError(
                ATOMICALS_INVALID_TX,
                f"the transaction was rejected by atomicals rules.\n\n{e}\n[{raw_tx}]",
            )
        else:
            self.txs_sent += 1
            client_ver = util.protocol_tuple(self.client)
            if client_ver != (0,):
                msg = self.coin.warn_old_client_on_tx_broadcast(client_ver)
                if msg:
                    self.logger.info(
                        f"sent tx: {hex_hash}, and warned user to upgrade their " f"client from {self.client}"
                    )
                    return msg

            self.logger.info(f"sent tx: {hex_hash}")
            return hex_hash

    async def transaction_broadcast_force(self, raw_tx: str):
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        try:
            hex_hash = await self.session_mgr.broadcast_transaction(raw_tx)
        except DaemonError as e:
            (error,) = e.args
            message = error["message"]
            self.logger.info(f"error sending transaction: {message}")
            raise RPCError(
                BAD_REQUEST,
                "the transaction was rejected by " f"network rules.\n\n{message}\n[{raw_tx}]",
            )
        else:
            self.txs_sent += 1
            client_ver = util.protocol_tuple(self.client)
            if client_ver != (0,):
                msg = self.coin.warn_old_client_on_tx_broadcast(client_ver)
                if msg:
                    self.logger.info(
                        f"sent tx: {hex_hash}. and warned user to upgrade their " f"client from {self.client}"
                    )
                    return msg

            self.logger.info(f"sent tx: {hex_hash}")
            return hex_hash

    def transaction_validate_psbt_blueprint(self, psbt_hex: str):
        raw_tx, _ = parse_psbt_hex_and_operations(psbt_hex)
        return self.transaction_validate_tx_blueprint(raw_tx)

    def transaction_validate_tx_blueprint(self, raw_tx: str):
        result = self.session_mgr.validate_raw_tx_blueprint(raw_tx, raise_if_burned=False)
        self.logger.debug(f"transaction_validate_tx_blueprint: {result}")
        return {"result": dict(result)}

    async def transaction_decode_psbt(self, psbt_hex: str):
        tx, tap_leafs = parse_psbt_hex_and_operations(psbt_hex)
        return await self._transaction_decode(tx, tap_leafs)

    async def transaction_decode_tx(self, tx: str):
        return await self._transaction_decode(tx)

    async def _transaction_decode(self, tx: str, tap_leafs=None):
        raw_tx = bytes.fromhex(tx)
        self.bump_cost(0.25 + len(raw_tx) / 5000)
        result = await self.session_mgr.transaction_decode_raw_tx_blueprint(raw_tx, tap_leafs)
        self.logger.debug(f"transaction_decode: {result}")
        return {"result": result}

    async def transaction_get(self, tx_hash, verbose=False):
        """Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        """
        assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, '"verbose" must be a boolean')

        self.bump_cost(1.0)
        return await self.daemon_request("getrawtransaction", tx_hash, verbose)

    async def transaction_merkle(self, tx_hash, height):
        """Return the merkle branch to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        """
        tx_hash = assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        branch, tx_pos, cost = await self.session_mgr.merkle_branch_for_tx_hash(height, tx_hash)
        self.bump_cost(cost)

        return {"block_height": height, "merkle": branch, "pos": tx_pos}

    async def transaction_id_from_pos(self, height, tx_pos, merkle=False):
        """Return the txid and optionally a merkle proof, given
        a block height and position in the block.
        """
        tx_pos = non_negative_integer(tx_pos)
        height = non_negative_integer(height)
        if merkle not in (True, False):
            raise RPCError(BAD_REQUEST, '"merkle" must be a boolean')

        if merkle:
            branch, tx_hash, cost = await self.session_mgr.merkle_branch_for_tx_pos(height, tx_pos)
            self.bump_cost(cost)
            return {"tx_hash": tx_hash, "merkle": branch}
        else:
            tx_hashes, cost = await self.session_mgr.tx_hashes_at_blockheight(height)
            try:
                tx_hash = tx_hashes[tx_pos]
            except IndexError:
                raise RPCError(
                    BAD_REQUEST,
                    f"no tx at position {tx_pos:,d} in block at height {height:,d}",
                )
            self.bump_cost(cost)
            return hash_to_hex_str(tx_hash)

    ################################################################################################################

    async def _merkle_proof(self, cp_height, height):
        max_height = self.db.db_height
        if not height <= cp_height <= max_height:
            raise RPCError(
                BAD_REQUEST,
                f"require header height {height:,d} <= "
                f"cp_height {cp_height:,d} <= "
                f"chain height {max_height:,d}",
            )
        branch, root = await self.db.header_branch_and_root(cp_height + 1, height)
        return {
            "branch": [hash_to_hex_str(elt) for elt in branch],
            "root": hash_to_hex_str(root),
        }

    async def _get_summary_info(self, atomical_hash_count: int = 10):
        if atomical_hash_count and atomical_hash_count > 100:
            atomical_hash_count = 100
        db_height = self.db.db_height
        last_block_hash = self.db.get_atomicals_block_hash(db_height)
        ret = {
            "coin": self.coin.__name__,
            "network": self.coin.NET,
            "height": db_height,
            "block_tip": hash_to_hex_str(self.db.db_tip),
            "server_time": datetime.datetime.now().isoformat(),
            "atomicals_block_tip": last_block_hash,
            "atomical_count": self.db.db_atomical_count,
            "atomicals_block_hashes": {},
        }
        # ret['atomicals_block_hashes'][db_height] = last_block_hash
        for i in range(atomical_hash_count):
            next_db_height = db_height - i
            next_block_hash = self.db.get_atomicals_block_hash(next_db_height)
            ret["atomicals_block_hashes"][next_db_height] = next_block_hash
        return ret

    def _atomical_resolve_id(self, compact_atomical_id_or_atomical_number):
        compact_atomical_id = compact_atomical_id_or_atomical_number
        if is_compact_atomical_id(compact_atomical_id_or_atomical_number):
            assert_atomical_id(compact_atomical_id)
        else:
            found_atomical_id = self.db.get_atomical_id_by_atomical_number(compact_atomical_id_or_atomical_number)
            if not found_atomical_id:
                raise RPCError(
                    BAD_REQUEST,
                    f"not found atomical: {compact_atomical_id_or_atomical_number}",
                )
            compact_atomical_id = location_id_bytes_to_compact(found_atomical_id)
        return compact_atomical_id

    # Get atomicals base information from db or placeholder information if mint is still in the mempool and unconfirmed
    async def _atomical_id_get(self, compact_atomical_id):
        return await self.session_mgr.atomical_id_get(compact_atomical_id)

    async def _atomical_id_get_location(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self._atomical_id_get(compact_atomical_id)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def _atomical_id_get_state(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self._atomical_id_get(compact_atomical_id)
        height = self.bp.height
        self.db.populate_extended_mod_state_latest_atomical_info(atomical_id, atomical, height)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def _atomical_id_get_state_history(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self._atomical_id_get(compact_atomical_id)
        height = self.bp.height
        self.db.populate_extended_mod_state_history_atomical_info(atomical_id, atomical, height)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def _atomical_id_get_events(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self._atomical_id_get(compact_atomical_id)
        height = self.bp.height
        self.db.populate_extended_events_atomical_info(atomical_id, atomical, height)
        await self.db.populate_extended_location_atomical_info(atomical_id, atomical)
        return atomical

    async def _atomical_id_get_tx_history(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self._atomical_id_get(compact_atomical_id)
        history = await self.scripthash_get_history(hash_to_hex_str(double_sha256(atomical_id)))
        history.sort(key=lambda x: x["height"], reverse=True)
        atomical["tx"] = {"history": history}
        return atomical

    async def _atomical_id_get_ft_info(self, compact_atomical_id):
        atomical_id = compact_to_location_id_bytes(compact_atomical_id)
        atomical = await self.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
        if atomical["subtype"] == "decentralized":
            atomical = await self.bp.get_dft_mint_info_rpc_format_by_atomical_id(atomical_id)
        elif atomical["subtype"] == "direct":
            atomical = await self.bp.get_ft_mint_info_rpc_format_by_atomical_id(atomical_id)
        else:
            raise RPCError(BAD_REQUEST, f'"{compact_atomical_id}" is not a fungible token (FT)')

        if atomical:
            return atomical
        # Check mempool
        atomical_in_mempool = await self.mempool.get_atomical_mint(atomical_id)
        if atomical_in_mempool is None:
            raise RPCError(BAD_REQUEST, f'"{compact_atomical_id}" is not found')
        return atomical_in_mempool

    async def address_status(self, hash_x):
        """Returns an address status.

        Status is a hex string, but must be None if there is no history.
        """
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if it has unconfirmed inputs, otherwise 0
        db_history, cost = await self.session_mgr.limited_history(hash_x)
        mempool = await self.mempool.transaction_summaries(hash_x)
        status = "".join(f"{hash_to_hex_str(tx_hash)}:{height:d}:" for tx_hash, height in db_history)
        status += "".join(f"{hash_to_hex_str(tx.hash)}:{-tx.has_unconfirmed_inputs:d}:" for tx in mempool)
        # Add status hashing cost
        self.bump_cost(cost + 0.1 + len(status) * 0.00002)

        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None
        if mempool:
            self.mempool_status[hash_x] = status
        else:
            self.mempool_status.pop(hash_x, None)
        return status

    async def get_balance(self, hash_x):
        utxos = await self.db.all_utxos(hash_x)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = await self.mempool.balance_delta(hash_x)
        self.bump_cost(1.0 + len(utxos) / 50)
        return {"confirmed": confirmed, "unconfirmed": unconfirmed}

    async def _confirmed_and_unconfirmed_history(self, hash_x):
        # Note history is ordered but unconfirmed is unordered in e-s
        history, cost = await self.session_mgr.limited_history(hash_x)
        self.bump_cost(cost)
        conf = [{"tx_hash": hash_to_hex_str(tx_hash), "height": height} for tx_hash, height in history]
        return conf + await self._unconfirmed_history(hash_x)

    async def _unconfirmed_history(self, hash_x):
        # Note unconfirmed history is unordered in electrum-server
        # height is -1 if it has unconfirmed inputs, otherwise 0
        result = [
            {
                "tx_hash": hash_to_hex_str(tx.hash),
                "height": -tx.has_unconfirmed_inputs,
                "fee": tx.fee,
            }
            for tx in await self.mempool.transaction_summaries(hash_x)
        ]
        self.bump_cost(0.25 + len(result) / 50)
        return result

    async def _hash_x_list_unspent(self, hash_x):
        """Return the list of UTXOs of a script hash, including mempool
        effects."""
        utxos = await self.db.all_utxos(hash_x)
        utxos = sorted(utxos)
        utxos.extend(await self.mempool.unordered_UTXOs(hash_x))
        self.bump_cost(1.0 + len(utxos) / 50)
        spends = await self.mempool.potential_spends(hash_x)
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
            returned_utxos.append(
                {
                    "txid": hash_to_hex_str(utxo.tx_hash),
                    "tx_hash": hash_to_hex_str(utxo.tx_hash),
                    "index": utxo.tx_pos,
                    "tx_pos": utxo.tx_pos,
                    "vout": utxo.tx_pos,
                    "height": utxo.height,
                    "value": utxo.value,
                    "atomicals": atomicals_basic_infos,
                }
            )
        return returned_utxos

    async def _hash_x_subscribe(self, hash_x, alias):
        # Store the subscription only after address_status succeeds
        result = await self.address_status(hash_x)
        self.hash_x_subs[hash_x] = alias
        return result

    def unsubscribe_hash_x(self, hash_x):
        self.mempool_status.pop(hash_x, None)
        return self.hash_x_subs.pop(hash_x, None)

    async def _hash_x_ft_balances_atomicals(self, hash_x):
        utxos = await self.db.all_utxos(hash_x)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
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
                atomical_basic_info = await self.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                compact_id = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[compact_id] = atomical_basic_info
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[compact_id] = self.db.get_uxto_atomicals_value(location, atomical_id)
            if len(atomicals) > 0:
                returned_utxos.append(
                    {
                        "txid": hash_to_hex_str(utxo.tx_hash),
                        "index": utxo.tx_pos,
                        "vout": utxo.tx_pos,
                        "height": utxo.height,
                        "value": utxo.value,
                        "atomicals": atomicals_basic_infos,
                    }
                )
        # Aggregate balances
        balances = {}
        for returned_utxo in returned_utxos:
            for atomical_id_entry_compact in returned_utxo["atomicals"]:
                atomical_id_basic_info = atomicals_id_map[atomical_id_entry_compact]
                compact_id = atomical_id_basic_info["atomical_id"]
                assert compact_id == atomical_id_entry_compact
                if atomical_id_basic_info.get("type") != "FT":
                    continue
                if balances.get(compact_id) is None:
                    balances[compact_id] = {
                        "id": compact_id,
                        "ticker": atomical_id_basic_info.get("$ticker"),
                        "confirmed": 0,
                    }
                if returned_utxo["height"] > 0:
                    balances[compact_id]["confirmed"] += returned_utxo["atomicals"][compact_id]
        return {"balances": balances}

    async def _hash_x_nft_balances_atomicals(self, hash_x):
        utxos = await self.db.all_utxos(hash_x)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
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
                atomical_basic_info = await self.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                compact_id = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[compact_id] = atomical_basic_info
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[compact_id] = self.db.get_uxto_atomicals_value(location, atomical_id)
            if len(atomicals) > 0:
                returned_utxos.append(
                    {
                        "txid": hash_to_hex_str(utxo.tx_hash),
                        "index": utxo.tx_pos,
                        "vout": utxo.tx_pos,
                        "height": utxo.height,
                        "value": utxo.value,
                        "atomicals": atomicals_basic_infos,
                    }
                )
        # Aggregate balances
        balances = {}
        for returned_utxo in returned_utxos:
            for atomical_id_entry_compact in returned_utxo["atomicals"]:
                atomical_id_basic_info = atomicals_id_map[atomical_id_entry_compact]
                compact_id = atomical_id_basic_info["atomical_id"]
                assert compact_id == atomical_id_entry_compact
                if atomical_id_basic_info.get("type") != "NFT":
                    continue
                if balances.get(compact_id) is None:
                    balances[compact_id] = {
                        "id": compact_id,
                        "confirmed": 0,
                    }
                if atomical_id_basic_info.get("subtype"):
                    balances[compact_id]["subtype"] = atomical_id_basic_info.get("subtype")
                if atomical_id_basic_info.get("$request_container"):
                    balances[compact_id]["request_container"] = atomical_id_basic_info.get("$request_container")
                if atomical_id_basic_info.get("$container"):
                    balances[compact_id]["container"] = atomical_id_basic_info.get("$container")
                if atomical_id_basic_info.get("$dmitem"):
                    balances[compact_id]["dmitem"] = atomical_id_basic_info.get("$dmitem")
                if atomical_id_basic_info.get("$request_dmitem"):
                    balances[compact_id]["request_dmitem"] = atomical_id_basic_info.get("$request_dmitem")
                if atomical_id_basic_info.get("$realm"):
                    balances[compact_id]["realm"] = atomical_id_basic_info.get("$realm")
                if atomical_id_basic_info.get("$request_realm"):
                    balances[compact_id]["request_realm"] = atomical_id_basic_info.get("$request_realm")
                if atomical_id_basic_info.get("$subrealm"):
                    balances[compact_id]["subrealm"] = atomical_id_basic_info.get("$subrealm")
                if atomical_id_basic_info.get("$request_subrealm"):
                    balances[compact_id]["request_subrealm"] = atomical_id_basic_info.get("$request_subrealm")
                if atomical_id_basic_info.get("$full_realm_name"):
                    balances[compact_id]["full_realm_name"] = atomical_id_basic_info.get("$full_realm_name")
                if atomical_id_basic_info.get("$parent_container"):
                    balances[compact_id]["parent_container"] = atomical_id_basic_info.get("$parent_container")
                if atomical_id_basic_info.get("$parent_realm"):
                    balances[compact_id]["parent_realm"] = atomical_id_basic_info.get("$parent_realm")
                if atomical_id_basic_info.get("$parent_container_name"):
                    balances[compact_id]["parent_container_name"] = atomical_id_basic_info.get("$parent_container_name")
                if atomical_id_basic_info.get("$bitwork"):
                    balances[compact_id]["bitwork"] = atomical_id_basic_info.get("$bitwork")
                if atomical_id_basic_info.get("$parents"):
                    balances[compact_id]["parents"] = atomical_id_basic_info.get("$parents")
                if returned_utxo["height"] > 0:
                    balances[compact_id]["confirmed"] += returned_utxo["atomicals"][compact_id]
        return {"balances": balances}

    async def _hash_x_list_scripthash_atomicals(self, hash_x, verbose=False):
        utxos = await self.db.all_utxos(hash_x)
        utxos = sorted(utxos)
        # Comment out the utxos for now and add it in later
        # utxos.extend(await self.mempool.unordered_UTXOs(hashX))
        self.bump_cost(1.0 + len(utxos) / 50)
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
                basic_info = await self.bp.get_base_mint_info_rpc_format_by_atomical_id(atomical_id)
                atomical_id_compact = location_id_bytes_to_compact(atomical_id)
                atomicals_id_map[atomical_id_compact] = basic_info
                location = utxo.tx_hash + util.pack_le_uint32(utxo.tx_pos)
                atomicals_basic_infos[atomical_id_compact] = self.db.get_uxto_atomicals_value(location, atomical_id)
            if verbose or len(atomicals) > 0:
                returned_utxos.append(
                    {
                        "txid": hash_to_hex_str(utxo.tx_hash),
                        "index": utxo.tx_pos,
                        "vout": utxo.tx_pos,
                        "height": utxo.height,
                        "value": utxo.value,
                        "atomicals": atomicals_basic_infos,
                    }
                )
        # Aggregate balances
        return_struct = {
            "global": await self._get_summary_info(),
            "atomicals": {},
            "utxos": returned_utxos,
        }
        atomicals = {}

        for returned_utxo in returned_utxos:
            for atomical_id_entry_compact in returned_utxo["atomicals"]:
                basic_info = atomicals_id_map[atomical_id_entry_compact]
                id_ref = basic_info["atomical_id"]
                if atomicals.get(id_ref) is None:
                    atomicals[id_ref] = {
                        "atomical_id": id_ref,
                        "atomical_number": basic_info["atomical_number"],
                        "type": basic_info["type"],
                        "confirmed": 0,
                        # 'subtype': atomical_id_basic_info.get('subtype'),
                        "data": basic_info,
                    }
                    if basic_info.get("$realm"):
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["request_realm_status"] = basic_info.get("$request_realm_status")
                        atomicals[id_ref]["request_realm"] = basic_info.get("$request_realm")
                        atomicals[id_ref]["realm"] = basic_info.get("$realm")
                        atomicals[id_ref]["full_realm_name"] = basic_info.get("$full_realm_name")
                    elif basic_info.get("$subrealm"):
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["request_subrealm_status"] = basic_info.get("$request_subrealm_status")
                        atomicals[id_ref]["request_subrealm"] = basic_info.get("$request_subrealm")
                        atomicals[id_ref]["parent_realm"] = basic_info.get("$parent_realm")
                        atomicals[id_ref]["subrealm"] = basic_info.get("$subrealm")
                        atomicals[id_ref]["full_realm_name"] = basic_info.get("$full_realm_name")
                    elif basic_info.get("$dmitem"):
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["request_dmitem_status"] = basic_info.get("$request_dmitem_status")
                        atomicals[id_ref]["request_dmitem"] = basic_info.get("$request_dmitem")
                        atomicals[id_ref]["parent_container"] = basic_info.get("$parent_container")
                        atomicals[id_ref]["dmitem"] = basic_info.get("$dmitem")
                    elif basic_info.get("$ticker"):
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["ticker_candidates"] = basic_info.get("$ticker_candidates")
                        atomicals[id_ref]["request_ticker_status"] = basic_info.get("$request_ticker_status")
                        atomicals[id_ref]["request_ticker"] = basic_info.get("$request_ticker")
                        atomicals[id_ref]["ticker"] = basic_info.get("$ticker")
                    elif basic_info.get("$container"):
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["request_container_status"] = basic_info.get("$request_container_status")
                        atomicals[id_ref]["container"] = basic_info.get("$container")
                        atomicals[id_ref]["request_container"] = basic_info.get("$request_container")
                    # Label them as candidates if they were candidates
                    elif basic_info.get("subtype") == "request_realm":
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["request_realm_status"] = basic_info.get("$request_realm_status")
                        atomicals[id_ref]["request_realm"] = basic_info.get("$request_realm")
                        atomicals[id_ref]["realm_candidates"] = basic_info.get("$realm_candidates")
                    elif basic_info.get("subtype") == "request_subrealm":
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["subrealm_candidates"] = basic_info.get("$subrealm_candidates")
                        atomicals[id_ref]["request_subrealm_status"] = basic_info.get("$request_subrealm_status")
                        atomicals[id_ref]["request_full_realm_name"] = basic_info.get("$request_full_realm_name")
                        atomicals[id_ref]["request_subrealm"] = basic_info.get("$request_subrealm")
                        atomicals[id_ref]["parent_realm"] = basic_info.get("$parent_realm")
                    elif basic_info.get("subtype") == "request_dmitem":
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["dmitem_candidates"] = basic_info.get("$dmitem_candidates")
                        atomicals[id_ref]["request_dmitem_status"] = basic_info.get("$request_dmitem_status")
                        atomicals[id_ref]["request_dmitem"] = basic_info.get("$request_dmitem")
                        atomicals[id_ref]["parent_container"] = basic_info.get("$parent_container")
                    elif basic_info.get("subtype") == "request_container":
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["container_candidates"] = basic_info.get("$container_candidates")
                        atomicals[id_ref]["request_container_status"] = basic_info.get("$request_container_status")
                        atomicals[id_ref]["request_container"] = basic_info.get("$request_container")
                    elif basic_info.get("$request_ticker_status"):
                        atomicals[id_ref]["subtype"] = basic_info.get("subtype")
                        atomicals[id_ref]["ticker_candidates"] = basic_info.get("$ticker_candidates")
                        atomicals[id_ref]["request_ticker_status"] = basic_info.get("$request_ticker_status")
                        atomicals[id_ref]["request_ticker"] = basic_info.get("$request_ticker")

                if returned_utxo["height"] <= 0:
                    atomicals[id_ref]["unconfirmed"] += returned_utxo["atomicals"][id_ref]
                else:
                    atomicals[id_ref]["confirmed"] += returned_utxo["atomicals"][id_ref]

        return_struct["atomicals"] = atomicals
        return return_struct

    # Perform a search for tickers, containers, and realms
    def _atomicals_search_name_template(
        self,
        db_prefix,
        name_type_str,
        parent_prefix=None,
        prefix=None,
        reverse=False,
        limit=1000,
        offset=0,
        is_verified_only=False,
    ):
        db_entries = self.db.get_name_entries_template_limited(db_prefix, parent_prefix, prefix, reverse, limit, offset)
        formatted_results = []
        for item in db_entries:
            height = self.bp.height
            status = None
            if name_type_str == "ticker":
                status, _, _ = self.bp.get_effective_name_template(
                    b"tick", item["name"], height, self.bp.ticker_data_cache
                )
            elif name_type_str == "realm":
                status, _, _ = self.bp.get_effective_name_template(
                    b"rlm", item["name"], height, self.bp.realm_data_cache
                )
            elif name_type_str == "collection":
                status, _, _ = self.bp.get_effective_name_template(
                    b"co", item["name"], height, self.bp.container_data_cache
                )
            elif name_type_str == "subrealm":
                status, _, _ = self.bp.get_effective_subrealm(parent_prefix, item["name"], height)
            obj = {
                "atomical_id": location_id_bytes_to_compact(item["atomical_id"]),
                "tx_num": item["tx_num"],
                name_type_str + "_hex": item["name_hex"],
                name_type_str: item["name"],
                "status": status,
            }
            if is_verified_only and status == "verified":
                formatted_results.append(obj)
            elif not is_verified_only:
                formatted_results.append(obj)
        return {"result": formatted_results}

    async def get_transaction_detail_by_height(self, height, limit, offset, op_type, reverse=True):
        res = []
        txs_list = []
        txs = self.db.get_atomicals_block_txs(height)
        for tx in txs:
            # get operation by db method
            tx_num, _ = self.db.get_tx_num_height_from_tx_hash(hex_str_to_hash(tx))
            txs_list.append({"tx_num": tx_num, "tx_hash": tx, "height": height})

        txs_list.sort(key=lambda x: x["tx_num"], reverse=reverse)
        for tx in txs_list:
            data = await self.session_mgr.get_transaction_detail(tx["tx_hash"], height, tx["tx_num"])
            if (op_type and op_type == data["op"]) or (not op_type and data["op"]):
                res.append(data)
        total = len(res)
        return res[offset : offset + limit], total


########################################################################################################################


def _auto_populate_container_regular_items_fields(items):
    if not items or not isinstance(items, dict):
        return {}
    for _item, value in items.items():
        provided_id = value.get("id")
        value["status"] = "verified"
        if provided_id and isinstance(provided_id, bytes) and len(provided_id) == 36:
            value["$id"] = location_id_bytes_to_compact(provided_id)
    return auto_encode_bytes_elements(items)


def _auto_populate_container_dmint_items_fields(items):
    if not items or not isinstance(items, dict):
        return {}
    for _item, value in items.items():
        provided_id = value.get("id")
        if provided_id and isinstance(provided_id, bytes) and len(provided_id) == 36:
            value["$id"] = location_id_bytes_to_compact(provided_id)
    return auto_encode_bytes_elements(items)
