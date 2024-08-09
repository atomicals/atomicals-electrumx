# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import asyncio
import time
from typing import TYPE_CHECKING, Callable, List, Optional, Sequence, Tuple, Type, Union

from aiorpcx import CancelledError, run_in_thread

from electrumx.lib.atomicals_blueprint_builder import AtomicalColoredOutputNft, AtomicalsTransferBlueprintBuilder
from electrumx.lib.hash import HASHX_LEN, double_sha256, hash_to_hex_str
from electrumx.lib.script import (
    SCRIPTHASH_LEN,
    is_unspendable_genesis,
    is_unspendable_legacy,
)
from electrumx.lib.tx import Tx
from electrumx.lib.util import (
    OldTaskGroup,
    chunks,
    class_logger,
    pack_be_uint64,
    pack_le_uint16,
    pack_le_uint32,
    pack_le_uint64,
    unpack_le_uint16_from,
    unpack_le_uint32,
    unpack_le_uint32_from,
    unpack_le_uint64,
    unpack_le_uint64_from,
)
from electrumx.lib.util_atomicals import (
    DMINT_PATH,
    MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS,
    MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS,
    MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
    SUBREALM_MINT_PATH,
    auto_encode_bytes_elements,
    calculate_expected_bitwork,
    calculate_latest_state_from_mod_history,
    compact_to_location_id_bytes,
    convert_db_mint_info_to_rpc_mint_info_format,
    encode_atomical_ids_hex,
    expand_spend_utxo_data,
    format_name_type_candidates_to_rpc,
    format_name_type_candidates_to_rpc_for_subname,
    get_container_dmint_format_status,
    get_mint_info_op_factory,
    get_name_request_candidate_status,
    get_subname_request_candidate_status,
    has_requested_proof_of_work,
    is_compact_atomical_id,
    is_event_operation,
    is_mint_pow_valid,
    is_seal_operation,
    is_txid_valid_for_perpetual_bitwork,
    is_valid_bitwork_string,
    is_valid_container_string_name,
    is_valid_dmt_op_format,
    is_valid_realm_string_name,
    is_valid_regex,
    is_valid_subrealm_string_name,
    is_valid_ticker_string,
    is_within_acceptable_blocks_for_general_reveal,
    is_within_acceptable_blocks_for_name_reveal,
    is_within_acceptable_blocks_for_sub_item_payment,
    location_id_bytes_to_compact,
    pad_bytes_n,
    parse_protocols_operations_from_witness_array,
    unpack_mint_info,
    validate_dmitem_mint_args_with_container_dmint,
    validate_rules_data,
)
from electrumx.server.daemon import Daemon, DaemonError
from electrumx.server.db import COMP_TXID_LEN, DB, FlushData
from electrumx.server.history import TXNUM_LEN
from electrumx.version import electrumx_version

if TYPE_CHECKING:
    from electrumx.lib.coins import AtomicalsCoinMixin, Coin
    from electrumx.server.controller import Notifications
    from electrumx.server.env import Env

import re
import sys

import pylru
from cbor2 import dumps, loads

TX_HASH_LEN = 32
ATOMICAL_ID_LEN = 36
LOCATION_ID_LEN = 36
TX_OUTPUT_IDX_LEN = 4


# Block prefetcher and chain processor.


class Prefetcher:
    """Prefetches blocks (in the forward direction only)."""

    def __init__(
        self,
        daemon: "Daemon",
        coin: Type[Union["Coin", "AtomicalsCoinMixin"]],
        blocks_event: asyncio.Event,
        *,
        polling_delay_secs,
    ):
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.daemon = daemon
        self.coin = coin
        self.blocks_event = blocks_event
        self.blocks = []
        self.caught_up = False
        # Access to fetched_height should be protected by the semaphore
        self.fetched_height = None
        self.semaphore = asyncio.Semaphore()
        self.refill_event = asyncio.Event()
        # The prefetched block cache size.  The min cache size has
        # little effect on sync time.
        self.cache_size = 0
        self.min_cache_size = 10 * 1024 * 1024
        # This makes the first fetch be 10 blocks
        self.ave_size = self.min_cache_size // 10
        self.polling_delay = polling_delay_secs

    async def main_loop(self, bp_height):
        """Loop forever polling for more blocks."""
        await self.reset_height(bp_height)
        while True:
            try:
                # Sleep a while if there is nothing to prefetch
                await self.refill_event.wait()
                if not await self._prefetch_blocks():
                    await asyncio.sleep(self.polling_delay)
            except DaemonError as e:
                self.logger.info(f"ignoring daemon error: {e}")
            except asyncio.CancelledError as e:
                self.logger.info(f"cancelled; prefetcher stopping {e}")
                raise
            except Exception as e:
                self.logger.exception(f"ignoring unexpected exception {e}")

    def get_prefetched_blocks(self):
        """Called by block processor when it is processing queued blocks."""
        blocks = self.blocks
        self.blocks = []
        self.cache_size = 0
        self.refill_event.set()
        return blocks

    async def reset_height(self, height):
        """Reset to prefetch blocks from the block processor's height.

        Used in blockchain reorganisations.  This coroutine can be
        called asynchronously to the _prefetch_blocks coroutine so we
        must synchronize with a semaphore.
        """
        async with self.semaphore:
            self.blocks.clear()
            self.cache_size = 0
            self.fetched_height = height
            self.refill_event.set()

        daemon_height = await self.daemon.height()
        behind = daemon_height - height
        if behind > 0:
            self.logger.info(f"catching up to daemon height {daemon_height:,d} ({behind:,d} " f"blocks behind)")
        else:
            self.logger.info(f"caught up to daemon height {daemon_height:,d}")

    async def _prefetch_blocks(self):
        """Prefetch some blocks and put them on the queue.

        Repeats until the queue is full or caught up.
        """
        daemon = self.daemon
        daemon_height = await daemon.height()
        async with self.semaphore:
            while self.cache_size < self.min_cache_size:
                first = self.fetched_height + 1
                # Try and catch up all blocks but limit to room in cache.
                cache_room = max(self.min_cache_size // self.ave_size, 1)
                count: int = min(daemon_height - self.fetched_height, cache_room)
                # Don't make too large a request
                count = min(self.coin.max_fetch_blocks(first), max(count, 0))
                if not count:
                    self.caught_up = True
                    return False

                hex_hashes = await daemon.block_hex_hashes(first, count)
                if self.caught_up:
                    self.logger.info(f"new block height {first + count - 1:,d} hash {hex_hashes[-1]}")
                blocks = await daemon.raw_blocks(hex_hashes)

                assert count == len(blocks)

                # Special handling for genesis block
                if first == 0:
                    blocks[0] = self.coin.genesis_block(blocks[0])
                    self.logger.info(f"verified genesis block with hash " f"{hex_hashes[0]}")

                # Update our recent average block size estimate
                size = sum(len(block) for block in blocks)
                if count >= 10:
                    self.ave_size = size // count
                else:
                    self.ave_size = (size + (10 - count) * self.ave_size) // 10

                self.blocks.extend(blocks)
                self.cache_size += size
                self.fetched_height += count
                self.blocks_event.set()

        self.refill_event.clear()
        return True


class ChainError(Exception):
    """Raised on error processing blocks."""


class BlockProcessor:
    """Process blocks and update the DB state to match.

    Employ a prefetcher to prefetch blocks in batches for processing.
    Coordinate backing up in case of chain reorganisations.
    """

    def __init__(self, env: "Env", db: DB, daemon: Daemon, notifications: "Notifications"):
        self.env = env
        self.db = db
        self.daemon = daemon
        self.notifications = notifications

        self.coin = env.coin
        # blocks_event: set when new blocks are put on the queue by the Prefetcher, to be processed
        self.blocks_event = asyncio.Event()
        self.prefetcher = Prefetcher(
            daemon,
            env.coin,
            self.blocks_event,
            polling_delay_secs=env.daemon_poll_interval_blocks_msec / 1000,
        )
        self.logger = class_logger(__name__, self.__class__.__name__)

        # Meta
        self.next_cache_check = 0
        self.touched = set()
        self.semaphore = asyncio.Semaphore()
        self.reorg_count = 0
        self.height = -1
        self.tip = None  # type: Optional[bytes]
        self.tip_advanced_event = asyncio.Event()
        self.tx_count = 0
        self.atomical_count = 0  # Total number of Atomicals minted (Includes all NFT/FT types)
        self._caught_up_event = None

        # Caches of unflushed items.
        self.headers = []
        self.tx_hashes = []
        self.undo_infos = []  # type: List[Tuple[Sequence[bytes], int]]
        self.atomicals_undo_infos = []  # type: List[Tuple[Sequence[bytes], int]]

        # UTXO cache
        self.utxo_cache = {}
        self.atomicals_utxo_cache = {}  # The cache of atomicals UTXOs
        self.general_data_cache = {}  # General data cache for atomicals related actions
        self.ticker_data_cache = {}  # Caches the tickers created
        self.realm_data_cache = {}  # Caches the realms created
        self.subrealm_data_cache = {}  # Caches the subrealms created
        self.subrealmpay_data_cache = {}  # Caches the subrealmpays created
        self.dmitem_data_cache = {}  # Caches the dmitems created
        self.dmpay_data_cache = {}  # Caches the dmitems payments created
        self.container_data_cache = {}  # Caches the containers created
        self.distmint_data_cache = {}  # Caches the distributed mints created
        self.state_data_cache = {}  # Caches the state updates
        self.op_data_cache = {}  # Caches the tx op
        self.db_deletes = []

        # If the lock is successfully acquired, in-memory chain state
        # is consistent with self.height
        self.state_lock = asyncio.Lock()

        # Signalled after backing up during a reorg
        self.backed_up_event = asyncio.Event()

        self.atomicals_id_cache = pylru.lrucache(1000000)
        self.atomicals_rpc_format_cache = pylru.lrucache(100000)
        self.atomicals_rpc_general_cache = pylru.lrucache(100000)
        self.atomicals_dft_mint_count_cache = pylru.lrucache(
            1000
        )  # tracks number of minted tokens per dft mint to make processing faster per blocks
        self.op_list = {
            "mint-dft": 1,
            "mint-ft": 2,
            "mint-nft": 3,
            "mint-nft-realm": 4,
            "mint-nft-subrealm": 5,
            "mint-nft-container": 6,
            "mint-nft-dmitem": 7,
            "dft": 20,
            "dat": 21,
            "split": 22,
            "splat": 23,
            "seal": 24,
            "evt": 25,
            "mod": 26,
            "custom-color": 27,
            "transfer": 30,
            "payment-subrealm": 40,
            "payment-dmitem": 41,
            "payment-subrealm-failed": 42,
            "payment-dmitem-failed": 43,
            "mint-dft-failed": 51,
            "mint-ft-failed": 52,
            "mint-nft-failed": 53,
            "mint-nft-realm-failed": 54,
            "mint-nft-subrealm-failed": 55,
            "mint-nft-container-failed": 56,
            "mint-nft-dmitem-failed": 57,
            "invalid-mint": 59,
            "burn": 70,
        }
        self.op_list_vk = {v: k for k, v in self.op_list.items()}

    async def run_in_thread_with_lock(self, func, *args):
        # Run in a thread to prevent blocking.  Shielded so that
        # cancellations from shutdown don't lose work - when the task
        # completes the data will be flushed and then we shut down.
        # Take the state lock to be certain in-memory state is
        # consistent and not being updated elsewhere.
        async def run_in_thread_locked():
            async with self.state_lock:
                return await run_in_thread(func, *args)

        return await asyncio.shield(run_in_thread_locked())

    async def check_and_advance_blocks(self, raw_blocks):
        """Process the list of raw blocks passed.  Detects and handles
        reorgs.
        """
        if not raw_blocks:
            return
        first = self.height + 1
        blocks = [self.coin.block(raw_block, first + n) for n, raw_block in enumerate(raw_blocks)]
        headers = [block.header for block in blocks]
        hprevs = [self.coin.header_prevhash(h) for h in headers]
        chain = [self.tip] + [self.coin.header_hash(h) for h in headers[:-1]]

        if hprevs == chain:
            start = time.monotonic()
            await self.run_in_thread_with_lock(self.advance_blocks, blocks)
            await self._maybe_flush()
            if not self.db.first_sync:
                s = "" if len(blocks) == 1 else "s"
                blocks_size = sum(len(block) for block in raw_blocks) / 1_000_000
                self.logger.info(
                    f"processed {len(blocks):,d} block{s} size {blocks_size:.2f} MB "
                    f"in {time.monotonic() - start:.1f}s"
                )
            if self._caught_up_event.is_set():
                await self.notifications.on_block(self.touched, self.height)
            self.touched = set()
        elif hprevs[0] != chain[0]:
            self.logger.info(f"check_and_advance_blocks reorg: {first}")
            await self.reorg_chain()
        else:
            # It is probably possible but extremely rare that what
            # bitcoind returns doesn't form a chain because it
            # reorg-ed the chain as it was processing the batched
            # block hash requests.  Should this happen it's simplest
            # just to reset the prefetcher and try again.
            self.logger.warning("daemon blocks do not form a chain; " "resetting the prefetcher")
            await self.prefetcher.reset_height(self.height)

    async def reorg_chain(self, count=None):
        # Use Semaphore to ensure only one reorg signal was held.
        async with self.semaphore:
            """Handle a chain reorganisation.

            Count is the number of blocks to simulate a reorg, or None for
            a real reorg."""
            if count is None:
                self.logger.info("chain reorg detected")
            else:
                self.logger.info(f"faking a reorg of {count:,d} blocks")
            await self.flush(True)

            async def get_raw_blocks(last_height, hex_hashes) -> Sequence[bytes]:
                heights = range(last_height, last_height - len(hex_hashes), -1)
                try:
                    blocks = [self.db.read_raw_block(height) for height in heights]
                    self.logger.info(f"read {len(blocks)} blocks from disk")
                    return blocks
                except FileNotFoundError:
                    return await self.daemon.raw_blocks(hex_hashes)

            def flush_backup():
                # self.touched can include other addresses which is
                # harmless, but remove None.
                self.touched.discard(None)
                self.db.flush_backup(self.flush_data(), self.touched)

            _start, last, hashes = await self.reorg_hashes(count)
            # Reverse and convert to hex strings.
            hashes = [hash_to_hex_str(hash) for hash in reversed(hashes)]
            for hex_hashes in chunks(hashes, 50):
                raw_blocks = await get_raw_blocks(last, hex_hashes)
                await self.run_in_thread_with_lock(self.backup_blocks, raw_blocks)
                await self.run_in_thread_with_lock(flush_backup)
                last -= len(raw_blocks)
            await self.prefetcher.reset_height(self.height)
            self.backed_up_event.set()
            self.backed_up_event.clear()

    async def reorg_hashes(self, count):
        """Return a pair (start, last, hashes) of blocks to back up during a
        reorg.

        The hashes are returned in order of increasing height.  Start
        is the height of the first hash, last of the last.
        """
        start, count = await self.calc_reorg_range(count)
        last = start + count - 1
        s = "" if count == 1 else "s"
        self.logger.info(f"chain was reorganised replacing {count:,d} " f"block{s} at heights {start:,d}-{last:,d}")

        return start, last, await self.db.fs_block_hashes(start, count)

    async def calc_reorg_range(self, count):
        """Calculate the reorg range"""

        def diff_pos(hashes1, hashes2):
            """Returns the index of the first difference in the hash lists.
            If both lists match returns their length."""
            for n, (hash1, hash2) in enumerate(zip(hashes1, hashes2, strict=False)):
                if hash1 != hash2:
                    return n
            return len(hashes)

        if count is None:
            # A real reorg
            start = self.height - 1
            count = 1
            while start > 0:
                hashes = await self.db.fs_block_hashes(start, count)
                hex_hashes = [hash_to_hex_str(hash) for hash in hashes]
                d_hex_hashes = await self.daemon.block_hex_hashes(start, count)
                n = diff_pos(hex_hashes, d_hex_hashes)
                if n > 0:
                    start += n
                    break
                count = min(count * 2, start)
                start -= count

            count = (self.height - start) + 1
        else:
            start = (self.height - count) + 1

        return start, count

    def estimate_txs_remaining(self):
        # Try to estimate how many txs there are to go
        daemon_height = self.daemon.cached_height()
        coin = self.coin
        tail_count = daemon_height - max(self.height, coin.TX_COUNT_HEIGHT)
        # Damp the initial enthusiasm
        realism = max(2.0 - 0.9 * self.height / coin.TX_COUNT_HEIGHT, 1.0)
        return (tail_count * coin.TX_PER_BLOCK + max(coin.TX_COUNT - self.tx_count, 0)) * realism

    # - Flushing
    def flush_data(self):
        """The data for a flush.  The lock must be taken."""
        assert self.state_lock.locked()
        return FlushData(
            self.height,
            self.tx_count,
            self.headers,
            self.tx_hashes,
            self.undo_infos,
            self.utxo_cache,
            self.db_deletes,
            self.tip,
            self.atomical_count,
            self.atomicals_undo_infos,
            self.atomicals_utxo_cache,
            self.general_data_cache,
            self.ticker_data_cache,
            self.realm_data_cache,
            self.subrealm_data_cache,
            self.subrealmpay_data_cache,
            self.dmitem_data_cache,
            self.dmpay_data_cache,
            self.container_data_cache,
            self.distmint_data_cache,
            self.state_data_cache,
            self.op_data_cache,
        )

    async def flush(self, flush_utxos):
        def flush():
            self.db.flush_dbs(self.flush_data(), flush_utxos, self.estimate_txs_remaining)

        await self.run_in_thread_with_lock(flush)

    async def _maybe_flush(self):
        # If caught up, flush everything as client queries are
        # performed on the DB.
        if self._caught_up_event.is_set():
            await self.flush(True)
        elif time.monotonic() > self.next_cache_check:
            flush_arg = self.check_cache_size()
            if flush_arg is not None:
                await self.flush(flush_arg)
            self.next_cache_check = time.monotonic() + 30

    def check_cache_size(self):
        """Flush a cache if it gets too big."""
        # Good average estimates based on traversal of subobjects and
        # requesting size from Python (see deep_getsizeof).
        one_MB = 1000 * 1000
        utxo_cache_size = len(self.utxo_cache) * 205
        db_deletes_size = len(self.db_deletes) * 57
        hist_cache_size = self.db.history.unflushed_memsize()
        # Roughly ntxs * 32 + nblocks * 42
        tx_hash_size = (self.tx_count - self.db.fs_tx_count) * 32 + (self.height - self.db.fs_height) * 42
        utxo_MB = (db_deletes_size + utxo_cache_size) // one_MB
        hist_MB = (hist_cache_size + tx_hash_size) // one_MB

        self.logger.info(
            f"our height: {self.height:,d} daemon: "
            f"{self.daemon.cached_height():,d} "
            f"UTXOs {utxo_MB:,d}MB hist {hist_MB:,d}MB"
        )

        # Flush history if it takes up over 20% of cache memory.
        # Flush UTXOs once they take up 80% of cache memory.
        cache_MB = self.env.cache_MB
        if utxo_MB + hist_MB >= cache_MB or hist_MB >= cache_MB // 5:
            return utxo_MB >= cache_MB * 4 // 5
        return None

    def advance_blocks(self, blocks):
        """Synchronously advance the blocks.

        It is already verified they correctly connect onto our tip.
        """
        min_height = self.db.min_undo_height(self.daemon.cached_height())
        height = self.height
        genesis_activation = self.coin.GENESIS_ACTIVATION

        for block in blocks:
            height += 1
            is_unspendable = is_unspendable_genesis if height >= genesis_activation else is_unspendable_legacy
            undo_info, atomicals_undo_info = self.advance_txs(block.transactions, is_unspendable, block.header, height)
            if height >= min_height:
                self.undo_infos.append((undo_info, height))
                self.atomicals_undo_infos.append((atomicals_undo_info, height))
                self.db.write_raw_block(block.raw, height)

        headers = [block.header for block in blocks]
        self.height = height
        self.headers += headers
        self.tip = self.coin.header_hash(headers[-1])
        self.tip_advanced_event.set()
        self.tip_advanced_event.clear()

    def get_atomicals_block_txs(self, height):
        return self.db.get_atomicals_block_txs(height)

    # Query general data including the cache
    def get_general_data_with_cache(self, key):
        cache = self.general_data_cache.get(key)
        if not cache:
            cache = self.db.get_general_data(key)
            if cache:
                self.general_data_cache[key] = cache
        return cache

    # Get the mint information and LRU cache it for fast retrieval
    # Used for quickly getting the mint information for an atomical
    def get_atomicals_id_mint_info(self, atomical_id, with_cache):
        result = None
        if with_cache:
            self.logger.debug(
                f"get_atomicals_id_mint_info with_cache={with_cache} atomical_id={location_id_bytes_to_compact(atomical_id)}"
            )
            result = self.atomicals_id_cache.get(atomical_id)
            if result:
                self.logger.debug(
                    f"get_atomicals_id_mint_info hit=True with_cache={with_cache} atomical_id={location_id_bytes_to_compact(atomical_id)}"
                )
                return result

        result = self.general_data_cache.get(b"mi" + atomical_id)
        if result:
            self.logger.debug(
                f"get_atomicals_id_mint_info hit=True general_data_cache=True atomical_id={location_id_bytes_to_compact(atomical_id)}"
            )
            result = unpack_mint_info(result)
            self.atomicals_id_cache[atomical_id] = result
            return result

        mint_info_dump = self.db.get_atomical_mint_info_dump(atomical_id)
        if not mint_info_dump:
            self.logger.debug(
                f"get_atomicals_id_mint_info get_atomical_mint_info_dump=True atomical_id={location_id_bytes_to_compact(atomical_id)}"
            )
            return None

        result = unpack_mint_info(mint_info_dump)
        self.atomicals_id_cache[atomical_id] = result
        self.logger.debug(
            f"get_atomicals_id_mint_info no_cache=True with_cache={with_cache} atomical_id={location_id_bytes_to_compact(atomical_id)}"
        )
        return result

    # Get basic atomical information in a format that can be attached to utxos in an RPC call
    # Must be called for known existing atomicals or will throw an exception
    def get_atomicals_id_mint_info_basic_struct(self, atomical_id):
        result = self.get_atomicals_id_mint_info(atomical_id, True)
        obj = {
            "atomical_id": location_id_bytes_to_compact(result["id"]),
            "atomical_number": result["number"],
            "atomical_ref": result.get("ref"),
            "type": result["type"],
        }

        return obj

    # Get the expected payment amount and destination for an atomical subrealm
    def get_expected_subrealm_payment_info(self, found_atomical_id_for_potential_subrealm, current_height):
        # Lookup the subrealm atomical to obtain the details of which subrealm parent it is for
        found_atomical_mint_info_for_potential_subrealm = self.get_atomicals_id_mint_info(
            found_atomical_id_for_potential_subrealm, False
        )
        if found_atomical_mint_info_for_potential_subrealm:
            # Found the mint information. Use the mint details to determine the parent realm id and name requested
            # Along with the price that was expected according to the mint reveal height
            args = found_atomical_mint_info_for_potential_subrealm.get("args")
            if not args:
                return None, None, None, None
            args_subrealm = args.get("request_subrealm")
            if not args_subrealm:
                return None, None, None, None
            request_subrealm = found_atomical_mint_info_for_potential_subrealm.get("$request_subrealm")
            # Check that $request_subrealm was set because it will only be set if the basic validation succeeded
            # If it's not set, then the atomical subrealm mint was not valid on a basic level and must be rejected
            if not request_subrealm:
                self.logger.info(
                    f"get_expected_subrealm_payment_info: not request_subrealm. request_subrealm={request_subrealm}"
                )
                return None, None, None, None
            # Sanity check
            assert args_subrealm == request_subrealm
            # Also ensure that the claim_type == 'rule'
            claim_type = found_atomical_mint_info_for_potential_subrealm["args"].get("claim_type")
            if not isinstance(claim_type, str) or claim_type != "rule":
                self.logger.info(
                    f"get_expected_subrealm_payment_info: not claim_type rule. request_subrealm={request_subrealm}"
                )
                return None, None, None, None

            # More sanity checks on the formats and validity
            if isinstance(request_subrealm, str) and is_valid_subrealm_string_name(request_subrealm):
                # Validate that the current payment came in before MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS after the mint reveal of the atomical
                # This is done to ensure that payments must be made in a timely fashion or else someone else can claim the subrealm
                if not is_within_acceptable_blocks_for_sub_item_payment(
                    found_atomical_mint_info_for_potential_subrealm["commit_height"],
                    current_height,
                ):
                    # The reveal_location_height (mint/reveal height) is too old and this payment came in far too late
                    # Ignore the payment therefore.
                    self.logger.info(
                        f"get_expected_subrealm_payment_info: not is_within_acceptable_blocks_for_sub_item_payment. request_subrealm={request_subrealm}"
                    )
                    return None, None, None, None
                # The parent realm id is in a compact form string to make it easier for users and developers
                # Only store the details if the pid is also set correctly
                request_parent_realm_id_compact = found_atomical_mint_info_for_potential_subrealm["args"].get(
                    "parent_realm"
                )
                parent_realm_id_compact = found_atomical_mint_info_for_potential_subrealm.get("$parent_realm")
                parent_realm_id = compact_to_location_id_bytes(parent_realm_id_compact)
                assert request_parent_realm_id_compact == parent_realm_id_compact
                if isinstance(parent_realm_id_compact, str) and is_compact_atomical_id(parent_realm_id_compact):
                    # We have a validated potential parent id, now look it up to see if the parent is a valid atomical
                    found_parent_mint_info = self.get_base_mint_info_by_atomical_id(
                        parent_realm_id, height=current_height
                    )
                    if found_parent_mint_info:
                        # We have found the parent atomical, which may or may not be a valid realm
                        # Do the basic check for $request_realm which indicates it succeeded the basic validity checks
                        # args_realm = found_parent_mint_info['mint_info']['args'].get('request_realm') or found_parent_mint_info['mint_info']['args'].get('request_subrealm')
                        parent_request_realm = found_parent_mint_info.get("$request_realm")
                        parent_request_subrealm = found_parent_mint_info.get("$request_subrealm")
                        # One or both was empty and therefore didn't pass the basic checks
                        # Someone apparently made a payment marker for an invalid parent realm id. They made a mistake, ignoring it..
                        if not parent_request_realm and not parent_request_subrealm:
                            self.logger.info(
                                "get_expected_subrealm_payment_info: not parent_request_realm or not parent_request_subrealm."
                            )
                            return None, None, None, None

                        # Make sure it's the right type and format checks pass again just in case
                        if parent_request_realm and (
                            not isinstance(parent_request_realm, str)
                            or not is_valid_realm_string_name(parent_request_realm)
                        ):
                            self.logger.info(
                                f"get_expected_subrealm_payment_info invalid realm request name parent_request_realm={parent_request_realm}"
                            )
                            return None, None, None, None

                        if parent_request_subrealm and (
                            not isinstance(parent_request_subrealm, str)
                            or not is_valid_subrealm_string_name(parent_request_subrealm)
                        ):
                            self.logger.info(
                                f"get_expected_subrealm_payment_info invalid subrealm request name parent_request_subrealm={parent_request_subrealm}"
                            )
                            return None, None, None, None

                        if not isinstance(request_subrealm, str) or not is_valid_subrealm_string_name(request_subrealm):
                            self.logger.info(
                                f"get_expected_subrealm_payment_info invalid subrealm request name request_subrealm={request_subrealm}"
                            )
                            return None, None, None, None

                        if not found_parent_mint_info.get("$full_realm_name"):
                            self.logger.info(
                                f"get_expected_subrealm_payment_info: not full_realm_name. request_subrealm={request_subrealm}, parent_realm_id_compact={parent_realm_id_compact}"
                            )
                            return None, None, None, None

                        # At this point we know we have a valid parent, but because realm allocation is delayed by MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS
                        # ... we do not actually know if the parent was awarded the realm or not until the required heights are met
                        # Nonetheless, someone DID make a payment and referenced the parent by the specific atomical id and therefore we will try to apply to payment
                        # It does not mean in the end that they actually get the subrealm if they paid the wrong parent. But that's their mistake and was easily avoided
                        # Here we go and check for the required payment amount and details now...
                        # We also use the commit_height of the subrealm to determine what price they should be paying
                        expected_payment_height = found_atomical_mint_info_for_potential_subrealm["commit_height"]
                        (
                            matched_price_point,
                            state_at_height,
                        ) = self.get_applicable_rule_by_height(
                            parent_realm_id,
                            request_subrealm,
                            expected_payment_height - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
                            SUBREALM_MINT_PATH,
                        )
                        if matched_price_point:
                            self.logger.info(
                                f"get_expected_subrealm_payment_info: matched_price_point={matched_price_point}, request_subrealm={request_subrealm}"
                            )
                            return (
                                matched_price_point,
                                parent_realm_id,
                                request_subrealm,
                                "subrealm",
                            )
        self.logger.info(
            f"get_expected_subrealm_payment_info: not found_atomical_mint_info_for_potential_subrealm {found_atomical_id_for_potential_subrealm}"
        )
        return None, None, None, None

    def get_expected_dmitem_payment_info(self, found_atomical_id_for_potential_dmitem, current_height):
        # Lookup the dmitem atomical to obtain the details of which container parent it is for
        found_atomical_mint_info_for_potential_dmitem = self.get_atomicals_id_mint_info(
            found_atomical_id_for_potential_dmitem, False
        )
        if not found_atomical_mint_info_for_potential_dmitem:
            self.logger.info(
                f"get_expected_dmitem_payment_info: not found_atomical_mint_info_for_potential_dmitem {location_id_bytes_to_compact(found_atomical_id_for_potential_dmitem)}"
            )
            return None, None, None, None
        # Found the mint information. Use the mint details to determine the parent realm id and name requested
        # Along with the price that was expected according to the mint reveal height
        args = found_atomical_mint_info_for_potential_dmitem.get("args")
        if not args:
            self.logger.info(
                f"get_expected_dmitem_payment_info: not_args_found found_atomical_mint_info_for_potential_dmitem {location_id_bytes_to_compact(found_atomical_id_for_potential_dmitem)} "
            )
            return None, None, None, None
        args_dmitem = args.get("request_dmitem")
        if not args_dmitem:
            self.logger.info(
                f"get_expected_dmitem_payment_info: not_args_request_dmitem_found found_atomical_mint_info_for_potential_dmitem {location_id_bytes_to_compact(found_atomical_id_for_potential_dmitem)}"
            )
            return None, None, None, None
        request_dmitem = found_atomical_mint_info_for_potential_dmitem.get("$request_dmitem")
        # Check that $request_dmitem was set because it will only be set if the basic validation succeeded
        # If it's not set, then the atomical dm item mint was not valid on a basic level and must be rejected
        if not request_dmitem:
            self.logger.info(f"get_expected_dmitem_payment_info: not request_dmitem. request_dmitem={request_dmitem}")
            return None, None, None, None
        # Sanity check
        assert args_dmitem == request_dmitem
        # More sanity checks on the formats and validity
        if not isinstance(request_dmitem, str) or len(request_dmitem) == 0:
            self.logger.info(
                f"get_expected_dmitem_payment_info: request_dmitem is not a str or is empty {location_id_bytes_to_compact(found_atomical_id_for_potential_dmitem)} request_dmitem={request_dmitem}"
            )
            return None, None, None, None
        # Validate that the current payment came in before MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS after the mint reveal of the atomical
        # This is done to ensure that payments must be made in a timely fashion or else someone else can claim the subrealm
        if not is_within_acceptable_blocks_for_sub_item_payment(
            found_atomical_mint_info_for_potential_dmitem["commit_height"],
            current_height,
        ):
            # The reveal_location_height (mint/reveal height) is too old and this payment came in far too late
            # Ignore the payment therefore.
            self.logger.info(
                f"get_expected_dmitem_payment_info: not is_within_acceptable_blocks_for_sub_item_payment. request_subrealm={request_dmitem}"
            )
            return None, None, None, None
        # The parent realm id is in a compact form string to make it easier for users and developers
        # Only store the details if the pid is also set correctly
        request_parent_container_id_compact = found_atomical_mint_info_for_potential_dmitem["args"].get(
            "parent_container"
        )
        parent_container_id_compact = found_atomical_mint_info_for_potential_dmitem.get("$parent_container")
        parent_container_id = compact_to_location_id_bytes(parent_container_id_compact)
        assert request_parent_container_id_compact == parent_container_id_compact
        if not isinstance(parent_container_id_compact, str) or not is_compact_atomical_id(parent_container_id_compact):
            self.logger.info(
                f"get_expected_dmitem_payment_info: parent_container_id_compact not string or compact atomical id {location_id_bytes_to_compact(found_atomical_id_for_potential_dmitem)} parent_container_id_compact={parent_container_id_compact}"
            )
            return None, None, None, None
        # We have a validated potential parent id, now look it up to see if the parent is a valid atomical
        found_parent_mint_info = self.get_base_mint_info_by_atomical_id(parent_container_id, height=current_height)
        if not found_parent_mint_info:
            self.logger.info(
                f"get_expected_dmitem_payment_info: not found_parent_mint_info found_atomical_id_for_potential_dmitem={location_id_bytes_to_compact(found_atomical_id_for_potential_dmitem)} parent_container_id_compact={parent_container_id_compact} found_atomical_mint_info_for_potential_dmitem={found_atomical_mint_info_for_potential_dmitem}"
            )
            return None, None, None, None
        # We have found the parent atomical, which may or may not be a valid realm
        # Do the basic check for $request_realm which indicates it succeeded the basic validity checks
        request_container_and_dmitem = found_parent_mint_info.get("$request_container") or found_parent_mint_info.get(
            "$request_dmitem"
        )
        # One or both was empty and therefore didn't pass the basic checks
        # Someone apparently made a payment marker for an invalid parent realm id. They made a mistake, ignoring it..
        if not request_container_and_dmitem:
            self.logger.info(
                f"get_expected_dmitem_payment_info: not request_container_and_dmitem. found_parent_mint_info={found_parent_mint_info} request_dmitem={request_dmitem}"
            )
            return None, None, None, None
        # Make sure it's the right type and format checks pass again just in case
        if not isinstance(request_dmitem, str):
            self.logger.info(
                f"get_expected_dmitem_payment_info: not isinstance(request_dmitem, str). request_dmitem={request_dmitem}"
            )
            return None, None, None, None
        if not found_parent_mint_info.get("$container"):
            self.logger.info(
                f"get_expected_dmitem_payment_info: not container. found_parent_mint_info={found_parent_mint_info} request_dmitem={request_dmitem}, parent_container_id_compact={parent_container_id_compact}"
            )
            return None, None, None, None
        # At this point we know we have a valid parent, but because container allocation is delayed by MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS
        # ... we do not actually know if the parent was awarded the container or not until the required heights are met
        # Nonetheless, someone DID make a payment and referenced the parent by the specific atomical id and therefore we will try to apply to payment
        # It does not mean in the end that they actually get the subrealm if they paid the wrong parent. But that's their mistake and was easily avoided
        # Here we go and check for the required payment amount and details now...
        # We also use the commit_height of the sub name to determine what price they should be paying
        expected_payment_height = found_atomical_mint_info_for_potential_dmitem["commit_height"]
        (
            matched_price_point,
            state_at_height_not_used,
        ) = self.get_applicable_rule_by_height(
            parent_container_id,
            request_dmitem,
            expected_payment_height - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
            DMINT_PATH,
        )
        if matched_price_point:
            self.logger.info(
                f"get_expected_dmitem_payment_info: matched_price_point={matched_price_point}, request_dmitem={request_dmitem}, parent_container_id={parent_container_id}"
            )
            return matched_price_point, parent_container_id, request_dmitem, "dmitem"
        self.logger.info(
            f"get_expected_dmitem_payment_info: not matched_price_point request_dmitem={request_dmitem} parent_container_id={parent_container_id} found_atomical_id_for_potential_dmitem={found_atomical_id_for_potential_dmitem}"
        )
        return None, None, None, None

    def get_earliest_dmitem_payment(self, atomical_id):
        dmpay_key_atomical_id = b"dmpay" + atomical_id
        # Check if it's located in the cache first
        dmitempay_value = self.dmpay_data_cache.get(dmpay_key_atomical_id)
        payments = []
        if dmitempay_value:
            for tx_num, pay_outpoint in dmitempay_value.items():
                payments.append(
                    {
                        "tx_num": tx_num,
                        "payment_tx_outpoint": pay_outpoint[:36],
                        "mint_initiated": pay_outpoint[36:],
                    }
                )
        db_payments = self.db.get_earliest_dmitem_payments(atomical_id)
        payments.extend(db_payments)
        payments.sort(key=lambda x: x["tx_num"])
        if len(payments) > 0:
            return payments[0]
        return None

    def get_earliest_subrealm_payment(self, atomical_id):
        spay_key_atomical_id = b"spay" + atomical_id
        # Check if it's located in the cache first
        subrealmpay_value = self.subrealmpay_data_cache.get(spay_key_atomical_id)
        payments = []
        if subrealmpay_value:
            for tx_num, pay_outpoint in subrealmpay_value.items():
                payments.append(
                    {
                        "tx_num": tx_num,
                        "payment_tx_outpoint": pay_outpoint[:36],
                        "mint_initiated": pay_outpoint[36:],
                    }
                )
        db_payments = self.db.get_earliest_subrealm_payments(atomical_id)
        payments.extend(db_payments)
        payments.sort(key=lambda x: x["tx_num"])
        if len(payments) > 0:
            return payments[0]
        return None

    # Save distributed mint information for the atomical
    # Mints are only stored if they are less than the max_mints amount
    def put_decentralized_mint_data(self, atomical_id, location_id, value):
        self.logger.debug(
            f"put_decentralized_mint_data: atomical_id={atomical_id.hex()}, location_id={location_id.hex()}, value={value.hex()}"
        )
        if self.distmint_data_cache.get(atomical_id) is None:
            self.distmint_data_cache[atomical_id] = {}
        self.distmint_data_cache[atomical_id][location_id] = value

    # Save atomicals UTXO to cache that will be flushed to db
    def put_atomicals_utxo(self, location_id, atomical_id, value):
        self.logger.debug(
            f"put_atomicals_utxo: atomical_id={location_id_bytes_to_compact(atomical_id)}, location_id={location_id_bytes_to_compact(location_id)}, value={value.hex()}"
        )
        cache = self.atomicals_utxo_cache.get(location_id)
        if cache is None:
            cache = {}
        # Use a tombstone to mark deleted because even if it's removed we must
        # store the b'i' value
        cache[atomical_id] = {"deleted": False, "value": value}
        self.atomicals_utxo_cache[location_id] = cache

    def get_distmints_by_atomical_id(self, atomical_id, limit, offset):
        def lookup_gi_entries(atomical_id):
            # Query all the gi key in the db for the atomical
            prefix = b"gi" + atomical_id
            location_ids = []
            limit_counter = 0
            offset_counter = 0
            for _atomical_gi_db_key, atomical_gi_db_value in self.db.utxo_db.iterator(prefix=prefix):
                if offset_counter >= offset:
                    location_ids.append(atomical_gi_db_value.hex())
                    limit_counter += 1
                    if limit_counter >= limit:
                        break
                offset_counter += 1
            return location_ids

        return lookup_gi_entries(atomical_id)

    # Get the total number of distributed mints for an atomical id and check the cache and db
    # This can be a heavy operation with many 10's of thousands in the db
    def get_distmints_count_by_atomical_id(self, height, atomical_id, use_block_db_cache):
        # Count the number of mints in the cache and add it to the number of mints in the db below
        cache_count = 0
        location_map_for_atomical = self.distmint_data_cache.get(atomical_id, None)
        if location_map_for_atomical is not None:
            cache_count = len(location_map_for_atomical)

        def lookup_db_count(atomical_id):
            # Query all the gi key in the db for the atomical
            prefix = b"gi" + atomical_id
            count = 0
            for _atomical_gi_db_key, _atomical_gi_db_value in self.db.utxo_db.iterator(prefix=prefix):
                count += 1
            return count

        db_count = 0
        # If we use the block db cache then check the cache for the cached mints from the db
        if use_block_db_cache:
            db_count = self.atomicals_dft_mint_count_cache.get(atomical_id)
            # If the cache key was not found then query from the db the first time to populate
            if not db_count:
                # We got the db count as of the latest block
                db_count = lookup_db_count(atomical_id)
                self.atomicals_dft_mint_count_cache[atomical_id] = db_count
                self.logger.debug(
                    f"height={height}, dft_atomical_id={location_id_bytes_to_compact(atomical_id)}, db_count={db_count}, cache_count={cache_count}"
                )
        else:
            # No block db cache was used, grab it from the db now
            db_count = lookup_db_count(atomical_id)
        # The number minted is equal to the cache and db
        total_mints = cache_count + db_count
        # Some sanity checks to make sure no developer error
        assert cache_count >= 0
        assert db_count >= 0
        assert total_mints >= 0
        assert isinstance(total_mints, int)
        return total_mints

    # Spend all of the atomicals at a location
    def spend_atomicals_utxo(self, tx_hash: bytes, tx_idx: int, live_run) -> bytes:
        """Spend the atomicals entry for UTXO and return atomicals[]."""
        idx_packed = pack_le_uint32(tx_idx)
        location_id = tx_hash + idx_packed
        cache_map = self.atomicals_utxo_cache.get(location_id)
        if cache_map:
            self.logger.debug(
                f"spend_atomicals_utxo: cache_map. location_id={location_id_bytes_to_compact(location_id)} has Atomicals..."
            )
            atomicals_data_list_cached = []
            for key in cache_map.keys():
                value_with_tombstone = cache_map[key]
                value = value_with_tombstone["value"]
                atomicals_data_list_cached.append(
                    {
                        "atomical_id": key,
                        "location_id": location_id,
                        "data": value,
                        "data_value": expand_spend_utxo_data(value),
                    }
                )
                if live_run:
                    value_with_tombstone["found_in_cache"] = True
                    value_with_tombstone[
                        "deleted"
                    ] = True  # Flag it as deleted so the b'a' active location will not be written on flushed
                self.logger.debug(
                    f"spend_atomicals_utxo: cache_map. key={key}, location_id={location_id_bytes_to_compact(location_id)} atomical_id={location_id_bytes_to_compact(key)}, value={value}"
                )
            if len(atomicals_data_list_cached) > 0:
                return atomicals_data_list_cached
        # Search the locations of existing atomicals
        # Key:  b'i' + location(tx_hash + txout_idx) + atomical_id(mint_tx_hash + mint_txout_idx)
        # Value: hashX + scripthash + value
        prefix = b"i" + location_id
        found_at_least_one = False
        atomicals_data_list = []
        for atomical_i_db_key, atomical_i_db_value in self.db.utxo_db.iterator(prefix=prefix):
            # Get all of the atomicals for an address to be deleted
            atomical_id = atomical_i_db_key[1 + ATOMICAL_ID_LEN :]
            prefix = b"a" + atomical_id + location_id
            found_at_least_one = False
            for _atomical_a_db_key, _atomical_a_db_value in self.db.utxo_db.iterator(prefix=prefix):
                found_at_least_one = True
            # For live_run == True we must throw an exception since the b'a' record
            # should always be there when we are spending
            if live_run and not found_at_least_one:
                raise IndexError(
                    "Did not find expected at least one entry for atomicals table for atomical: "
                    f"{location_id_bytes_to_compact(atomical_id)} at location "
                    f"{location_id_bytes_to_compact(location_id)}"
                )
            # Only do the db delete if this was a live run
            if live_run:
                self.delete_general_data(b"a" + atomical_id + location_id)
                self.logger.debug(
                    f"spend_atomicals_utxo: utxo_db. location_id={location_id_bytes_to_compact(location_id)} atomical_id={location_id_bytes_to_compact(atomical_id)}, value={atomical_i_db_value}"
                )

            atomicals_data_list.append(
                {
                    "atomical_id": atomical_id,
                    "location_id": location_id,
                    "data": atomical_i_db_value,
                    "data_value": expand_spend_utxo_data(atomical_i_db_value),  # expand spend uxto data for token value
                }
            )

            # Return all of the atomicals spent at the address
        return atomicals_data_list

    # Function to cache and eventually flush the mod, modpath, evt, and evtpath updates
    def put_state_data(self, db_key_prefix, db_key_suffix, db_value):
        if not self.state_data_cache.get(db_key_prefix):
            self.state_data_cache[db_key_prefix] = {}
        self.state_data_cache[db_key_prefix][db_key_suffix] = db_value

    # Function to cache and eventually flush the mod, modpath, evt, and evtpath updates
    def delete_state_data(self, db_key_prefix, db_key_suffix, expected_entry_value):
        state_map = self.state_data_cache.get(db_key_prefix)
        cached_value = None
        if state_map:
            cached_value = state_map.pop(db_key_suffix, None)
            if cached_value != expected_entry_value:
                raise IndexError(
                    "IndexError: delete_state_data cache data does not match expected value"
                    f"{expected_entry_value} {cached_value}"
                )
            # return  intentionally fall through to catch in db just in case

        db_delete_key = db_key_prefix + db_key_suffix
        db_value = self.db.utxo_db.get(db_delete_key)
        if db_value:
            if db_value != expected_entry_value:
                raise IndexError(
                    "IndexError: delete_state_data db data does not match expected atomical id"
                    f"{expected_entry_value} {db_value}"
                )
            self.delete_general_data(db_delete_key)
        return cached_value or db_value

    # Function to cache and eventually flush the op
    def put_op_data(self, tx_num, tx_hash, op):
        op_num = self.op_list.get(op)
        if op_num:
            op_prefix_key = b"op" + pack_le_uint64(tx_num)
            self.logger.debug(f"add the {op} op transaction detail for {hash_to_hex_str(tx_hash)}")
            self.op_data_cache[op_prefix_key] = pack_le_uint32(op_num)

    # Function to put the container, realm, and ticker names to the db.
    # This does not handle subrealms, because subrealms have a payment component and are handled slightly differently in another method
    def put_name_element_template(
        self,
        db_prefix_key,
        optional_subject_prefix,
        subject,
        tx_num,
        payload_value,
        name_data_cache,
    ):
        self.logger.debug(
            f"put_name_element_template: db_prefix_key={db_prefix_key}, optional_subject_prefix={optional_subject_prefix}, subject={subject}, tx_num={tx_num}, payload_value={payload_value.hex()}"
        )
        subject_enc = subject.encode()
        record_key = db_prefix_key + optional_subject_prefix + subject_enc + pack_le_uint32(len(subject_enc))
        if not name_data_cache.get(record_key):
            name_data_cache[record_key] = {}
        name_data_cache[record_key][tx_num] = payload_value

    # Function to delete the container, realm, and ticker names from the db.
    # This does not handle subrealms, because subrealms have a payment component and are handled slightly differently in another method
    def delete_name_element_template(
        self,
        db_delete_prefix,
        optional_subject_prefix,
        subject,
        tx_num,
        expected_entry_value,
        name_data_cache,
    ):
        self.logger.debug(
            f"delete_name_element_template: db_delete_prefix={db_delete_prefix}, optional_subject_prefix={optional_subject_prefix}, subject={subject}, tx_num={tx_num}, expected_entry_value={expected_entry_value.hex()}"
        )
        subject_enc = subject.encode()
        record_key = db_delete_prefix + optional_subject_prefix + subject_enc + pack_le_uint32(len(subject_enc))
        # Check if it's located in the cache first
        name_map = name_data_cache.get(record_key)
        cached_value = None
        if name_map:
            cached_value = name_map.get(tx_num)
            if cached_value:
                if cached_value != expected_entry_value:
                    raise IndexError(
                        f"IndexError: delete_name_element_template cache name data does not match expected value {db_delete_prefix} {subject} {tx_num} {expected_entry_value} {cached_value}"
                    )
                # remove from the cache
                name_map.pop(tx_num)
            # Intentionally fall through to catch it in the db as well just in case

        # Check the db whether or not it was in the cache as a safety measure (todo: Can be removed later as codebase proves robust)
        # In the db we serialize the length of the subject as well to disambiguate with other names that may be prefixes of other names
        db_delete_key = record_key + pack_le_uint64(tx_num)
        db_value = self.db.utxo_db.get(db_delete_key)
        if db_value:
            if db_value != expected_entry_value:
                raise IndexError(
                    f"IndexError: delete_name_element_template db data does not match expected atomical id {db_delete_prefix} {subject} {tx_num} {expected_entry_value} {db_value}"
                )
            self.delete_general_data(db_delete_key)
        return cached_value or db_value

    def put_pay_record(self, atomical_id, tx_num, payload_value, db_prefix, pay_data_cache):
        self.logger.debug(
            f"put_pay_record: db_prefix={db_prefix} atomical_id={location_id_bytes_to_compact(atomical_id)}, tx_num={tx_num}, payload_value={payload_value.hex()}"
        )
        record_key = db_prefix + atomical_id
        if not pay_data_cache.get(record_key):
            pay_data_cache[record_key] = {}
        pay_data_cache[record_key][tx_num] = payload_value

    def delete_pay_record(self, atomical_id, tx_num, expected_entry_value, db_prefix, pay_data_cache):
        self.logger.debug(
            f"delete_pay_record: atomical_id={location_id_bytes_to_compact(atomical_id)}, tx_num={tx_num}, expected_entry_value={expected_entry_value.hex()}"
        )
        record_key = db_prefix + atomical_id
        # Check if it's located in the cache first
        name_map = pay_data_cache.get(record_key)
        cached_value = None
        if name_map:
            cached_value = name_map.get(tx_num)
            if cached_value:
                if cached_value != expected_entry_value:
                    raise IndexError(
                        f"IndexError: delete_pay_record cache name data does not match expected value {atomical_id} {expected_entry_value} {cached_value}"
                    )
                # remove from the cache
                name_map.pop(tx_num)
            # Intentionally fall through to catch it in the db as well just in case

        # Check the db whether or not it was in the cache as a safety measure (todo: Can be removed later as codebase proves robust)
        # In the db we serialize the length of the subject as well to disambiguate with other names that may be prefixes of other names
        db_delete_key = record_key + pack_le_uint64(tx_num)
        db_value = self.db.utxo_db.get(db_delete_key)
        if db_value:
            if db_value != expected_entry_value:
                raise IndexError(
                    f"IndexError: delete_pay_record db data does not match expected atomical id {atomical_id} {tx_num} {expected_entry_value} {db_value}"
                )
            self.delete_general_data(db_delete_key)
        return cached_value or db_value

    # Delete the distributed mint data that is used to track how many mints were made
    def delete_decentralized_mint_data(self, atomical_id, location_id):
        cache_map = self.distmint_data_cache.get(atomical_id, None)
        if cache_map is not None:
            cache_map.pop(location_id, None)
            self.logger.info(
                "delete_decentralized_mint_data: distmint_data_cache. "
                f"location_id={location_id_bytes_to_compact(location_id)}, "
                f"atomical_id={location_id_bytes_to_compact(atomical_id)}"
            )
        gi_key = b"gi" + atomical_id + location_id
        gi_value = self.db.utxo_db.get(gi_key)
        if gi_value:
            # not do the i entry beuse it's deleted elsewhere
            self.delete_general_data(gi_key)
            self.logger.info(
                "delete_decentralized_mint_data: db_deletes:. "
                f"location_id={location_id_bytes_to_compact(location_id)}, "
                f"atomical_id={location_id_bytes_to_compact(atomical_id)}"
            )

    def log_subrealm_request(self, method, msg, status, subrealm, parent_realm_atomical_id, height):
        self.logger.info(
            f"{method} - {msg}, status={status} subrealm={subrealm}, parent_realm_atomical_id={parent_realm_atomical_id.hex()}, height={height}"
        )

    def log_can_be_created(self, method, msg, subject, validity, val):
        self.logger.info(f"{method} - {msg}: {subject} value {val} is acceptable to be created: {validity}")

    # Validate the parameters for an NFT and validate realm/subrealm/container data
    def validate_and_create_nft_mint_utxo(self, mint_info, txout, height, tx_hash):
        if not mint_info or not isinstance(mint_info, dict):
            return False
        sat_value = pack_le_uint64(mint_info["reveal_location_value"])
        # Minted value is definitely equals to the sat value.
        atomical_value = sat_value
        # Save the initial location to have the atomical located there
        tx_numb = pack_le_uint64(mint_info["reveal_location_tx_num"])[:TXNUM_LEN]
        put_bytes: bytes = (
            mint_info["reveal_location_hashX"]
            + mint_info["reveal_location_scripthash"]
            + sat_value
            + atomical_value
            + tx_numb
        )
        self.put_atomicals_utxo(mint_info["reveal_location"], mint_info["id"], put_bytes)
        atomical_id = mint_info["id"]
        self.logger.debug(
            f"validate_and_create_nft_mint_utxo: atomical_id={location_id_bytes_to_compact(atomical_id)}, tx_hash={hash_to_hex_str(tx_hash)}, mint_info={mint_info}"
        )
        return True

    # Validate the parameters for a FT
    def validate_and_create_ft_mint_utxo(self, mint_info, tx_hash):
        self.logger.debug(f"validate_and_create_ft_mint_utxo: tx_hash={hash_to_hex_str(tx_hash)}")
        sat_value = pack_le_uint64(mint_info["reveal_location_value"])
        # Minted value is definitely equals to the sat value.
        atomical_value = sat_value
        # Save the initial location to have the atomical located there
        if mint_info["subtype"] != "decentralized":
            tx_numb = pack_le_uint64(mint_info["reveal_location_tx_num"])[:TXNUM_LEN]
            put_bytes: bytes = (
                mint_info["reveal_location_hashX"]
                + mint_info["reveal_location_scripthash"]
                + sat_value
                + atomical_value
                + tx_numb
            )
            self.put_atomicals_utxo(mint_info["reveal_location"], mint_info["id"], put_bytes)
        subtype = mint_info["subtype"]
        atomical_id = mint_info["id"]
        self.logger.debug(
            f"validate_and_create_ft_mint_utxo: subtype={subtype}, atomical_id={location_id_bytes_to_compact(atomical_id)}, tx_hash={hash_to_hex_str(tx_hash)}"
        )
        return True

    def get_tx_num_height_from_tx_hash(self, tx_hash):
        tx_hash_value = self.general_data_cache.get(b"tx" + tx_hash)
        if tx_hash_value:
            (unpacked_tx_num,) = unpack_le_uint64(tx_hash_value[:8])
            (unpacked_height,) = unpack_le_uint32(tx_hash_value[-4:])
            return unpacked_tx_num, unpacked_height
        return self.db.get_tx_num_height_from_tx_hash(tx_hash)

    def create_or_delete_realm_entry_if_requested(self, mint_info, height, Delete):
        request_realm = mint_info.get("$request_realm")
        if not request_realm:
            # No name was requested, consider the operation successful noop
            return True
        if not is_valid_realm_string_name(request_realm):
            return False
        # Also check that there is no candidates already committed earlier than the current one
        self.logger.debug(
            f"create_or_delete_realm_entry_if_requested mint_info={mint_info} request_realm={request_realm}"
        )
        status, atomical_id, candidates = self.get_effective_realm(request_realm, height)
        for candidate in candidates:
            if candidate["tx_num"] < mint_info["commit_tx_num"]:
                return False
        if Delete:
            self.delete_name_element_template(
                b"rlm",
                b"",
                mint_info.get("$request_realm"),
                mint_info["commit_tx_num"],
                mint_info["id"],
                self.realm_data_cache,
            )
        else:
            self.put_name_element_template(
                b"rlm",
                b"",
                request_realm,
                mint_info["commit_tx_num"],
                mint_info["id"],
                self.realm_data_cache,
            )
        return True

    def create_or_delete_container_entry_if_requested(self, mint_info, height, Delete=False):
        request_container = mint_info.get("$request_container")
        if not request_container:
            # No name was requested, consider the operation successful noop
            return True

        if not is_valid_container_string_name(request_container):
            return False

        # Also check that there is no candidates already committed earlier than the current one
        status, atomical_id, candidates = self.get_effective_container(request_container, height)
        for candidate in candidates:
            if candidate["tx_num"] < mint_info["commit_tx_num"]:
                return False
        if Delete:
            self.delete_name_element_template(
                b"co",
                b"",
                request_container,
                mint_info["commit_tx_num"],
                mint_info["id"],
                self.container_data_cache,
            )
        else:
            self.put_name_element_template(
                b"co",
                b"",
                request_container,
                mint_info["commit_tx_num"],
                mint_info["id"],
                self.container_data_cache,
            )
        return True

    def create_or_delete_ticker_entry_if_requested(self, mint_info, height, Delete=False):
        request_ticker = mint_info.get("$request_ticker")
        if not request_ticker:
            # No name was requested, consider the operation successful noop
            return True
        if not is_valid_ticker_string(request_ticker):
            return False
        self.logger.debug(f"create_or_delete_ticker_entry_if_requested: request_ticker={request_ticker}")
        # Also check that there is no candidates already committed earlier than the current one
        status, atomical_id, candidates = self.get_effective_ticker(request_ticker, height)
        for candidate in candidates:
            candidate_tx_num = candidate["tx_num"]
            mint_info_commit_tx_num = mint_info["commit_tx_num"]
            if candidate_tx_num < mint_info_commit_tx_num:
                self.logger.debug(
                    f"create_or_delete_ticker_entry_if_requested: request_ticker={request_ticker}, candidate_tx_num={candidate_tx_num}, mint_info_commit_tx_num={mint_info_commit_tx_num}"
                )
                return False
        if Delete:
            self.delete_name_element_template(
                b"tick",
                b"",
                mint_info.get("$request_ticker"),
                mint_info["commit_tx_num"],
                mint_info["id"],
                self.ticker_data_cache,
            )
        else:
            self.put_name_element_template(
                b"tick",
                b"",
                request_ticker,
                mint_info["commit_tx_num"],
                mint_info["id"],
                self.ticker_data_cache,
            )
        return True

    def is_subname_entry_verified_or_going_to_be_verified(self, status):
        return status and (status == "verified" or status == "pending_previous_candidate_payment")

    # Create the subrealm entry if requested correctly
    def create_or_delete_subrealm_entry_if_requested(self, mint_info, atomicals_spent_at_inputs, height, Delete):
        request_subrealm = mint_info.get("$request_subrealm")
        if not request_subrealm:
            return True
        if not is_valid_subrealm_string_name(request_subrealm):
            return False
        parent_realm_id, mint_initiated_result = self.get_subrealm_parent_realm_info(
            mint_info, atomicals_spent_at_inputs, height
        )
        self.logger.debug(
            f"create_or_delete_subrealm_entry_if_requested mint_initiated_result={mint_initiated_result} check_if_bitwork_mint"
        )
        if parent_realm_id:
            self.logger.debug(
                f"create_or_delete_subrealm_entry_if_requested: has_parent_realm_id request_subrealm={request_subrealm} parent_realm_id={parent_realm_id}"
            )
            # Also check that there is no candidates already committed earlier than the current one
            status, atomical_id, candidates = self.get_effective_subrealm(parent_realm_id, request_subrealm, height)
            if self.is_subname_entry_verified_or_going_to_be_verified(status):
                self.logger.debug(
                    f"create_or_delete_subrealm_entry_if_requested: is_subname_entry_verified_or_going_to_be_verified, parent_realm_id {parent_realm_id}, request_subrealm={request_subrealm} "
                )
                # Do not attempt to mint subrealm if there is one verified already
                return False
            if Delete:
                self.delete_name_element_template(
                    b"srlm",
                    parent_realm_id,
                    request_subrealm,
                    mint_info["commit_tx_num"],
                    mint_info["id"],
                    self.subrealm_data_cache,
                )
            else:
                self.logger.debug(
                    f"create_or_delete_subrealm_entry_if_requested: request_subrealm={request_subrealm} mint_bitwork_attempt"
                )
                self.put_name_element_template(
                    b"srlm",
                    parent_realm_id,
                    request_subrealm,
                    mint_info["commit_tx_num"],
                    mint_info["id"],
                    self.subrealm_data_cache,
                )
            # If it was initiated by the parent, then there is no expected separate payment and the mint itself is considered the payment
            # Therefore add the current mint tx as the payment
            if mint_initiated_result == "parent":
                self.logger.debug(
                    f"create_or_delete_subrealm_entry_if_requested: mint_initiated_result={mint_initiated_result}, mint_info={mint_info}"
                )
                # Add the b'01' flag to indicate it was initiated by the parent
                if Delete:
                    # Add the b'01' flag to indicate it was initiated by the parent
                    self.delete_pay_record(
                        mint_info["id"],
                        mint_info["reveal_location_tx_num"],
                        mint_info["reveal_location"] + b"01",
                        b"spay",
                        self.subrealmpay_data_cache,
                    )
                else:
                    self.put_pay_record(
                        mint_info["id"],
                        mint_info["reveal_location_tx_num"],
                        mint_info["reveal_location"] + b"01",
                        b"spay",
                        self.subrealmpay_data_cache,
                    )
            elif mint_initiated_result == "bitwork":
                self.logger.debug(
                    f"create_or_delete_subrealm_entry_if_requested: bitwork_initiated mint_initiated_result={mint_initiated_result}, mint_info={mint_info}"
                )
                # Add the b'02' flag to indicate it was bitwork only
                if Delete:
                    self.delete_pay_record(
                        mint_info["id"],
                        mint_info["reveal_location_tx_num"],
                        mint_info["reveal_location"] + b"02",
                        b"spay",
                        self.subrealmpay_data_cache,
                    )
                else:
                    self.put_pay_record(
                        mint_info["id"],
                        mint_info["reveal_location_tx_num"],
                        mint_info["reveal_location"] + b"02",
                        b"spay",
                        self.subrealmpay_data_cache,
                    )
            return True
        return False

    def create_or_delete_dmitem_entry_if_requested(self, mint_info, mint_data_payload, height, Delete):
        request_dmitem = mint_info.get("$request_dmitem")
        if not request_dmitem:
            return True
        (
            parent_container_id,
            mint_initiated_result,
        ) = self.get_dmitem_parent_container_info(mint_info, mint_data_payload, height)
        self.logger.debug(
            f"create_or_delete_dmitem_entry_if_requested mint_initiated_result={mint_initiated_result} check_if_bitwork_mint"
        )
        if parent_container_id:
            self.logger.debug(
                f"create_or_delete_dmitem_entry_if_requested: has_parent_container_id request_dmitem={request_dmitem} parent_container_id={parent_container_id}"
            )
            # Also check that there is no candidates already committed earlier than the current one
            status, atomical_id, candidates = self.get_effective_dmitem(parent_container_id, request_dmitem, height)
            self.logger.debug(
                f"get_effective_dmitem_status status={status} candidates={encode_atomical_ids_hex(candidates)}"
            )
            if self.is_subname_entry_verified_or_going_to_be_verified(status):
                self.logger.warning(
                    f"create_or_delete_dmitem_entry_if_requested: is_subname_entry_verified_or_going_to_be_verified, parent_container_id {location_id_bytes_to_compact(parent_container_id)}, request_dmitem={request_dmitem} "
                )
                # Do not attempt to mint if there is one verified already
                return False
            if Delete:
                self.logger.debug(
                    f"create_or_delete_dmitem_entry_if_requested: request_dmitem={request_dmitem} mint_bitwork_attempt in Delete mode"
                )
                self.delete_name_element_template(
                    b"codmt",
                    parent_container_id,
                    request_dmitem,
                    mint_info["commit_tx_num"],
                    mint_info["id"],
                    self.dmitem_data_cache,
                )
            else:
                self.logger.debug(
                    f"create_or_delete_dmitem_entry_if_requested: request_dmitem={request_dmitem} mint_bitwork_attempt"
                )
                self.put_name_element_template(
                    b"codmt",
                    parent_container_id,
                    request_dmitem,
                    mint_info["commit_tx_num"],
                    mint_info["id"],
                    self.dmitem_data_cache,
                )
            # If it was initiated by only bitwork, then there is no expected separate payment and the mint itself is considered the payment
            if mint_initiated_result == "bitwork":
                self.logger.debug(
                    f"create_or_delete_dmitem_entry_if_requested: bitwork_initiated mint_initiated_result={mint_initiated_result}, mint_info={mint_info}"
                )
                # Add the b'02' flag to indicate it was bitwork only
                if Delete:
                    self.delete_pay_record(
                        mint_info["id"],
                        mint_info["reveal_location_tx_num"],
                        mint_info["reveal_location"] + b"02",
                        b"dmpay",
                        self.dmpay_data_cache,
                    )
                else:
                    self.put_pay_record(
                        mint_info["id"],
                        mint_info["reveal_location_tx_num"],
                        mint_info["reveal_location"] + b"02",
                        b"dmpay",
                        self.dmpay_data_cache,
                    )
            return True
        return False

    # Check for the payment and parent information for a subrealm mint request
    # This information is used to determine how to put and delete the record in the index
    def get_subrealm_parent_realm_info(self, mint_info, atomicals_spent_at_inputs, height):
        request_subrealm = mint_info.get("$request_subrealm")
        if not is_valid_subrealm_string_name(request_subrealm):
            return None, None
        # Check to see if the parent realm was spent as part of the inputs to authorize the direct creation of the subrealm
        # If the parent realm was spent as one of the inputs, then there does not need to be a payment made, we consider the current transaction
        # as the payment then
        self.logger.info(f"get_subrealm_parent_realm_info: mint_info {mint_info}")
        parent_realm_id = compact_to_location_id_bytes(mint_info["$parent_realm"])
        mint_initiated_result = None
        claim_type = mint_info.get("args").get("claim_type")
        # Only allow it to be considered initiated by parent if the claim_type == 'direct'
        if claim_type == "direct":
            self.logger.info(f"get_subrealm_parent_realm_info claim_type_is_not_direct {mint_info}")
            # return parent_realm_id, mint_initiated_result
            for _idx, atomical_entry_list in atomicals_spent_at_inputs.items():
                for atomical_entry in atomical_entry_list:
                    atomical_id = atomical_entry["atomical_id"]
                    if atomical_id == parent_realm_id:
                        mint_initiated_result = "parent"
                        break
                # parent atomical matches being spent
                if mint_initiated_result:
                    return parent_realm_id, mint_initiated_result
            return None, None
        # It must be a rule based mint then
        if claim_type != "rule":
            self.logger.info("get_subrealm_parent_realm_info: claim type was not direct or rule, skipping...")
            return None, None
        # if we got this far then it means it was not parent initiated and it could require bitwork to proceed
        expected_payment_height = mint_info["commit_height"]
        matched_price_point, state_at_height = self.get_applicable_rule_by_height(
            parent_realm_id,
            request_subrealm,
            expected_payment_height - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
            SUBREALM_MINT_PATH,
        )
        if matched_price_point:
            self.logger.info(
                f"get_subrealm_parent_realm_info: matched_price_point={matched_price_point}, request_subrealm={request_subrealm}"
            )
            # A rule was matched
            matched_rule = matched_price_point["matched_rule"]
            bitworkc = matched_rule.get("bitworkc")
            bitworkr = matched_rule.get("bitworkr")
            bitworkc_actual = mint_info.get("$bitworkc")
            bitworkr_actual = mint_info.get("$bitworkr")
            if bitworkc == "any":
                pass
            elif bitworkc:
                if bitworkc_actual != bitworkc:
                    self.logger.info(
                        f"get_subrealm_parent_realm_info bitworkc_required but not valid {bitworkc} bitworkc_actual={bitworkc_actual}"
                    )
                    return None, None
            if bitworkr == "any":
                pass
            elif bitworkr:
                if bitworkr_actual != bitworkr:
                    self.logger.info(
                        f"get_subrealm_parent_realm_info bitworkr_required but not valid {bitworkr} bitworkc_actual={bitworkr_actual}"
                    )
                    return None, None

            # There was outputs required, so it's a payment type (it could have bitwork or not)
            if matched_rule.get("o"):
                return parent_realm_id, None

            if bitworkc or bitworkr:
                return parent_realm_id, "bitwork"
            else:
                self.logger.info(
                    "get_subrealm_parent_realm_info no outputs or bitworkc or bitworkr provided therefore invalid subrealm"
                )
                return None, None

        self.logger.info(f"get_subrealm_parent_realm_info no_matched_price_point request_subrealm={request_subrealm}")
        return None, None

    def get_dmitem_parent_container_info(self, mint_info, mint_data_payload, height):
        request_dmitem = mint_info.get("$request_dmitem")
        if not isinstance(request_dmitem, str):
            return None, None
        self.logger.debug(f"get_dmitem_parent_container_info: mint_info {mint_info}")
        parent_container_id = compact_to_location_id_bytes(mint_info["$parent_container"])
        # if we got this far then it means it was not parent initiated and it could require bitwork to proceed
        expected_payment_height = mint_info["commit_height"]
        (
            matched_price_point,
            state_at_height_not_used,
        ) = self.get_applicable_rule_by_height(
            parent_container_id,
            request_dmitem,
            expected_payment_height - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
            DMINT_PATH,
        )
        if matched_price_point:
            # But first validate that there is a valid 'dmint' entry in the container
            dmint_validated_status = self.make_container_dmint_status_by_atomical_id_at_height(
                parent_container_id, height
            )
            if not dmint_validated_status or dmint_validated_status.get("status") != "valid":
                self.logger.warning(
                    f"get_dmitem_parent_container_info: parent container dmint is not valid dmint_validated_status={dmint_validated_status}"
                )
                return None, None
            # User tried to commit the mint before the official launch mint_height
            mint_height = dmint_validated_status["dmint"]["mint_height"]
            if expected_payment_height < mint_height:
                self.logger.warning(
                    f"get_dmitem_parent_container_info: mint commit height={expected_payment_height} is less than mint_height={mint_height} mint_info={mint_info}"
                )
                return None, None
            # Check for mint_height
            if height < mint_height:
                self.logger.warning(
                    f"get_dmitem_parent_container_info: parent container current height={height} is less than mint_height={mint_height} mint_info={mint_info}"
                )
                return None, None
            is_proof_valid = validate_dmitem_mint_args_with_container_dmint(
                mint_info["args"], mint_data_payload, dmint_validated_status["dmint"]
            )
            if not is_proof_valid:
                self.logger.warning(
                    f"get_dmitem_parent_container_info: invalid dmitem mint args and or proof mint_info={mint_info} dmint_validated_status={dmint_validated_status}"
                )
                return None, None
            # A rule was matched
            matched_rule = matched_price_point["matched_rule"]
            bitworkc = matched_rule.get("bitworkc")
            bitworkr = matched_rule.get("bitworkr")
            bitworkc_actual = mint_info.get("$bitworkc")
            bitworkr_actual = mint_info.get("$bitworkr")
            if bitworkc == "any":
                pass
            elif bitworkc:
                if bitworkc_actual != bitworkc:
                    self.logger.info(
                        f"get_subrealm_parent_realm_info bitworkc_required but not valid {bitworkc} bitworkc_actual={bitworkc_actual}"
                    )
                    return None, None
            if bitworkr == "any":
                pass
            elif bitworkr:
                if bitworkr_actual != bitworkr:
                    self.logger.info(
                        f"get_subrealm_parent_realm_info bitworkr_required but not valid {bitworkr} bitworkc_actual={bitworkr_actual}"
                    )
                    return None, None
            # There was outputs required, so it's a payment type (it could have bitwork or not)
            if matched_rule.get("o"):
                return parent_container_id, None
            if bitworkc or bitworkr:
                return parent_container_id, "bitwork"
            else:
                self.logger.warning(
                    "get_dmitem_parent_container_info no outputs or bitworkc or bitworkr provided therefore invalid dmint item"
                )
                return None, None
        self.logger.warning(f"get_dmitem_parent_container_info no_matched_price_point request_dmitem={request_dmitem}")
        return None, None

    # Check whether to create an atomical NFT/FT
    # Validates the format of the detected input operation and then checks the correct extra data is valid
    # such as realm, container, ticker, etc. Only succeeds if the appropriate names can be assigned
    def create_or_delete_atomical(
        self,
        operations_found_at_inputs,
        atomicals_spent_at_inputs,
        header,
        height,
        tx_num,
        atomical_num,
        tx,
        tx_hash,
        Delete,
    ):
        if not operations_found_at_inputs:
            return None

        # Catch the strange case where there are no outputs
        if len(tx.outputs) == 0:
            return None

        # All mint types always look at only input 0 to determine if the operation was found
        # This is done to preclude complex scenarios of valid/invalid different mint types across inputs
        valid_create_op_type, mint_info = get_mint_info_op_factory(
            self.coin,
            tx,
            tx_hash,
            operations_found_at_inputs,
            atomicals_spent_at_inputs,
            height,
            self.logger,
        )
        if not valid_create_op_type or (valid_create_op_type != "NFT" and valid_create_op_type != "FT"):
            return None

        # The atomical would always be created at the first output
        txout = tx.outputs[0]

        # If the ATOMICALS_ACTIVATION_HEIGHT was not reached yet, then we do not map tx_hash->tx_num
        # And therefore the commit_txid will not be found
        # The prev tx number is the prev input being spent that creates the atomical
        commit_txid = mint_info["commit_txid"]
        commit_tx_num, commit_tx_height = self.get_tx_num_height_from_tx_hash(commit_txid)
        if not commit_tx_num:
            self.logger.info(
                f"create_or_delete_atomical: commit_txid not found for reveal_tx {hash_to_hex_str(commit_txid)}. Skipping..."
            )
            return None
        if commit_tx_height < self.coin.ATOMICALS_ACTIVATION_HEIGHT:
            self.logger.warning(
                f"create_or_delete_atomical: commit_tx_height={commit_tx_height} is less than ATOMICALS_ACTIVATION_HEIGHT. Skipping..."
            )
            return None

        # We add the following as a final sanity check to make sure invalid POW minted atomicals never get created
        # However, it should be excluded in get_mint_info_op_factory to begin with so we will never actually fail her
        # Perhaps this validity check can be remoed in the future....
        # Check if there was any proof of work requested for the commit or reveal
        # If the client requested any proof of work, then for the mint to be valid, the proof of work (in the commit or reveal, or both) must be valid
        is_pow_requested, pow_result = has_requested_proof_of_work(operations_found_at_inputs)
        if is_pow_requested and not pow_result:
            self.logger.warning(
                f"create_or_delete_atomical: proof of work was requested, but the proof of work was invalid. Not minting Atomical at {hash_to_hex_str(tx_hash)}. Skipping..."
            )
            return None

        atomical_id = mint_info["id"]
        mint_info["number"] = atomical_num
        # The mint tx num is used to determine precedence for names like tickers, realms, containers
        mint_info["commit_tx_num"] = commit_tx_num
        mint_info["commit_height"] = commit_tx_height
        mint_info["reveal_location_header"] = header
        mint_info["reveal_location_height"] = height
        mint_info["reveal_location_tx_num"] = tx_num

        # Too late to reveal in general
        if not is_within_acceptable_blocks_for_general_reveal(
            mint_info["commit_height"], mint_info["reveal_location_height"]
        ):
            self.logger.warning(
                f"create_or_delete_atomical: not is_within_acceptable_blocks_for_general_reveal. Not minting Atomical at {hash_to_hex_str(tx_hash)}. Skipping..."
            )
            return None

        # Do not allow mints if it is a name type if the name is invalid or known that it will fail (ex: because it was claimed already)
        is_name_type = False
        if mint_info.get("$request_realm"):
            is_name_type = True
        if mint_info.get("$request_subrealm"):
            is_name_type = True
        if mint_info.get("$request_container"):
            is_name_type = True
        if mint_info.get("$request_ticker"):
            is_name_type = True
        if mint_info.get("$request_dmitem"):
            is_name_type = True

        # Too late to reveal, fail to mint then
        if is_name_type and not is_within_acceptable_blocks_for_name_reveal(
            mint_info["commit_height"], mint_info["reveal_location_height"]
        ):
            self.logger.warning(
                f"reveal_not_within_acceptable_blocks_for_name_reveal: txid={hash_to_hex_str(tx_hash)}. Skipping..."
            )
            return None

        if is_name_type and height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_COMMITZ and mint_info["commit_index"] != 0:
            self.logger.warning(f"attempt_to_mint_from_non_zero_output: txid={hash_to_hex_str(tx_hash)}. Skipping...")
            return None

        if valid_create_op_type == "NFT":
            # Handle the special case of a subrealm and it's $parent_realm (parent realm)
            # Ensure that the parent $parent_realm is at least a valid atomical
            if mint_info.get("$request_subrealm"):
                parent_atomical_id_compact = mint_info["$parent_realm"]
                parent_atomical_id = compact_to_location_id_bytes(parent_atomical_id_compact)
                parent_atomical_mint_info = self.get_atomicals_id_mint_info(parent_atomical_id, False)
                if not parent_atomical_mint_info:
                    self.logger.warning(f"invalid_parent_realm: txid={hash_to_hex_str(tx_hash)}. Skipping...")
                    return None

            # Also handle the special case of a dmitem and it's $parent_container
            # Ensure that the parent $parent_container is at least a valid atomical
            if mint_info.get("$request_dmitem"):
                parent_atomical_id_compact = mint_info["$parent_container"]
                parent_atomical_id = compact_to_location_id_bytes(parent_atomical_id_compact)
                parent_atomical_mint_info = self.get_atomicals_id_mint_info(parent_atomical_id, False)
                if not parent_atomical_mint_info:
                    self.logger.warning(f"invalid_parent_container: txid={hash_to_hex_str(tx_hash)}. Skipping...")
                    return None

            # Ensure that the creates are noops or successful
            if not self.create_or_delete_realm_entry_if_requested(mint_info, height, Delete):
                return None

            if not self.create_or_delete_container_entry_if_requested(mint_info, height, Delete):
                return None

            if not self.create_or_delete_subrealm_entry_if_requested(
                mint_info, atomicals_spent_at_inputs, height, Delete
            ):
                return None

            if height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_DMINT:
                if not self.create_or_delete_dmitem_entry_if_requested(
                    mint_info, operations_found_at_inputs["payload"], height, Delete
                ):
                    return None
            if not Delete:
                if not self.validate_and_create_nft_mint_utxo(mint_info, txout, height, tx_hash):
                    if mint_info.get("$request_realm"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-realm-failed")
                    elif mint_info.get("$request_subrealm"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-subrealm-failed")
                    elif mint_info.get("$request_container"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-container-failed")
                    elif mint_info.get("$request_dmitem"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-dmitem-failed")
                    else:
                        self.put_op_data(tx_num, tx_hash, "mint-nft-failed")
                    self.logger.info(
                        f"create_or_delete_atomical: validate_and_create_nft_mint_utxo returned FALSE in Transaction {hash_to_hex_str(tx_hash)}. Skipping..."
                    )
                    return None
                else:
                    self.logger.info(f"mint: {hash_to_hex_str(tx_hash)}")
                    if mint_info.get("$request_realm"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-realm")
                    elif mint_info.get("$request_subrealm"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-subrealm")
                    elif mint_info.get("$request_container"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-container")
                    elif mint_info.get("$request_dmitem"):
                        self.put_op_data(tx_num, tx_hash, "mint-nft-dmitem")
                    else:
                        self.put_op_data(tx_num, tx_hash, "mint-nft")

        elif valid_create_op_type == "FT":
            # Add $max_supply informative property
            if mint_info["subtype"] == "decentralized":
                # For perpetual mints the max supply is unbounded
                if mint_info.get("$mint_mode") == "perpetual":
                    if mint_info.get("$max_mints_global"):
                        mint_info["$max_supply"] = mint_info["$mint_amount"] * mint_info.get("$max_mints_global")
                    else:
                        mint_info["$max_supply"] = -1
                else:
                    mint_info["$max_supply"] = mint_info["$mint_amount"] * mint_info["$max_mints"]
            else:
                mint_info["$max_supply"] = txout.value
            if not self.create_or_delete_ticker_entry_if_requested(mint_info, height, Delete):
                return None
            if not Delete:
                if not self.validate_and_create_ft_mint_utxo(mint_info, tx_hash):
                    self.logger.info(
                        f"create_or_delete_atomical: validate_and_create_ft_mint_utxo returned FALSE in Transaction {hash_to_hex_str(tx_hash)}. Skipping..."
                    )
                    if mint_info["subtype"] == "decentralized":
                        self.put_op_data(tx_num, tx_hash, "mint-dft-failed")
                    else:
                        self.put_op_data(tx_num, tx_hash, "mint-ft-failed")
                    return None
                else:
                    if mint_info["subtype"] == "decentralized":
                        if operations_found_at_inputs["op"] == "dft" and operations_found_at_inputs["input_index"] == 0:
                            self.put_op_data(tx_num, tx_hash, "dft")
                        else:
                            self.put_op_data(tx_num, tx_hash, "mint-dft")
                    else:
                        self.put_op_data(tx_num, tx_hash, "mint-ft")
        else:
            raise IndexError("Fatal index error Create Invalid")

        # Save mint data fields
        put_general_data = self.general_data_cache.__setitem__

        md_atomical_id_key = b"md" + atomical_id
        if Delete:
            self.delete_general_data(md_atomical_id_key)
        else:
            put_general_data(md_atomical_id_key, operations_found_at_inputs["payload_bytes"])

        # Save mint info fields and metadata
        mi_atomical_id_key = b"mi" + atomical_id
        if Delete:
            self.delete_general_data(mi_atomical_id_key)
        else:
            put_general_data(mi_atomical_id_key, dumps(mint_info))

        # Track the atomical number for the newly minted atomical
        atomical_count_numb = pack_be_uint64(atomical_num)
        n_atomical_count_numb_key = b"n" + atomical_count_numb
        if Delete:
            self.delete_general_data(n_atomical_count_numb_key)
        else:
            put_general_data(n_atomical_count_numb_key, atomical_id)

        # Save the output script of the atomical reveal mint outputs to lookup at a future point for resolving address script
        po_reveal_location_key = b"po" + mint_info["reveal_location"]
        if Delete:
            self.delete_general_data(po_reveal_location_key)
        else:
            put_general_data(po_reveal_location_key, txout.pk_script)

        # Save a lookup by first reveal location to atomical id
        rloc_reveal_location_key = b"rloc" + mint_info["reveal_location"]
        if Delete:
            self.delete_general_data(rloc_reveal_location_key)
        else:
            put_general_data(rloc_reveal_location_key, atomical_id)

        self.put_or_delete_init_state_updates(mint_info, operations_found_at_inputs["payload"], Delete)
        return atomical_id

    # Delete the general data from the cache
    def delete_general_data(self, the_key):
        self.general_data_cache.pop(the_key, None)
        self.db_deletes.append(the_key)

    # Detect and apply updates-related like operations for an atomical such as mod/evt/sl
    def put_or_delete_state_updates(
        self,
        operations_found_at_inputs,
        atomical_id,
        tx_num,
        tx_hash,
        output_idx_le,
        height,
        apply_type,
        Delete,
    ):
        if not operations_found_at_inputs:
            return

        op_name = "mod"
        main_key_prefix = b"mod"
        if apply_type == 1:
            op_name = "evt"
            main_key_prefix = b"evt"

        if (
            operations_found_at_inputs
            and operations_found_at_inputs.get("op") == op_name
            and operations_found_at_inputs.get("input_index") == 0
        ):
            self.logger.debug(
                f"put_or_delete_state_updates: op={op_name}, height={height}, atomical_id={atomical_id.hex()}, tx_hash={hash_to_hex_str(tx_hash)}"
            )
            tx_numb = pack_le_uint64(tx_num)[:TXNUM_LEN]
            db_key_prefix = main_key_prefix + atomical_id
            db_key_suffix = tx_numb + tx_hash + output_idx_le
            db_value = operations_found_at_inputs["payload_bytes"]
            if not Delete:
                self.put_state_data(db_key_prefix, db_key_suffix, db_value)
            else:
                self.delete_state_data(db_key_prefix, db_key_suffix, db_value)

    # apply the seal updates
    def put_or_delete_sealed(self, operations_found_at_inputs, atomical_id, location, Delete=False):
        # Useful for locking container collections, locking parent realms, and even locking any NFT atomical permanently
        if is_seal_operation(operations_found_at_inputs):
            self.logger.debug(
                f"put_or_delete_sealed: {location_id_bytes_to_compact(atomical_id)} at seal operation transaction {hash_to_hex_str(location)}"
            )
            # Save the data so that we can recall later if an atomical was sealed to warn clients
            db_key = b"sealed" + atomical_id
            if not Delete:
                put_general_data = self.general_data_cache.__setitem__
                put_general_data(db_key, location)
            else:
                self.delete_general_data(db_key)
            return True
        return False

    # Refactor this later to combine with put_or_delete_state_updates
    def put_or_delete_init_state_updates(self, mint_info, data_payload, Delete):
        tx_hash = mint_info["reveal_location_txid"]
        atomical_id = mint_info["id"]
        height = mint_info["reveal_location_height"]

        # Make a deep copy of the data payload and remove the reserved sections
        copied_data_state = {}
        for k, v in data_payload.items():
            if k != "args":
                copied_data_state[k] = v
        init_payload_bytes = dumps(copied_data_state)
        op_struct = {
            "op": "mod",
            "input_index": 0,
            "payload": copied_data_state,
            "payload_bytes": init_payload_bytes,
        }
        if len(copied_data_state.keys()) > 0:
            self.put_or_delete_state_updates(
                op_struct,
                atomical_id,
                mint_info["reveal_location_tx_num"],
                tx_hash,
                pack_le_uint32(mint_info["reveal_location_index"]),
                height,
                0,
                Delete,
            )

    def put_or_delete_event_updates_if_found(
        self, operations_found_at_inputs, atomical_id, tx_num, tx_hash, tx, height
    ):
        # If there was an event, then save it for the first FT only
        if is_event_operation(operations_found_at_inputs):
            # Only allow an event to be posted to the first FT in the list, sorted
            output_idx_le = pack_le_uint32(0)  # Always save to 0th location
            # location = tx_hash + output_idx_le
            # txout = tx.outputs[0]
            # scripthash = double_sha256(txout.pk_script)
            # hashX = self.coin.hashX_from_script(txout.pk_script)
            # sat_value = pack_le_uint64(txout.value)
            self.put_or_delete_state_updates(
                operations_found_at_inputs,
                atomical_id,
                tx_num,
                tx_hash,
                output_idx_le,
                height,
                1,
                False,
            )

    def build_put_atomicals_utxo(self, atomical_id, tx_hash, tx, tx_num, out_idx, atomical_value):
        output_idx_le = pack_le_uint32(out_idx)
        location = tx_hash + output_idx_le
        txout = tx.outputs[out_idx]
        scripthash = double_sha256(txout.pk_script)
        hashX = self.coin.hashX_from_script(txout.pk_script)
        sat_value = pack_le_uint64(txout.value)
        atomical_value = pack_le_uint64(atomical_value)
        put_general_data = self.general_data_cache.__setitem__
        put_general_data(b"po" + location, txout.pk_script)
        tx_numb = pack_le_uint64(tx_num)[:TXNUM_LEN]
        self.put_atomicals_utxo(
            location,
            atomical_id,
            hashX + scripthash + sat_value + atomical_value + tx_numb,
        )

    def put_nft_outputs_by_blueprint(self, nft_blueprint, operations_found_at_inputs, tx_hash, tx, tx_num, height):
        put_general_data = self.general_data_cache.__setitem__
        self.logger.debug(f"nft_blueprint={nft_blueprint}")
        for output_idx, value_info in nft_blueprint.outputs.items():
            output_idx_le = pack_le_uint32(output_idx)
            location = tx_hash + output_idx_le
            txout = tx.outputs[output_idx]
            scripthash = double_sha256(txout.pk_script)
            hashX = self.coin.hashX_from_script(txout.pk_script)
            sat_value = pack_le_uint64(txout.value)
            # NFT value is definitely equals to the sat value.
            atomical_value = sat_value
            put_general_data(b"po" + location, txout.pk_script)
            for atomical_id, atomical_info in value_info["atomicals"].items():
                # Only allow state or event updates if it is not immutable
                if not atomical_info.input_summary_info.mint_info.get("$immutable"):
                    if operations_found_at_inputs:
                        if operations_found_at_inputs["op"] == "mod":
                            self.put_op_data(tx_num, tx_hash, "mod")
                        if operations_found_at_inputs["op"] == "evt":
                            self.put_op_data(tx_num, tx_hash, "evt")
                        if operations_found_at_inputs["op"] == "x":
                            self.put_op_data(tx_num, tx_hash, "splat")
                        if operations_found_at_inputs["op"] == "y":
                            self.put_op_data(tx_num, tx_hash, "split")
                        if operations_found_at_inputs["op"] == "z":
                            self.put_op_data(tx_num, tx_hash, "custom-color")
                    self.put_or_delete_state_updates(
                        operations_found_at_inputs,
                        atomical_id,
                        tx_num,
                        tx_hash,
                        output_idx_le,
                        height,
                        0,
                        False,
                    )
                    self.put_or_delete_state_updates(
                        operations_found_at_inputs,
                        atomical_id,
                        tx_num,
                        tx_hash,
                        output_idx_le,
                        height,
                        1,
                        False,
                    )
                # Only allow NFTs to be sealed.
                # Useful for locking container collections, locking parent realms, and even locking any NFT atomical permanently
                was_sealed = self.put_or_delete_sealed(operations_found_at_inputs, atomical_id, location, False)
                if was_sealed:
                    self.put_op_data(tx_num, tx_hash, "seal")
                    continue
                # Only advance the UTXO if it was not sealed
                tx_numb = pack_le_uint64(tx_num)[:TXNUM_LEN]
                put_bytes: bytes = hashX + scripthash + sat_value + atomical_value + tx_numb
                self.put_atomicals_utxo(location, atomical_id, put_bytes)

    def put_ft_outputs_by_blueprint(self, ft_blueprint, operations_found_at_inputs, tx_hash, tx, tx_num, height):
        for output_idx, value_info in ft_blueprint.outputs.items():
            for atomical_id, atomical_transfer_info in value_info["atomicals"].items():
                atomical_value = atomical_transfer_info.atomical_value
                self.logger.debug(f"atomical_transfer_info={atomical_transfer_info}")
                self.build_put_atomicals_utxo(atomical_id, tx_hash, tx, tx_num, output_idx, atomical_value)
            # Only allow an event to be posted to the first FT in the list, sorted
            if ft_blueprint.first_atomical_id:
                if operations_found_at_inputs:
                    if operations_found_at_inputs["op"] == "x":
                        self.put_op_data(tx_num, tx_hash, "splat")
                    if operations_found_at_inputs["op"] == "y":
                        self.put_op_data(tx_num, tx_hash, "split")
                    if operations_found_at_inputs["op"] == "z":
                        self.put_op_data(tx_num, tx_hash, "custom-color")
                    else:
                        self.put_op_data(tx_num, tx_hash, operations_found_at_inputs["op"])
                self.put_or_delete_event_updates_if_found(
                    operations_found_at_inputs,
                    ft_blueprint.first_atomical_id,
                    tx_num,
                    tx_hash,
                    tx,
                    height,
                )

    # Apply the rules to color the outputs of the atomicals
    def color_atomicals_outputs(
        self,
        operations_found_at_inputs,
        atomicals_spent_at_inputs,
        tx,
        tx_hash,
        tx_num,
        height,
    ):
        # Build the "blueprint" for how to assign all atomicals
        blueprint_builder = AtomicalsTransferBlueprintBuilder(
            self.logger,
            atomicals_spent_at_inputs,
            operations_found_at_inputs,
            tx_hash,
            tx,
            self.get_atomicals_id_mint_info,
            self.is_dmint_activated(height),
            self.is_custom_coloring_activated(height),
        )

        nft_output_blueprint = blueprint_builder.get_nft_output_blueprint()
        if nft_output_blueprint and len(nft_output_blueprint.outputs):
            if not operations_found_at_inputs or not operations_found_at_inputs["op"]:
                self.put_op_data(tx_num, tx_hash, "transfer")
            self.logger.debug(f"color_atomicals_outputs nft_output_blueprint={nft_output_blueprint}")
            self.put_nft_outputs_by_blueprint(
                nft_output_blueprint,
                operations_found_at_inputs,
                tx_hash,
                tx,
                tx_num,
                height,
            )

        ft_output_blueprint = blueprint_builder.get_ft_output_blueprint()
        if ft_output_blueprint and len(ft_output_blueprint.outputs):
            if not operations_found_at_inputs or not operations_found_at_inputs["op"]:
                self.put_op_data(tx_num, tx_hash, "transfer")
            self.logger.debug(f"color_atomicals_outputs ft_output_blueprint={ft_output_blueprint}")
            self.put_ft_outputs_by_blueprint(
                ft_output_blueprint,
                operations_found_at_inputs,
                tx_hash,
                tx,
                tx_num,
                height,
            )

        # Log that there were tokens burned due to not being cleanly assigned
        if blueprint_builder.get_are_fts_burned():
            self.logger.debug(
                f"color_atomicals_outputs:are_fts_burned=True tx_hash={tx_hash} ft_output_blueprint={ft_output_blueprint}"
            )

        return blueprint_builder

    # Create or delete data that was found at the location
    def create_or_delete_data_location(self, tx_hash, operations_found_at_inputs, Delete=False):
        if not operations_found_at_inputs or operations_found_at_inputs["op"] != "dat":
            return False
        the_key = b"dat" + tx_hash + pack_le_uint32(0)
        if Delete:
            self.delete_general_data(the_key)
        else:
            put_general_data = self.general_data_cache.__setitem__
            put_general_data(the_key, operations_found_at_inputs["payload_bytes"])
        return True

    # create or delete the proof of work records
    def create_or_delete_pow_records(self, tx_hash, tx_num, height, operations_found_at_inputs, Delete=False):
        if not operations_found_at_inputs:
            return False

        put_general_data = self.general_data_cache.__setitem__

        # Sanity check, should be the same
        assert tx_hash == operations_found_at_inputs["reveal_location_txid"]

        is_pow_requested, pow_result = has_requested_proof_of_work(operations_found_at_inputs)
        if not is_pow_requested or not pow_result:
            return False

        if not pow_result or (not pow_result["pow_commit"] and not pow_result["pow_reveal"]):
            return False

        tx_numb = pack_le_uint64(tx_num)[:TXNUM_LEN]
        commit_txid = operations_found_at_inputs["commit_txid"]
        commit_location = operations_found_at_inputs["commit_location"]
        reveal_location_txid = operations_found_at_inputs["reveal_location_txid"]
        op = operations_found_at_inputs["op"]
        op_padded = pad_bytes_n(op.encode(), 3)
        # Save any commit tx proof of work (ie: by commit_txid)
        if pow_result["pow_commit"]:
            valid_commit_str, bitwork_commit_parts = is_valid_bitwork_string(pow_result["pow_commit"])
            bitworkcx = bitwork_commit_parts["ext"] or 0
            pow_len_commit = pack_le_uint16(len(pow_result["pow_commit"]))
            pow_commit_padded = pad_bytes_n(pow_result["pow_commit"].encode(), 32)
            # Create the atomicals mint specific pow indexes
            if op == "nft" or op == "ft" or op == "dft":
                atomical_id = commit_location
                powcmb_key = (
                    b"powcmb"
                    + pack_le_uint32(height)
                    + pow_len_commit
                    + pack_le_uint16(bitworkcx)
                    + atomical_id
                    + op_padded
                )
                powcmr_key = b"powcmr" + pow_commit_padded + pack_le_uint32(height) + atomical_id + op_padded
                if Delete:
                    self.delete_general_data(powcmb_key)
                    self.delete_general_data(powcmr_key)
                else:
                    put_general_data(powcmb_key, operations_found_at_inputs["payload_bytes"])
                    put_general_data(powcmr_key, operations_found_at_inputs["payload_bytes"])
            else:
                # Create non-mint (other) operations
                powcob_key = (
                    b"powcob"
                    + pack_le_uint32(height)
                    + pow_len_commit
                    + pack_le_uint16(bitworkcx)
                    + commit_location
                    + op_padded
                )
                powcor_key = b"powcor" + pow_commit_padded + pack_le_uint32(height) + commit_location + op_padded
                if Delete:
                    self.delete_general_data(powcob_key)
                    self.delete_general_data(powcor_key)
                else:
                    put_general_data(powcob_key, operations_found_at_inputs["payload_bytes"])
                    put_general_data(powcor_key, operations_found_at_inputs["payload_bytes"])

        # Save the transaction reveal focused proof of work (ie: by reveal_location_txid)
        # This will index all reveals across all operations
        if pow_result["pow_reveal"]:
            valid_reveal_str, bitwork_reveal_parts = is_valid_bitwork_string(pow_result["pow_reveal"])
            bitworkrx = bitwork_reveal_parts["ext"] or 0
            pow_len_reveal = pack_le_uint16(len(pow_result["pow_reveal"]))
            pow_reveal_padded = pad_bytes_n(pow_result["pow_reveal"].encode(), 32)
            # Create the atomicals mint specific pow indexes
            powrb_key = (
                b"powrb"
                + pack_le_uint32(height)
                + pow_len_reveal
                + pack_le_uint16(bitworkrx)
                + reveal_location_txid
                + op_padded
            )
            powrr_key = b"powrr" + pow_reveal_padded + pack_le_uint32(height) + reveal_location_txid + op_padded
            if Delete:
                self.delete_general_data(powrb_key)
                self.delete_general_data(powrr_key)
            else:
                put_general_data(powrb_key, operations_found_at_inputs["payload_bytes"])
                put_general_data(powrr_key, operations_found_at_inputs["payload_bytes"])

        return pow_result["pow_commit"] or pow_result["pow_reveal"]

    # Get the effective realm considering cache and database
    def get_effective_realm(self, realm_name, height):
        return self.get_effective_name_template(b"rlm", realm_name, height, self.realm_data_cache)

    # Get the effective container considering cache and database
    def get_effective_container(self, container_name, height):
        return self.get_effective_name_template(b"co", container_name, height, self.container_data_cache)

    # Get the effective ticker considering cache and database
    def get_effective_ticker(self, ticker_name, height):
        return self.get_effective_name_template(b"tick", ticker_name, height, self.ticker_data_cache)

    def get_effective_subrealm(self, parent_realm_id, subrealm_name, height):
        current_height = height
        db_prefix = b"srlm"
        # Get the effective name entries from the database
        all_entries = []
        subrealm_name_enc = subrealm_name.encode()
        # Store name len as 4 bytes
        cached_subrealm_name_candidates = self.subrealm_data_cache.get(
            db_prefix + parent_realm_id + subrealm_name_enc + pack_le_uint32(len(subrealm_name_enc))
        )
        if cached_subrealm_name_candidates and len(cached_subrealm_name_candidates) > 0:
            for tx_num, value in cached_subrealm_name_candidates.items():
                all_entries.append({"value": value, "tx_num": tx_num, "cache": True})
        # Store name len as 4 bytes
        db_entries = self.db.get_name_entries_template(
            db_prefix,
            parent_realm_id + subrealm_name_enc + pack_le_uint32(len(subrealm_name_enc)),
        )
        all_entries.extend(db_entries)
        if len(all_entries) == 0:
            return None, None, []
        all_entries.sort(key=lambda x: x["tx_num"])
        for index, entry in enumerate(all_entries):
            atomical_id = entry["value"]
            mint_info = self.get_atomicals_id_mint_info(atomical_id, False)
            # Sanity check to make sure it matches
            self.logger.info(
                f"get_effective_subrealm subrealm_name={subrealm_name} atomical_id={location_id_bytes_to_compact(atomical_id)} parent_realm_id={location_id_bytes_to_compact(parent_realm_id)}entry={entry}"
            )
            assert mint_info["commit_tx_num"] == entry["tx_num"]
            # Get any payments (correct and valid or even premature, just get them all for now)
            payment_entry = self.get_earliest_subrealm_payment(atomical_id)
            self.logger.debug(f"get_effective_subrealm_payment_entry={payment_entry}")

            commit_height = mint_info["commit_height"]
            height_difference = current_height - commit_height
            # If the current candidate doesn't have a payment entry and the MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS
            # has passed, then we know the candidate is expired and invalid.
            if height_difference >= MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS:
                if payment_entry:
                    # Verified and settled fully
                    return "verified", atomical_id, all_entries
                # Skip because the payment window has elapsed and no payment was found
                continue

            # If we got this far it means we are in a potential payment window
            # (potential because the `applicable_rule` could be invalid).
            # A special case is that if the MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS elapsed,
            # and payment was made in the window, then we know no one else can take the sub item, therefore we consider
            # it verified immediately in the payment window.
            if payment_entry:
                if height_difference >= MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS:
                    if index == 0:
                        return "verified", atomical_id, all_entries
                    # For non-leading candidates, they must wait for their previous candidates before the final window.
                    else:
                        return (
                            "pending_previous_candidate_payment",
                            atomical_id,
                            all_entries,
                        )
                else:
                    # Even though a payment was made, we are not after the
                    # MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS to say conclusively that it is verified.
                    return "pending", atomical_id, all_entries

            # If we got this far then it means we are within a potential payment window, with no payment yet made.
            # But we do not want to tell the user it is 'pending_awaiting_payment' until at least
            # MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS blocks has passed, because someone else may have
            # committed the same name and hasn't revealed yet, therefore check which case it is
            if height_difference >= MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS:
                return "pending_awaiting_payment", atomical_id, all_entries
            else:
                # Just indicate it is pending.
                return "pending", atomical_id, all_entries

        # If we fell off to the end it means there are no pending candidates.
        return None, None, all_entries

    async def get_effective_dmitems_paginated(self, parent_container_id, limit, offset, height):
        if limit > 100:
            limit = 100
        dmitem_names = await self.db.get_dmitem_entries_paginated(parent_container_id, limit, offset)
        populated_entries = {}
        for dmitem_name in dmitem_names:
            status, atomical_id, candidates = self.get_effective_dmitem(parent_container_id, dmitem_name, height)
            if status == "verified":
                populated_entries[dmitem_name] = {
                    "status": status,
                    "id": atomical_id,
                    "$id": location_id_bytes_to_compact(atomical_id),
                }
        return populated_entries

    def get_effective_dmitem(self, parent_container_id, dmitem_name, height):
        current_height = height
        db_prefix = b"codmt"
        # Get the effective name entries from the database
        all_entries = []
        dmitem_name_enc = dmitem_name.encode()
        # Store name len as 4 bytes
        cached_dmitem_name_candidates = self.dmitem_data_cache.get(
            db_prefix + parent_container_id + dmitem_name_enc + pack_le_uint32(len(dmitem_name_enc))
        )
        if cached_dmitem_name_candidates and len(cached_dmitem_name_candidates) > 0:
            for tx_num, value in cached_dmitem_name_candidates.items():
                all_entries.append({"value": value, "tx_num": tx_num, "cache": True})
        self.logger.debug(
            f"get_effective_dmitem_db_prefix={db_prefix} parent_container_id={parent_container_id} dmitem_name={dmitem_name} dmitem_name_enc={dmitem_name_enc}"
        )
        # Store name len as 4 bytes
        db_entries = self.db.get_name_entries_template(
            db_prefix,
            parent_container_id + dmitem_name_enc + pack_le_uint32(len(dmitem_name_enc)),
        )
        all_entries.extend(db_entries)
        if len(all_entries) == 0:
            return None, None, []
        all_entries.sort(key=lambda x: x["tx_num"])
        for index, entry in enumerate(all_entries):
            atomical_id = entry["value"]
            mint_info = self.get_atomicals_id_mint_info(atomical_id, False)
            # Sanity check to make sure it matches
            self.logger.debug(
                f"get_effective_dmitem dmitem_name={dmitem_name} atomical_id={location_id_bytes_to_compact(atomical_id)} parent_container_id={location_id_bytes_to_compact(parent_container_id)} entry={entry} height={height}"
            )
            assert mint_info["commit_tx_num"] == entry["tx_num"]
            # Get any payments (correct and valid or even premature, just get them all for now)
            payment_entry = self.get_earliest_dmitem_payment(atomical_id)
            self.logger.debug(f"get_effective_dmitem_payment_entry={payment_entry}")

            commit_height = mint_info["commit_height"]
            height_difference = current_height - commit_height
            # If the current candidate doesn't have a payment entry and the MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS
            # has passed, then we know the candidate is expired and invalid.
            if height_difference >= MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS:
                if payment_entry:
                    # Verified and settled fully
                    return "verified", atomical_id, all_entries
                # Skip because the payment window has elapsed and no payment was found
                continue

            # If we got this far it means we are in a potential payment window
            # (potential because the `applicable_rule` could be invalid).
            # A special case is that if the MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS elapsed,
            # and payment was made in the window, then we know no one else can take the sub item, therefore we consider
            # it verified immediately in the payment window.
            if payment_entry:
                if height_difference >= MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS:
                    if index == 0:
                        return "verified", atomical_id, all_entries
                    # For non-leading candidates, they must wait for their previous candidates before the final window.
                    else:
                        return (
                            "pending_previous_candidate_payment",
                            atomical_id,
                            all_entries,
                        )
                else:
                    # Even though a payment was made, we are not after the
                    # MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS to say conclusively that it is verified.
                    return "pending", atomical_id, all_entries

            # If we got this far then it means we are within a potential payment window, with no payment yet made.
            # But we do not want to tell the user it is 'pending_awaiting_payment' until at least
            # MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS blocks has passed, because someone else may have
            # committed the same name and hasn't revealed yet, therefore check which case it is
            if height_difference >= MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS:
                return "pending_awaiting_payment", atomical_id, all_entries
            else:
                # Just indicate it is pending.
                return "pending", atomical_id, all_entries

        # If we fell off to the end it means there are no pending candidates.
        return None, None, all_entries

    # Get the effective name for realms, containers, and tickers. Does NOT work for subrealms, use the get_effective_subrealm method directly
    def get_effective_name_template(self, db_prefix, subject, height, name_data_cache):
        current_height = height
        # Get the effective name entries from the database
        all_entries = []
        # ex: Key: b'rlm' + name bytes + commit_tx_num
        # Value: atomical_id bytes
        subject_enc = subject.encode()
        # Store name len as 4 bytes
        cached_name_candidates = name_data_cache.get(db_prefix + subject_enc + pack_le_uint32(len(subject_enc)))
        if cached_name_candidates and len(cached_name_candidates) > 0:
            for tx_num, value in cached_name_candidates.items():
                all_entries.append({"value": value, "tx_num": tx_num, "cache": True})
        # Store name len as 4 bytes
        db_entries = self.db.get_name_entries_template(db_prefix, subject_enc + pack_le_uint32(len(subject_enc)))
        all_entries.extend(db_entries)
        # sort by the earliest tx number because it was the first one committed
        all_entries.sort(key=lambda x: x["tx_num"])
        if len(all_entries) > 0:
            candidate_entry = all_entries[0]
            atomical_id = candidate_entry["value"]
            mint_info = self.get_atomicals_id_mint_info(atomical_id, True)
            # Sanity check to make sure it matches
            assert mint_info["commit_tx_num"] == candidate_entry["tx_num"]
            # Only consider the name as valid if the required MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS has elapsed from the earliest
            # commit. We use this technique to ensure that any front running problems would have been resolved by then
            # And anyone who committed a name transaction had sufficient time to reveal it.
            commit_height = mint_info["commit_height"]
            if mint_info["commit_height"] <= current_height - MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS:
                return "verified", atomical_id, all_entries
            else:
                return "pending", atomical_id, all_entries
        return None, None, []

    # Populates a summary of the mint data fields for informational purposes
    def populate_extended_field_summary_atomical_info(self, atomical_id, atomical):
        # Get Mint data fields
        atomical_mint_data_key = b"md" + atomical_id
        db_mint_value = self.db.utxo_db.get(atomical_mint_data_key)
        if db_mint_value:
            decoded_object = loads(db_mint_value)
            unpacked_data_summary = auto_encode_bytes_elements(decoded_object)
            atomical["mint_data"] = {}
            if unpacked_data_summary is not None:
                atomical["mint_data"]["fields"] = unpacked_data_summary
            else:
                atomical["mint_data"]["fields"] = {}
        return atomical

    async def get_base_mint_info_rpc_format_by_atomical_id(self, atomical_id):
        atomical_result = self.atomicals_rpc_format_cache.get(atomical_id)
        if not atomical_result:
            atomical_result = await self.get_base_mint_info_by_atomical_id_async(atomical_id)
            if not atomical_result:
                return None
            convert_db_mint_info_to_rpc_mint_info_format(self.coin.header_hash, atomical_result)
            self.populate_extended_field_summary_atomical_info(atomical_id, atomical_result)
            self.atomicals_rpc_format_cache[atomical_id] = atomical_result
        return atomical_result

    # Get the atomical details base info CACHED wrapper
    async def get_dft_mint_info_rpc_format_by_atomical_id(self, atomical_id):
        if not atomical_id:
            return None

        atomical_result = self.atomicals_rpc_format_cache.get(atomical_id)
        if not atomical_result:
            atomical_result = await self.get_base_mint_info_by_atomical_id_async(atomical_id)
            if not atomical_result:
                return None
            convert_db_mint_info_to_rpc_mint_info_format(self.coin.header_hash, atomical_result)
            self.atomicals_rpc_format_cache[atomical_id] = atomical_result

        # format for the wire format
        if not atomical_result:
            return None

        if atomical_result["type"] != "FT":
            return None

        # Try to get the dft cached info
        dft_results = self.atomicals_rpc_general_cache.get(b"dft_info" + atomical_id)
        if not dft_results:
            atomical_result["dft_info"] = {"mint_count": 0}
            mint_count = self.get_distmints_count_by_atomical_id(self.height, atomical_id, True)
            atomical_result["dft_info"]["mint_count"] = mint_count
            if atomical_result.get("$mint_mode") == "perpetual":
                self.logger.debug(f"atomical_result={atomical_result}")
                mint_bitwork_vec = atomical_result.get("$mint_bitwork_vec")
                mint_bitworkc_inc = atomical_result.get("$mint_bitworkc_inc")
                mint_bitworkr_inc = atomical_result.get("$mint_bitworkr_inc")
                max_mints = atomical_result.get("$max_mints")
                if mint_bitworkc_inc:
                    mint_bitworkc_start = atomical_result["$mint_bitworkc_start"]
                    remaining = max_mints - (mint_count % max_mints)
                    upcoming_bitworks = [
                        {"label": "_current", "mints": mint_count},
                        {
                            "label": "_next",
                            "mints": mint_count + remaining,
                        },
                        {
                            "label": "_next_next",
                            "mints": mint_count + remaining + max_mints,
                        },
                    ]
                    for elem in upcoming_bitworks:
                        atomical_result["dft_info"]["mint_bitworkc" + elem["label"]] = calculate_expected_bitwork(
                            mint_bitwork_vec,
                            elem["mints"],
                            max_mints,
                            mint_bitworkc_inc,
                            mint_bitworkc_start,
                        )
                if mint_bitworkr_inc:
                    mint_bitworkr_start = atomical_result["$mint_bitworkr_start"]
                    remaining = max_mints - (mint_count % max_mints)
                    upcoming_bitworks = [
                        {"label": "_current", "mints": mint_count},
                        {
                            "label": "_next",
                            "mints": mint_count + remaining,
                        },
                        {
                            "label": "_next_next",
                            "mints": mint_count + remaining + max_mints,
                        },
                    ]
                    for elem in upcoming_bitworks:
                        atomical_result["dft_info"]["mint_bitworkr" + elem["label"]] = calculate_expected_bitwork(
                            mint_bitwork_vec,
                            elem["mints"],
                            max_mints,
                            mint_bitworkr_inc,
                            mint_bitworkr_start,
                        )

            atomical_result["location_summary"] = {}
            self.populate_location_info_summary(atomical_id, atomical_result["location_summary"])
            self.atomicals_rpc_general_cache[b"dft_info" + atomical_id] = atomical_result
            return atomical_result
        return dft_results

    # Populate location information
    def populate_location_info_summary(self, atomical_id, atomical_result):
        unique_holders = {}
        active_supply = 0
        atomical_active_location_key_prefix = b"a" + atomical_id
        for (
            atomical_active_location_key,
            atomical_active_location_value,
        ) in self.db.utxo_db.iterator(prefix=atomical_active_location_key_prefix):
            location = atomical_active_location_key[1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
            atomical_value = self.db.get_uxto_atomicals_value(location, atomical_id)
            active_supply += atomical_value
            scripthash = atomical_active_location_value[HASHX_LEN : HASHX_LEN + SCRIPTHASH_LEN]
            unique_holders[scripthash] = True
        atomical_result["unique_holders"] = len(unique_holders)
        atomical_result["circulating_supply"] = active_supply

    # Get the atomical details base info CACHED wrapper
    async def get_ft_mint_info_rpc_format_by_atomical_id(self, atomical_id):
        if not atomical_id:
            return None
        atomical_result = self.atomicals_rpc_format_cache.get(atomical_id)
        if not atomical_result:
            atomical_result = await self.get_base_mint_info_by_atomical_id_async(atomical_id)
            if not atomical_result:
                return None
            convert_db_mint_info_to_rpc_mint_info_format(self.coin.header_hash, atomical_result)
            self.atomicals_rpc_format_cache[atomical_id] = atomical_result

        # format for the wire format
        if not atomical_result:
            return None
        if atomical_result["type"] != "FT":
            return None

        ft_results = self.atomicals_rpc_general_cache.get(b"ft_info" + atomical_id)
        if not ft_results:
            atomical_result["ft_info"] = {}
            atomical_result["location_summary"] = {}
            self.populate_location_info_summary(atomical_id, atomical_result["location_summary"])
            self.atomicals_rpc_general_cache[b"ft_info" + atomical_id] = atomical_result
            return atomical_result
        return ft_results

    # Get the raw stored mint info in the db
    def get_raw_mint_info_by_atomical_id_notused(self, atomical_id):
        atomical_mint_info_key = b"mi" + atomical_id

        atomical_mint_info_value = self.db.utxo_db.get(atomical_mint_info_key)
        if not atomical_mint_info_value:
            return None
        return loads(atomical_mint_info_value)

    # Get the atomical details base info
    # Does not retrieve the active b'a' locations in this method because there could be many thousands (in the case of FTs)
    # Another method is provided to layer on the active location and gives the user control over whether to retrieve them
    def get_base_mint_info_by_atomical_id(self, atomical_id, height: Optional[int] = None):
        height = height or self.height
        init_mint_info = self.get_atomicals_id_mint_info(atomical_id, True)
        if not init_mint_info:
            return None
        atomical_number = init_mint_info["number"]
        atomical = {
            "atomical_id": atomical_id,
            "atomical_number": atomical_number,
            "atomical_ref": init_mint_info.get("ref"),
            "type": init_mint_info["type"],
            "confirmed": True,
            "mint_info": {
                "commit_txid": init_mint_info["commit_txid"],
                "commit_index": init_mint_info["commit_index"],
                "commit_location": init_mint_info["commit_location"],
                "commit_tx_num": init_mint_info["commit_tx_num"],
                "commit_height": init_mint_info["commit_height"],
                "reveal_location_txid": init_mint_info["reveal_location_txid"],
                "reveal_location_index": init_mint_info["reveal_location_index"],
                "reveal_location": init_mint_info["reveal_location"],
                "reveal_location_tx_num": init_mint_info["reveal_location_tx_num"],
                "reveal_location_height": init_mint_info["reveal_location_height"],
                "reveal_location_header": init_mint_info["reveal_location_header"],
                "reveal_location_blockhash": self.coin.header_hash(init_mint_info["reveal_location_header"]),
                "reveal_location_scripthash": init_mint_info["reveal_location_scripthash"],
                "reveal_location_script": init_mint_info["reveal_location_script"],
                "reveal_location_value": init_mint_info["reveal_location_value"],
                "args": init_mint_info["args"],
                "meta": init_mint_info["meta"],
                "ctx": init_mint_info["ctx"],
                # Do not include init data by default since it could be rather large binary
                # It can be retrieved via the state
                # 'init': init_mint_info.get('init')
            },
        }

        # Attach the type specific information
        if atomical["type"] == "NFT":
            # Attach any auxiliary information that was already successfully parsed before
            request_realm = init_mint_info.get("$request_realm")
            if request_realm:
                atomical["mint_info"]["$request_realm"] = request_realm

            request_subrealm = init_mint_info.get("$request_subrealm")
            if request_subrealm:
                atomical["mint_info"]["$request_subrealm"] = request_subrealm
                # The pid is known to be set
                atomical["mint_info"]["$parent_realm"] = init_mint_info["$parent_realm"]

            request_container = init_mint_info.get("$request_container")
            if request_container:
                atomical["mint_info"]["$request_container"] = request_container

            request_dmitem = init_mint_info.get("$request_dmitem")
            if request_dmitem:
                atomical["mint_info"]["$request_dmitem"] = request_dmitem
                # The pid is known to be set
                atomical["mint_info"]["$parent_container"] = init_mint_info["$parent_container"]

            immutable = init_mint_info.get("$immutable")
            if immutable:
                atomical["mint_info"]["$immutable"] = immutable
            else:
                atomical["mint_info"]["$immutable"] = False

        elif atomical["type"] == "FT":
            subtype = init_mint_info.get("subtype")
            atomical["subtype"] = subtype
            if subtype == "decentralized":
                # The mint mode can be fixed with a known max_supply
                # Or the mode mint can be perpetual with an unbounded max_supply
                atomical["$mint_mode"] = init_mint_info.get("$mint_mode") or "fixed"
                if init_mint_info.get("$mint_mode") == "perpetual":
                    atomical["$max_supply"] = init_mint_info["$max_supply"]
                    atomical["$mint_bitwork_vec"] = init_mint_info["$mint_bitwork_vec"]
                    atomical["$mint_bitworkc_inc"] = init_mint_info.get("$mint_bitworkc_inc")
                    atomical["$mint_bitworkc_start"] = init_mint_info.get("$mint_bitworkc_start")
                    atomical["$mint_bitworkr_inc"] = init_mint_info.get("$mint_bitworkr_inc")
                    atomical["$mint_bitworkr_start"] = init_mint_info.get("$mint_bitworkr_start")
                    atomical["$max_mints_global"] = init_mint_info.get("$max_mints_global")
                else:
                    atomical["$max_supply"] = init_mint_info["$max_supply"]

                atomical["$mint_height"] = init_mint_info["$mint_height"]
                atomical["$mint_amount"] = init_mint_info["$mint_amount"]
                # The semantics of max_mints is total number of mints when mint_mode=fixed and it is the
                # max mints per epoch step increment with perpetual mint_mode
                atomical["$max_mints"] = init_mint_info["$max_mints"]
                # The decentralized FT also has a proof of work option such that it requires some proof of work
                # To be minted by users. The deployer can determine if the proof of work must appear in the
                # Commit or the reveal transaction (or both)
                mint_pow_commit = init_mint_info.get("$mint_bitworkc")
                if mint_pow_commit:
                    atomical["mint_info"]["$mint_bitworkc"] = mint_pow_commit
                    atomical["$mint_bitworkc"] = mint_pow_commit

                mint_pow_reveal = init_mint_info.get("$mint_bitworkr")
                if mint_pow_reveal:
                    atomical["mint_info"]["$mint_bitworkr"] = mint_pow_reveal
                    atomical["$mint_bitworkr"] = mint_pow_reveal

            else:
                atomical["$max_supply"] = init_mint_info["$max_supply"]
            request_ticker = init_mint_info.get("$request_ticker")
            if request_ticker:
                atomical["mint_info"]["$request_ticker"] = request_ticker

        # Check if there is the $bitwork variable and bring it to the top
        pow_val = init_mint_info.get("$bitwork")
        if pow_val:
            atomical["mint_info"]["$bitwork"] = pow_val
            atomical["$bitwork"] = pow_val

        # Check if there was a parent assigned
        parents = init_mint_info.get("$parents")
        if parents:
            atomical["mint_info"]["$parents"] = parents
            atomical["$parents"] = parents

        # Resolve any name like details such as realms, subrealms, containers and tickers
        self.populate_extended_atomical_subtype_info(atomical, height)
        self.populate_sealed_status(atomical)
        self.populate_container_dmint_status(atomical, height)

        return atomical

    # Get the atomical details base info async
    async def get_base_mint_info_by_atomical_id_async(self, atomical_id):
        that = self

        def read_atomical():
            return that.get_base_mint_info_by_atomical_id(atomical_id)

        return await run_in_thread(read_atomical)

    # Populate the sealed status of an atomical
    def populate_sealed_status(self, atomical):
        sealed_location = self.get_general_data_with_cache(b"sealed" + atomical["atomical_id"])
        if sealed_location:
            atomical["$sealed"] = location_id_bytes_to_compact(sealed_location)

    # Populate the sealed status of an atomical
    def populate_container_dmint_status(self, atomical, height: int):
        if not atomical.get("$container"):
            return
        status = self.make_container_dmint_status_by_atomical_id_at_height(atomical["atomical_id"], height)
        if not status:
            return
        atomical["$container_dmint_status"] = status

    def make_container_dmint_status_by_atomical_id_at_height(self, atomical_id, height):
        rule_mint_mod_history = self.get_mod_history(atomical_id, height)
        latest_state = calculate_latest_state_from_mod_history(rule_mint_mod_history)
        return self.get_container_dmint_status_for_atomical_id(atomical_id, latest_state)

    def get_container_dmint_status_for_atomical_id(self, atomical_id, latest_state):
        if not latest_state:
            return None
        dmint = latest_state.get(DMINT_PATH)
        if not dmint:
            return None
        dmint_format_status = get_container_dmint_format_status(dmint)
        items = latest_state.get("items")
        if items:
            dmint_format_status["errors"].append("items cannot be set manually for dmint")
            dmint_format_status["status"] = "invalid"

        sealed_location = self.get_general_data_with_cache(b"sealed" + atomical_id)
        if not sealed_location:
            dmint_format_status["errors"].append("container not sealed")
            dmint_format_status["status"] = "invalid"

        dmint_format_status["dmint"] = dmint
        return dmint_format_status

    # Build a map for the name candidates (not subrealms, that's handled below in another function)
    # We use this method to fetch information such as commit_height and reveal_location_height for informative purposes to display to client
    def build_atomical_id_to_candidate_map(self, raw_candidate_entries):
        atomical_id_to_candidates_map = {}
        for raw_candidate_entry in raw_candidate_entries:
            candidate_atomical_id = raw_candidate_entry["value"]
            raw_mint_info_for_candidate_id = self.get_atomicals_id_mint_info(candidate_atomical_id, True)
            atomical_id_to_candidates_map[candidate_atomical_id] = {
                "commit_height": raw_mint_info_for_candidate_id["commit_height"],
                "reveal_location_height": raw_mint_info_for_candidate_id["reveal_location_height"],
            }
        return atomical_id_to_candidates_map

    # Populate the requested full realm name to provide context for a subrealm request
    def populate_request_full_realm_name(self, atomical, pid, request_subrealm, height: Optional[int] = None):
        # Resolve the parent realm to get the parent realm path and construct the full_realm_name
        parent_realm = self.get_base_mint_info_by_atomical_id(pid, height)
        if not parent_realm:
            atomical_id = atomical["mint_info"]["id"]
            raise IndexError(
                f"populate_request_full_realm_name: parent realm not found atomical_id={atomical_id}, parent_realm={parent_realm}"
            )
        parent_full_realm_name = parent_realm.get("$full_realm_name")
        if parent_full_realm_name:
            atomical["$request_full_realm_name"] = parent_full_realm_name + "." + request_subrealm
        return atomical

    # Build a map of applicable rules for each candidate
    def build_applicable_rule_map(self, all_entries, arg_pid, arg_request_subrealm):
        applicable_rule_map = {}
        for candidate_entry in all_entries:
            self.logger.debug(f"build_applicable_rule_map: candidate_entry={candidate_entry}")
            subrealm_candidate_atomical_id = candidate_entry["value"]
            raw_mint_info_for_candidate_id = self.get_atomicals_id_mint_info(subrealm_candidate_atomical_id, True)
            applicable_rule_map[subrealm_candidate_atomical_id] = {
                "commit_height": raw_mint_info_for_candidate_id["commit_height"],
                "reveal_location_height": raw_mint_info_for_candidate_id["reveal_location_height"],
            }
            applicable_rule_map[subrealm_candidate_atomical_id]["payment"] = None
            payment_data = self.get_earliest_subrealm_payment(subrealm_candidate_atomical_id)
            payment_type = "applicable_rule"
            payment_subtype = None
            if payment_data and payment_data.get("mint_initiated") == b"01":
                payment_type = "mint_initiated"
                payment_subtype = "parent"
            elif payment_data and payment_data.get("mint_initiated") == b"02":
                payment_type = "mint_initiated"
                payment_subtype = "bitwork"

            # Whether or not it was initiated by the parent or the mint only needed bitwork, we attached the applicable rule anyways
            applicable_rule, state_at_height = self.get_applicable_rule_by_height(
                arg_pid,
                arg_request_subrealm,
                raw_mint_info_for_candidate_id["commit_height"] - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
                SUBREALM_MINT_PATH,
            )
            applicable_rule_map[subrealm_candidate_atomical_id]["applicable_rule"] = applicable_rule
            if payment_data:
                applicable_rule_map[subrealm_candidate_atomical_id]["payment"] = location_id_bytes_to_compact(
                    payment_data["payment_tx_outpoint"]
                )
            applicable_rule_map[subrealm_candidate_atomical_id]["payment_type"] = payment_type
            applicable_rule_map[subrealm_candidate_atomical_id]["payment_subtype"] = payment_subtype
        return applicable_rule_map

    # Build a map of applicable rules for each candidate
    def build_applicable_rule_map_dmitem(self, all_entries, arg_pid, arg_request_dmitem):
        applicable_rule_map = {}
        for candidate_entry in all_entries:
            self.logger.debug(f"build_applicable_rule_map: candidate_entry={candidate_entry}")
            candidate_atomical_id = candidate_entry["value"]
            raw_mint_info_for_candidate_id = self.get_atomicals_id_mint_info(candidate_atomical_id, True)
            applicable_rule_map[candidate_atomical_id] = {
                "commit_height": raw_mint_info_for_candidate_id["commit_height"],
                "reveal_location_height": raw_mint_info_for_candidate_id["reveal_location_height"],
            }
            applicable_rule_map[candidate_atomical_id]["payment"] = None
            payment_data = self.get_earliest_dmitem_payment(candidate_atomical_id)
            payment_type = "applicable_rule"
            payment_subtype = None
            if payment_data and payment_data.get("mint_initiated") == b"02":
                payment_type = "mint_initiated"
                payment_subtype = "bitwork"
            # Whether or not it was initiated by the parent or the mint only needed bitwork, we attached the applicable rule anyways
            applicable_rule, state_at_height = self.get_applicable_rule_by_height(
                arg_pid,
                arg_request_dmitem,
                raw_mint_info_for_candidate_id["commit_height"] - MINT_SUBNAME_RULES_BECOME_EFFECTIVE_IN_BLOCKS,
                DMINT_PATH,
            )
            applicable_rule_map[candidate_atomical_id]["applicable_rule"] = applicable_rule
            if payment_data:
                applicable_rule_map[candidate_atomical_id]["payment"] = location_id_bytes_to_compact(
                    payment_data["payment_tx_outpoint"]
                )
            applicable_rule_map[candidate_atomical_id]["payment_type"] = payment_type
            applicable_rule_map[candidate_atomical_id]["payment_subtype"] = payment_subtype
        return applicable_rule_map

    # Populate the specific name or request type for containers, tickers, and realms (sub-realms excluded)
    def populate_name_subtype_specific_fields(self, atomical, type_str, get_effective_name_func, height: int):
        request_name = atomical["mint_info"].get("$request_" + type_str)
        if not request_name:
            return None, None
        status, candidate_id, raw_candidate_entries = get_effective_name_func(request_name, height)
        atomical["$" + type_str + "_candidates"] = format_name_type_candidates_to_rpc(
            raw_candidate_entries,
            self.build_atomical_id_to_candidate_map(raw_candidate_entries),
        )
        atomical["$request_" + type_str + "_status"] = get_name_request_candidate_status(
            atomical, status, candidate_id, type_str
        )
        # Populate the request specific fields
        atomical["$request_" + type_str] = atomical["mint_info"].get("$request_" + type_str)
        return (
            request_name,
            status == "verified" and atomical["atomical_id"] == candidate_id,
        )

    # Populate the specific subrealm request type information
    def populate_subrealm_subtype_specific_fields(self, atomical, height: int):
        # Check if the effective subrealm is for the current atomical and also resolve its parent.
        request_subrealm = atomical["mint_info"].get("$request_subrealm")
        if not request_subrealm:
            return None, None
        pid_compact = atomical["mint_info"]["$parent_realm"]
        pid = compact_to_location_id_bytes(pid_compact)
        status, candidate_id, raw_candidate_entries = self.get_effective_subrealm(pid, request_subrealm, height)
        atomical["subtype"] = "request_subrealm"  # Will change to 'subrealm' if it is found to be valid
        # Populate the requested full realm name
        self.populate_request_full_realm_name(atomical, pid, request_subrealm, height)
        # Build the applicable rule set mapping of atomical_id to the rule that will need to be matched and paid.
        # We use this information to display to each candidate what rule would apply to their mint
        # and how much to pay and by which block height they must submit their payment
        # (assuming they are the leading candidate)
        applicable_rule_map = self.build_applicable_rule_map(raw_candidate_entries, pid, request_subrealm)
        self.logger.info(
            f"populate_subrealm_subtype_specific_fields_applicable_rule_map {applicable_rule_map} "
            f"raw_candidate_entries={raw_candidate_entries}",
        )
        atomical["$subrealm_candidates"] = format_name_type_candidates_to_rpc_for_subname(
            raw_candidate_entries,
            applicable_rule_map,
        )
        atomical["$request_subrealm_status"] = get_subname_request_candidate_status(
            self.height,
            atomical,
            status,
            candidate_id,
            "subrealm",
        )
        # Populate the request specific fields.
        atomical["$request_subrealm"] = atomical["mint_info"].get("$request_subrealm")
        atomical["$parent_realm"] = pid_compact
        # Resolve the parent realm to get the parent realm path and construct the `full_realm_name`.
        parent_realm = self.get_base_mint_info_by_atomical_id(pid, height)
        if not parent_realm:
            atomical_id = atomical["mint_info"]["id"]
            raise IndexError(
                f"populate_subrealm_subtype_specific_fields: "
                f"parent realm not found atomical_id={atomical_id}, "
                f"parent_realm={parent_realm}",
            )
        self.logger.info(f"populate_subrealm_subtype_specific_fields: parent_realm={parent_realm}")
        # The parent full realm name may not be populated if it's still in the mempool,
        # or it's not settled realm request yet. Therefore, check to make sure it exists
        # before we can populate this subrealm's full realm name.
        if parent_realm.get("$full_realm_name"):
            parent_realm_name = parent_realm["$full_realm_name"]
            atomical["$full_realm_name"] = f"{parent_realm_name}.{request_subrealm}"
        if status == "verified" and candidate_id == atomical["atomical_id"]:
            atomical["subtype"] = "subrealm"
            atomical["$subrealm"] = request_subrealm
            atomical["$parent_realm"] = pid_compact
            return request_subrealm, True
        return request_subrealm, False

    # Populate the specific dmitem request type information
    def populate_dmitem_subtype_specific_fields(self, atomical, height: int):
        # Check if the effective dmitem is for the current atomical and also resolve its parent.
        request_dmitem = atomical["mint_info"].get("$request_dmitem")
        if not request_dmitem:
            return None, None
        pid_compact = atomical["mint_info"]["$parent_container"]
        pid = compact_to_location_id_bytes(pid_compact)
        status, candidate_id, raw_candidate_entries = self.get_effective_dmitem(pid, request_dmitem, height)
        atomical["subtype"] = "request_dmitem"  # Will change to 'dmitem' if it is found to be valid.
        # Build the applicable rule set mapping of atomical_id to the rule that will need to be matched and paid.
        # We use this information to display to each candidate what rule would apply to their mint
        # and how much to pay and by which block height they must submit their payment
        # (assuming they are the leading candidate).
        applicable_rule_map = self.build_applicable_rule_map_dmitem(raw_candidate_entries, pid, request_dmitem)
        self.logger.info(
            f"populate_dmitem_subtype_specific_fields "
            f"build_applicable_rule_map_dmitem "
            f"applicable_rule_map={applicable_rule_map} "
            f"raw_candidate_entries={raw_candidate_entries}",
        )
        atomical["$dmitem_candidates"] = format_name_type_candidates_to_rpc_for_subname(
            raw_candidate_entries,
            applicable_rule_map,
        )
        atomical["$request_dmitem_status"] = get_subname_request_candidate_status(
            self.height,
            atomical,
            status,
            candidate_id,
            "dmitem",
        )
        # Populate the request specific fields.
        atomical["$request_dmitem"] = atomical["mint_info"].get("$request_dmitem")
        atomical["$parent_container"] = pid_compact
        # Resolve the parent to get the parent path and construct the `parent_container_name`.
        parent_container = self.get_base_mint_info_by_atomical_id(pid, height)
        if not parent_container:
            atomical_id = atomical["mint_info"]["id"]
            raise IndexError(
                f"populate_dmitem_subtype_specific_fields: "
                f"parent container not found atomical_id={atomical_id}, "
                f"parent_container={parent_container}",
            )
        # The parent container name may not be populated if it's still in the mempool,
        # or it's not settled realm request yet. Therefore, check to make sure it exists
        # before we can populate this dmitem's container name.
        if parent_container.get("$container"):
            atomical["$parent_container_name"] = parent_container["$container"]
        if status == "verified" and candidate_id == atomical["atomical_id"]:
            atomical["subtype"] = "dmitem"
            atomical["$dmitem"] = request_dmitem
            return request_dmitem, True
        return request_dmitem, False

    # Populate the subtype information such as realms, subrealms, containers and tickers
    # An atomical can have a naming element if it passed all the validity checks of the assignment
    # and for that reason there is the concept of "effective" name which is based on a commit/reveal delay pattern
    def populate_extended_atomical_subtype_info(self, atomical, height: int):
        #
        # TOP-REALM (TLR) Type Fields
        #
        (
            the_name_request,
            is_atomical_name_verified_found,
        ) = self.populate_name_subtype_specific_fields(atomical, "realm", self.get_effective_realm, height)
        if is_atomical_name_verified_found:
            atomical["subtype"] = "realm"
            atomical["$realm"] = the_name_request
            atomical["$full_realm_name"] = the_name_request
            return atomical
        elif the_name_request:
            # False indicates it is a request for the name, but it was not the current one
            atomical["subtype"] = "request_realm"
            return atomical
        #
        # CONTAINER Type Fields
        #
        (
            the_name_request,
            is_atomical_name_verified_found,
        ) = self.populate_name_subtype_specific_fields(atomical, "container", self.get_effective_container, height)
        if is_atomical_name_verified_found:
            atomical["subtype"] = "container"
            atomical["$container"] = the_name_request
            return atomical
        elif the_name_request:
            # False indicates it is a request for the name, but it was not the current one
            atomical["subtype"] = "request_container"
            return atomical
        #
        # TICKER NAME FIELDS
        #
        (
            the_name_request,
            is_atomical_name_verified_found,
        ) = self.populate_name_subtype_specific_fields(atomical, "ticker", self.get_effective_ticker, height)
        if is_atomical_name_verified_found:
            atomical["$ticker"] = the_name_request
            return atomical
        elif the_name_request:
            # False indicates it is a request for the name, but it was not the current one
            return atomical
        #
        # SUBREALM type fields
        #
        # The method populates all the fields and nothing more needs to be done at this level for subrealms
        self.populate_subrealm_subtype_specific_fields(atomical, height)
        #
        # DMITEM type fields
        #
        # The method populates all the fields and nothing more needs to be done at this level for dmitems
        self.populate_dmitem_subtype_specific_fields(atomical, height)

        return atomical

    def is_dft_bitwork_rollover_activated(self, height):
        return height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_DFT_BITWORK_ROLLOVER

    # Create a distributed mint output as long as the rules are satisfied
    def create_or_delete_decentralized_mint_output(
        self,
        atomicals_operations_found_at_inputs,
        tx_num,
        tx_hash,
        tx,
        height,
        ticker_cache,
        Delete,
    ):
        if not atomicals_operations_found_at_inputs:
            return None

        dmt_valid, dmt_return_struct = is_valid_dmt_op_format(tx_hash, atomicals_operations_found_at_inputs)
        if not dmt_valid:
            return None

        # get the potential dmt (distributed mint) atomical_id from the ticker given
        ticker = dmt_return_struct["$mint_ticker"]

        # Save the mint info for the ticker
        mint_info_for_ticker = ticker_cache.get(ticker)
        if not mint_info_for_ticker:
            status, potential_dmt_atomical_id, all_entries = self.get_effective_ticker(ticker, height)
            if status != "verified":
                self.logger.info(
                    f"create_or_delete_decentralized_mint_output: potential_dmt_atomical_id not found for dmt operation in {hash_to_hex_str(tx_hash)}. Attempt was made for invalid ticker mint info. Ignoring..."
                )
                return None
            mint_info_for_ticker = self.get_atomicals_id_mint_info(potential_dmt_atomical_id, True)
            if not mint_info_for_ticker:
                raise IndexError(
                    f"create_or_delete_decentralized_mint_outputs: mint_info_for_ticker not found for expected atomical={potential_dmt_atomical_id}"
                )
            ticker_cache[ticker] = mint_info_for_ticker

        if mint_info_for_ticker["subtype"] != "decentralized":
            self.logger.info(
                f"create_or_delete_decentralized_mint_outputs: Detected invalid mint attempt in {hash_to_hex_str(tx_hash)} for ticker {ticker} which is not a decentralized mint type. Ignoring..."
            )
            return None

        # For perpetual mints mint_mode=perpetual otherwise it is fixed (None or 'fixed')
        mint_mode = mint_info_for_ticker.get("$mint_mode")
        max_mints = mint_info_for_ticker["$max_mints"]
        mint_amount = mint_info_for_ticker["$mint_amount"]
        mint_height = mint_info_for_ticker["$mint_height"]
        if height < mint_height:
            self.logger.info(
                f"create_or_delete_decentralized_mint_outputs found premature mint operation in {hash_to_hex_str(tx_hash)} for {ticker} in {height} before {mint_height}. Ignoring..."
            )
            return None

        commit_txid = atomicals_operations_found_at_inputs["commit_txid"]
        commit_tx_num, commit_tx_height = self.get_tx_num_height_from_tx_hash(commit_txid)
        if not commit_tx_num:
            self.logger.info(
                f"create_or_delete_decentralized_mint_output: commit_txid not found for distmint reveal_tx {hash_to_hex_str(commit_txid)}. Skipping..."
            )
            return None
        if commit_tx_height < mint_height:
            self.logger.info(
                f"create_or_delete_decentralized_mint_output: commit_tx_height={commit_tx_height} is less than DFT mint_height. Skipping..."
            )
            return None
        commit_index = atomicals_operations_found_at_inputs["commit_index"]
        if height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_COMMITZ and commit_index != 0:
            self.logger.info(
                f"create_or_delete_decentralized_mint_output: commit_index={commit_index} is not equal to 0 in tx {hash_to_hex_str(commit_txid)}. Skipping..."
            )
            return None

        dmt_mint_atomical_id = mint_info_for_ticker["atomical_id"]
        expected_output_index = 0
        output_idx_le = pack_le_uint32(expected_output_index)
        location = tx_hash + output_idx_le
        txout = tx.outputs[expected_output_index]
        scripthash = double_sha256(txout.pk_script)
        hashX = self.coin.hashX_from_script(txout.pk_script)
        sat_value = pack_le_uint64(txout.value)
        # Minted value is definitely equals to the sat value.
        atomical_value = sat_value
        # Mint is valid and active if the value is what is expected
        if mint_amount == txout.value:
            # Count the number of existing b'gi' entries and ensure it is strictly less than max_mints
            decentralized_mints = self.get_distmints_count_by_atomical_id(height, dmt_mint_atomical_id, True)
            # Assess whether we allow the mint based on 'fixed' or 'perpetual' mint modes
            # The perpetual mint mode will derive the minimum expected bitworkr/c needed given the quantity of already minted units
            allow_mint = False
            if mint_mode == "perpetual":
                # If the perpetual token as a global max, then validate
                max_mints_global = mint_info_for_ticker.get("$max_mints_global")
                if max_mints_global:
                    if decentralized_mints > max_mints_global:
                        raise IndexError(
                            f"create_or_delete_decentralized_mint_outputs: Fatal IndexError decentralized_mints > max_mints_global for {location_id_bytes_to_compact(dmt_mint_atomical_id)}. Too many mints detected in db"
                        )
                    if decentralized_mints == max_mints_global:
                        self.logger.debug(
                            f"create_or_delete_decentralized_mint_outputs found invalid mint infinit operation because it is minted out completely due to global max mints. {hash_to_hex_str(tx_hash)}. Ignoring..."
                        )
                        return None

                self.logger.debug(
                    f"create_or_delete_decentralized_mint_outputs: found perpetual mint request in {hash_to_hex_str(tx_hash)} for {ticker}. Checking for any POW in distributed mint record..."
                )
                # In the 'perpetual' mint mode an unbounded number of tokens can be minted according to the ever increasing bitworkc/r
                mint_bitwork_vec = mint_info_for_ticker.get("$mint_bitwork_vec")
                mint_bitworkc_inc = mint_info_for_ticker.get("$mint_bitworkc_inc")
                mint_bitworkr_inc = mint_info_for_ticker.get("$mint_bitworkr_inc")

                # If there was a commit bitwork required, then assess the stage of the minimum we expect to allow the mint
                if mint_bitworkc_inc:
                    mint_bitworkc_start = mint_info_for_ticker.get("$mint_bitworkc_start")
                    if self.is_dft_bitwork_rollover_activated(height):
                        success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
                            atomicals_operations_found_at_inputs["commit_txid"],
                            mint_bitwork_vec,
                            decentralized_mints,
                            max_mints,
                            mint_bitworkc_inc,
                            mint_bitworkc_start,
                            True,
                        )
                        if not success:
                            self.logger.warning(
                                f"create_or_delete_decentralized_mint_output: mint_bitworkc_inc not is_mint_pow_valid {hash_to_hex_str(tx_hash)}, atomicals_operations_found_at_inputs={atomicals_operations_found_at_inputs}..."
                            )
                            return None
                    else:
                        success, bitwork_str = is_txid_valid_for_perpetual_bitwork(
                            atomicals_operations_found_at_inputs["commit_txid"],
                            mint_bitwork_vec,
                            decentralized_mints,
                            max_mints,
                            mint_bitworkc_inc,
                            mint_bitworkc_start,
                            False,
                        )
                        if not success:
                            self.logger.warning(
                                f"create_or_delete_decentralized_mint_output: mint_bitworkc_inc not is_mint_pow_valid {hash_to_hex_str(tx_hash)}, atomicals_operations_found_at_inputs={atomicals_operations_found_at_inputs}..."
                            )
                            return None

                # If there was a reveal bitwork required, then assess the stage of the minimum we expect to allow the mint
                if mint_bitworkr_inc:
                    mint_bitworkr_start = mint_info_for_ticker.get("$mint_bitworkr_start")
                    if self.is_dft_bitwork_rollover_activated(height):
                        if not is_txid_valid_for_perpetual_bitwork(
                            atomicals_operations_found_at_inputs["reveal_location_txid"],
                            mint_bitwork_vec,
                            decentralized_mints,
                            max_mints,
                            mint_bitworkr_inc,
                            mint_bitworkr_start,
                            True,
                        ):
                            self.logger.warning(
                                f"create_or_delete_decentralized_mint_output: mint_bitworkr_inc not is_mint_pow_valid {hash_to_hex_str(tx_hash)}, atomicals_operations_found_at_inputs={atomicals_operations_found_at_inputs}..."
                            )
                            return None
                    else:
                        if not is_txid_valid_for_perpetual_bitwork(
                            atomicals_operations_found_at_inputs["reveal_location_txid"],
                            mint_bitwork_vec,
                            decentralized_mints,
                            max_mints,
                            mint_bitworkr_inc,
                            mint_bitworkr_start,
                            False,
                        ):
                            self.logger.warning(
                                f"create_or_delete_decentralized_mint_output: mint_bitworkr_inc not is_mint_pow_valid {hash_to_hex_str(tx_hash)}, atomicals_operations_found_at_inputs={atomicals_operations_found_at_inputs}..."
                            )
                            return None

                allow_mint = True
            else:
                # It is the 'fixed' mint mode and the bitworkc/r is static
                mint_pow_commit = mint_info_for_ticker.get("$mint_bitworkc")
                mint_pow_reveal = mint_info_for_ticker.get("$mint_bitworkr")
                # In the fixed mode there is a max number of mints allowed and then no more
                if decentralized_mints > max_mints:
                    raise IndexError(
                        f"create_or_delete_decentralized_mint_outputs: Fatal IndexError decentralized_mints > max_mints for {location_id_bytes_to_compact(dmt_mint_atomical_id)}. Too many mints detected in db"
                    )

                if decentralized_mints < max_mints:
                    self.logger.debug(
                        f"create_or_delete_decentralized_mint_outputs: found mint request in {hash_to_hex_str(tx_hash)} for {ticker}. Checking for any POW in distributed mint record..."
                    )
                    # If this was a POW mint, then validate that the POW is valid
                    if mint_pow_commit:
                        if not is_mint_pow_valid(
                            atomicals_operations_found_at_inputs["commit_txid"],
                            mint_pow_commit,
                        ):
                            self.logger.warning(
                                f"create_or_delete_decentralized_mint_output: not is_mint_pow_valid {hash_to_hex_str(tx_hash)}, mint_pow_commit={mint_pow_commit}, atomicals_operations_found_at_inputs={atomicals_operations_found_at_inputs}..."
                            )
                            return None
                    if mint_pow_reveal:
                        if not is_mint_pow_valid(
                            atomicals_operations_found_at_inputs["reveal_location_txid"],
                            mint_pow_reveal,
                        ):
                            self.logger.warning(
                                f"create_or_delete_decentralized_mint_output: not is_mint_pow_valid {hash_to_hex_str(tx_hash)}, mint_pow_reveal={mint_pow_reveal}, atomicals_operations_found_at_inputs={atomicals_operations_found_at_inputs}..."
                            )
                            return None
                    allow_mint = True

            if allow_mint:
                the_key = b"po" + location
                if Delete:
                    atomicals_found_list = self.spend_atomicals_utxo(tx_hash, expected_output_index, True)
                    assert len(atomicals_found_list) > 0
                    self.delete_general_data(the_key)
                    self.delete_decentralized_mint_data(dmt_mint_atomical_id, location)
                    return dmt_mint_atomical_id
                else:
                    put_general_data = self.general_data_cache.__setitem__
                    put_general_data(the_key, txout.pk_script)
                    tx_numb = pack_le_uint64(tx_num)[:TXNUM_LEN]
                    put_bytes: bytes = hashX + scripthash + sat_value + atomical_value + tx_numb
                    self.put_atomicals_utxo(location, dmt_mint_atomical_id, put_bytes)
                    self.put_decentralized_mint_data(dmt_mint_atomical_id, location, scripthash + sat_value)
                    self.logger.debug(
                        f"create_or_delete_decentralized_mint_outputs found valid request in {hash_to_hex_str(tx_hash)} for {ticker}. Granting and creating decentralized mint..."
                    )
                    self.put_op_data(tx_num, tx_hash, "mint-dft")
                    return dmt_mint_atomical_id
            else:
                self.logger.debug(
                    f"create_or_delete_decentralized_mint_outputs found invalid mint operation because it is minted out completely. {hash_to_hex_str(tx_hash)}. Ignoring..."
                )
                self.put_op_data(tx_num, tx_hash, "mint-dft-failed")
                return None
        else:
            self.logger.warning(
                f"create_or_delete_decentralized_mint_outputs: found invalid mint operation in {hash_to_hex_str(tx_hash)} for {ticker} because incorrect txout.value {txout.value} when expected {mint_amount}"
            )
            self.put_op_data(tx_num, tx_hash, "mint-dft-failed")
            return None

    def is_atomicals_activated(self, height):
        if height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT:
            return True
        return False

    def is_dmint_activated(self, height):
        if height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_DMINT:
            return True
        return False

    def is_density_activated(self, height):
        if height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_DENSITY:
            return True
        return False

    def is_custom_coloring_activated(self, height):
        if height >= self.coin.ATOMICALS_ACTIVATION_HEIGHT_CUSTOM_COLORING:
            return True
        if height <= 0:
            return True
        return False

    # Builds a map of the atomicals spent at a tx
    # It uses the spend_atomicals_utxo method but with live_run == False
    def build_atomicals_spent_at_inputs_for_validation_only(self, tx):
        spend_atomicals_utxo = self.spend_atomicals_utxo
        atomicals_spent_at_inputs = {}
        txin_index = 0
        for txin in tx.inputs:
            if txin.is_generation():
                continue
            # Find all the existing transferred atomicals and DO NOT spend the Atomicals utxos (live_run == False)
            atomicals_transferred_list = spend_atomicals_utxo(txin.prev_hash, txin.prev_idx, False)
            if len(atomicals_transferred_list):
                atomicals_spent_at_inputs[txin_index] = atomicals_transferred_list
            txin_index += 1
        return atomicals_spent_at_inputs

    # Builds a map of the atomicals spent at a tx
    # It uses the spend_atomicals_utxo method but with live_run == False
    def build_atomicals_receive_at_ouutput_for_validation_only(self, tx, txid):
        spend_atomicals_utxo = self.spend_atomicals_utxo
        atomicals_receive_at_outputs = {}
        txout_index = 0
        for _txout in tx.outputs:
            # Find all the existing transferred atomicals and DO NOT spend the Atomicals utxos (live_run == False)
            atomicals_transferred_list = spend_atomicals_utxo(txid, txout_index, False)
            if len(atomicals_transferred_list):
                atomicals_receive_at_outputs[txout_index] = atomicals_transferred_list
            txout_index += 1
        return atomicals_receive_at_outputs

    def advance_txs(
        self,
        txs: Sequence[Tuple[Tx, bytes]],
        is_unspendable: Callable[[bytes], bool],
        header,
        height,
    ) -> Tuple[list[bytes], list[bytes]]:
        self.tx_hashes.append(b"".join(tx_hash for tx, tx_hash in txs))
        self.atomicals_rpc_format_cache.clear()
        self.atomicals_rpc_general_cache.clear()
        self.atomicals_id_cache.clear()
        self.atomicals_dft_mint_count_cache.clear()
        # Track the Atomicals hash for the block
        # First we concatenate the previous block height hash to chain them together
        # The purpose of this is to create a unique hash fingerprint to make it easy to determine if indexers (such as this one) or other implementations
        # are correctly tracking which transaction hashes have valid atomicals operations in them.
        # It makes it really easy to see if anyone goes out of sync and identify the problem within the most recent block
        # Use the block hash as the starting point
        concatenation_of_tx_hashes_with_valid_atomical_operation = []
        prev_atomicals_block_hash = b""
        if self.is_atomicals_activated(height):
            block_header_hash = self.coin.header_hash(header)
            if height == self.coin.ATOMICALS_ACTIVATION_HEIGHT:
                self.logger.info(f"Atomicals Genesis Block Hash: {hash_to_hex_str(block_header_hash)}")
                concatenation_of_tx_hashes_with_valid_atomical_operation.append(block_header_hash)
            elif height > self.coin.ATOMICALS_ACTIVATION_HEIGHT:
                prev_atomicals_block_hash = self.get_general_data_with_cache(b"tt" + pack_le_uint32(height - 1))
                concatenation_of_tx_hashes_with_valid_atomical_operation.append(
                    block_header_hash + prev_atomicals_block_hash
                )
        # Use local vars for speed in the loops
        undo_info: list[bytes] = []
        atomicals_undo_info: list[bytes] = []
        tx_num = self.tx_count
        atomical_num = self.atomical_count
        script_hashX = self.coin.hashX_from_script
        put_utxo = self.utxo_cache.__setitem__
        put_general_data = self.general_data_cache.__setitem__
        spend_utxo = self.spend_utxo
        spend_atomicals_utxo = self.spend_atomicals_utxo
        undo_info_append = undo_info.append
        atomicals_undo_info_extend = atomicals_undo_info.extend
        update_touched = self.touched.update
        hashXs_by_tx = []
        append_hashXs = hashXs_by_tx.append
        to_le_uint32 = pack_le_uint32
        to_le_uint64 = pack_le_uint64
        to_be_uint64 = pack_be_uint64

        # track which dft tickers have mints to perform a sanity check at the end
        atomical_ids_which_have_valid_dft_mints = {}
        # Speed up distmint processing by caching the ticker mint request info
        distmint_ticker_cache = {}
        dft_count = 0
        for tx, tx_hash in txs:
            has_at_least_one_valid_atomicals_operation = False
            hashXs = []
            append_hashX = hashXs.append
            tx_numb = to_le_uint64(tx_num)[:TXNUM_LEN]
            atomicals_spent_at_inputs = {}
            # Spend the inputs
            txin_index = 0
            for txin in tx.inputs:
                if txin.is_generation():
                    continue
                cache_value = spend_utxo(txin.prev_hash, txin.prev_idx)
                undo_info_append(cache_value)
                append_hashX(cache_value[:HASHX_LEN])

                # Only search and spend atomicals utxos if activated
                if self.is_atomicals_activated(height):
                    # Find all the existing transferred atomicals and spend the Atomicals utxos
                    atomicals_transferred_list = spend_atomicals_utxo(txin.prev_hash, txin.prev_idx, True)
                    if len(atomicals_transferred_list):
                        atomicals_spent_at_inputs[txin_index] = atomicals_transferred_list
                        for atomical_spent in atomicals_transferred_list:
                            atomical_id = atomical_spent["atomical_id"]
                            self.logger.debug(
                                f"atomicals_transferred_list - tx_hash={hash_to_hex_str(tx_hash)}, txin_index={txin_index}, txin_hash={hash_to_hex_str(txin.prev_hash)}, txin_previdx={txin.prev_idx}, atomical_id_spent={location_id_bytes_to_compact(atomical_id)}"
                            )
                    # Get the undo format for the spent atomicals
                    reformatted_for_undo_entries = []
                    for atomicals_entry in atomicals_transferred_list:
                        reformatted_for_undo_entries.append(
                            atomicals_entry["location_id"] + atomicals_entry["atomical_id"] + atomicals_entry["data"]
                        )

                    atomicals_undo_info_extend(reformatted_for_undo_entries)
                txin_index = txin_index + 1

            # Add the new UTXOs
            for idx, txout in enumerate(tx.outputs):
                # Ignore unspendable outputs
                if is_unspendable(txout.pk_script):
                    continue
                # Get the hashX
                hashX = self.coin.hashX_from_script(txout.pk_script)
                append_hashX(hashX)
                put_utxo(
                    tx_hash + to_le_uint32(idx),
                    hashX + tx_numb + to_le_uint64(txout.value),
                )

            # Only create Atomicals if the activation height is reached
            if self.is_atomicals_activated(height):
                # Save the tx number for the current tx
                # This index is used to lookup the height of a commit tx when minting an atomical
                # For example if the reveal of a realm/container/ticker mint is greater than
                # MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS then the realm request is invalid.
                put_general_data(b"tx" + tx_hash, to_le_uint64(tx_num) + to_le_uint32(height))
                # Detect all protocol operations in the transaction witness inputs
                # Only parse witness information for Atomicals if activated
                atomicals_operations_found_at_inputs = parse_protocols_operations_from_witness_array(
                    tx, tx_hash, self.is_density_activated(height)
                )
                if atomicals_operations_found_at_inputs:
                    # TODO
                    # Log information to help troubleshoot
                    size_payload = sys.getsizeof(atomicals_operations_found_at_inputs["payload_bytes"])
                    operation_found = atomicals_operations_found_at_inputs["op"]
                    operation_input_index = atomicals_operations_found_at_inputs["input_index"]
                    commit_txid = atomicals_operations_found_at_inputs["commit_txid"]
                    commit_index = atomicals_operations_found_at_inputs["commit_index"]
                    reveal_location_txid = atomicals_operations_found_at_inputs["reveal_location_txid"]
                    reveal_location_index = atomicals_operations_found_at_inputs["reveal_location_index"]
                    self.logger.debug(
                        f"advance_txs: atomicals_operations_found_at_inputs operation_found={operation_found}, operation_input_index={operation_input_index}, size_payload={size_payload}, tx_hash={hash_to_hex_str(tx_hash)}, commit_txid={hash_to_hex_str(commit_txid)}, commit_index={commit_index}, reveal_location_txid={hash_to_hex_str(reveal_location_txid)}, reveal_location_index={reveal_location_index}"
                    )

                # Color the outputs of any transferred NFT/FT atomicals according to the rules
                blueprint_builder = self.color_atomicals_outputs(
                    atomicals_operations_found_at_inputs,
                    atomicals_spent_at_inputs,
                    tx,
                    tx_hash,
                    tx_num,
                    height,
                )
                for atomical_id in blueprint_builder.get_atomical_ids_spent():
                    has_at_least_one_valid_atomicals_operation = True
                    self.logger.debug(
                        f"advance_txs: color_atomicals_outputs atomical_ids_transferred. atomical_id={atomical_id.hex()}, tx_hash={hash_to_hex_str(tx_hash)}"
                    )
                    # Double hash the atomical_id to add it to the history to leverage the existing history db for all operations involving the atomical
                    append_hashX(double_sha256(atomical_id))

                # Track whether we encountered a valid operation so we can skip other steps in the processing pipeline for efficiency
                already_found_valid_operation = False

                atomical_id_of_distmint = self.create_or_delete_decentralized_mint_output(
                    atomicals_operations_found_at_inputs,
                    tx_num,
                    tx_hash,
                    tx,
                    height,
                    distmint_ticker_cache,
                    False,
                )
                if atomical_id_of_distmint:
                    dft_count += 1
                    already_found_valid_operation = True
                    atomical_ids_which_have_valid_dft_mints[atomical_id_of_distmint] = True
                    has_at_least_one_valid_atomicals_operation = True
                    # Double hash the atomical_id_of_distmint to add it to the history to leverage the existing history db for all operations involving the atomical
                    append_hashX(double_sha256(atomical_id_of_distmint))
                    self.logger.debug(
                        f"advance_txs: create_or_delete_decentralized_mint_output:atomical_id_of_distmint - atomical_id={atomical_id_of_distmint.hex()}, tx_hash={hash_to_hex_str(tx_hash)}"
                    )

                    if dft_count % 100 == 0:
                        self.logger.info(f"height={height}, dft_count={dft_count}")

                # Create NFT/FT atomicals if it is defined in the tx
                if not already_found_valid_operation:
                    created_atomical_id = self.create_or_delete_atomical(
                        atomicals_operations_found_at_inputs,
                        atomicals_spent_at_inputs,
                        header,
                        height,
                        tx_num,
                        atomical_num,
                        tx,
                        tx_hash,
                        False,
                    )
                    if created_atomical_id:
                        already_found_valid_operation = True
                        has_at_least_one_valid_atomicals_operation = True
                        atomical_num += 1
                        # Double hash the created_atomical_id to add it to the history to leverage the existing history db for all operations involving the atomical
                        append_hashX(double_sha256(created_atomical_id))
                        self.logger.debug(
                            f"advance_txs: create_or_delete_atomical created_atomical_id atomical_id={created_atomical_id.hex()}, tx_hash={hash_to_hex_str(tx_hash)}"
                        )

                # Check if there were any regular 'dat' files definitions
                if not already_found_valid_operation:
                    if self.create_or_delete_data_location(tx_hash, atomicals_operations_found_at_inputs):
                        self.put_op_data(tx_num, tx_hash, "dat")
                        has_at_least_one_valid_atomicals_operation = True
                        already_found_valid_operation = True

                # Note: We do not skip checking for payment tx's even if already_found_valid_operation = True
                # because there could be valid mints in one and the same tx as making a payment.
                # It's not advisable to do so, but it's a valid possibility.

                # Check if there were any payments for subrealms in tx
                (
                    subrealm_payment_tx_hash,
                    verified,
                ) = self.create_or_delete_subname_payment_output_if_valid(
                    tx_hash,
                    tx,
                    tx_num,
                    height,
                    atomicals_operations_found_at_inputs,
                    atomicals_spent_at_inputs,
                    b"spay",
                    self.subrealmpay_data_cache,
                    self.get_expected_subrealm_payment_info,
                    False,
                )
                if subrealm_payment_tx_hash:
                    if verified:
                        self.logger.info(
                            "advance_txs: found valid subrealm payment "
                            "create_or_delete_subname_payment_output_if_valid "
                            f"{hash_to_hex_str(tx_hash)}"
                        )
                        self.put_op_data(tx_num, tx_hash, "payment-subrealm")
                    else:
                        self.logger.info(
                            "advance_txs: found invalid subrealm payment "
                            "create_or_delete_subname_payment_output_if_valid "
                            f"{hash_to_hex_str(tx_hash)}"
                        )
                        self.put_op_data(tx_num, tx_hash, "payment-subrealm-failed")
                    append_hashX(double_sha256(subrealm_payment_tx_hash))
                    has_at_least_one_valid_atomicals_operation = True

                # Check if there were any payments for dmitems in tx
                (
                    dmitem_payment_tx_hash,
                    verified,
                ) = self.create_or_delete_subname_payment_output_if_valid(
                    tx_hash,
                    tx,
                    tx_num,
                    height,
                    atomicals_operations_found_at_inputs,
                    atomicals_spent_at_inputs,
                    b"dmpay",
                    self.dmpay_data_cache,
                    self.get_expected_dmitem_payment_info,
                    False,
                )
                if dmitem_payment_tx_hash:
                    if verified:
                        self.logger.info(
                            "advance_txs: found valid dmitem payment "
                            "create_or_delete_subname_payment_output_if_valid "
                            f"{hash_to_hex_str(tx_hash)}"
                        )
                        self.put_op_data(tx_num, tx_hash, "payment-dmitem")
                    else:
                        self.logger.info(
                            "advance_txs: found invalid dmitem payment "
                            "create_or_delete_subname_payment_output_if_valid "
                            f"{hash_to_hex_str(tx_hash)}"
                        )
                        self.put_op_data(tx_num, tx_hash, "payment-dmitem-failed")
                    append_hashX(double_sha256(dmitem_payment_tx_hash))
                    has_at_least_one_valid_atomicals_operation = True

                # Create a proof of work record if there was valid proof of work attached
                if self.create_or_delete_pow_records(tx_hash, tx_num, height, atomicals_operations_found_at_inputs):
                    has_at_least_one_valid_atomicals_operation = True
                    self.logger.debug(f"advance_txs: create_or_delete_pow_records tx_hash={hash_to_hex_str(tx_hash)}")

                # Concat the tx_hash if there was at least one valid atomicals operation
                if self.is_atomicals_activated(height) and has_at_least_one_valid_atomicals_operation:
                    concatenation_of_tx_hashes_with_valid_atomical_operation.append(tx_hash)

                if has_at_least_one_valid_atomicals_operation:
                    put_general_data(
                        b"th" + pack_le_uint32(height) + pack_le_uint64(tx_num) + tx_hash,
                        tx_hash,
                    )
                    # only save the tx has at least one vaild atomical
                    raw_tx = tx.serialize()
                    _tx, _tx_hash = self.coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
                    assert _tx == tx
                    assert _tx_hash == tx_hash
                    put_general_data(b"rtx" + tx_hash, raw_tx)
                    del _tx
                    del _tx_hash

            append_hashXs(hashXs)
            update_touched(hashXs)
            tx_num += 1

        # dft mint sanity check here
        # Because we are using a cache of the minted dfts from the db
        # We track all the mints of a dft for their atomical ids and then perform one final lookup going straight to db as well
        # Then we ensure the max mints cannot be exceeded just in case
        self.validate_no_dft_inflation(atomical_ids_which_have_valid_dft_mints, height)

        self.db.history.add_unflushed(hashXs_by_tx, self.tx_count)
        self.tx_count = tx_num
        self.db.tx_counts.append(tx_num)
        self.atomical_count = atomical_num
        self.db.atomical_counts.append(atomical_num)

        if self.is_atomicals_activated(height):
            # Save the atomicals hash for the current block
            current_height_atomicals_block_hash = self.coin.header_hash(
                b"".join(concatenation_of_tx_hashes_with_valid_atomical_operation)
            )
            put_general_data(b"tt" + pack_le_uint32(height), current_height_atomicals_block_hash)
            self.logger.info(
                f"height={height}, atomicals_block_hash={hash_to_hex_str(current_height_atomicals_block_hash)}"
            )

        return undo_info, atomicals_undo_info

    # Sanity safety check method to call at end of block processing to ensure no dft token inflation
    def validate_no_dft_inflation(self, atomical_id_map, height):
        for atomical_id_of_dft_ticker, _ in atomical_id_map.items():
            # Get the max mints allowed for the dft ticker (if set)
            mint_info_for_ticker = self.get_atomicals_id_mint_info(atomical_id_of_dft_ticker, False)
            max_mints = mint_info_for_ticker["$max_mints"]
            dft_mode = mint_info_for_ticker.get("$mint_mode")
            # If it's mining mode, then use the max_mints_global if it's set
            if dft_mode == "perpetual":
                if not mint_info_for_ticker.get("$max_mints_global"):
                    continue
                max_mints = mint_info_for_ticker.get("$max_mints_global")
            # Count the number of existing b'gi' entries and ensure it is strictly less than max_mints
            decentralized_mints = self.get_distmints_count_by_atomical_id(height, atomical_id_of_dft_ticker, False)
            if decentralized_mints > max_mints:
                raise IndexError(
                    f"validate_no_dft_inflation - inflation_bug_found: atomical_id_of_dft_ticker={location_id_bytes_to_compact(atomical_id_of_dft_ticker)} decentralized_mints={decentralized_mints} max_mints={max_mints}"
                )

    def create_or_delete_subname_payment_output_if_valid(
        self,
        tx_hash,
        tx,
        tx_num,
        height,
        operations_found_at_inputs,
        atomicals_spent_at_inputs,
        db_prefix,
        subname_data_cache,
        get_expected_subname_payment_info,
        Delete=False,
    ):
        (
            atomical_id_for_payment,
            payment_marker_idx,
            entity_type,
        ) = AtomicalsTransferBlueprintBuilder.get_atomical_id_for_payment_marker_if_found(tx)
        if not atomical_id_for_payment:
            return None, False
        # Make sure the payment type for the right type subrealm or dmitem is correct
        if entity_type == "subrealm" and db_prefix != b"spay":
            return None, False
        if entity_type == "dmitem" and db_prefix != b"dmpay":
            return None, False

        # Rebuild the blueprint builder here
        blueprint_builder = AtomicalsTransferBlueprintBuilder(
            self.logger,
            atomicals_spent_at_inputs,
            operations_found_at_inputs,
            tx_hash,
            tx,
            self.get_atomicals_id_mint_info,
            self.is_dmint_activated(height),
            self.is_custom_coloring_activated(height),
        )
        if blueprint_builder.is_split_operation():
            self.logger.warning(
                f"create_or_delete_subname_payment_output_if_valid: invalid payment split op found tx_hash={hash_to_hex_str(tx_hash)}"
            )
            return tx_hash, False

        (
            matched_price_point,
            parent_id,
            request_subname,
            subname_type,
        ) = get_expected_subname_payment_info(atomical_id_for_payment, height)

        # An expected payment amount might not be set if there is no valid subrealm minting rules, or something invalid was found
        if not matched_price_point:
            self.logger.warning(
                f"create_or_delete_subname_payment_output_if_valid: {hash_to_hex_str(tx_hash)} NOT MATCHED PRICE - create_or_delete_subrealm_payment_output_if_valid atomical_id_for_payment={location_id_bytes_to_compact(atomical_id_for_payment)}"
            )
            return tx_hash, False

        regex = matched_price_point["matched_rule"]["p"]
        if not is_valid_regex(regex):
            self.logger.warning(
                f"create_or_delete_subname_payment_output_if_valid invalid matched regex. regex={regex} atomical_id_for_payment={location_id_bytes_to_compact(atomical_id_for_payment)}"
            )
            return tx_hash, False

        # The pattern should have already matched, sanity check
        valid_pattern = re.compile(rf"{regex}")
        if not valid_pattern.match(request_subname):
            raise IndexError(
                f"create_or_delete_subname_payment_output_if_valid: valid pattern failed. DeveloperError request_subname={request_subname}, regex={regex}"
            )

        if not blueprint_builder.are_payments_satisfied(matched_price_point["matched_rule"].get("o")):
            self.logger.warning(
                f"create_or_delete_subname_payment_output_if_valid: payments not satisfied. request_subname={request_subname}, regex={regex} atomical_id_for_payment={location_id_bytes_to_compact(atomical_id_for_payment)}"
            )
            return tx_hash, False

        # Delete or create the record based on whether we are reorg rollback or creating new
        payment_outpoint = tx_hash + pack_le_uint32(payment_marker_idx)
        not_initated_by_parent = b"00"  # Used to indicate it was minted according to rules payment match
        if Delete:
            self.delete_pay_record(
                atomical_id_for_payment,
                tx_num,
                payment_outpoint + not_initated_by_parent,
                db_prefix,
                subname_data_cache,
            )
        else:
            self.put_pay_record(
                atomical_id_for_payment,
                tx_num,
                payment_outpoint + not_initated_by_parent,
                db_prefix,
                subname_data_cache,
            )

        return tx_hash, True

    def backup_blocks(self, raw_blocks: Sequence[bytes]):
        """Backup the raw blocks and flush.

        The blocks should be in order of decreasing height, starting at.
        self.height.  A flush is performed once the blocks are backed up.
        """
        self.db.assert_flushed(self.flush_data())
        assert self.height >= len(raw_blocks)
        genesis_activation = self.coin.GENESIS_ACTIVATION

        coin = self.coin
        for raw_block in raw_blocks:
            # Check and update self.tip
            block = coin.block(raw_block, self.height)
            header_hash = coin.header_hash(block.header)
            if header_hash != self.tip:
                raise ChainError(
                    f"backup block {hash_to_hex_str(header_hash)} not tip "
                    f"{hash_to_hex_str(self.tip)} at height {self.height:,d}"
                )
            self.tip = coin.header_prevhash(block.header)
            is_unspendable = is_unspendable_genesis if self.height >= genesis_activation else is_unspendable_legacy
            self.backup_txs(block.transactions, is_unspendable)
            self.height -= 1
            self.db.tx_counts.pop()
            self.db.atomical_counts.pop()
        self.logger.info(f"backed up to height {self.height:,d}")

    # Rollback the spending of an atomical
    def rollback_spend_atomicals(self, tx_hash, tx, idx, tx_num, height, operations_found_at_inputs):
        output_index_packed = pack_le_uint32(idx)
        current_location = tx_hash + output_index_packed
        # Spend the atomicals if there were any
        spent_atomicals = self.spend_atomicals_utxo(tx_hash, idx, True)
        if len(spent_atomicals) > 0:
            # Remove the stored output
            self.delete_general_data(b"po" + current_location)
        hashXs = []
        for spent_atomical in spent_atomicals:
            atomical_id = spent_atomical["atomical_id"]
            location_id = spent_atomical["location_id"]
            self.logger.debug(
                f"rollback_spend_atomicals: atomical_id={atomical_id.hex()}, tx_hash={hash_to_hex_str(tx_hash)}"
            )
            hashX = spent_atomical["data"][:HASHX_LEN]
            hashXs.append(hashX)
            # Just try to delete all states regardless of whether they are immutable or not, just easier this way
            self.put_or_delete_state_updates(
                operations_found_at_inputs,
                atomical_id,
                tx_num,
                tx_hash,
                output_index_packed,
                height,
                0,
                True,
            )
            self.put_or_delete_state_updates(
                operations_found_at_inputs,
                atomical_id,
                tx_num,
                tx_hash,
                output_index_packed,
                height,
                1,
                True,
            )
            self.put_or_delete_sealed(operations_found_at_inputs, atomical_id, location_id, True)
        return hashXs, spent_atomicals

    # Query all the modpath history properties and return them sorted descending by tx_num by default
    # Uses cache and combines it with db results
    def get_mod_history(self, parent_atomical_id, max_height):
        prefix_key = b"mod"
        PREFIX_BYTE_LEN = len(prefix_key)
        state_key_prefix = prefix_key + parent_atomical_id
        cache_mod_prefix_map = self.state_data_cache.get(state_key_prefix)
        cache_mod_history = []  # must sort this at the end with the return
        if cache_mod_prefix_map:
            self.logger.debug(f"get_mod_history: cache_mod_prefix_map={cache_mod_prefix_map}")
            for state_key_suffix, state_value in cache_mod_prefix_map.items():
                # Key: prefix_key + atomical_id + path_padded + tx_numb + tx_hash + out_idx + height
                # Unpack the tx number
                atomical_id_key = state_key_prefix + state_key_suffix
                tx_numb = atomical_id_key[
                    PREFIX_BYTE_LEN + ATOMICAL_ID_LEN : PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN
                ]
                txnum_padding = bytes(8 - TXNUM_LEN)
                (tx_num_padded,) = unpack_le_uint64(tx_numb + txnum_padding)
                tx_hash = atomical_id_key[
                    PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN : PREFIX_BYTE_LEN
                    + ATOMICAL_ID_LEN
                    + TXNUM_LEN
                    + TX_HASH_LEN
                ]
                out_idx_packed = atomical_id_key[
                    PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN + TX_HASH_LEN : PREFIX_BYTE_LEN
                    + ATOMICAL_ID_LEN
                    + TXNUM_LEN
                    + TX_HASH_LEN
                    + 4
                ]
                (out_idx,) = unpack_le_uint32(out_idx_packed)
                height_le = atomical_id_key[-4:]
                (height,) = unpack_le_uint32(height_le)
                # Skip too high heights
                if height > max_height:
                    break
                obj = {
                    "tx_num": tx_num_padded,
                    "height": height,
                    "txid": hash_to_hex_str(tx_hash),
                    "index": out_idx,
                    "data": loads(state_value),
                }
                cache_mod_history.append(obj)
        db_mod_history = self.db.get_mod_history(parent_atomical_id, max_height)
        # Sort them together
        if len(cache_mod_history) > 0:
            self.logger.debug(f"cache_mod_history: CACHE_HIT: {location_id_bytes_to_compact(parent_atomical_id)}")

        cache_mod_history.extend(db_mod_history)
        cache_mod_history.sort(key=lambda x: x["tx_num"], reverse=True)
        return cache_mod_history

    def get_applicable_rule_by_height(self, parent_atomical_id, proposed_subnameid, height, RULE_DATA_NAMESPACE):
        # Log an item with a prefix
        def print_applicable_rule_log(item):
            self.logger.debug(
                f"get_applicable_rule_by_height: {item}. parent_atomical_id={parent_atomical_id.hex()}, proposed_subnameid={proposed_subnameid}, height={height}"
            )

        # Note: we must query the modpath history with the cache in case we have not yet flushed to disk
        # db_key = b'modpath' + atomical_id + mod_path_padded + tx_numb + output_idx_le + height_packed
        rule_mint_mod_history = self.get_mod_history(parent_atomical_id, height)
        print_applicable_rule_log(f"get_applicable_rule_by_height: rule_mint_mod_history {rule_mint_mod_history}")
        latest_state = calculate_latest_state_from_mod_history(rule_mint_mod_history)
        regex_price_point_list = validate_rules_data(latest_state.get(RULE_DATA_NAMESPACE, None))
        if not regex_price_point_list:
            return None, None
        # match the specific regex
        for regex_price_point in regex_price_point_list:
            print_applicable_rule_log(
                f"get_applicable_rule_by_height: processing rule item regex_price_point={regex_price_point}"
            )
            regex_pattern = regex_price_point.get("p", None)
            if not regex_pattern:
                print_applicable_rule_log("get_applicable_rule_by_height: empty pattern")
                continue

            if "(" in regex_pattern or ")" in regex_pattern:
                print_applicable_rule_log("get_applicable_rule_by_height: invalid regex with parens")
                return None

            try:
                # Compile the regular expression
                valid_pattern = re.compile(rf"{regex_pattern}")
                # Match the pattern to the proposed subrealm_name
                if not valid_pattern.match(proposed_subnameid):
                    print_applicable_rule_log("get_applicable_rule_by_height: invalid pattern match")
                    continue
                print_applicable_rule_log(
                    f"get_applicable_rule_by_height: successfully matched pattern and price regex_pattern={regex_pattern}"
                )
                return {"matched_rule": regex_price_point}, latest_state
            except Exception as e:
                print_applicable_rule_log(
                    f"get_applicable_rule_by_height: exception matching pattern e={e}. Continuing..."
                )
                # If it failed, then try the next matches if any
                pass
        return None, None

    def spent_atomical_serialize(self, spent_array):
        if not spent_array:
            return
        self.logger.info("spent_atomical_serialize:START ")

        for spent in spent_array:
            atomical_id = location_id_bytes_to_compact(spent["atomical_id"])
            location_id = location_id_bytes_to_compact(spent["location_id"])
            data = spent["data"]
            self.logger.info(f"spent_item atomical_id={atomical_id}")
            self.logger.info(f"spent_item location_id={location_id}")
            self.logger.info(f"spent_item data={data.hex()}")

        self.logger.info("spent_atomical_serialize:END")
        return

    def backup_txs(
        self,
        txs: Sequence[Tuple[Tx, bytes]],
        is_unspendable: Callable[[bytes], bool],
    ):
        # Clear the cache just in case there are old values cached for a mint that are stale
        # In particular for $realm and $ticker values if something changed on reorg
        self.atomicals_id_cache.clear()
        self.atomicals_rpc_format_cache.clear()
        self.atomicals_rpc_general_cache.clear()
        self.atomicals_dft_mint_count_cache.clear()

        # Delete the Atomicals hash for the current height as we are rolling back
        self.delete_general_data(b"tt" + pack_le_uint32(self.height))

        # Prevout values, in order down the block (coinbase first if present)
        # undo_info is in reverse block order
        undo_info = self.db.read_undo_info(self.height)
        if undo_info is None:
            raise ChainError(f"no undo information found for height " f"{self.height:,d}")
        n = len(undo_info)

        ############################################
        #
        # Begin Atomicals Undo Procedure Setup
        #
        ############################################
        atomicals_undo_info = self.db.read_atomicals_undo_info(self.height)
        if atomicals_undo_info is None:
            raise ChainError(f"no atomicals undo information found for height " f"{self.height:,d}")
        m = len(atomicals_undo_info)
        atomicals_undo_entry_len = ATOMICAL_ID_LEN + ATOMICAL_ID_LEN + HASHX_LEN + SCRIPTHASH_LEN + 8 + 8 + TXNUM_LEN
        atomicals_count = m / atomicals_undo_entry_len
        # has_undo_info_for_atomicals = False
        # if m > 0:
        #    has_undo_info_for_atomicals = True
        c = m
        atomicals_undo_info_map = {}  # Build a map of atomicals location to atomicals located there
        counted_atomicals_count = 0
        self.logger.info(f"backup_txs m={m}")
        self.logger.info(f"atomicals_undo_info_map={atomicals_undo_info_map}")
        while c > 0:
            c -= atomicals_undo_entry_len
            self.logger.info(
                f"atomicals_undo_entry_len {c} - count {counted_atomicals_count} - {atomicals_undo_entry_len}"
            )
            assert c >= 0
            atomicals_undo_item = atomicals_undo_info[c : c + atomicals_undo_entry_len]
            self.logger.info(f"Reorg undo_info_item {c} {atomicals_undo_item.hex()}")
            atomicals_location = atomicals_undo_item[:ATOMICAL_ID_LEN]
            atomicals_atomical_id = atomicals_undo_item[ATOMICAL_ID_LEN : ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
            atomicals_value = atomicals_undo_item[ATOMICAL_ID_LEN + ATOMICAL_ID_LEN :]
            # There can be many atomicals at the same location
            # Group them by the location
            if atomicals_undo_info_map.get(atomicals_location, None) is None:
                atomicals_undo_info_map[atomicals_location] = []
            atomicals_undo_info_map[atomicals_location].append(
                {
                    "location_id": atomicals_location,
                    "atomical_id": atomicals_atomical_id,
                    "data": atomicals_value,
                }
            )
            counted_atomicals_count += 1
        assert counted_atomicals_count == atomicals_count
        ############################################
        #
        # Finished Atomicals Undo Procedure Setup
        #
        # The atomicals_undo_info_map contains the mapping of the atomicals at each location and their value
        # It is a way to get the total input value grouped by atomical id
        #
        ############################################

        # Use local vars for speed in the loops
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo

        touched = self.touched
        undo_entry_len = HASHX_LEN + TXNUM_LEN + 8
        tx_num = self.tx_count
        atomical_num = self.atomical_count
        atomicals_minted = 0
        # Track the atomicals being rolled back to be used primarily for determining subrealm rollback validity
        atomicals_spent_at_inputs = {}
        for tx, tx_hash in reversed(txs):
            # There could be mod, evt, seal and a host of other things like nft and ft mints
            operations_found_at_inputs = parse_protocols_operations_from_witness_array(
                tx, tx_hash, self.is_density_activated(self.height)
            )
            self.logger.info(f"{operations_found_at_inputs}, txid = {hash_to_hex_str(tx_hash)}")
            for idx, txout in enumerate(tx.outputs):
                # Spend the TX outputs.  Be careful with unspendable
                # outputs - we didn't save those in the first place.
                if is_unspendable(txout.pk_script):
                    continue
                # Get the hashX
                cache_value = spend_utxo(tx_hash, idx)
                hashX = cache_value[:HASHX_LEN]
                touched.add(hashX)
                # Rollback the atomicals that were created at the output
                hashXs_spent, spent_atomicals = self.rollback_spend_atomicals(
                    tx_hash, tx, idx, tx_num, self.height, operations_found_at_inputs
                )
                for hashX_spent in hashXs_spent:
                    touched.add(hashX_spent)
                # The idx is not where it was spent, because this is the rollback operation
                # Nonetheless we use the output idx as the "spent at" just to keep a consistent format when
                # the variable atomicals_spent_at_inputs is used in other places. There is no usage for the index, but informational purpose only
                atomicals_spent_at_inputs[idx] = spent_atomicals
                if len(spent_atomicals) > 0:
                    self.spent_atomical_serialize(spent_atomicals)

            # Delete the tx hash number
            self.delete_general_data(b"tx" + tx_hash)

            # Backup any Atomicals NFT, FT, or DFT mints
            fake_header = b""  # Header is not needed in the Delete=True context
            atomical_id_deleted = self.create_or_delete_atomical(
                operations_found_at_inputs,
                atomicals_spent_at_inputs,
                fake_header,
                self.height,
                tx_num,
                atomical_num,
                tx,
                tx_hash,
                True,
            )
            if atomical_id_deleted:
                atomical_num -= 1
                atomicals_minted += 1

            # Rollback any subrealm payments
            self.create_or_delete_subname_payment_output_if_valid(
                tx_hash,
                tx,
                tx_num,
                self.height,
                operations_found_at_inputs,
                atomicals_spent_at_inputs,
                b"spay",
                self.subrealmpay_data_cache,
                self.get_expected_subrealm_payment_info,
                True,
            )

            # Rollback any dmint payments
            self.create_or_delete_subname_payment_output_if_valid(
                tx_hash,
                tx,
                tx_num,
                self.height,
                operations_found_at_inputs,
                atomicals_spent_at_inputs,
                b"dmpay",
                self.dmpay_data_cache,
                self.get_expected_dmitem_payment_info,
                True,
            )

            # If there were any distributed mint creation, then delete
            self.create_or_delete_decentralized_mint_output(
                operations_found_at_inputs, tx_num, tx_hash, tx, self.height, {}, True
            )

            # Check if there were any regular 'dat' files definitions to delete
            self.create_or_delete_data_location(tx_hash, operations_found_at_inputs, True)

            # Check a proof of work record if there was valid proof of work attached to delete
            self.create_or_delete_pow_records(tx_hash, tx_num, self.height, operations_found_at_inputs, True)
            self.delete_general_data(b"th" + pack_le_uint32(self.height) + pack_le_uint64(tx_num) + tx_hash)

            # Restore the inputs
            for txin in reversed(tx.inputs):
                if txin.is_generation():
                    continue
                n -= undo_entry_len
                undo_item = undo_info[n : n + undo_entry_len]
                put_utxo(txin.prev_hash + pack_le_uint32(txin.prev_idx), undo_item)
                hashX = undo_item[:HASHX_LEN]
                touched.add(hashX)
                # Restore the atomicals utxos in the undo information
                potential_atomicals_list_to_restore = atomicals_undo_info_map.get(
                    txin.prev_hash + pack_le_uint32(txin.prev_idx)
                )
                if potential_atomicals_list_to_restore is not None:
                    for atomical_to_restore in potential_atomicals_list_to_restore:
                        atomical_id = atomical_to_restore["atomical_id"]
                        location_id = atomical_to_restore["location_id"]
                        dat = atomical_to_restore["data"].hex()
                        self.logger.info(
                            f"atomical_to_restore {atomical_to_restore} atomical_id={location_id_bytes_to_compact(atomical_id)} location_id={location_id_bytes_to_compact(location_id)} dat={dat}"
                        )
                        self.put_atomicals_utxo(
                            atomical_to_restore["location_id"],
                            atomical_to_restore["atomical_id"],
                            atomical_to_restore["data"],
                        )
                        self.logger.info(f"m_before={m}")
                        m -= atomicals_undo_entry_len
                        self.logger.info(f"m_after={m}")
                        touched.add(double_sha256(atomical_to_restore["atomical_id"]))

            tx_num -= 1

        assert n == 0
        self.logger.info(f"m == 0 assert failure m={m} n={n} atomicals_minted={atomicals_minted}")
        assert m == 0

        self.tx_count -= len(txs)
        self.atomical_count -= atomicals_minted

        # Sanity checks...
        assert atomical_num == self.atomical_count

    """An in-memory UTXO cache, representing all changes to UTXO state
    since the last DB flush.

    We want to store millions of these in memory for optimal
    performance during initial sync, because then it is possible to
    spend UTXOs without ever going to the database (other than as an
    entry in the address history, and there is only one such entry per
    TX not per UTXO).  So store them in a Python dictionary with
    binary keys and values.

      Key:    TX_HASH + TX_IDX           (32 + 4 = 36 bytes)
      Value:  HASHX + TX_NUM + VALUE     (11 + 5 + 8 = 24 bytes)

    That's 60 bytes of raw data in-memory.  Python dictionary overhead
    means each entry actually uses about 205 bytes of memory.  So
    almost 5 million UTXOs can fit in 1GB of RAM.  There are
    approximately 42 million UTXOs on bitcoin mainnet at height
    433,000.

    Semantics:

      add:   Add it to the cache dictionary.

      spend: Remove it if in the cache dictionary.  Otherwise it's
             been flushed to the DB.  Each UTXO is responsible for two
             entries in the DB.  Mark them for deletion in the next
             cache flush.

    The UTXO database format has to be able to do two things efficiently:

      1.  Given an address be able to list its UTXOs and their values
          so its balance can be efficiently computed.

      2.  When processing transactions, for each prevout spent - a (tx_hash,
          idx) pair - we have to be able to remove it from the DB.  To send
          notifications to clients we also need to know any address it paid
          to.

    To this end we maintain two "tables", one for each point above:

      1.  Key: b'u' + address_hashX + tx_idx + tx_num
          Value: the UTXO value as a 64-bit unsigned integer

      2.  Key: b'h' + compressed_tx_hash + tx_idx + tx_num
          Value: hashX

    The compressed tx hash is just the first few bytes of the hash of
    the tx in which the UTXO was created.  As this is not unique there
    will be potential collisions so tx_num is also in the key.  When
    looking up a UTXO the prefix space of the compressed hash needs to
    be searched and resolved if necessary with the tx_num.  The
    collision rate is low (<0.1%).
    """

    def spend_utxo(self, tx_hash: bytes, tx_idx: int) -> bytes:
        """Spend a UTXO and return (hashX + tx_num + sat_value).

        If the UTXO is not in the cache it must be on disk.  We store
        all UTXOs so not finding one indicates a logic error or DB
        corruption.
        """
        # Fast track is it being in the cache
        idx_packed = pack_le_uint32(tx_idx)
        cache_value: Optional[bytes] = self.utxo_cache.pop(tx_hash + idx_packed, None)
        if cache_value:
            return cache_value

        # Spend it from the DB.
        txnum_padding = bytes(8 - TXNUM_LEN)

        # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
        # Value: hashX
        prefix = b"h" + tx_hash[:COMP_TXID_LEN] + idx_packed
        candidates = {db_key: hashX for db_key, hashX in self.db.utxo_db.iterator(prefix=prefix)}

        for hdb_key, hashX in candidates.items():
            tx_num_packed = hdb_key[-TXNUM_LEN:]

            if len(candidates) > 1:
                (tx_num,) = unpack_le_uint64(tx_num_packed + txnum_padding)
                hash, _height = self.db.fs_tx_hash(tx_num)
                if hash != tx_hash:
                    assert hash is not None  # Should always be found
                    continue

            # Key: b'u' + address_hashX + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            udb_key = b"u" + hashX + hdb_key[-4 - TXNUM_LEN :]
            utxo_value_packed = self.db.utxo_db.get(udb_key)
            if utxo_value_packed:
                # Remove both entries for this UTXO
                self.delete_general_data(hdb_key)
                self.delete_general_data(udb_key)
                return hashX + tx_num_packed + utxo_value_packed

        raise ChainError(f"UTXO {hash_to_hex_str(tx_hash)} / {tx_idx:,d} not " f'found in "h" table')

    async def _process_prefetched_blocks(self):
        """Loop forever processing blocks as they arrive."""
        while True:
            if self.height == self.daemon.cached_height():
                if not self._caught_up_event.is_set():
                    await self._first_caught_up()
                    self._caught_up_event.set()
            await self.blocks_event.wait()
            self.blocks_event.clear()
            if self.reorg_count:
                self.logger.info(f"_process_prefetched_blocks reorg: {self.reorg_count}")
                await self.reorg_chain(self.reorg_count)
                self.reorg_count = 0
            else:
                blocks = self.prefetcher.get_prefetched_blocks()
                await self.check_and_advance_blocks(blocks)

    async def _first_caught_up(self):
        self.logger.info(f"caught up to height {self.height}")
        # Flush everything but with first_sync->False state.
        first_sync = self.db.first_sync
        self.db.first_sync = False
        await self.flush(True)
        if first_sync:
            self.logger.info(f"{electrumx_version} synced to height {self.height:,d}")
        # Reopen for serving
        await self.db.open_for_serving()

    async def _first_open_dbs(self):
        await self.db.open_for_sync()
        self.height = self.db.db_height
        self.tip = self.db.db_tip
        self.tx_count = self.db.db_tx_count
        self.atomical_count = self.db.db_atomical_count

    # --- External API

    async def fetch_and_process_blocks(self, caught_up_event):
        """Fetch, process and index blocks from the daemon.

        Sets caught_up_event when first caught up.  Flushes to disk
        and shuts down cleanly if cancelled.

        This is mainly because if, during initial sync ElectrumX is
        asked to shut down when a large number of blocks have been
        processed but not written to disk, it should write those to
        disk before exiting, as otherwise a significant amount of work
        could be lost.
        """
        self._caught_up_event = caught_up_event
        await self._first_open_dbs()
        try:
            async with OldTaskGroup() as group:
                await group.spawn(self.prefetcher.main_loop(self.height))
                await group.spawn(self._process_prefetched_blocks())
        # Don't flush for arbitrary exceptions as they might be a cause or consequence of
        # corrupted data
        except CancelledError:
            self.logger.info("flushing to DB for a clean shutdown...")
            await self.flush(True)

    def force_chain_reorg(self, count):
        """Force a reorg of the given number of blocks.

        Returns True if a reorg is queued, false if not caught up.
        """
        if self._caught_up_event.is_set():
            self.reorg_count = count
            self.blocks_event.set()
            return True
        return False


class DecredBlockProcessor(BlockProcessor):
    async def calc_reorg_range(self, count):
        start, count = await super().calc_reorg_range(count)
        if start > 0:
            # A reorg in Decred can invalidate the previous block
            start -= 1
            count += 1
        return start, count


class NameIndexBlockProcessor(BlockProcessor):
    def advance_txs(
        self,
        txs: Sequence[Tuple[Tx, bytes]],
        is_unspendable: Callable[[bytes], bool],
        header,
        height,
    ):
        result = super().advance_txs(txs, is_unspendable, header, height)

        tx_num = self.tx_count - len(txs)
        script_name_hashX = self.coin.name_hashX_from_script
        update_touched = self.touched.update
        hashXs_by_tx = []
        append_hashXs = hashXs_by_tx.append

        for tx, _tx_hash in txs:
            hashXs = []
            append_hashX = hashXs.append

            # Add the new UTXOs and associate them with the name script
            for txout in tx.outputs:
                # Get the hashX of the name script.  Ignore non-name scripts.
                hashX = script_name_hashX(txout.pk_script)
                if hashX:
                    append_hashX(hashX)

            append_hashXs(hashXs)
            update_touched(hashXs)
            tx_num += 1

        self.db.history.add_unflushed(hashXs_by_tx, self.tx_count - len(txs))

        return result


class LTORBlockProcessor(BlockProcessor):
    def advance_txs(
        self,
        txs: Sequence[Tuple[Tx, bytes]],
        is_unspendable: Callable[[bytes], bool],
        header,
        height,
    ):
        self.tx_hashes.append(b"".join(tx_hash for tx, tx_hash in txs))

        # Use local vars for speed in the loops
        undo_info = []
        tx_num = self.tx_count
        script_hashX = self.coin.hashX_from_script
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        undo_info_append = undo_info.append
        update_touched = self.touched.update
        to_le_uint32 = pack_le_uint32
        to_le_uint64 = pack_le_uint64

        hashXs_by_tx = [set() for _ in txs]

        # Add the new UTXOs
        for (tx, tx_hash), hashXs in zip(txs, hashXs_by_tx, strict=False):
            add_hashXs = hashXs.add
            tx_numb = to_le_uint64(tx_num)[:TXNUM_LEN]

            for idx, txout in enumerate(tx.outputs):
                # Ignore unspendable outputs
                if is_unspendable(txout.pk_script):
                    continue

                # Get the hashX
                hashX = script_hashX(txout.pk_script)
                add_hashXs(hashX)
                put_utxo(
                    tx_hash + to_le_uint32(idx),
                    hashX + tx_numb + to_le_uint64(txout.value),
                )
            tx_num += 1

        # Spend the inputs
        # A separate for-loop here allows any tx ordering in block.
        for (tx, _tx_hash), hashXs in zip(txs, hashXs_by_tx, strict=False):
            add_hashXs = hashXs.add
            for txin in tx.inputs:
                if txin.is_generation():
                    continue
                cache_value = spend_utxo(txin.prev_hash, txin.prev_idx)
                undo_info_append(cache_value)
                add_hashXs(cache_value[:HASHX_LEN])

        # Update touched set for notifications
        for hashXs in hashXs_by_tx:
            update_touched(hashXs)

        self.db.history.add_unflushed(hashXs_by_tx, self.tx_count)

        self.tx_count = tx_num
        self.db.tx_counts.append(tx_num)

        return undo_info

    def backup_txs(self, txs, is_unspendable):
        undo_info = self.db.read_undo_info(self.height)
        if undo_info is None:
            raise ChainError(f"no undo information found for height {self.height:,d}")

        # Use local vars for speed in the loops
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        add_touched = self.touched.add
        undo_entry_len = HASHX_LEN + TXNUM_LEN + 8

        # Restore coins that had been spent
        # (may include coins made then spent in this block)
        n = 0
        for tx, _tx_hash in txs:
            for txin in tx.inputs:
                if txin.is_generation():
                    continue
                undo_item = undo_info[n : n + undo_entry_len]
                put_utxo(txin.prev_hash + pack_le_uint32(txin.prev_idx), undo_item)
                add_touched(undo_item[:HASHX_LEN])
                n += undo_entry_len

        assert n == len(undo_info)

        # Remove tx outputs made in this block, by spending them.
        for tx, tx_hash in txs:
            for idx, txout in enumerate(tx.outputs):
                # Spend the TX outputs.  Be careful with unspendable
                # outputs - we didn't save those in the first place.
                if is_unspendable(txout.pk_script):
                    continue

                # Get the hashX
                cache_value = spend_utxo(tx_hash, idx)
                hashX = cache_value[:HASHX_LEN]
                add_touched(hashX)

        self.tx_count -= len(txs)
