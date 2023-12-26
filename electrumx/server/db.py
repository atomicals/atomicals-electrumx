# Copyright (c) 2016-2020, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Interface to the blockchain database.'''

from array import array
import ast
import os
import time
from bisect import bisect_right
from dataclasses import dataclass
from glob import glob
from typing import Dict, List, Sequence, Tuple, Optional, TYPE_CHECKING

import attr
from aiorpcx import run_in_thread, sleep

import electrumx.lib.util as util
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN, double_sha256
from electrumx.lib.merkle import Merkle, MerkleCache
from electrumx.lib.util import (
    formatted_time, pack_be_uint16, pack_be_uint32, pack_le_uint64, pack_be_uint64, pack_le_uint32,
    unpack_le_uint32, unpack_be_uint32, unpack_le_uint64, unpack_be_uint64, unpack_le_uint16_from
)
from electrumx.lib.util_atomicals import auto_encode_bytes_elements, pad_bytes64, get_tx_hash_index_from_location_id, location_id_bytes_to_compact, calculate_latest_state_from_mod_history
from electrumx.server.storage import db_class, Storage
from electrumx.server.history import History, TXNUM_LEN
from electrumx.lib.script import SCRIPTHASH_LEN
from cbor2 import dumps, loads, CBORDecodeError

import pickle

if TYPE_CHECKING:
    from electrumx.server.env import Env

ATOMICAL_ID_LEN = 36
TX_HASH_LEN = 32

@dataclass(order=True)
class UTXO:
    __slots__ = 'tx_num', 'tx_pos', 'tx_hash', 'height', 'value'
    tx_num: int      # index of tx in chain order
    tx_pos: int      # tx output idx
    tx_hash: bytes   # txid
    height: int      # block height
    value: int       # in satoshis

@attr.s(slots=True)

class FlushData:
    height = attr.ib()
    tx_count = attr.ib() 
    headers = attr.ib()
    block_tx_hashes = attr.ib()
    # The following are flushed to the UTXO DB if undo_infos is not None
    undo_infos = attr.ib()  # type: List[Tuple[Sequence[bytes], int]]
    adds = attr.ib()  # type: Dict[bytes, bytes]  # txid+out_idx -> hashX+tx_num+value_sats
    deletes = attr.ib()  # type: List[bytes]  # b'h' db keys, and b'u' db keys, and Atomicals and related keys
    tip = attr.ib()
    
    # Atomicals specific cache flush data below:
    # ------------------------------------------
    # atomical_count of Atomicals operates exactly similarly to tx_count
    atomical_count = attr.ib()          # Count of total Atomicals created
    # atomicals_undo_infos operates exactly similarly to undo_infos and contains enough information to reconstruct all indexes on reorg rollback
    atomicals_undo_infos = attr.ib()    # type: List[Tuple[Sequence[bytes], int]]
    # atomicals_adds is used to track atomicals locations and unspent utxos with the b'i' and b'a' indexes
    # It uses a field 'deleted' to indicate whether to write the b'a' (active unspent utxo) or not - because it may have been spent before the cache flushed
    # Maps location_id to atomical_ids and the value/deleted entry
    atomicals_adds = attr.ib()          # type: Dict[bytes, Dict[bytes, { value: bytes, deleted: Boolean}] ] 
    # general_adds is a general purpose storage for key-value, used for the majority of atomicals data
    general_adds = attr.ib()            # type: List[Tuple[Sequence[bytes], Sequence[bytes]]]
    # realm_adds map realm names to tx_num ints, which then map onto an atomical_id
    # The purpose is to track the earliest appearance of a realm name claim request in the order of the commit tx number
    realm_adds = attr.ib()              # type: Dict[bytes, Dict[int, bytes]
    # container_adds map container names to tx_num ints, which then map onto an atomical_id
    # The purpose is to track the earliest appearance of a container name claim request in the order of the commit tx number
    container_adds = attr.ib()          # type: List[Tuple[Sequence[bytes], Sequence[bytes]]]
    # ticker_adds map ticker names to tx_num ints, which then map onto an atomical_id
    # The purpose is to track the earliest appearance of a ticker name claim request in the order of the commit tx number
    ticker_adds = attr.ib()             # type: List[Tuple[Sequence[bytes], Sequence[bytes]]]
    # subrealm_adds maps parent_realm_id + subrealm name to tx_num ints, which then map onto an atomical_id
    subrealm_adds = attr.ib()           # type: Dict[bytes, Dict[int, bytes]
    # subrealmpay_adds maps atomical_id to tx_num ints, which then map onto payment_outpoints
    subrealmpay_adds = attr.ib()           # type: Dict[bytes, Dict[int, bytes]
    # dmitem_adds maps parent_realm_id + dmitem name to tx_num ints, which then map onto an atomical_id
    dmitem_adds = attr.ib()           # type: Dict[bytes, Dict[int, bytes]
    # dmpay_adds maps atomical_id to tx_num ints, which then map onto payment_outpoints
    dmpay_adds = attr.ib()           # type: Dict[bytes, Dict[int, bytes]
    # distmint_adds tracks the b'gi' which is the initial distributed mint location tracked to determine if any more mints are allowed
    # It maps atomical_id (of the dft deploy token mint) to location_ids and then the details of the scripthash+value_sats of the mint        
    distmint_adds = attr.ib()           # type: Dict[bytes, Dict[bytes, bytes]
    # state_adds is for evt, mod state updates
    # It maps atomical_id to the data of the state update      
    state_adds = attr.ib()           # type: Dict[bytes, Dict[bytes, bytes]
    
COMP_TXID_LEN = 4

class DB:
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = (6, 7, 8)

    utxo_db: Optional['Storage']

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env: 'Env'):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.env = env
        self.coin = env.coin

        # Setup block header size handlers
        if self.coin.STATIC_BLOCK_HEADERS:
            self.header_offset = self.coin.static_header_offset
            self.header_len = self.coin.static_header_len
        else:
            self.header_offset = self.dynamic_header_offset
            self.header_len = self.dynamic_header_len

        self.logger.info(f'switching current directory to {env.db_dir}')
        os.chdir(env.db_dir)

        self.db_class = db_class(self.env.db_engine)
        self.history = History()
        # Key: b'u' + address_hashX + txout_idx + tx_num
        # Value: the UTXO value as a 64-bit unsigned integer (in satoshis)
        # "at address, at outpoint, there is a UTXO of value v"
        # ---
        # Key: b'h' + compressed_tx_hash + txout_idx + tx_num
        # Value: hashX
        # "some outpoint created a UTXO at address"
        # ---
        # Key: b'U' + block_height
        # Value: byte-concat list of (hashX + tx_num + value_sats)
        # "undo data: list of UTXOs spent at block height"
        # ---
        #
        #
        #
        # Atomicals specific index below:
        # ------------------------------------------
        # Key: b'i' + location(tx_hash + txout_idx) + atomical_id(tx_hash + txout_idx)
        # Value: hashX + scripthash + value_sats
        # "map location to all the Atomicals which are located there. Permanently stored for every location even if spent."
        # ---
        # Key: b'a' + atomical_id(tx_hash + txout_idx) + location(tx_hash + txout_idx)
        # Value: hashX + scripthash + value_sats + tx_num
        # "map atomical to an unspent location. Used to located the NFT/FT Atomical unspent UTXOs"
        # ---
        # Key: b'L' + block_height
        # Value: byte-concat list of (tx_hash + txout_idx + atomical_id(mint_tx_hash + mint_txout_idx) + hashX + scripthash + value_sats)
        # "undo data: list of atomicals UTXOs spent at block height"
        # ---
        # Key: b'md' + atomical_id
        # Value: mint data serialized.
        # "maps atomical_id to mint data fields { object key-value pairs } "
        # ---
        # Key: b'mi' + atomical_id
        # Value: mint info serialized.
        # "maps atomical_id to mint information such as block info"
        # ---
        # Key: b'n' + atomical_number (8 bytes integer)
        # Value: atomical_id
        # "maps atomical number to an atomical_id"
        # ---
        # Key: b'mod' + atomical_id + tx_hash + out_idx
        # Value: payload data
        # "maps the atomical, transaction hash and output for the general mod state update data
        # ---
        # Key: b'evt' + atomical_id + tx_num + out_idx
        # Value: payload data
        # "maps the atomical, transaction number and output for the event data"
        # ---
        # Key: b'po' + tx_hash + tx_out_idx
        # Value: pk_script output
        # "maps arbitrary location to an output script. Useful for decoding the address and script located at some output"
        # ---
        # Key: b'tx' + tx_hash
        # Value: tx_num
        # "maps tx_hash to the tx number as counted from the genesis block"
        # ---
        # Key: b'rlm' + name bytes + commit_tx_num
        # Value: atomical_id bytes
        # "maps top level realm name and commit tx number to atomical id"
        # ---
        # Key: b'srlm' + parent_realm(atomical_id) + name + commit_tx_num
        # Value: atomical_id bytes
        # "maps parent realm atomical id and sub-name and commit tx number to the atomical_id"
        # ---
        # Key: b'spay' + atomical_id (of potential subrealm in the value of the b'srlm' index) + payment_tx_outpoint 
        # Value: satoshi value of the payment
        # "maps atomical id and payment outpoint to the satoshi value. Used with b'srlm' to associate payments"
        # ---
        # Key: b'tick' + tick bytes + tx_num
        # Value: atomical_id bytes
        # "maps name to atomical id (FT)"
        # ---
        # Key: b'gi' + atomical_id + location_id
        # Value: satoshis at the output 
        # "maps generated atomical mint and location to a value"
        # ---
        # Key: b'dat' + location_id
        # Value: bytes of files data stored at location. Ideally cbor encoded blob
        # "maps a location to files data"
        # ---
        # Key: b'sealed' + atomical_id
        # Value: location
        # "maps whether atomical id was sealed at a location"
        # ---
        # Key: b'tt' + height
        # Value: atomical header
        # "maps block height to an atomical header"
        #
        #
        #
        # --- Proof of work based indexes below --- 
        # The following indexes are for proof of work ranking and content scanning, they are non-functional to operations of atomicals
        #
        #
        # Key: b'powcmb' + pack_le_uint32(height) + pow_len_commit + pack_le_uint16(mint_bitworkc|rx) + atomical_id + op_padded
        # Value: paylaod_bytes of the operation found
        # "maps block height to the pow commit length score to the atomical id and the operation data"
        # --- 
        # Key: b'powcmr' + pow_commit_padded + pack_le_uint32(height) + atomical_id + op_padded
        # Value: paylaod_bytes of the operation found
        # "maps pow commit prefix to height and atomical id"
        # --- 
        # Key:  b'powcob' + pack_le_uint32(height) + pow_len_commit + pack_le_uint16(mint_bitworkc|rx) + commit_location + op_padded
        # Value: paylaod_bytes of the operation found
        # "maps pow commit for other non atomicals operation by height to pow score and commit location data"
        # ---
        # Key:  b'powcor' + pow_commit_padded + pack_le_uint32(height) + commit_location + op_padded
        # Value: paylaod_bytes of the operation found
        # "maps pow commit prefix to height for other non atomicals operation to height and location data"
        # ---
        # Key: b'powrb' + pack_le_uint32(height) + pow_len_reveal + pack_le_uint16(bitworkc|rx) + reveal_location_txid + op_padded
        # Value: paylaod_bytes of the operation found
        # "maps block height to the pow reveal length score to non atomicals operation data"
        # ---
        # Key: b'powrr' + pow_reveal_padded + pack_le_uint32(height) + reveal_location_txid + op_padded
        # Value: paylaod_bytes of the operation found
        # "maps pow reveal prefix to height  to non atomicals operation data"

        self.utxo_db = None
        self.utxo_flush_count = 0
        self.fs_height = -1
        self.fs_tx_count = 0
        self.fs_atomical_count = 0
        self.db_height = -1
        self.db_tx_count = 0
        self.db_atomical_count = 0
        self.db_tip = None  # type: Optional[bytes]
        self.tx_counts = None
        self.atomical_counts = None
        self.last_flush = time.time()
        self.last_flush_tx_count = 0
        self.last_flush_atomical_count = 0
        self.wall_time = 0
        self.first_sync = True
        self.db_version = -1
        self.logger.info(f'using {self.env.db_engine} for DB backend')

        # Header merkle cache
        self.merkle = Merkle()
        self.header_mc = MerkleCache(self.merkle, self.fs_block_hashes)

        # on-disk: raw block headers in chain order
        self.headers_file = util.LogicalFile('meta/headers', 2, 16000000)
        # on-disk: cumulative number of txs at the end of height N
        self.tx_counts_file = util.LogicalFile('meta/txcounts', 2, 2000000)
        # on-disk: cumulative number of atomicals counts at the end of height N
        self.atomical_counts_file = util.LogicalFile('meta/atomicalscounts', 2, 2000000)
        # on-disk: 32 byte txids in chain order, allows (tx_num -> txid) map
        self.hashes_file = util.LogicalFile('meta/hashes', 4, 16000000)
        if not self.coin.STATIC_BLOCK_HEADERS:
            self.headers_offsets_file = util.LogicalFile(
                'meta/headers_offsets', 2, 16000000)

    async def _read_tx_counts(self):
        if self.tx_counts is not None:
            return
        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.db_height + 1) * 8
        tx_counts = self.tx_counts_file.read(0, size)
        assert len(tx_counts) == size
        self.tx_counts = array('Q', tx_counts)
        if self.tx_counts:
            assert self.db_tx_count == self.tx_counts[-1]
        else:
            assert self.db_tx_count == 0
    
    async def _read_atomical_counts(self):
        if self.atomical_counts is not None:
            return
        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.db_height + 1) * 8
        atomical_counts = self.atomical_counts_file.read(0, size)
        assert len(atomical_counts) == size
        self.atomical_counts = array('Q', atomical_counts)
        if self.atomical_counts:
            assert self.db_atomical_count == self.atomical_counts[-1]
        else:
            assert self.db_atomical_count == 0

    async def _open_dbs(self, for_sync: bool, compacting: bool):
        assert self.utxo_db is None

        # First UTXO DB
        self.utxo_db = self.db_class('utxo', for_sync)
        if self.utxo_db.is_new:
            self.logger.info('created new database')
            self.logger.info('creating metadata directory')
            os.mkdir('meta')
            with util.open_file('COIN', create=True) as f:
                f.write(f'ElectrumX databases and metadata for '
                        f'{self.coin.NAME} {self.coin.NET}'.encode())
            if not self.coin.STATIC_BLOCK_HEADERS:
                self.headers_offsets_file.write(0, b'\0\0\0\0\0\0\0\0')
        else:
            self.logger.info(f'opened UTXO DB (for sync: {for_sync})')
        self.read_utxo_state()

        # Then history DB
        self.utxo_flush_count = self.history.open_db(self.db_class, for_sync,
                                                     self.utxo_flush_count,
                                                     compacting)
        self.clear_excess_undo_info()

        self.clear_excess_atomicals_undo_info()

        # Read TX counts (requires meta directory)
        await self._read_tx_counts()

        # Read Atomicals counts (requires meta directory)
        await self._read_atomical_counts()

    async def open_for_compacting(self):
        await self._open_dbs(True, True)

    async def open_for_sync(self):
        '''Open the databases to sync to the daemon.

        When syncing we want to reserve a lot of open files for the
        synchronization.  When serving clients we want the open files for
        serving network connections.
        '''
        await self._open_dbs(True, False)

    async def open_for_serving(self):
        '''Open the databases for serving.  If they are already open they are
        closed first.
        '''
        if self.utxo_db:
            self.logger.info('closing DBs to re-open for serving')
            self.utxo_db.close()
            self.history.close_db()
            self.utxo_db = None
        await self._open_dbs(False, False)

    # Header merkle cache

    async def populate_header_merkle_cache(self):
        self.logger.info('populating header merkle cache...')
        length = max(1, self.db_height - self.env.reorg_limit)
        start = time.monotonic()
        await self.header_mc.initialize(length)
        elapsed = time.monotonic() - start
        self.logger.info(f'header merkle cache populated in {elapsed:.1f}s')

    async def header_branch_and_root(self, length, height):
        return await self.header_mc.branch_and_root(length, height)

    # Flushing
    def assert_flushed(self, flush_data):
        '''Asserts state is fully flushed.'''
        assert flush_data.tx_count == self.fs_tx_count == self.db_tx_count
        assert flush_data.atomical_count == self.fs_atomical_count == self.db_atomical_count
        assert flush_data.height == self.fs_height == self.db_height
        assert flush_data.tip == self.db_tip
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert not flush_data.adds
        assert not flush_data.atomicals_adds
        assert not flush_data.general_adds
        assert not flush_data.ticker_adds
        assert not flush_data.realm_adds
        assert not flush_data.subrealm_adds
        assert not flush_data.subrealmpay_adds
        assert not flush_data.dmitem_adds
        assert not flush_data.dmpay_adds
        assert not flush_data.container_adds
        assert not flush_data.distmint_adds
        assert not flush_data.state_adds
        assert not flush_data.deletes
        assert not flush_data.undo_infos
        assert not flush_data.atomicals_undo_infos
        self.history.assert_flushed()

    def flush_dbs(self, flush_data, flush_utxos, estimate_txs_remaining):
        '''Flush out cached state.  History is always flushed; UTXOs are
        flushed if flush_utxos.'''
        if flush_data.height == self.db_height:
            self.assert_flushed(flush_data)
            return

        start_time = time.time()
        prior_flush = self.last_flush
        tx_delta = flush_data.tx_count - self.last_flush_tx_count
        atomical_delta = flush_data.atomical_count - self.last_flush_atomical_count

        # Flush to file system
        self.flush_fs(flush_data)

        # Then history
        self.flush_history()

        # Flush state last as it reads the wall time.
        with self.utxo_db.write_batch() as batch:
            if flush_utxos:
                self.flush_utxo_db(batch, flush_data)
            self.flush_state(batch)

        # Update and put the wall time again - otherwise we drop the
        # time it took to commit the batch
        self.flush_state(self.utxo_db)

        elapsed = self.last_flush - start_time
        self.logger.info(f'flush #{self.history.flush_count:,d} took '
                         f'{elapsed:.1f}s.  Height {flush_data.height:,d} '
                         f'txs: {flush_data.tx_count:,d} ({tx_delta:+,d}) '
                         f'Atomical txs: {flush_data.atomical_count:,d} ({atomical_delta:+,d})')

        # Catch-up stats
        if self.utxo_db.for_sync:
            flush_interval = self.last_flush - prior_flush
            tx_per_sec_gen = int(flush_data.tx_count / self.wall_time)
            tx_per_sec_last = 1 + int(tx_delta / flush_interval)
            eta = estimate_txs_remaining() / tx_per_sec_last
            self.logger.info(f'tx/sec since genesis: {tx_per_sec_gen:,d}, '
                             f'since last flush: {tx_per_sec_last:,d}')
            self.logger.info(f'sync time: {formatted_time(self.wall_time)}  '
                             f'ETA: {formatted_time(eta)}')

    def flush_fs(self, flush_data):
        '''Write headers, tx counts and block tx hashes to the filesystem.

        The first height to write is self.fs_height + 1.  The FS
        metadata is all append-only, so in a crash we just pick up
        again from the height stored in the DB.
        '''
        prior_tx_count = (self.tx_counts[self.fs_height]
                          if self.fs_height >= 0 else 0)
        assert len(flush_data.block_tx_hashes) == len(flush_data.headers)
        assert flush_data.height == self.fs_height + len(flush_data.headers)
        assert flush_data.tx_count == (self.tx_counts[-1] if self.tx_counts
                                       else 0)
        assert len(self.tx_counts) == flush_data.height + 1
        hashes = b''.join(flush_data.block_tx_hashes)
        flush_data.block_tx_hashes.clear()
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == flush_data.tx_count - prior_tx_count

        # Write the headers, tx counts, and tx hashes
        start_time = time.monotonic()
        height_start = self.fs_height + 1
        offset = self.header_offset(height_start)
        self.headers_file.write(offset, b''.join(flush_data.headers))
        self.fs_update_header_offsets(offset, height_start, flush_data.headers)
        flush_data.headers.clear()

        offset = height_start * self.tx_counts.itemsize
        self.tx_counts_file.write(offset,
                                  self.tx_counts[height_start:].tobytes())

        atomical_offset = height_start * self.atomical_counts.itemsize
        self.atomical_counts_file.write(atomical_offset,
                                  self.atomical_counts[height_start:].tobytes())

        offset = prior_tx_count * 32
        self.hashes_file.write(offset, hashes)

        self.fs_height = flush_data.height
        self.fs_tx_count = flush_data.tx_count
        self.fs_atomical_count = flush_data.atomical_count

        if self.utxo_db.for_sync:
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed filesystem data in {elapsed:.2f}s')

    def flush_history(self):
        self.history.flush()

    def flush_utxo_db(self, batch, flush_data: FlushData):
        '''Flush the cached DB writes and UTXO set to the batch.'''
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        start_time = time.monotonic()
        add_count = len(flush_data.adds)

        atomical_add_count = 0
        for location_key, atomical_map in flush_data.atomicals_adds.items():
            for atomical_id, value_with_tombstone in atomical_map.items():
                atomical_add_count = atomical_add_count + 1

        spend_count = len(flush_data.deletes) // 2

        # Spends
        batch_delete = batch.delete

        for key in sorted(flush_data.deletes):
            batch_delete(key)

        flush_data.deletes.clear()

        # General data adds (ie: for Atomicals mints)
        batch_put = batch.put
        for key, v in flush_data.general_adds.items():
            batch_put(key, v)
        flush_data.general_adds.clear()

        # ticker data adds
        batch_put = batch.put
        for key, v in flush_data.ticker_adds.items():
            for tx_num, atomical_id in v.items():
                batch_put(key + pack_le_uint64(tx_num), atomical_id)
        flush_data.ticker_adds.clear()

        # realm data adds
        # Realms are grouped by realm name and distinguished by commit_tx_num
        # The earliest commit_tx_num is the first-seen registration of the name
        batch_put = batch.put
        for key, v in flush_data.realm_adds.items():
            for tx_num, atomical_id in v.items():
                batch_put(key + pack_le_uint64(tx_num), atomical_id)
        flush_data.realm_adds.clear()

        # container data adds
        # Containers are grouped by container name and distinguished by commit_tx_num
        # The earliest commit_tx_num is the first-seen registration of the name
        batch_put = batch.put
        for key, v in flush_data.container_adds.items():
            for tx_num, atomical_id in v.items():
                batch_put(key + pack_le_uint64(tx_num), atomical_id)
        flush_data.container_adds.clear()

        # subrealm data adds
        # Subrealms are grouped by parent realm id and subrealm name and distinguished by commit_tx_num
        # The earliest commit_tx_num is the first-seen registration of the name
        batch_put = batch.put
        for key, v in flush_data.subrealm_adds.items():
            for tx_num, atomical_id in v.items():
                batch_put(key + pack_le_uint64(tx_num), atomical_id)
        flush_data.subrealm_adds.clear()

        # subrealm pay data adds
        batch_put = batch.put
        for key, v in flush_data.subrealmpay_adds.items():
            for tx_num, pay_outpoint in v.items():
                batch_put(key + pack_le_uint64(tx_num), pay_outpoint)
        flush_data.subrealmpay_adds.clear()

        # dmitem data adds
        # dmitems are grouped by parent container id and dmitem name and distinguished by commit_tx_num
        # The earliest commit_tx_num is the first-seen registration of the dm item name
        batch_put = batch.put
        for key, v in flush_data.dmitem_adds.items():
            for tx_num, atomical_id in v.items():
                batch_put(key + pack_le_uint64(tx_num), atomical_id)
        flush_data.dmitem_adds.clear()

        # dmitem pay data adds
        batch_put = batch.put
        for key, v in flush_data.dmpay_adds.items():
            for tx_num, pay_outpoint in v.items():
                batch_put(key + pack_le_uint64(tx_num), pay_outpoint)
        flush_data.dmpay_adds.clear()

        # New UTXOs
        batch_put = batch.put
        for key, value in flush_data.adds.items():
            # key: txid+out_idx, value: hashX+tx_num+value_sats
            hashX = value[:HASHX_LEN]
            txout_idx = key[-4:]
            tx_num = value[HASHX_LEN: HASHX_LEN+TXNUM_LEN]
            value_sats = value[-8:]
            suffix = txout_idx + tx_num
            batch_put(b'h' + key[:COMP_TXID_LEN] + suffix, hashX)
            batch_put(b'u' + hashX + suffix, value_sats)
        flush_data.adds.clear()
        
        # New atomicals location UTXOs
        # Tracks the atomicals that passed through each location and maintains active unspent utxos
        batch_put = batch.put
        for location_key, atomical_map in flush_data.atomicals_adds.items():
            for atomical_id, value_with_tombstone in atomical_map.items():
                value = value_with_tombstone['value']
                hashX = value[:HASHX_LEN]
                scripthash = value[HASHX_LEN : HASHX_LEN + SCRIPTHASH_LEN]
                value_sats = value[HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8]
                exponent = value[HASHX_LEN + SCRIPTHASH_LEN + 8: HASHX_LEN + SCRIPTHASH_LEN + 8 + 2]
                tx_numb = value[-TXNUM_LEN:]  
                self.logger.info(f'batch atomicals_adds value_sats={value_sats} exponent={exponent}')
                batch_put(b'i' + location_key + atomical_id, hashX + scripthash + value_sats + exponent + tx_numb) 
                # Add the active b'a' atomicals location if it was not deleted
                if not value_with_tombstone.get('deleted', False):
                    batch_put(b'a' + atomical_id + location_key, hashX + scripthash + value_sats + exponent + tx_numb) 
        flush_data.atomicals_adds.clear()
 
        # Distributed mint data adds
        # Grouped by the atomical and locations. Maintains the global location of all initial mints of distributed ft tokens
        batch_put = batch.put
        for atomical_id_key, location_map in flush_data.distmint_adds.items():
            for location_id, value in location_map.items():
                # the value is the format of: scripthash + value_sats
                batch_put(b'gi' + atomical_id_key + location_id, value)
        flush_data.distmint_adds.clear()

        # State data adds
        # Grouped by prefix and atomical id 
        batch_put = batch.put
        for state_id_prefix_key, state_id_suffix_map in flush_data.state_adds.items():
            for state_id_suffix_key, value in state_id_suffix_map.items():
                batch_put(state_id_prefix_key + state_id_suffix_key, value)
        flush_data.state_adds.clear()

        # New undo information
        self.flush_undo_infos(batch_put, flush_data.undo_infos)
        flush_data.undo_infos.clear()

        self.flush_atomicals_undo_infos(batch_put, flush_data.atomicals_undo_infos)
        flush_data.atomicals_undo_infos.clear()

        if self.utxo_db.for_sync:
            block_count = flush_data.height - self.db_height
            tx_count = flush_data.tx_count - self.db_tx_count
            atomical_count = flush_data.atomical_count - self.db_atomical_count
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed {block_count:,d} blocks with '
                             f'{tx_count:,d} txs, {add_count:,d} UTXO adds, '
                             f'{atomical_count:,d} Atomical txs, {atomical_add_count:,d} Atomical UTXO adds, '
                             f'{spend_count:,d} spends in '
                             f'{elapsed:.1f}s, committing...')

        self.utxo_flush_count = self.history.flush_count
        self.db_height = flush_data.height
        self.db_tx_count = flush_data.tx_count
        self.db_atomical_count = flush_data.atomical_count
        self.db_tip = flush_data.tip

    def flush_state(self, batch):
        '''Flush chain state to the batch.'''
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        self.last_flush_tx_count = self.fs_tx_count
        self.last_flush_atomical_count = self.fs_atomical_count
        self.write_utxo_state(batch)

    def flush_backup(self, flush_data, touched):
        '''Like flush_dbs() but when backing up.  All UTXOs are flushed.'''
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert flush_data.height < self.db_height
        self.history.assert_flushed()

        start_time = time.time()
        tx_delta = flush_data.tx_count - self.last_flush_tx_count
        atomical_delta = flush_data.atomical_count - self.last_flush_atomical_count

        self.backup_fs(flush_data.height, flush_data.tx_count, flush_data.atomical_count)
        # Do not need to do anything with atomical_count for history.backup
        self.history.backup(touched, flush_data.tx_count)
        with self.utxo_db.write_batch() as batch:
            self.flush_utxo_db(batch, flush_data)
            # Flush state last as it reads the wall time.
            self.flush_state(batch)
            
        elapsed = self.last_flush - start_time
        self.logger.info(f'backup flush #{self.history.flush_count:,d} took '
                         f'{elapsed:.1f}s.  Height {flush_data.height:,d} '
                         f'txs: {flush_data.tx_count:,d}'  f'({tx_delta:+,d}) ' 
                         f'Atomical txs: {flush_data.atomical_count:,d} ({atomical_delta:+,d})')

    def fs_update_header_offsets(self, offset_start, height_start, headers):
        if self.coin.STATIC_BLOCK_HEADERS:
            return
        offset = offset_start
        offsets = []
        for h in headers:
            offset += len(h)
            offsets.append(pack_le_uint64(offset))
        # For each header we get the offset of the next header, hence we
        # start writing from the next height
        pos = (height_start + 1) * 8
        self.headers_offsets_file.write(pos, b''.join(offsets))

    def dynamic_header_offset(self, height):
        assert not self.coin.STATIC_BLOCK_HEADERS
        offset, = unpack_le_uint64(self.headers_offsets_file.read(height * 8, 8))
        return offset

    def dynamic_header_len(self, height):
        return self.dynamic_header_offset(height + 1)\
               - self.dynamic_header_offset(height)

    def backup_fs(self, height, tx_count, atomical_count):
        '''Back up during a reorg.  This just updates our pointers.'''
        self.fs_height = height
        self.fs_tx_count = tx_count
        self.fs_atomical_count = atomical_count
        # Truncate header_mc: header count is 1 more than the height.
        self.header_mc.truncate(height + 1)

    async def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = await self.read_headers(height, 1)
        if n != 1:
            raise IndexError(f'height {height:,d} out of range')
        return header

    async def read_headers(self, start_height, count):
        '''Requires start_height >= 0, count >= 0.  Reads as many headers as
        are available starting at start_height up to count.  This
        would be zero if start_height is beyond self.db_height, for
        example.

        Returns a (binary, n) pair where binary is the concatenated
        binary headers, and n is the count of headers returned.
        '''
        if start_height < 0 or count < 0:
            raise self.DBError(f'{count:,d} headers starting at '
                               f'{start_height:,d} not on disk')

        def read_headers():
            # Read some from disk
            disk_count = max(0, min(count, self.db_height + 1 - start_height))
            if disk_count:
                offset = self.header_offset(start_height)
                size = self.header_offset(start_height + disk_count) - offset
                return self.headers_file.read(offset, size), disk_count
            return b'', 0

        return await run_in_thread(read_headers)

    def fs_tx_hash(self, tx_num):
        '''Return a pair (tx_hash, tx_height) for the given tx number.

        If the tx_height is not on disk, returns (None, tx_height).'''
        tx_height = bisect_right(self.tx_counts, tx_num)
        if tx_height > self.db_height:
            tx_hash = None
        else:
            tx_hash = self.hashes_file.read(tx_num * 32, 32)
        return tx_hash, tx_height

    def fs_tx_hashes_at_blockheight(self, block_height):
        '''Return a list of tx_hashes at given block height,
        in the same order as in the block.
        '''
        if block_height > self.db_height:
            raise self.DBError(f'block {block_height:,d} not on disk (>{self.db_height:,d})')
        assert block_height >= 0
        if block_height > 0:
            first_tx_num = self.tx_counts[block_height - 1]
        else:
            first_tx_num = 0
        num_txs_in_block = self.tx_counts[block_height] - first_tx_num
        tx_hashes = self.hashes_file.read(first_tx_num * 32, num_txs_in_block * 32)
        assert num_txs_in_block == len(tx_hashes) // 32
        return [tx_hashes[idx * 32: (idx+1) * 32] for idx in range(num_txs_in_block)]

    async def tx_hashes_at_blockheight(self, block_height):
        return await run_in_thread(self.fs_tx_hashes_at_blockheight, block_height)

    async def fs_block_hashes(self, height, count):
        headers_concat, headers_count = await self.read_headers(height, count)
        if headers_count != count:
            raise self.DBError(f'only got {headers_count:,d} headers starting '
                               f'at {height:,d}, not {count:,d}')
        offset = 0
        headers = []
        for n in range(count):
            hlen = self.header_len(height + n)
            headers.append(headers_concat[offset:offset + hlen])
            offset += hlen

        return [self.coin.header_hash(header) for header in headers]

    async def limited_history(self, hashX, *, limit=1000):
        '''Return an unpruned, sorted list of (tx_hash, height) tuples of
        confirmed transactions that touched the address, earliest in
        the blockchain first.  Includes both spending and receiving
        transactions.  By default returns at most 1000 entries.  Set
        limit to None to get them all.
        '''
        def read_history():
            tx_nums = list(self.history.get_txnums(hashX, limit))
            fs_tx_hash = self.fs_tx_hash
            return [fs_tx_hash(tx_num) for tx_num in tx_nums]

        while True:
            history = await run_in_thread(read_history)
            if all(hash is not None for hash, height in history):
                return history
            self.logger.warning(f'limited_history: tx hash '
                                f'not found (reorg?), retrying...')
            await sleep(0.25)

    # -- Undo information

    def min_undo_height(self, max_height):
        '''Returns a height from which we should store undo info.'''
        return max_height - self.env.reorg_limit + 1

    def undo_key(self, height: int) -> bytes:
        '''DB key for undo information at the given height.'''
        return b'U' + pack_be_uint32(height)

    def atomicals_undo_key(self, height: int) -> bytes:
        '''DB key for atomicals undo information at the given height.'''
        return b'L' + pack_be_uint32(height)

    def read_undo_info(self, height):
        '''Read undo information from a file for the current height.'''
        return self.utxo_db.get(self.undo_key(height))

    def read_atomicals_undo_info(self, height):
        '''Read atomicals undo information from a file for the current height.'''
        return self.utxo_db.get(self.atomicals_undo_key(height))

    def flush_undo_infos(
            self, batch_put, undo_infos: Sequence[Tuple[Sequence[bytes], int]]
    ):
        '''undo_infos is a list of (undo_info, height) pairs.'''
        for undo_info, height in undo_infos:
            batch_put(self.undo_key(height), b''.join(undo_info))

    def flush_atomicals_undo_infos(
                self, batch_put, atomicals_undo_infos: Sequence[Tuple[Sequence[bytes], Sequence[bytes]]]
        ):
        '''undo_infos is a list of (atomicals_undo_info, height) pairs.'''
        for atomicals_undo_info, height in atomicals_undo_infos:
            batch_put(self.atomicals_undo_key(height), b''.join(atomicals_undo_info))

    def raw_block_prefix(self):
        return 'meta/block'

    def raw_block_path(self, height):
        return f'{self.raw_block_prefix()}{height:d}'

    def read_raw_block(self, height):
        '''Returns a raw block read from disk.  Raises FileNotFoundError
        if the block isn't on-disk.'''
        with util.open_file(self.raw_block_path(height)) as f:
            return f.read(-1)

    def write_raw_block(self, block, height):
        '''Write a raw block to disk.'''
        with util.open_truncate(self.raw_block_path(height)) as f:
            f.write(block)
        # Delete old blocks to prevent them accumulating
        try:
            del_height = self.min_undo_height(height) - 1
            os.remove(self.raw_block_path(del_height))
        except FileNotFoundError:
            pass

    def clear_excess_undo_info(self):
        '''Clear excess undo info.  Only most recent N are kept.'''
        prefix = b'U'
        min_height = self.min_undo_height(self.db_height)
        keys = []
        for key, _hist in self.utxo_db.iterator(prefix=prefix):
            height, = unpack_be_uint32(key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            self.logger.info(f'deleted {len(keys):,d} stale undo entries')

        # delete old block files
        prefix = self.raw_block_prefix()
        paths = [path for path in glob(f'{prefix}[0-9]*')
                 if len(path) > len(prefix)
                 and int(path[len(prefix):]) < min_height]
        if paths:
            for path in paths:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            self.logger.info(f'deleted {len(paths):,d} stale block files')

    def clear_excess_atomicals_undo_info(self):
        '''Clear excess atomicals undo info.  Only most recent N are kept.'''
        prefix = b'L'
        min_height = self.min_undo_height(self.db_height)
        keys = []
        for key, _hist in self.utxo_db.iterator(prefix=prefix):
            height, = unpack_be_uint32(key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            self.logger.info(f'deleted {len(keys):,d} stale atomicals undo entries')

        # delete old block files
        prefix = self.raw_block_prefix()
        paths = [path for path in glob(f'{prefix}[0-9]*')
                 if len(path) > len(prefix)
                 and int(path[len(prefix):]) < min_height]
        if paths:
            for path in paths:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            self.logger.info(f'deleted {len(paths):,d} stale atomicals block files')

    # -- UTXO database

    def read_utxo_state(self):
        state = self.utxo_db.get(b'state')
        if not state:
            self.db_height = -1
            self.db_tx_count = 0
            self.db_atomical_count = 0
            self.db_tip = b'\0' * 32
            self.db_version = max(self.DB_VERSIONS)
            self.utxo_flush_count = 0
            self.wall_time = 0
            self.first_sync = True
        else:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from DB')
            self.db_version = state['db_version']
            if self.db_version not in self.DB_VERSIONS:
                raise self.DBError(f'your UTXO DB version is {self.db_version} '
                                   f'but this software only handles versions '
                                   f'{self.DB_VERSIONS}')
            # backwards compat
            genesis_hash = state['genesis']
            if isinstance(genesis_hash, bytes):
                genesis_hash = genesis_hash.decode()
            if genesis_hash != self.coin.GENESIS_HASH:
                raise self.DBError(f'DB genesis hash {genesis_hash} does not '
                                   f'match coin {self.coin.GENESIS_HASH}')
            self.db_height = state['height']
            self.db_tx_count = state['tx_count']
            self.db_atomical_count = state['atomical_count']
           
            self.db_tip = state['tip']
            self.utxo_flush_count = state['utxo_flush_count']
            self.wall_time = state['wall_time']
            self.first_sync = state['first_sync']

        # These are our state as we move ahead of DB state
        self.fs_height = self.db_height
        self.fs_tx_count = self.db_tx_count
        self.fs_atomical_count = self.db_atomical_count

        self.last_flush_tx_count = self.fs_tx_count
        self.last_flush_atomical_count = self.fs_atomical_count

        # Upgrade DB
        if self.db_version != max(self.DB_VERSIONS):
            self.upgrade_db()

        # Log some stats
        self.logger.info(f'UTXO DB version: {self.db_version:d}')
        self.logger.info(f'coin: {self.coin.NAME}')
        self.logger.info(f'network: {self.coin.NET}')
        self.logger.info(f'height: {self.db_height:,d}')
        self.logger.info(f'tip: {hash_to_hex_str(self.db_tip)}')
        self.logger.info(f'tx count: {self.db_tx_count:,d}')
        self.logger.info(f'atomical count: {self.db_atomical_count:,d}')

        if self.utxo_db.for_sync:
            self.logger.info(f'flushing DB cache at {self.env.cache_MB:,d} MB')
        if self.first_sync:
            self.logger.info(
                f'sync time so far: {util.formatted_time(self.wall_time)}'
            )

    def upgrade_db(self):
        self.logger.info(f'UTXO DB version: {self.db_version}')
        self.logger.info('Upgrading your DB; this can take some time...')

        def upgrade_u_prefix(prefix):
            count = 0
            with self.utxo_db.write_batch() as batch:
                batch_delete = batch.delete
                batch_put = batch.put
                # Key: b'u' + address_hashX + tx_idx + tx_num
                for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                    if len(db_key) == 21:
                        return
                    break
                if self.db_version == 6:
                    for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                        count += 1
                        batch_delete(db_key)
                        batch_put(db_key[:14] + b'\0\0' + db_key[14:] + b'\0', db_value)
                else:
                    for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                        count += 1
                        batch_delete(db_key)
                        batch_put(db_key + b'\0', db_value)
            return count

        last = time.monotonic()
        count = 0
        for cursor in range(65536):
            prefix = b'u' + pack_be_uint16(cursor)
            count += upgrade_u_prefix(prefix)
            now = time.monotonic()
            if now > last + 10:
                last = now
                self.logger.info(f'DB 1 of 3: {count:,d} entries updated, '
                                 f'{cursor * 100 / 65536:.1f}% complete')
        self.logger.info('DB 1 of 3 upgraded successfully')

        def upgrade_h_prefix(prefix):
            count = 0
            with self.utxo_db.write_batch() as batch:
                batch_delete = batch.delete
                batch_put = batch.put
                # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
                for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                    if len(db_key) == 14:
                        return
                    break
                if self.db_version == 6:
                    for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                        count += 1
                        batch_delete(db_key)
                        batch_put(db_key[:7] + b'\0\0' + db_key[7:] + b'\0', db_value)
                else:
                    for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                        count += 1
                        batch_delete(db_key)
                        batch_put(db_key + b'\0', db_value)
            return count

        last = time.monotonic()
        count = 0
        for cursor in range(65536):
            prefix = b'h' + pack_be_uint16(cursor)
            count += upgrade_h_prefix(prefix)
            now = time.monotonic()
            if now > last + 10:
                last = now
                self.logger.info(f'DB 2 of 3: {count:,d} entries updated, '
                                 f'{cursor * 100 / 65536:.1f}% complete')

        # Upgrade tx_counts file
        size = (self.db_height + 1) * 8
        tx_counts = self.tx_counts_file.read(0, size)
        if len(tx_counts) == (self.db_height + 1) * 4:
            tx_counts = array('I', tx_counts)
            tx_counts = array('Q', tx_counts)
            self.tx_counts_file.write(0, tx_counts.tobytes())

        self.db_version = max(self.DB_VERSIONS)
        with self.utxo_db.write_batch() as batch:
            self.write_utxo_state(batch)
        self.logger.info('DB 2 of 3 upgraded successfully')

    def write_utxo_state(self, batch):
        '''Write (UTXO) state to the batch.'''
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.db_height,
            'tx_count': self.db_tx_count,
            'atomical_count': self.db_atomical_count,
            'tip': self.db_tip,
            'utxo_flush_count': self.utxo_flush_count,
            'wall_time': self.wall_time,
            'first_sync': self.first_sync,
            'db_version': self.db_version,
        }
        batch.put(b'state', repr(state).encode())

    def set_flush_count(self, count):
        self.utxo_flush_count = count
        with self.utxo_db.write_batch() as batch:
            self.write_utxo_state(batch)

    async def all_utxos(self, hashX):
        '''Return all UTXOs for an address sorted in no particular order.'''
        def read_utxos():
            utxos = []
            utxos_append = utxos.append
            txnum_padding = bytes(8-TXNUM_LEN)
            # Key: b'u' + address_hashX + txout_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            prefix = b'u' + hashX
            for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                txout_idx, = unpack_le_uint32(db_key[-TXNUM_LEN-4:-TXNUM_LEN])
                tx_num, = unpack_le_uint64(db_key[-TXNUM_LEN:] + txnum_padding)
                value, = unpack_le_uint64(db_value)
                tx_hash, height = self.fs_tx_hash(tx_num)
                utxos_append(UTXO(tx_num, txout_idx, tx_hash, height, value))
            return utxos

        while True:
            utxos = await run_in_thread(read_utxos)
            if all(utxo.tx_hash is not None for utxo in utxos):
                return utxos
            self.logger.warning(f'all_utxos: tx hash not '
                                f'found (reorg?), retrying...')
            await sleep(0.25)
 
    async def lookup_utxos(self, prevouts):
        '''For each prevout, lookup it up in the DB and return a (hashX,
        value) pair or None if not found.

        Used by the mempool code.
        '''
        def lookup_hashXs():
            '''Return (hashX, suffix) pairs, or None if not found,
            for each prevout.
            '''
            def lookup_hashX(tx_hash, tx_idx):
                idx_packed = pack_le_uint32(tx_idx)
                txnum_padding = bytes(8-TXNUM_LEN)

                # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
                # Value: hashX
                prefix = b'h' + tx_hash[:COMP_TXID_LEN] + idx_packed

                # Find which entry, if any, the TX_HASH matches.
                for db_key, hashX in self.utxo_db.iterator(prefix=prefix):
                    tx_num_packed = db_key[-TXNUM_LEN:]
                    tx_num, = unpack_le_uint64(tx_num_packed + txnum_padding)
                    hash, _height = self.fs_tx_hash(tx_num)
                    if hash == tx_hash:
                        return hashX, idx_packed + tx_num_packed
                return None, None
            return [lookup_hashX(*prevout) for prevout in prevouts]

        def lookup_utxos(hashX_pairs):
            def lookup_utxo(hashX, suffix):
                if not hashX:
                    # This can happen when the daemon is a block ahead
                    # of us and has mempool txs spending outputs from
                    # that new block
                    return None
                # Key: b'u' + address_hashX + tx_idx + tx_num
                # Value: the UTXO value as a 64-bit unsigned integer
                key = b'u' + hashX + suffix
                db_value = self.utxo_db.get(key)
                if not db_value:
                    # This can happen if the DB was updated between
                    # getting the hashXs and getting the UTXOs
                    return None
                value, = unpack_le_uint64(db_value)
                return hashX, value
            return [lookup_utxo(*hashX_pair) for hashX_pair in hashX_pairs]

        hashX_pairs = await run_in_thread(lookup_hashXs)
        return await run_in_thread(lookup_utxos, hashX_pairs)

    # Get the raw mint information for an atomical
    def get_atomical_mint_info_dump(self, atomical_id):
        return self.utxo_db.get(b'mi' + atomical_id)
    
    # Resolve the atomical id for a given atomical number
    def get_atomical_id_by_atomical_number(self, atomical_number):
        atomical_num_key = b'n' + pack_be_uint64(int(atomical_number))
        atomical_id_value = self.utxo_db.get(atomical_num_key)
        if not atomical_id_value:
            self.logger.error(f'get_atomical_id_by_atomical_number {atomical_number} atomical number not found')
            return None
        return atomical_id_value
    
    def get_tx_num_height_from_tx_hash(self, tx_hash):
        tx_hash_key = b'tx' + tx_hash
        tx_hash_value = self.utxo_db.get(tx_hash_key)
        if tx_hash_value:
            unpacked_tx_num, = unpack_le_uint64(tx_hash_value[:8])
            unpacked_height, = unpack_le_uint32(tx_hash_value[-4:])
            return unpacked_tx_num, unpacked_height
        return None, None

    def get_earliest_subrealm_payments(self, atomical_id):
        spay_key_atomical_id = b'spay' + atomical_id
        payments = []
        for subrealmpay_key, subrealmpay_value in self.utxo_db.iterator(prefix=spay_key_atomical_id):
            tx_numb = subrealmpay_key[-8:]
            tx_num, = unpack_le_uint64(tx_numb)
            outpoint_of_payment = subrealmpay_value[:36]
            payments.append({
                'tx_num': tx_num,
                'payment_tx_outpoint': outpoint_of_payment,
                'mint_initiated': subrealmpay_value[36:]
            })
        return payments 
    
    def get_earliest_dmitem_payments(self, atomical_id):
        dmpay_key_atomical_id = b'dmpay' + atomical_id
        payments = []
        for dmitemmpay_key, dmitempay_value in self.utxo_db.iterator(prefix=dmpay_key_atomical_id):
            tx_numb = dmitemmpay_key[-8:]
            tx_num, = unpack_le_uint64(tx_numb)
            outpoint_of_payment = dmitempay_value[:36]
            payments.append({
                'tx_num': tx_num,
                'payment_tx_outpoint': outpoint_of_payment,
                'mint_initiated': dmitempay_value[36:]
            })
        return payments 

    # Get general data by key
    def get_general_data(self, key):
        return self.utxo_db.get(key)

    # Get all of the atomicals that passed through the location
    # Never deleted, kept for historical purposes.
    def get_atomicals_by_location(self, location): 
        long_form_ids = self.get_atomicals_by_location_long_form(location)
        atomicals_at_location = []
        for long_form_id in long_form_ids:
            atomicals_at_location.append(location_id_bytes_to_compact(long_form_id))
        return atomicals_at_location

    # Get all of the atomicals that passed through the location
    # Never deleted, kept for historical purposes.
    def get_atomicals_by_location_long_form(self, location): 
        # Get any other atomicals at the same location
        atomicals_at_location = []
        atomicals_at_location_prefix = b'i' + location
        for location_key, location_result_value in self.utxo_db.iterator(prefix=atomicals_at_location_prefix):
            atomicals_at_location.append(location_key[ 1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN])
        return atomicals_at_location

    # Gets the full information about the location_info
    def get_atomicals_by_location_extended_info_long_form(self, location): 
        # Get any other atomicals at the same location
        atomicals_at_location = []
        atomicals_at_location_prefix = b'i' + location
        tx_hash, index = get_tx_hash_index_from_location_id(location)
        last_scripthash = None 
        last_value = None
        # Get the location information, do a sanity check to ensure all the locations are the same
        for location_key, location_result_value in self.utxo_db.iterator(prefix=atomicals_at_location_prefix):
            atomicals_at_location.append(location_key[ 1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN])
            # extract the location information, it should be the same for all
            # batch_put(b'i' + location_key + atomical_id, hashX + scripthash + value_sats)
            curr_scripthash = location_result_value[ HASHX_LEN : HASHX_LEN + SCRIPTHASH_LEN ]
            if last_scripthash and last_scripthash != curr_scripthash:
                    raise IndexError(f'get_atomicals_by_location_extended_info_long_form curr_scripthash exception mismatch at location tx {hash_to_hex_str(tx_hash)}')
            else:
                last_scripthash = curr_scripthash
            curr_value, = unpack_le_uint64(location_result_value[ HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
            if last_value and last_value != curr_value:
                    raise IndexError(f'get_atomicals_by_location_extended_info_long_form curr_value exception mismatch at location tx {hash_to_hex_str(tx_hash)}')
            else:
                last_value = curr_value
        # They all share the same location script entry
        location_info = {}
        if last_value and last_scripthash:
            script = self.utxo_db.get(b'po' + location)
            location_info = {
                'location': location_id_bytes_to_compact(location),
                'txid': hash_to_hex_str(tx_hash),
                'index': index,
                'scripthash': hash_to_hex_str(last_scripthash),
                'script': script.hex(),
                'value': last_value
            }
        return {
            'location_info_obj': {
                'locations': [
                    location_info
                ]
            },
            'location_info': location_info,
            'atomicals': atomicals_at_location
        }
    # Get the atomicals at a specific utxo
    # Longform_ids indicates whether to use the long form atomical ids (36 bytes). By default returns the compact form with the 'i' 
    def get_atomicals_by_utxo(self, utxo, Longform_ids=False):
        location = utxo.tx_hash + pack_le_uint32(utxo.tx_pos)
        if Longform_ids:
            return self.get_atomicals_by_location_long_form(location)
        else:
            return self.get_atomicals_by_location(location)

    # Get atomicals hash by height
    def get_atomicals_block_hash(self, height):
        atomicals_block_hash_key = b'tt' + pack_le_uint32(height)
        abh = self.utxo_db.get(atomicals_block_hash_key)
        if abh:
            return hash_to_hex_str(abh)
        return None

    def get_atomicals_block_txs(self, height):
        block_txs_prefix = b'th' + pack_le_uint32(height)
        txs_list = []
        for block_txs_prefix_key, block_txs_prefix_value in self.utxo_db.iterator(prefix=block_txs_prefix):
            key_height, = unpack_le_uint32(block_txs_prefix_key[2 : 6])
            if key_height != height:
                break
            txs_list.append(hash_to_hex_str(block_txs_prefix_value))
        return txs_list

    def get_active_supply(self, atomical_id):
        active_supply = 0
        atomical_active_location_key_prefix = b'a' + atomical_id
        for atomical_active_location_key, atomical_active_location_value in self.utxo_db.iterator(prefix=atomical_active_location_key_prefix):
            if atomical_active_location_value:
                location = atomical_active_location_key[1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
                location_value, = unpack_le_uint64(atomical_active_location_value[HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
                active_supply += location_value
        return active_supply   

    # Get the atomical details with location information added
    # In the case of NFTs, there will only be every 1 maximum active location
    # In the case of FTs, there can be an unbounded nu mber of maximum active locations (one for each UTXO for all holders)
    # This makees it easy to get all top holders and locations of the token to audit the supply
    async def populate_extended_location_atomical_info(self, atomical_id, atomical):
        # self.logger.info(f'populate_ext ended_location_atomical_info {atomical_id}')
        def query_location():
            locations = []
            atomical_active_location_key_prefix = b'a' + atomical_id
            limit = 50
            counter = 0
            for atomical_active_location_key, atomical_active_location_value in self.utxo_db.iterator(prefix=atomical_active_location_key_prefix):
                if atomical_active_location_value:
                    location = atomical_active_location_key[1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
                    atomical_output_script_key = b'po' + location
                    atomical_output_script_value = self.utxo_db.get(atomical_output_script_key)
                    location_script = atomical_output_script_value
                    location_tx_hash = location[ : 32]
                    atomical_location_idx, = unpack_le_uint32(location[ 32 : 36])
                    location_scripthash = atomical_active_location_value[HASHX_LEN : HASHX_LEN + SCRIPTHASH_LEN]  
                    location_value, = unpack_le_uint64(atomical_active_location_value[HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
                    tx_numb = atomical_active_location_value[-TXNUM_LEN:]  
                    txnum_padding = bytes(8-TXNUM_LEN)
                    tx_num_padded, = unpack_le_uint64(tx_numb + txnum_padding)
                    atomicals_at_location = self.get_atomicals_by_location(location)
                    if counter < limit:
                        locations.append({
                            'location': location_id_bytes_to_compact(location),
                            'txid': hash_to_hex_str(location_tx_hash),
                            'index': atomical_location_idx,
                            'scripthash': hash_to_hex_str(location_scripthash),
                            'value': location_value,
                            'script': location_script.hex(),
                            'atomicals_at_location': atomicals_at_location,
                            'tx_num': tx_num_padded
                        })
                counter += 1 

            # Sort by most recent transactions first
            locations.sort(key=lambda x: x['tx_num'], reverse=True)
            atomical['location_info_obj'] = {
                'locations': locations 
            }
            atomical['location_info'] = locations
            atomical['location_counts'] = counter
            self.logger.info(f'populate_extended_location_atomical_info atomical{atomical}')
            return atomical
        return await run_in_thread(query_location)
    
    # Get the atomical holder info details added.
    async def populate_extended_atomical_holder_info(self, atomical_id, atomical):
        def query_holders():
            holder_dict = {}
            holders = []
            atomical_active_location_key_prefix = b'a' + atomical_id
            # set for get holders
            for atomical_active_location_key, atomical_active_location_value in self.utxo_db.iterator(prefix=atomical_active_location_key_prefix):
                if atomical_active_location_value:
                    location = atomical_active_location_key[1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
                    atomical_output_script_key = b'po' + location
                    atomical_output_script_value = self.utxo_db.get(atomical_output_script_key)
                    location_script = atomical_output_script_value
                    location_value, = unpack_le_uint64(atomical_active_location_value[HASHX_LEN + SCRIPTHASH_LEN : HASHX_LEN + SCRIPTHASH_LEN + 8])
                    
                    script = location_script.hex()
                    # TODO
                    # some location atomical_id might be burned
                    # the location alue will less than 1000
                    if holder_dict.get(script, None):
                        holder_dict[script] += location_value
                    else:
                        holder_dict[script] = location_value

            for script, holding in holder_dict.items():
                holders.append({
                    "holding": holding,
                    "script": script,
                })

            # Sort by holding count
            holders.sort(key=lambda x: x['holding'], reverse=True)
            atomical['holders'] = holders
            return atomical
        return await run_in_thread(query_holders)

    def dump(self):
        i_prefix = b'i'
        # Print sorted highscores print to file
        arr = []
        arrlocs = []
       
        file = open('/home/ubuntu/dbdump/i_prefix.txt', 'w') #write to file
        for location_key, location_result_value in self.utxo_db.iterator(prefix=i_prefix):
            arr.append(location_key.hex() + '-' + location_result_value.hex())
            arrlocs.append(location_key)
        for item in arr:
            file.write(item + '\n')
            
        file.close() #close file

        filelocs = open('/home/ubuntu/dbdump/i_prefix_locs.txt', 'w') #write to file
        counter = 0
        for item in arrlocs:
            atomid = item[ 1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
            locid = item[ 1 : 1 + ATOMICAL_ID_LEN]
            filelocs.write('locfirst:' + location_id_bytes_to_compact(atomid) + ' for ' +  location_id_bytes_to_compact(locid) + '\n')
            counter += 1
        filelocs.close() #close file

        gi_prefix = b'gi'
        # Print sorted highscores print to file
        arr = []
        gfile = open('/home/ubuntu/dbdump/gi_prefix.txt', 'w') #write to file
        for location_key, location_result_value in self.utxo_db.iterator(prefix=gi_prefix):
            arr.append(location_id_bytes_to_compact(location_key[2: 2 + ATOMICAL_ID_LEN]) + '-' + location_id_bytes_to_compact(location_key[2 + ATOMICAL_ID_LEN: 2 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]))
        for item in arr:
            gfile.write(item + '\n')
        gfile.close() #close file

        a_prefix = b'a'
        # Print sorted highscores print to file
        arr = []
        arrlocs = []
        afile = open('/home/ubuntu/dbdump/a_prefix.txt', 'w') #write to file
        for location_key, location_result_value in self.utxo_db.iterator(prefix=a_prefix):
            arr.append(location_key.hex() + '-' + location_result_value.hex())
            arrlocs.append(location_key)
        for item in arr:
            afile.write(item + '\n')
        afile.close() #close file

        afilelocs = open('/home/ubuntu/dbdump/a_prefix_locs.txt', 'w') #write to file
        counter = 0
        for item in arrlocs:
            if len(item) < 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN:
                continue
            locid = item[ 1 + ATOMICAL_ID_LEN : 1 + ATOMICAL_ID_LEN + ATOMICAL_ID_LEN]
            atomid = item[ 1 : 1 + ATOMICAL_ID_LEN]
            afilelocs.write('atomfirst: ' + location_id_bytes_to_compact(atomid) + ' @ ' +  location_id_bytes_to_compact(locid) + '\n')
            counter += 1
        afilelocs.close() #close file

        # realms
        arr = []
        arrlocs = []
        realmsfile = open('/home/ubuntu/dbdump/rlm_prefix.txt', 'w') 
        rlm_prefix = b'rlm'
        for the_key, the_value in self.utxo_db.iterator(prefix=rlm_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            realmsfile.write(item + '\n')
        realmsfile.close() 

        # subrealms
        arr = []
        arrlocs = []
        subrealmsfile = open('/home/ubuntu/dbdump/srlm_prefix.txt', 'w') 
        srlm_prefix = b'srlm'
        for the_key, the_value in self.utxo_db.iterator(prefix=srlm_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            subrealmsfile.write(item + '\n')
        subrealmsfile.close() 

        # payments
        arr = []
        arrlocs = []
        spayfile = open('/home/ubuntu/dbdump/spay_prefix.txt', 'w') 
        spay_prefix = b'spay'
        for the_key, the_value in self.utxo_db.iterator(prefix=spay_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            spayfile.write(item + '\n')
        spayfile.close() 

        # mod
        arr = []
        arrlocs = []
        modfile = open('/home/ubuntu/dbdump/mod_prefix.txt', 'w') 
        mod_prefix = b'mod'
        modobjs = []
        for the_key, the_value in self.utxo_db.iterator(prefix=mod_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
            modobjs.append(the_value)
        for item in arr:
            modfile.write(item + '\n')
        for modobj in modobjs:
            modfile.write(f'{loads(modobj)}\n')
        
        modfile.close() 

        # tick
        arr = []
        arrlocs = []
        tickfile = open('/home/ubuntu/dbdump/tick_prefix.txt', 'w') 
        tick_prefix = b'tick'
        for the_key, the_value in self.utxo_db.iterator(prefix=tick_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            tickfile.write(item + '\n')
        tickfile.close() 

        arr = []
        arrlocs = []
        mintfile = open('/home/ubuntu/dbdump/mddata.txt', 'w') 
        mint_prefix = b'md'
        for the_key, the_value in self.utxo_db.iterator(prefix=mint_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            mintfile.write(item + '\n')
        mintfile.close() 

        arr = []
        arrlocs = []
        mintinfofile = open('/home/ubuntu/dbdump/midata.txt', 'w') 
        mintinfo_prefix = b'mi'
        for the_key, the_value in self.utxo_db.iterator(prefix=mintinfo_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            mintinfofile.write(item + '\n')
        mintinfofile.close() 

        arr = []
        arrlocs = []
        sealedfile = open('/home/ubuntu/dbdump/sealed.txt', 'w') 
        sealed_prefix = b'sealed'
        for the_key, the_value in self.utxo_db.iterator(prefix=sealed_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            sealedfile.write(item + '\n')
        sealedfile.close() 

        arr = []
        arrlocs = []
        nfile = open('/home/ubuntu/dbdump/n.txt', 'w') 
        n_prefix = b'n'
        for the_key, the_value in self.utxo_db.iterator(prefix=n_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            nfile.write(item + '\n')
        nfile.close() 

        arr = []
        arrlocs = []
        lundofile = open('/home/ubuntu/dbdump/Lundo.txt', 'w') 
        L_prefix = b'L'
        for the_key, the_value in self.utxo_db.iterator(prefix=L_prefix):
            arr.append(the_key.hex() + '-' + the_value.hex())
        for item in arr:
            lundofile.write(item + '\n')
        lundofile.close() 


    def get_name_entries_template(self, db_prefix, subject_encoded):
        db_key_prefix = db_prefix + subject_encoded
        entries = []
        for db_key, db_value in self.utxo_db.iterator(prefix=db_key_prefix):
            tx_numb = db_key[-8:]
            atomical_id = db_value
            tx_num, = unpack_le_uint64(tx_numb)
            entries.append({
                'value': db_value,
                'tx_num': tx_num
            })
        return entries

    # Gets the paginated values of the db_prefix_key
    async def get_dmitem_entries_paginated(self, parent_container_id, limit, offset):
        entries = []
        entries_deduped = {}
        current_counter = 0
        db_prefix = b'codmt'
        db_prefix_len_with_parent = len(db_prefix) + 36
        db_search_prefix = b'codmt' + parent_container_id
        for db_key, db_value in self.utxo_db.iterator(prefix=db_search_prefix):
            if current_counter < offset:
                current_counter += 1
                continue
            if current_counter > offset + limit:
                break

            name_len, = unpack_le_uint16_from(db_key[-10:-8])
            dmitem_name = db_key[len(db_prefix)]
            if entries_deduped.get(dmitem_name):
                continue 
            dmitem_name_str = db_key[db_prefix_len_with_parent : db_prefix_len_with_parent + name_len].decode()
            entries_deduped[dmitem_name_str] = {
                'dmitem_name': dmitem_name_str,
                'db_key': db_key,
                'db_value': db_value,
                'counter': current_counter
            }
            current_counter += 1

        entries_intermediate = []
        for entry_key, entry_value in entries_deduped.items():
            entries_intermediate.append({
                'dmitem_name': entry_value['dmitem_name'],
                'counter': entry_value['counter']
            })
        entries_intermediate.sort(key=lambda x: x['counter'])
        for item in entries_intermediate:
            entries.append(item['dmitem_name'])
        return entries

    # Perform a search (usually through session rpc) to query for names. Limited to random 1000 results
    # If a user needs to dump all the results they can write custom logic to dump it
    def get_name_entries_template_limited(self, db_prefix, subject_encoded, Reverse=False, Limit=100, Offset=0):
        # Do not allow searching beyond the first 1000 matches of a prefix to protect server load
        if Limit <= 0:
            Limit = 1
        if Limit > 100:
            Limit = 100
        if Offset < 0:
            Offset = 0
        if Offset > 900:
            Offset = 900

        db_key_prefix = db_prefix + subject_encoded
        entries = []
        limit_count = 0
        start_count = 0
        reverse_bool = False
        if Reverse:
            reverse_bool = True 
        else:
            reverse_bool = False
        for db_key, db_value in self.utxo_db.iterator(prefix=db_key_prefix, reverse=reverse_bool):
            if start_count < Offset: 
                start_count += 1
                continue 
            tx_numb = db_key[-8:]
            atomical_id = db_value
            tx_num, = unpack_le_uint64(tx_numb)
            name_len, = unpack_le_uint16_from(db_key[-10:-8])
            db_prefix_len = len(db_prefix)
            self.logger.info(f'db_key, {db_key} {db_prefix_len} {name_len}')
            entries.append({
                'name': db_key[db_prefix_len : db_prefix_len + name_len].decode('latin-1'), # Extract the name portion
                'atomical_id': db_value,
                'tx_num': tx_num
            })
            limit_count += 1
            if limit_count == Limit:
                break
        return entries
 
    # Populate the latest state of an atomical for a path
    def populate_extended_mod_state_latest_atomical_info(self, atomical_id, atomical, height):
        mod_history = self.get_mod_history(atomical_id, height)
        latest_state = calculate_latest_state_from_mod_history(mod_history)
        latest_state_auto_encoded = auto_encode_bytes_elements(latest_state)
        atomical['state'] = {
            'latest': latest_state_auto_encoded
        }
        return atomical
 
    # Populate the mod state history for an atomical
    def get_mod_history(self, atomical_id, max_height):
        return self.get_mod_or_event_history(atomical_id, max_height, b'mod')

    # Populate the evt state history for an atomical
    def get_evt_history(self, atomical_id, max_height):
        return self.get_mod_or_event_history(atomical_id, max_height, b'evt')

    # Populate mod or event history for an atomical
    def get_mod_or_event_history(self, atomical_id, max_height, prefix_key):
        PREFIX_BYTE_LEN = 3
        prefix = prefix_key + atomical_id
        history = []
        for db_key, db_value in self.utxo_db.iterator(prefix=prefix, reverse=True):
            # Key: b'mod' + atomical_id + tx_hash + out_idx
            tx_hash = db_key[ PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN: PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN + TX_HASH_LEN]
            tx_num, tx_height = self.get_tx_num_height_from_tx_hash(tx_hash)
            # Requested limits on history
            if tx_height > max_height:
                break
            out_idx_packed = db_key[ PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN + TX_HASH_LEN: PREFIX_BYTE_LEN + ATOMICAL_ID_LEN + TXNUM_LEN + TX_HASH_LEN + 4]
            out_idx, = unpack_le_uint32(out_idx_packed)
            entry = {
                'tx_num': tx_num, 
                'height': tx_height, 
                'txid': hash_to_hex_str(tx_hash), 
                'index': out_idx,
                'data': loads(db_value)
            }
            history.append(entry)
        # Sort by descending tx_num
        history.sort(key=lambda x: x['tx_num'], reverse=True)
        return history
 
    # Populate the mod(ify) state information for an Atomical.
    # There could be potentially many updates for an Atomical and this should be called to enumerate the entire state history
    # From the state history, clients can reconstruct the "latest state" of an Atomical dynamic data fields
    def populate_extended_mod_state_history_atomical_info(self, atomical_id, atomical, max_height):
        atomical['state'] = {
            'history': self.get_mod_history(atomical_id, max_height)
        }
        return atomical

    # Populate the events data information for an Atomical.
    # There could be potentially many events for an Atomical and this should be called to enumerate the entire event history
    # From the event history, clients can play back all of the events emitted for an Atomical.
    # This is very similar to the "mod" operation, but the semantics are different and follow an emit/event like pattern
    # ...whereas the "mod" operation is intended to modify stable state.
    def populate_extended_events_atomical_info(self, atomical_id, atomical, max_height):
        atomical['events'] = {
            'history': self.get_evt_history(atomical_id, max_height)
        }
        return atomical
    
    # Retrieve the list feed of Atomicals in order
    # Can be used to construct a "latest Atomicals mints" page and a feed of the global activity
    async def get_atomicals_list(self, limit, offset, asc = False):
        if limit > 50:
            limit = 50
        # Todo: update the logic to correctly list
        atomical_number_tip = self.db_atomical_count
        def read_atomical_list():   
            atomical_ids = []
            # If no offset provided, then assume we want to start from the highest one
            search_starting_at_atomical_number = atomical_number_tip
            if offset >= 0:
                search_starting_at_atomical_number = offset
            elif offset < 0:
                # if offset is negative, then we assume it is subtracted from the latest number
                search_starting_at_atomical_number = atomical_number_tip + offset # adding a minus

            # safety checking for less than 0   
            if search_starting_at_atomical_number < 0:
                search_starting_at_atomical_number = 0

            # Generate up to limit number of keys to search
            list_of_keys = []
            x = 0
            while x < limit:
                if asc:
                    current_key = b'n' + pack_be_uint64(search_starting_at_atomical_number + x)
                    list_of_keys.append(current_key)
                else:
                    # Do not go to 0 or below
                    if search_starting_at_atomical_number - x < 0:
                        break 
                    current_key = b'n' + pack_be_uint64(search_starting_at_atomical_number - x)
                    list_of_keys.append(current_key)
                x += 1

            # Get all of the atomicals in the order of the keys
            for search_key in list_of_keys:
                atomical_id_value = self.utxo_db.get(search_key)
                if atomical_id_value:
                    atomical_ids.append(atomical_id_value)
                else: 
                    # Once we do not find one, then we are done because there should be no more
                    break
            return atomical_ids
        return await run_in_thread(read_atomical_list)
 
    # Get all atomicals by number to atomical id
    async def get_num_to_id(self, limit, offset, asc = False):
        if limit > 1000000:
            limit = 1000000
        # Todo: update the logic to correctly list
        atomical_number_tip = self.db_atomical_count
        def read_atomical_list():   
            atomical_num_ids = {}
            # If no offset provided, then assume we want to start from the highest one
            search_starting_at_atomical_number = atomical_number_tip
            if offset >= 0:
                search_starting_at_atomical_number = offset
            elif offset < 0:
                # if offset is negative, then we assume it is subtracted from the latest number
                search_starting_at_atomical_number = atomical_number_tip + offset # adding a minus

            # safety checking for less than 0   
            if search_starting_at_atomical_number < 0:
                search_starting_at_atomical_number = 0

            # Generate up to limit number of keys to search
            list_of_keys = []
            x = 0
            while x < limit:
                if asc:
                    number = search_starting_at_atomical_number + x
                    current_key = b'n' + pack_be_uint64(number)
                    list_of_keys.append({
                        'search_key': current_key,
                        'number': number
                    })
                else:
                    number = search_starting_at_atomical_number - x
                    # Do not go to 0 or below
                    if number < 0:
                        break 
                    current_key = b'n' + pack_be_uint64(number)
                    list_of_keys.append({
                        'search_key': current_key,
                        'number': number
                    })
                x += 1

            # Get all of the atomicals in the order of the keys
            for search_entry in list_of_keys:
                search_key = search_entry['search_key']
                number = search_entry['number']
                atomical_id_value = self.utxo_db.get(search_key)
                if atomical_id_value:
                    atomical_num_ids[number] = atomical_id_value
                else: 
                    # Once we do not find one, then we are done because there should be no more
                    break
            return atomical_num_ids
        return await run_in_thread(read_atomical_list)
 
    