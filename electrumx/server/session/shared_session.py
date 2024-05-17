from aiorpcx import RPCError
from logging import LoggerAdapter

from electrumx.lib import util
from electrumx.lib.util_atomicals import AtomicalsValidationError
from electrumx.server.daemon import DaemonError
from electrumx.server.session import ATOMICALS_INVALID_TX, BAD_REQUEST


class SharedSession:
    def __init__(self, session_mgr: 'SessionManager', logger: LoggerAdapter):
        self.session_mgr = session_mgr
        self.logger = logger
        self.txs_sent = 0

    async def transaction_broadcast_validate(self, raw_tx: str = ""):
        """Simulate a Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string to validate for Atomicals FT rules"""
        # This returns errors as JSON RPC errors, as is natural
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, False)
            return hex_hash
        except AtomicalsValidationError as e:
            self.logger.info(f'error validating atomicals transaction: {e}')
            raise RPCError(
                ATOMICALS_INVALID_TX,
                f'the transaction was rejected by atomicals rules.\n\n{e}\n[{raw_tx}]'
            )

    async def transaction_broadcast(self, raw_tx):
        """Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string"""
        # This returns errors as JSON RPC errors, as is natural.
        try:
            hex_hash = await self.session_mgr.broadcast_transaction_validated(raw_tx, True)
            hex_hash = await self.session_mgr.broadcast_transaction(raw_tx)
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info(f'error sending transaction: {message}')
            raise RPCError(
                BAD_REQUEST,
                f'the transaction was rejected by network rules.\n\n{message}\n[{raw_tx}]'
            )
        except AtomicalsValidationError as e:
            self.logger.info(f'error validating atomicals transaction: {e}')
            raise RPCError(
                ATOMICALS_INVALID_TX,
                f'the transaction was rejected by atomicals rules.\n\n{e}\n[{raw_tx}]'
            )
        else:
            self.txs_sent += 1
            client_ver = util.protocol_tuple(self.client)
            if client_ver != (0,):
                msg = self.coin.warn_old_client_on_tx_broadcast(client_ver)
                if msg:
                    self.logger.info(f'sent tx: {hex_hash}. and warned user to upgrade their '
                                     f'client from {self.client}')
                    return msg

            self.logger.info(f'sent tx: {hex_hash}')
            return hex_hash
