import pytest

from electrumx.lib.atomicals_blueprint_builder import AtomicalsTransferBlueprintBuilder, get_nominal_token_value
from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash, hash_to_hex_str
from electrumx.lib.tx import Tx, TxInput, TxOutput
from electrumx.lib.avm_factory import AVMFactory

from electrumx.lib.util_atomicals import (
    location_id_bytes_to_compact
)

coin = Bitcoin
 
class MockLogger:
    def debug(self, msg):
        return 
    def info(self, msg):
        return 
    def warning(self, msg):
        return 

def test_empty_spends():
    avm_factory = AVMFactory(MockLogger(), {}, {})
    assert(avm_factory)

    result = avm_factory.get_modified_atomicals_spent_at_inputs()
    assert(result == {})
   