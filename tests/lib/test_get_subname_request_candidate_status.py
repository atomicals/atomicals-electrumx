import pytest

from electrumx.lib.coins import Bitcoin

from electrumx.lib.util_atomicals import (
    location_id_bytes_to_compact,
    get_subname_request_candidate_status,
    MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS
)

coin = Bitcoin

MAX_BLOCKS_STR = str(MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS)

class MockLogger:
    def debug(self, msg):
        return 
    def info(self, msg):
        return 
    def warning(self, msg):
        return 
 
def test_get_subname_request_candidate_status_verified_self():
    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    subject_atomical_id2 = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of at first: 
    # verified
    # pending
    # pending_awaiting_payment
    # None
    #
    # Then emerges:
    #
    # pending_candidate
    # claimed_by_other
    # expired_payment_not_received
    # pending_awaiting_confirmations_payment_received_prematurely
    # pending_awaiting_confirmations_for_payment_window
    # pending_awaiting_confirmations
    # expired_payment_not_received
    # invalid_request_fault ???? Is this even a valid state possible? It is seen in practice, but indicates an error?
    # None
    atomical_info = {
        'atomical_id': subject_atomical_id,
        'mint_info': {
            'commit_height': 890000,
            'reveal_location_height': 890000
        }
    }  
    result = get_subname_request_candidate_status(890000, atomical_info, 'verified', subject_atomical_id, 'realm')
    assert({
        'status': 'verified',
        'verified_atomical_id': subject_atomical_id_compact,
        'note': 'Successfully verified and claimed realm for current Atomical'
    } == result)

def test_get_subname_request_candidate_status_verified_other():
    subject_atomical_id = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    subject_atomical_id2 = b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of at first: 
    # verified
    # pending
    # pending_awaiting_payment
    # None
    #
    # Then emerges:
    #
    # pending_candidate
    # claimed_by_other
    # expired_payment_not_received
    # pending_awaiting_confirmations_payment_received_prematurely
    # pending_awaiting_confirmations_for_payment_window
    # pending_awaiting_confirmations
    # expired_payment_not_received
    # invalid_request_fault ???? Is this even a valid state possible? It is seen in practice, but indicates an error?
    # None
    atomical_info = {
        'atomical_id': subject_atomical_id,
        'mint_info': {
            'commit_height': 890000,
            'reveal_location_height': 890000
        },
        '$realm_candidates': [
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890000,
                "reveal_location_height": 890000
            }
        ]
    }  
    result = get_subname_request_candidate_status(890000, atomical_info, 'verified', subject_atomical_id2, 'realm')
    assert({
        'status': 'verified',
        'verified_atomical_id': subject_atomical_id_compact,
        'note': 'Successfully verified and claimed realm for current Atomical'
    } == result)