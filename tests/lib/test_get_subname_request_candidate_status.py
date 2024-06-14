import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.util_atomicals import (
    MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS,
    MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS,
    get_subname_request_candidate_status,
    location_id_bytes_to_compact,
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
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_subname_request_candidate_status(890000, atomical_info, "verified", subject_atomical_id, "realm")
    assert {
        "status": "verified",
        "verified_atomical_id": subject_atomical_id_compact,
        "note": "Successfully verified and claimed realm for current Atomical.",
    } == result


def test_get_subname_request_candidate_status_verified_claimed_by_other():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
        "$realm_candidates": [
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            }
        ]
        # 'applicable_rule': {
        #     "o": {
        #       "0123456789": {
        #         "v": 600
        #       }
        #     },
        #     "p": "8$"
        # }
    }
    result = get_subname_request_candidate_status(890006, atomical_info, "verified", subject_atomical_id2, "realm")
    assert {
        "status": "claimed_by_other",
        "claimed_by_atomical_id": subject_atomical_id_compact2,
        "note": "Claimed first by another Atomical.",
    } == result


def test_get_subname_request_candidate_status_verified_pending_candidate():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
        "$realm_candidates": [
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            }
        ]
        # 'applicable_rule': {
        #     "o": {
        #       "0123456789": {
        #         "v": 600
        #       }
        #     },
        #     "p": "8$"
        # }
    }
    result = get_subname_request_candidate_status(890006, atomical_info, "pending", subject_atomical_id2, "realm")
    assert {
        "status": "pending_awaiting_confirmations",
        "pending_candidate_atomical_id": subject_atomical_id_compact2,
        "note": "Await 3 blocks has elapsed to verify.",
    } == result


def test_get_subname_request_candidate_status_pending_awaiting_confirmations():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
    # pending_awaiting_confirmations
    # expired_payment_not_received
    # pending_awaiting_confirmations_payment_received_prematurely
    # pending_awaiting_confirmations_for_payment_window
    # expired_payment_not_received
    # invalid_request_fault ???? Is this even a valid state possible? It is seen in practice, but indicates an error?
    # None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
        "$realm_candidates": [
            {
                "tx_num": 995821344,
                "atomical_id": subject_atomical_id_compact2,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            },
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "41820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443711",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            },
        ]
        # 'applicable_rule': {
        #     "o": {
        #       "0123456789": {
        #         "v": 600
        #       }
        #     },
        #     "p": "8$"
        # }
    }
    result = get_subname_request_candidate_status(890006, atomical_info, "pending", subject_atomical_id2, "realm")
    assert {
        "status": "pending_awaiting_confirmations",
        "pending_candidate_atomical_id": subject_atomical_id_compact2,
        "note": "Await 3 blocks has elapsed to verify.",
    } == result


def test_get_subname_request_candidate_status_pending_awaiting_confirmations_for_payment_window():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
    # pending_awaiting_confirmations
    # expired_payment_not_received
    # pending_awaiting_confirmations_payment_received_prematurely
    # pending_awaiting_confirmations_for_payment_window
    # invalid_request_fault ???? Is this even a valid state possible? It is seen in practice, but indicates an error?
    # None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
        "$subrealm_candidates": [
            {
                "tx_num": 995821344,
                "atomical_id": subject_atomical_id_compact2,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            },
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "41820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443711",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "applicable_rule",
                "payment_due_no_later_than_height": 890005 + MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS,
                "applicable_rule": {"o": {"0123456789": {"v": 600}}, "p": "8$"},
            },
        ],
    }
    result = get_subname_request_candidate_status(890006, atomical_info, "pending", subject_atomical_id2, "subrealm")
    assert {
        "status": "pending_awaiting_confirmations_for_payment_window",
        "pending_candidate_atomical_id": subject_atomical_id_compact2,
        "note": 'Await until the "make_payment_from_height" block height for the payment window to be open.',
    } == result


def test_get_subname_request_candidate_status_pending_awaiting_confirmations_payment_received_prematurely():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
    # pending_awaiting_confirmations
    # expired_payment_not_received
    # pending_awaiting_confirmations_payment_received_prematurely
    # pending_awaiting_confirmations_for_payment_window
    # invalid_request_fault ???? Is this even a valid state possible? It is seen in practice, but indicates an error?
    # None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
        "$subrealm_candidates": [
            {
                "tx_num": 995821344,
                "atomical_id": subject_atomical_id_compact2,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            },
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "41820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443711",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "applicable_rule",
                "payment": "77720718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca79144371i3",
                "payment_due_no_later_than_height": 890005 + MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS,
                "applicable_rule": {"o": {"0123456789": {"v": 600}}, "p": "8$"},
            },
        ],
    }
    result = get_subname_request_candidate_status(890006, atomical_info, "pending", subject_atomical_id, "subrealm")
    assert {
        "status": "pending_awaiting_confirmations_payment_received_prematurely",
        "pending_candidate_atomical_id": subject_atomical_id_compact,
        "note": "The minimum delay of 3 blocks has not yet elapsed to declare a winner.",
    } == result

    result = get_subname_request_candidate_status(
        890006,
        atomical_info,
        "pending_awaiting_payment",
        subject_atomical_id,
        "subrealm",
    )
    assert {
        "status": "pending_awaiting_confirmations_payment_received_prematurely",
        "pending_candidate_atomical_id": subject_atomical_id_compact,
        "note": "The minimum delay of 3 blocks has not yet elapsed to declare a winner.",
    } == result

    result = get_subname_request_candidate_status(890009, atomical_info, "verified", subject_atomical_id, "subrealm")
    assert {
        "status": "verified",
        "verified_atomical_id": subject_atomical_id_compact,
        "note": "Successfully verified and claimed subrealm for current Atomical.",
    } == result


def test_get_subname_request_candidate_status_expired_payment_not_received():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
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
    # pending_awaiting_confirmations x
    # expired_payment_not_received x
    # pending_awaiting_confirmations_payment_received_prematurely x
    # pending_awaiting_confirmations_for_payment_window x
    # invalid_request_fault ???? Is this even a valid state possible? It is seen in practice, but indicates an error?
    # None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
        "$subrealm_candidates": [
            {
                "tx_num": 995821344,
                "atomical_id": subject_atomical_id_compact2,
                "txid": "11820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443722",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "mint_initiated",
                "applicable_rule": None,
            },
            {
                "tx_num": 995821345,
                "atomical_id": subject_atomical_id_compact,
                "txid": "41820718393b73ca9f862681f3093a045c5358e6ebe26bbdedc8eca791443711",
                "commit_height": 890005,
                "reveal_location_height": 890005,
                "payment_type": "applicable_rule",
                "payment": None,
                "payment_due_no_later_than_height": 890005 + MINT_SUBNAME_COMMIT_PAYMENT_DELAY_BLOCKS,
                "applicable_rule": {"o": {"0123456789": {"v": 600}}, "p": "8$"},
            },
        ],
    }

    result = get_subname_request_candidate_status(890120, atomical_info, "pending", subject_atomical_id, "subrealm")
    assert {
        "status": "expired_payment_not_received",
        "note": 'A valid payment was not received before the "payment_due_no_later_than_height" limit.',
    } == result
