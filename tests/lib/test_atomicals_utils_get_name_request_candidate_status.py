import pytest

from electrumx.lib.coins import Bitcoin
from electrumx.lib.util_atomicals import (
    MINT_REALM_CONTAINER_TICKER_COMMIT_REVEAL_DELAY_BLOCKS,
    get_name_request_candidate_status,
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


def test_get_name_request_candidate_status_invalid_height():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)

    # status can be one of: verified pending pending_awaiting_payment None
    possible_status = ["pending", "pending_awaiting_payment", "verified"]
    possible_name_types = ["realm", "ticker", "container", "subrealm", "dmitem"]
    possible_candidates = [None, subject_atomical_id]
    possible_mint_atomical_id = [subject_atomical_id, subject_atomical_id2]
    # Check to ensure under no circumstances would a late reveal be allowed
    for x in possible_status:
        for y in possible_name_types:
            for k in possible_candidates:
                for j in possible_mint_atomical_id:
                    atomical_info = {
                        "atomical_id": j,
                        "mint_info": {
                            "commit_height": 890000,
                            "reveal_location_height": 890004,
                        },
                    }
                    result = get_name_request_candidate_status(atomical_info, x, k, y)
                    assert {
                        "status": "expired_revealed_late",
                        "note": f"The maximum number of blocks between commit and reveal is {MAX_BLOCKS_STR} blocks.",
                    } == result


def test_get_name_request_candidate_status_valid_pending_claimed_by_other():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, "pending", subject_atomical_id2, "realm")
    assert {
        "status": "pending_claimed_by_other",
        "pending_claimed_by_atomical_id": subject_atomical_id_compact2,
        "note": "Failed to claim realm for current Atomical because it was claimed first by another Atomical.",
    } == result


def test_get_name_request_candidate_status_valid_pending_candidate():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id2,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, "pending", subject_atomical_id2, "realm")
    assert {
        "status": "pending_candidate",
        "pending_candidate_atomical_id": subject_atomical_id_compact2,
        "note": "The current Atomical is the leading candidate for the realm. "
        "Wait the 3 blocks after commit to achieve confirmation.",
    } == result


def test_get_name_request_candidate_status_valid_pending_candidate():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, "verified", subject_atomical_id2, "realm")
    assert {
        "status": "claimed_by_other",
        "claimed_by_atomical_id": subject_atomical_id_compact2,
        "note": "Failed to claim realm for current Atomical because it was claimed first by another Atomical.",
    } == result


def test_get_name_request_candidate_status_valid_none():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, None, None, "realm")
    assert {"status": None, "pending_candidate_atomical_id": None} == result


def test_get_name_request_candidate_status_valid_pending_candidate():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id2,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, "verified", subject_atomical_id2, "realm")
    assert {
        "status": "verified",
        "verified_atomical_id": subject_atomical_id_compact2,
        "note": "Successfully verified and claimed realm for current Atomical.",
    } == result


def test_get_name_request_candidate_status_valid_pending_candidate_subrealm():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id2,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, "pending", subject_atomical_id2, "subrealm")
    assert {
        "status": "pending",
        "pending_candidate_atomical_id": subject_atomical_id_compact2,
    } == result


def test_get_name_request_candidate_status_valid_pending_candidate_dmitem():
    subject_atomical_id = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x01\x00\x00\x00"
    )
    subject_atomical_id2 = (
        b"A\x03\x8f'\xe7\x85`l\xa0\xcc\x1e\xfd\x8e:\xa9\x12\xa1\\r\xd0o5\x9a\xeb\x05$=\xab+p\xa8V\x02\x00\x00\x00"
    )
    subject_atomical_id_compact = location_id_bytes_to_compact(subject_atomical_id)
    subject_atomical_id_compact2 = location_id_bytes_to_compact(subject_atomical_id2)
    # status can be one of: verified pending pending_awaiting_payment None
    atomical_info = {
        "atomical_id": subject_atomical_id2,
        "mint_info": {"commit_height": 890000, "reveal_location_height": 890000},
    }
    result = get_name_request_candidate_status(atomical_info, "pending", subject_atomical_id2, "dmitem")
    assert {
        "status": "pending",
        "pending_candidate_atomical_id": subject_atomical_id_compact2,
    } == result
