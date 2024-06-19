# Copyright (C) 2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest

from bitcointx.core import *  # noqa
from bitcointx.core.key import *  # noqa
from bitcointx.core.script import *  # noqa
from bitcointx.core.scripteval import *  # noqa
from bitcointx.core.serialize import *  # noqa
from bitcointx.core.secp256k1 import *  # noqa
from bitcointx.core.sha256 import *  # noqa
from bitcointx import *  # noqa
from bitcointx.base58 import *  # noqa
from bitcointx.bech32 import *  # noqa
from bitcointx.rpc import *  # noqa
from bitcointx.wallet import *  # noqa
from bitcointx.util import *  # noqa


class Test_Imports(unittest.TestCase):
    def test_all_imports_dummy(self) -> None:
        pass
