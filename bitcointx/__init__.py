# Copyright (C) 2012-2018 The python-bitcoinlib developers
# Copyright (C) 2018-2021 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import os
import platform

import types
from abc import ABCMeta
from contextlib import contextmanager
from collections import OrderedDict
from typing import (
    Dict, List, Tuple, Union, Optional, Type, Any, Generator, cast,
    TypeVar, Callable
)

import bitcointx.util

# Note that setup.py can break if __init__.py imports any external
# dependencies, as these might not be installed when setup.py runs. In this
# case __version__ could be moved to a separate version.py and imported here.
__version__ = '1.1.5'


# initialized at the end of the module, because it
# references BitcoinMainnetParams, which is not yet defined here.
_chain_params_context: 'ChainParamsContextVar'


T_ChainParamsMeta = TypeVar('T_ChainParamsMeta', bound='ChainParamsMeta')


class ChainParamsMeta(ABCMeta):
    _registered_classes: Dict[str, Type['ChainParamsBase']] = OrderedDict()
    _common_base_cls: Optional[Type['ChainParamsBase']] = None

    def __new__(cls: Type[T_ChainParamsMeta], cls_name: str,
                bases: Tuple[type], dct: Dict[str, Any],
                name: Optional[str] = None
                ) -> T_ChainParamsMeta:
        """check that the chainparams class uses unique base class
        (no two chain param classes can share a base class).
        if `name=` parameter is specified in the class declaration,
        set NAME attribute on a class, and register that class in
        a table for lookup by name."""
        cls_instance = cast(Type['ChainParamsBase'],
                            super().__new__(cls, cls_name, bases, dct))

        if len(bases):
            assert cls._common_base_cls is not None
            if not any(issubclass(b, cls._common_base_cls) for b in bases):
                raise TypeError(
                    '{} must be a subclass of {}'.format(
                        cls_name, cls._common_base_cls.__name__))

            if name is None:
                if 'NAME' in dct and not isinstance(dct['NAME'], str):
                    raise TypeError(f'{cls_name}: NAME is not a string')

            if 'RPC_PORT' in dct and not isinstance(dct['RPC_PORT'], int):
                raise TypeError(f'{cls_name}: RPC_PORT is not an int')

            if name is not None:
                if isinstance(name, str):
                    names = [name]
                elif isinstance(name, (list, tuple)):
                    names = cast(List[str], list(name))
                else:
                    raise TypeError(
                        'name argument must be string, list, or tuple')
                for name in names:
                    if name in cls._registered_classes:
                        raise AssertionError(
                            'name {} is not allowed to be registered twice, '
                            'it was already registered by {} before'
                            .format(
                                name, cls._registered_classes[name].__name__))
                    cls._registered_classes[name] = cls_instance

                cls_instance.NAME = names[0]
        else:
            if cls._common_base_cls:
                raise TypeError(
                    '{} cannot be used with more than one class, '
                    '{} was here first'.format(cls.__name__,
                                               cls._common_base_cls))
            cls._common_base_cls = cls_instance

        return cast(T_ChainParamsMeta, cls_instance)


def find_chain_params(*, name: str) -> Optional[Type['ChainParamsBase']]:
    return ChainParamsMeta._registered_classes.get(name)


def get_registered_chain_params() -> List[Type['ChainParamsBase']]:
    result: List[Type[ChainParamsBase]] = []
    for param_cls in ChainParamsMeta._registered_classes.values():
        if param_cls not in result:
            result.append(param_cls)

    return result


class ChainParamsBase(metaclass=ChainParamsMeta):
    """All chain param classes must be a subclass of this class."""

    NAME: str
    RPC_PORT: int
    WALLET_DISPATCHER: Union[
        Type['bitcointx.wallet.WalletCoinClassDispatcher'],
        Callable[[object], Type['bitcointx.wallet.WalletCoinClassDispatcher']]
    ]
    PSBT_DISPATCHER: Union[
        Type['bitcointx.core.psbt.PSBT_CoinClassDispatcher'],
        Callable[[object],
                 Type['bitcointx.core.psbt.PSBT_CoinClassDispatcher']]
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()

    def get_confdir_path(self) -> str:
        """Return default location for config directory"""
        name = self.NAME.split('/')[0]

        if platform.system() == 'Darwin':
            return os.path.expanduser(
                '~/Library/Application Support/{}'.format(name.capitalize()))
        elif platform.system() == 'Windows':
            return os.path.join(os.environ['APPDATA'], name.capitalize())

        return os.path.expanduser('~/.{}'.format(name))

    def get_config_path(self) -> str:
        """Return default location for config file"""
        name = self.NAME.split('/')[0]
        return '{}/{}.conf'.format(self.get_confdir_path(), name)

    def get_datadir_extra_name(self) -> str:
        """Return appropriate dir name to find data for the chain,
        and .cookie file. For mainnet, it will be an empty string -
        because data directory is the same as config directory.
        For others, like testnet or regtest, it will differ."""
        name_parts = self.NAME.split('/')
        if len(name_parts) == 1:
            return ''
        return name_parts[1]

    def get_network_id(self) -> str:
        """Return appropriate dir name to find data for the chain,
        and .cookie file. For mainnet, it will be an empty string -
        because data directory is the same as config directory.
        For others, like testnet or regtest, it will differ."""
        name_parts = self.NAME.split('/')
        if len(name_parts) == 1:
            return "main"
        return name_parts[1]

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def readable_name(self) -> str:
        name_parts = self.NAME.split('/')
        name_parts[0] = name_parts[0].capitalize()
        return ' '.join(name_parts)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name!r}>"


class BitcoinMainnetParams(ChainParamsBase,
                           name=('bitcoin', 'bitcoin/mainnet')):
    RPC_PORT = 8332

    # We want WALLET_DISPATCHER to be a proper class property
    # to not confuse mypy, but at the same time to be resolved at runtime.
    # This way we effectively make it a method, but allow descendant classes
    # to set this as property and still pass mypy strict checks
    WALLET_DISPATCHER: Union[
        Type['bitcointx.wallet.WalletCoinClassDispatcher'],
        Callable[[object], Type['bitcointx.wallet.WalletCoinClassDispatcher']]
    ] = lambda _: bitcointx.wallet.WalletBitcoinClassDispatcher

    PSBT_DISPATCHER: Union[
        Type['bitcointx.core.psbt.PSBT_CoinClassDispatcher'],
        Callable[[object],
                 Type['bitcointx.core.psbt.PSBT_CoinClassDispatcher']]
    ] = lambda _: bitcointx.core.psbt.PSBT_BitcoinClassDispatcher


class BitcoinTestnetParams(BitcoinMainnetParams, name='bitcoin/testnet'):
    RPC_PORT = 18332
    WALLET_DISPATCHER: Union[
        Type['bitcointx.wallet.WalletCoinClassDispatcher'],
        Callable[[object], Type['bitcointx.wallet.WalletCoinClassDispatcher']]
    ] = lambda _: bitcointx.wallet.WalletBitcoinTestnetClassDispatcher

    def get_datadir_extra_name(self) -> str:
        return "testnet3"

    def get_network_id(self) -> str:
        return "test"


class BitcoinRegtestParams(BitcoinMainnetParams, name='bitcoin/regtest'):
    RPC_PORT = 18443
    WALLET_DISPATCHER: Union[
        Type['bitcointx.wallet.WalletCoinClassDispatcher'],
        Callable[[object], Type['bitcointx.wallet.WalletCoinClassDispatcher']]
    ] = lambda _: bitcointx.wallet.WalletBitcoinRegtestClassDispatcher


class BitcoinSignetParams(BitcoinMainnetParams, name='bitcoin/signet'):
    RPC_PORT = 38332
    WALLET_DISPATCHER: Union[
        Type['bitcointx.wallet.WalletCoinClassDispatcher'],
        Callable[[object], Type['bitcointx.wallet.WalletCoinClassDispatcher']]
    ] = lambda _: bitcointx.wallet.WalletBitcoinSignetClassDispatcher


def get_current_chain_params() -> ChainParamsBase:
    return _chain_params_context.params


@contextmanager
def ChainParams(params: Union[str, ChainParamsBase,
                              Type[ChainParamsBase]],
                **kwargs: Any) -> Generator[ChainParamsBase, None, None]:
    """Context manager to temporarily switch chain parameters.
    """
    prev, new = select_chain_params(params, **kwargs)
    try:
        yield new
    finally:
        select_chain_params(prev)


def select_chain_params(params: Union[str, ChainParamsBase,
                                      Type[ChainParamsBase]],
                        **kwargs: Any
                        ) -> Tuple[ChainParamsBase, ChainParamsBase]:
    """Select the chain parameters to use

    if params is a string, then it is expected to be a name of
    is one of of the registered chain params, such as
    'bitcoin', 'bitcoin/testnet', or 'bitcoin/regtest'

    params can be an instance of ChainParamsBase.

    Default chain is 'bitcoin'.

    The references to new parameter classes are saved in global variables
    that are thread-local, so changing chain parameters is thread-safe.
    """

    if isinstance(params, str):
        params_cls = find_chain_params(name=params)
        if params_cls is None:
            raise ValueError('Unknown chain %r' % params)
        assert isinstance(params_cls, type)
        params = params_cls(**kwargs)
    elif isinstance(params, type):
        if not issubclass(params, ChainParamsBase):
            raise TypeError(
                'supplied class is not a subclass of ChainParamsBase')
        params = params(**kwargs)
    elif isinstance(params, ChainParamsBase):
        if len(kwargs):
            raise ValueError(
                'if an instance of ChainParamsBase is supplied, keyword '
                'arguments are not accepted (kwargs only make sense for '
                'instance creation, and we already have existing instance)')
    else:
        raise ValueError('Supplied chain params is not a string, not a '
                         'subclass of, nor an instance of ChainParamsBase')

    # the params are expected to be initialized
    prev_params = _chain_params_context.params
    _chain_params_context.params = params

    import bitcointx.wallet
    import bitcointx.core.psbt

    for disp_name in ('WALLET', 'PSBT'):
        disp = getattr(params, f'{disp_name}_DISPATCHER', None)
        if disp is None:
            continue

        if isinstance(disp, types.MethodType):
            disp_cls = disp()
        else:
            assert isinstance(disp, type)
            disp_cls = disp

        assert issubclass(disp_cls, bitcointx.util.ClassMappingDispatcher)

        bitcointx.util.activate_class_dispatcher(disp_cls)

    return prev_params, params


def set_custom_secp256k1_path(path: str) -> None:
    """Set the custom path that will be used to load secp256k1 library
    by bitcointx.core.secp256k1 module. For the calling of this
    function to have any effect, it has to be called before any function
    that uses secp256k1 library handle is called"""

    if not os.path.isfile(path):
        raise ValueError('supplied path does not point to a file')

    bitcointx.util._secp256k1_library_path = path


def get_custom_secp256k1_path() -> Optional[str]:
    """Return the path set earlier by set_custom_secp256k1_path().
    If custom path was not set, None is returned."""

    return bitcointx.util._secp256k1_library_path


class ChainParamsContextVar(bitcointx.util.ContextVarsCompat):
    params: ChainParamsBase


_chain_params_context = ChainParamsContextVar(params=BitcoinMainnetParams())


__all__ = (
    'ChainParamsBase',
    'BitcoinMainnetParams',
    'BitcoinTestnetParams',
    'BitcoinRegtestParams',
    'BitcoinSignetParams',
    'select_chain_params',
    'ChainParams',
    'get_current_chain_params',
    'get_registered_chain_params',
    'find_chain_params',
    'set_custom_secp256k1_path',
    'get_custom_secp256k1_path',
)
