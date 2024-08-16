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

# pylama:ignore=C901

try:
    from contextvars import ContextVar
    has_contextvars = True
except ImportError:
    import threading
    has_contextvars = False

import hashlib
import functools
from enum import Enum
from types import FunctionType
from abc import ABCMeta, ABC, abstractmethod
from typing import (
    Type, Set, Tuple, List, Dict, Union, Any, Callable, Iterable, Optional,
    TypeVar, Generic, cast, NoReturn, Mapping
)

_secp256k1_library_path: Optional[str] = None

_attributes_of_ABC = dir(ABC)

T_Callable = TypeVar('T_Callable', bound=Callable[..., Any])
T_ClassMappingDispatcher = TypeVar('T_ClassMappingDispatcher',
                                   bound='ClassMappingDispatcher')
T_unbounded = TypeVar('T_unbounded')
T_rettype = TypeVar('T_rettype')


class _NoBoolCallable():
    __slots__ = ['method_name', 'method']

    def __init__(self, name: str, method: Callable[[], bool]) -> None:
        self.method_name = name
        self.method = method

    def __int__(self) -> int:
        raise TypeError(
            'Using this attribute as integer property is disabled. '
            'please use {}()'.format(self.method_name))

    def __bool__(self) -> int:
        raise TypeError(
            'Using this attribute as boolean property is disabled. '
            'please use {}()'.format(self.method_name))

    def __call__(self) -> bool:
        return self.method()


class no_bool_use_as_property():
    """A decorator that disables use of an attribute
    as a property in a boolean context """

    def __init__(self, method: Callable[[Any], bool]) -> None:
        self.method = method

    def __get__(self, instance: object, owner: type) -> _NoBoolCallable:
        # mypy currently does not know that Callable can be a descriptor.
        # but we want to use Callable[[Any], bool] for the method so that
        # the decorator would only be applied to methods with expected
        # signature
        method = self.method.__get__(instance, owner)

        name = '{}{}.{}'.format(owner.__name__,
                                '' if instance is None else '()',
                                method.__name__)
        return _NoBoolCallable(name, cast(Callable[[], bool], method))


def get_class_dispatcher_depends(dclass: Type['ClassMappingDispatcher']
                                 ) -> Set[Type['ClassMappingDispatcher']]:
    """Return a set of dispatcher the supplied dispatcher class depends on"""
    dset: Set[Type['ClassMappingDispatcher']] = set()

    for dep_dclass in dclass._class_dispatcher__depends:
        dset.add(dep_dclass)
        dset |= get_class_dispatcher_depends(dep_dclass)

    assert len(dset) == len(set([elt._class_dispatcher__identity
                                 for elt in dset])), \
        "all the dispatcher in the set must have distinct identities"

    return dset


def activate_class_dispatcher(dclass: Type[T_ClassMappingDispatcher]
                              ) -> Type[T_ClassMappingDispatcher]:
    """Activate particular class dispatcher - so that the mapping it contains
    will be active. Activates its dependent dispatchers, recursively, too."""
    if not issubclass(dclass, ClassMappingDispatcher):
        raise TypeError(
            f'{dclass.__name__} is not a subclass '
            f'of ClassMappingDispatcher')

    if dclass._class_dispatcher__no_direct_use:
        raise ValueError("{} must not be used directly"
                         .format(dclass.__name__))

    prev = class_mapping_dispatch_data.get_dispatcher_class(
        dclass._class_dispatcher__identity)

    if dclass is not prev:
        for ddep in get_class_dispatcher_depends(dclass):
            activate_class_dispatcher(ddep)

        class_mapping_dispatch_data.set_dispatcher_class(
            dclass._class_dispatcher__identity,
            dclass)

    return prev  # type: ignore


def dispatcher_mapped_list(cls: T_ClassMappingDispatcher,
                           ) -> List[T_ClassMappingDispatcher]:
    """Get a list of the classes that particular class is to be
    dispatched to. Returns empty list when class is not in a dispatch map"""
    mcs = type(cls)
    if not issubclass(mcs, ClassMappingDispatcher):
        raise ValueError('{} is not a dispatcher class'.format(cls.__name__))

    dispatcher = class_mapping_dispatch_data.get_dispatcher_class(
        mcs._class_dispatcher__identity)

    if dispatcher is None:
        return []

    dclass_list = dispatcher._class_dispatcher__clsmap.get(cls, [])
    # We do not have type-annotead thread-local data at the moment,
    # - it requires custom thread-local class, which is in TODO.
    return cast(List[T_ClassMappingDispatcher], dclass_list)


class DispatcherMethodWrapper():
    """A helper class that allows to wrap both classmethods and staticmethods,
    in addition to normal instance methods"""
    def __init__(self, method: Union[FunctionType,
                                     'classmethod[Any, Any, Any]',
                                     'staticmethod[Any, Any]',
                                     'DispatcherMethodWrapper'],
                 wrapper: Callable[[Callable[..., Any], type],
                                   Callable[..., Any]]) -> None:
        self.method = method
        self.wrapper = wrapper

    def __get__(self, instance: object, owner: type) -> Callable[..., Any]:
        bound_method = self.method.__get__(instance, owner)
        return self.wrapper(bound_method, type(owner))


def dispatcher_wrap_methods(cls: 'ClassMappingDispatcher',
                            wrap_fn: Callable[[Callable[..., Any], type],
                                              Callable[..., Any]],
                            *,
                            dct: Optional[Dict[str, Any]] = None) -> None:
    """Wrap all methods of a class with a function, that would
    establish the dispatching context for that method"""

    classdict: Mapping[str, Any] = cls.__dict__ if dct is None else dct

    for attr_name, attr_value in classdict.items():
        if isinstance(attr_value, (FunctionType, classmethod, staticmethod,
                                   DispatcherMethodWrapper)):
            setattr(cls, attr_name,
                    DispatcherMethodWrapper(attr_value, wrap_fn))


class ClassMappingDispatcher(ABCMeta):
    """A custom class dispatcher that translates invocations and attribute
    access of a superclass to a certain subclass according to internal map

    This map is built from the actual superclass-subclass relations between
    the classes, with the help of a few additional flags that control the
    final mapping"""

    # metaclass attributes pollute the namespace of all the classes
    # that use the metaclass.
    # Use '_class_dispatcher__' prefix to minimize pollution.

    _class_dispatcher__final_dispatch: Set['ClassMappingDispatcher']
    _class_dispatcher__pre_final_dispatch: Set['ClassMappingDispatcher']
    _class_dispatcher__no_direct_use: bool
    _class_dispatcher__clsmap: Dict['ClassMappingDispatcher',
                                    List['ClassMappingDispatcher']]
    _class_dispatcher__identity: str
    _class_dispatcher__depends: Iterable[Type['ClassMappingDispatcher']]

    def __init_subclass__(
        mcs: Type['ClassMappingDispatcher'], identity: Optional[str] = None,
        depends: Iterable[Type['ClassMappingDispatcher']] = ()
    ) -> None:
        """Initialize the dispatcher metaclass

           Arguments:
                identity:
                    a string that sets the identity of the mapping:
                    the module that this mapping belongs to
                    (core, wallet, script, ...)
                    if identity is specified, that means that this is a
                    'base dispatcher' - it cannot be used directly,
                    and must be subclassed. Subclasses of the base
                    dispatcher cannot set their own identity, they all
                    will use the same identity set for the base dispatcher.
                depends:
                    a list of dispatchers that this dispatcher depends on.
                    the current dispatcher may directly use classes dispatched
                    by the dependent dispatchers, or the dependency may be
                    'structural' - as WalletBitcoinDispatcher, when activated,
                    implies that CoreBitcoinDispatcher should also be
                    activated, along with ScriptBitcoinDispatcher, for the
                    class dispatching situation to be consistent.
            """

        if identity is not None:
            if not class_mapping_dispatch_data.is_valid_identity(identity):
                raise ValueError('identity {} is not recognized'
                                 .format(identity))
            if hasattr(mcs, '_class_dispatcher__identity'):
                raise AssertionError("can't replace identity that was already "
                                     "set by the base class")
            mcs._class_dispatcher__identity = identity
            mcs._class_dispatcher__no_direct_use = True
            mcs._class_dispatcher__pre_final_dispatch = set()
            mcs._class_dispatcher__depends = depends
            for ddisp in depends:
                if not issubclass(ddisp, ClassMappingDispatcher):
                    raise TypeError('{} is not a dispatcher class'
                                    .format(ddisp.__name__))
            return

        if not getattr(mcs, '_class_dispatcher__identity', None):
            raise TypeError(
                "identity attribute is not set for the base dispatcher class")

        mcs._class_dispatcher__final_dispatch = set()
        mcs._class_dispatcher__no_direct_use = False
        mcs._class_dispatcher__clsmap = {}

        if depends:
            parent_depends = mcs._class_dispatcher__depends
            combined_depends = list(mcs._class_dispatcher__depends)
            for ddisp in depends:
                replaced_index = None
                for i, pdep in enumerate(parent_depends):
                    if issubclass(ddisp, pdep):
                        if combined_depends[i] != pdep:
                            raise TypeError(
                                '{} is specified in depends argument, but '
                                'it is in conflict with {}, that also tries '
                                'to replace {} from parent depenrs'
                                .format(ddisp, combined_depends[i], pdep))
                        if replaced_index is not None:
                            raise TypeError(
                                '{} is specified in depends argument, but '
                                'it is a subclass of both {} and {}'
                                .format(ddisp, parent_depends[replaced_index],
                                        pdep))
                        combined_depends[i] = ddisp
                        replaced_index = i

                if replaced_index is None:
                    raise TypeError(
                        '{} is specified in depends argument, but it is not '
                        'a subclass of any dependencies of the parent of {}'
                        .format(ddisp, mcs))

            mcs._class_dispatcher__depends = tuple(combined_depends)

    def __new__(mcs: Type[T_ClassMappingDispatcher], name: str,
                bases: Tuple[type, ...], namespace: Dict[str, Any],
                next_dispatch_final: bool = False,
                variant_of: Optional[type] = None) -> T_ClassMappingDispatcher:
        return super().__new__(mcs, name, bases, namespace)

    def __init__(cls: 'ClassMappingDispatcher', name: str,
                 bases: Tuple[type, ...], namespace: Dict[str, Any],
                 next_dispatch_final: bool = False,
                 variant_of: Optional[type] = None) -> None:
        """Build the dispatching map out of the superclass-subclass
        relationships, and wrap the methods of the classes so that appropriate
        dispatcher is active inside the methods

            Arguments:
                next_dispatch_final:
                    if True, means that this class should be mapped to
                    a single subclass, the mapping cannot be ambiguous.
                    If there's more than one subclasses, only one, 'default'
                    subclass may be in the mapping, an all other should
                    specify variant_of=<default_subclass>
                variant_of:
                    specifies another class that cls is a variant of,
                    when cls is not the default mapping for the superclass
                    that was marked with next_dispatch_final=True"""

        super().__init__(name, bases, namespace)

        # get the dispatcher class
        mcs = type(cls)

        # Wrap all methods of a class to enable the relevant dispatcher
        # within the methods.
        # For example, inside CBitcoinTransaction.deserialize(), CTxOut()
        # should produce CBitcoinTxOut, regardless of the current globally
        # chosen chain parameters.
        def wrap(fn: Callable[..., Any], mcs: Type['ClassMappingDispatcher']
                 ) -> Callable[..., Any]:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                if mcs._class_dispatcher__no_direct_use:
                    # The method of the class assigned to base dispatcher is
                    # called. Base dispatcher cannot be activated, so we
                    # just call the method.
                    # This happens when the base class is mapped to several
                    # subclasses, and the methods in the base class are
                    # supposed to do their own dispatching, using
                    # dispatcher_mapped_list function.
                    return fn(*args, **kwargs)

                prev_dispatcher = activate_class_dispatcher(mcs)
                try:
                    return fn(*args, **kwargs)
                finally:
                    activate_class_dispatcher(prev_dispatcher)

            return wrapper

        dispatcher_wrap_methods(cls, wrap)

        if next_dispatch_final:
            # for correctness, the classes that are not meant to be
            # dispatched to multiple candidate classes, but should only
            # have a mapping to one particular class, need to be marked
            # with next_dispatch_final=True parameter.
            # Here we store these classes to the set, to enable checking
            # the subsequent mappings against this set.
            mcs._class_dispatcher__pre_final_dispatch.add(cls)

        if mcs._class_dispatcher__no_direct_use:
            # No need to initialize classmap, this is a base dispatcher class
            return

        # walk the bases of the class to fill the classmap
        for bcs in cls.__mro__:
            if bcs is cls:
                # skip the current class
                continue

            if not isinstance(bcs, ClassMappingDispatcher):
                # skip if the base does not belong to our dispatch scheme
                continue

            if bcs in mcs._class_dispatcher__final_dispatch:
                # do not map subclasses after final dispatch reached
                continue

            target_list = mcs._class_dispatcher__clsmap.get(bcs, [])

            if any(issubclass(cls, target_cls) for target_cls in target_list):
                # if the mapped list contains a superclass of the
                # current class, do not add the class to the set, so that only
                # the direct subclasses will be in the mapping
                continue

            if variant_of is not None and variant_of in target_list:
                # If the class is a variant of the class that is already
                # is the target of the maping of some class, skip it
                continue

            if bcs in mcs._class_dispatcher__pre_final_dispatch:
                # if the class is a subclass of pre_final_dispatch class,
                # it is itself a final target of the dispatch.
                mcs._class_dispatcher__final_dispatch.add(cls)

                # check for correctness in regard to next_dispatch_final param
                if next_dispatch_final:
                    raise AssertionError(
                        '{} is marked with next_dispatch_final=True, '
                        'but {}, also marked with next_dispatch_final=Trye, '
                        'is mapped to it'.format(bcs.__name__, cls.__name__))
                if len(target_list) > 0:
                    raise AssertionError(
                        '{} is marked with next_dispatch_final=True, '
                        'adding {} to already-mapped {} will make the mapping '
                        'non-final. Maybe you want to set variant_of=... on {}'
                        .format(bcs.__name__, cls.__name__,
                                [c.__name__ for c in target_list],
                                cls.__name__))

            # add the class to the mapping
            target_list.append(cls)
            # assign to the map in case this is first time
            mcs._class_dispatcher__clsmap[bcs] = target_list

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        """Perform class mapping in accordance to the currently active
        dispatcher class"""
        mcs = type(cls)
        cur_dispatcher = class_mapping_dispatch_data.get_dispatcher_class(
            mcs._class_dispatcher__identity)
        if cur_dispatcher is None:
            return type.__call__(cls, *args, **kwargs)

        class_list = cur_dispatcher._class_dispatcher__clsmap.get(cls, [])
        if len(class_list) != 1:
            # There is more than one target, so this is not
            # a final mapping. Instantiate the original class, and allow
            # it to do its own dispatching.
            return type.__call__(cls, *args, **kwargs)
        # Unambigous target - do the substitution.
        return type.__call__(class_list[0], *args, **kwargs)

    def __getattribute__(cls, name: str) -> Any:
        """Perform class attribute mapping in accordance to the currently
        active dispatcher class (except python-specific attributes)"""
        if name.startswith('__') and name.endswith('__') \
                or name in _attributes_of_ABC:
            return type.__getattribute__(cls, name)
        mcs = type(cls)
        cur_dispatcher = class_mapping_dispatch_data.get_dispatcher_class(
            mcs._class_dispatcher__identity)
        if cur_dispatcher is None:
            return type.__getattribute__(cls, name)

        class_list = cur_dispatcher._class_dispatcher__clsmap.get(cls, [])
        if len(class_list) != 1:
            # There is more than one target, so this is not
            # a final mapping. The original class is doing
            # its own dispatching, and we do not need to do any
            # attribute substition here.
            return type.__getattribute__(cls, name)

        # Unambigous target - do the substitution.
        return getattr(class_list[0], name)


class classgetter(Generic[T_rettype]):
    """simple decorator to create a read-only class property
    from class method"""

    def __init__(self, f: Callable[..., T_rettype]):
        self.f = f

    def __get__(self, obj: object, owner: type) -> T_rettype:
        return self.f(owner)


def ensure_isinstance(var: object,
                      type_or_types: Union[Type[Any], Tuple[Type[Any], ...]],
                      var_description: str) -> None:

    if not isinstance(var, type_or_types):
        if isinstance(type_or_types, type):  # single type
            msg = (f"{var_description} is expected to be an instance of "
                   f"{type_or_types.__name__}, but an instance of "
                   f"{var.__class__.__name__} was supplied")
        else:
            names = ', '.join(t.__name__ for t in type_or_types)
            msg = (f"{var_description} is expected to be an instance of "
                   f"any of ({names}), but an instance of "
                   f"{var.__class__.__name__} was supplied")

        raise TypeError(msg)


def assert_never(x: NoReturn) -> NoReturn:
    """For use with static checking. The checker such as mypy will raise
    error if the statement `assert_never(...)` is reached. At runtime,
    an `AssertionError` will be raised.
    Useful to ensure that all variants of Enum is handled.
    Might become useful in other ways, and because of this, the message
    for `AssertionError` at runtime can differ on actual type of the argument.
    For full control of the message, just pass a string as the argument.
    """

    if isinstance(x, Enum):
        msg = f'Enum {x} is not handled'
    elif isinstance(x, str):
        msg = x
    elif isinstance(x, type):
        msg = f'{x.__name__} is not handled'
    else:
        msg = f'{x.__class__.__name__} is not handled'

    raise AssertionError(msg)


class ReadOnlyFieldGuard(ABC):
    """A unique class that is used as a guard type for ReadOnlyField.
    It cannot be instantiated at runtime, and the static check will also
    catch the attempts to instantiate it, because it has __new__()
    defined as abstractmethod."""

    @abstractmethod
    def __new__(cls) -> None:  # type: ignore
        raise NotImplementedError


class ReadOnlyField(Generic[T_unbounded]):
    """A class to annotate read-only fields.
    Only used for statically checking the code, and is not intended
    to be used at runtime.
    """
    def __get__(self: T_unbounded, instance: object, owner: type
                ) -> T_unbounded:
        raise NotImplementedError

    def __set__(self: T_unbounded, instance: object, value: ReadOnlyFieldGuard
                ) -> None:
        raise NotImplementedError


class WriteableField(ReadOnlyField[T_unbounded]):
    """A class to annotate the fields in the mutable subclasses of ths
    classes that use ReadOnlyField.
    Only used for statically checking the code, and is not intended
    to be used at runtime.
    """
    def __get__(self: T_unbounded, instance: object, owner: type
                ) -> T_unbounded:
        raise NotImplementedError

    def __set__(self: T_unbounded, instance: object, value: Any) -> None:
        raise NotImplementedError


if has_contextvars:
    class ContextVarsCompat:
        _context_vars_storage__: Dict[str, 'ContextVar[Any]']

        def __init__(self, **kwargs: Any):
            assert self.__class__ is not ContextVarsCompat, \
                "ContextVarsCompat should always be subclassed"
            vardict = {name: ContextVar(name, default=default_value)
                       for name, default_value in kwargs.items()}
            object.__setattr__(self, '_context_vars_storage__', vardict)

        def __getattr__(self, name: str) -> Any:
            if name not in self._context_vars_storage__:
                raise AttributeError
            return self._context_vars_storage__[name].get()

        def __setattr__(self, name: str, value: Any) -> None:
            if name not in self._context_vars_storage__:
                raise AttributeError(
                    f'context variable {name} was not specified on '
                    f'{self.__class__.__name__} creation')
            self._context_vars_storage__[name].set(value)
else:
    class ContextVarsCompat(threading.local):  # type: ignore
        _context_vars_defaults__: Dict[str, Any] = {}

        def __init__(self, **kwargs: Any):
            assert self.__class__ is not ContextVarsCompat, \
                "ContextVarsCompat should always be subclassed"
            defaults = self.__class__._context_vars_defaults__

            if not kwargs:
                kwargs = defaults
            elif defaults and kwargs != defaults:
                raise ValueError(
                    f'{self.__class__.__name__} cannot be instantiated twice '
                    f'with different default values')
            else:
                self.__class__._context_vars_defaults__ = kwargs

            for name, default_value in kwargs.items():
                setattr(self, name, default_value)

        def __setattr__(self, name: str, value: Any) -> None:
            if name not in self.__class__._context_vars_defaults__:
                raise AttributeError(
                    f'context variable {name} was not specified on '
                    f'{self.__class__.__name__} creation')
            super().__setattr__(name, value)


class ContextLocalClassDispatchers(ContextVarsCompat):

    _known_identities = ('core', 'wallet', 'script', 'psbt')

    core: Type[ClassMappingDispatcher]
    wallet: Type[ClassMappingDispatcher]
    script: Type[ClassMappingDispatcher]

    def __init__(self) -> None:
        super().__init__(**{k: None for k in self._known_identities})

    def is_valid_identity(self, identity: str) -> bool:
        return identity in self._known_identities

    def get_dispatcher_class(
        self, identity: str
    ) -> Optional[Type[ClassMappingDispatcher]]:
        assert self.is_valid_identity(identity)
        dclass = getattr(self, identity)
        if dclass is None:
            return None
        assert issubclass(dclass, ClassMappingDispatcher)
        return cast(Type[ClassMappingDispatcher], dclass)

    def set_dispatcher_class(self, identity: str,
                             value: Type[ClassMappingDispatcher]) -> None:
        assert self.is_valid_identity(identity)
        assert issubclass(value, ClassMappingDispatcher)
        setattr(self, identity, value)


def tagged_hasher(tag: bytes) -> Callable[[bytes], bytes]:
    thash = hashlib.sha256(tag).digest() * 2

    def hasher(data: bytes) -> bytes:
        return hashlib.sha256(thash+data).digest()

    return hasher


class_mapping_dispatch_data = ContextLocalClassDispatchers()

__all__ = (
    'no_bool_use_as_property',
    'get_class_dispatcher_depends',
    'activate_class_dispatcher',
    'dispatcher_mapped_list',
    'DispatcherMethodWrapper',
    'dispatcher_wrap_methods',
    'ClassMappingDispatcher',
    'classgetter',
    'ensure_isinstance',
    'assert_never',
    'ReadOnlyField',
    'WriteableField',
    'ContextVarsCompat',
    'tagged_hasher',
)
