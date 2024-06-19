# Copyright (C) 2007 Jan-Klaas Kollhof
# Copyright (C) 2011-2018 The python-bitcoinlib developers
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

"""Bitcoin Core RPC support

By default this uses the standard library ``json`` module. By monkey patching,
a different implementation can be used instead, at your own risk:

>>> import simplejson
>>> import bitcointx.rpc
>>> bitcointx.rpc.json = simplejson

(``simplejson`` is the externally maintained version of the same module and
thus better optimized but perhaps less stable.)
"""

import http.client
import base64
import decimal
import json
import os
import urllib.parse
from typing import (
    Type, Dict, Tuple, Optional, Union, Any, Callable, Iterable,
    TYPE_CHECKING
)

import bitcointx

try:
    from typing_extensions import Protocol
except ImportError:
    # This is relevant only for mypy.
    # Those who want to typecheck their code need to have typing_extensions
    # installed, or included with their newer python version (3.8+).
    if not TYPE_CHECKING:
        class Protocol:
            ...


class HTTPClient_Response_Protocol(Protocol):
    status: int
    response: str
    reason: str

    def read(self) -> bytes:
        ...


class HTTPClient_Protocol(Protocol):
    def request(self, method: str, path: str, postdata: str,
                headers: Dict[str, str]) -> None:
        ...

    def getresponse(self) -> HTTPClient_Response_Protocol:
        ...

    def close(self) -> None:
        ...


HTTPClient_Type = Union[http.client.HTTPConnection, HTTPClient_Protocol]


DEFAULT_USER_AGENT = "AuthServiceProxy/0.1"

DEFAULT_HTTP_TIMEOUT = 30


class DecimalJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, decimal.Decimal):
            r = float(o)
            if f'{r:.08f}' != f'{o:.08f}':
                raise TypeError(
                    f'value {o!r} lost precision beyond acceptable range '
                    f'when converted to float: {r:.08f} != {o:.08f}')
            return r
        return super().default(o)


class JSONRPCError(Exception):
    """JSON-RPC protocol error base class

    Subclasses of this class also exist for specific types of errors; the set
    of all subclasses is by no means complete.
    """

    error: Dict[str, Union[str, int]]
    RPC_ERROR_CODE: int
    SUBCLS_BY_CODE: Dict[int, Type['JSONRPCError']] = {}

    @classmethod
    def _register_subcls(cls, subcls: Type['JSONRPCError']
                         ) -> Type['JSONRPCError']:
        cls.SUBCLS_BY_CODE[subcls.RPC_ERROR_CODE] = subcls
        return subcls

    def __new__(cls, rpc_error: Dict[str, Union[int, str]]) -> 'JSONRPCError':
        assert cls is JSONRPCError
        assert isinstance(rpc_error['code'], int)
        cls = JSONRPCError.SUBCLS_BY_CODE.get(rpc_error['code'], cls)

        self = Exception.__new__(cls)

        super(JSONRPCError, self).__init__(
            'msg: %r  code: %r' %
            (rpc_error['message'], rpc_error['code']))

        self.error = rpc_error

        return self


@JSONRPCError._register_subcls
class ForbiddenBySafeModeError(JSONRPCError):
    RPC_ERROR_CODE = -2


@JSONRPCError._register_subcls
class InvalidAddressOrKeyError(JSONRPCError):
    RPC_ERROR_CODE = -5


@JSONRPCError._register_subcls
class InvalidParameterError(JSONRPCError):
    RPC_ERROR_CODE = -8


@JSONRPCError._register_subcls
class VerifyError(JSONRPCError):
    RPC_ERROR_CODE = -25


@JSONRPCError._register_subcls
class VerifyRejectedError(JSONRPCError):
    RPC_ERROR_CODE = -26


@JSONRPCError._register_subcls
class VerifyAlreadyInChainError(JSONRPCError):
    RPC_ERROR_CODE = -27


@JSONRPCError._register_subcls
class InWarmupError(JSONRPCError):
    RPC_ERROR_CODE = -28


def _try_read_conf_file(conf_file: Optional[str],
                        conf_file_contents: Optional[str],
                        allow_default_conf: bool
                        ) -> Dict[str, str]:
    assert ((conf_file is None) != (conf_file_contents is None))

    # Bitcoin Core accepts empty rpcuser,
    # not specified in conf_file
    conf = {'rpcuser': ""}

    section = ''

    def process_line(line: str) -> None:
        nonlocal section

        if '#' in line:
            line = line[:line.index('#')]

        line = line.strip()

        if not line:
            return

        if line[0] == '[' and line[-1] == ']':
            section = line[1:-1] + '.'
            return

        if '=' not in line:
            return

        k, v = line.split('=', 1)
        conf[f'{section}{k.strip()}'] = v.strip()

    if conf_file_contents is not None:
        buf = conf_file_contents
        while '\n' in buf:
            line, buf = buf.split('\n', 1)
            process_line(line)
        return conf

    assert conf_file is not None

    # Extract contents of bitcoin.conf to build service_url
    try:
        with open(conf_file, 'r') as fd:
            for line in fd.readlines():
                process_line(line)
    # Treat a missing bitcoin.conf as though it were empty
    except FileNotFoundError:
        if not allow_default_conf:
            # missing conf file is only allowed when allow_default_conf is True
            raise

    return conf


def split_hostport(hostport: str) -> Tuple[str, Optional[int]]:
    r = hostport.rsplit(':', maxsplit=1)
    if len(r) == 1:
        return (hostport, None)

    maybe_host, maybe_port = r

    if ':' in maybe_host:
        if not (maybe_host.startswith('[') and maybe_host.endswith(']')):
            return (hostport, None)

    if not maybe_port.isdigit():
        return (hostport, None)

    port = int(maybe_port)
    if port > 0 and port < 0x10000:
        return (maybe_host, port)

    return (hostport, None)


class RPCCaller:
    __port: int
    __auth_header: Optional[str]

    def __init__(self,  # noqa
                 service_url: Optional[str] = None,
                 service_port: Optional[int] = None,
                 conf_file: Optional[str] = None,
                 conf_file_contents: Optional[str] = None,
                 allow_default_conf: bool = False,
                 timeout: int = DEFAULT_HTTP_TIMEOUT,
                 connection: Optional[HTTPClient_Type] = None) -> None:

        if (conf_file is not None) and (conf_file_contents is not None):
            raise ValueError(
                'Either conf_file or conf_file_contents must be specified, '
                'but not both')
        # Create a dummy connection early on so if __init__() fails prior to
        # __conn being created __del__() can detect the condition and handle it
        # correctly.
        self.__conn: Optional[HTTPClient_Type] = None
        authpair = None

        self.__timeout = timeout

        if service_url is None:
            params = bitcointx.get_current_chain_params()

            # Figure out the path to the config file
            if conf_file is None and conf_file_contents is None:
                if not allow_default_conf:
                    raise ValueError("if conf_file is not specified, "
                                     "allow_default_conf must be True")
                conf_file = params.get_config_path()

            conf = _try_read_conf_file(conf_file, conf_file_contents,
                                       allow_default_conf)

            if service_port is None:
                service_port = params.RPC_PORT

            extraname = params.get_datadir_extra_name()
            network_id = conf.get('chain', params.get_network_id())

            (host, port) = split_hostport(
                conf.get(f'{network_id}.rpcconnect',
                         conf.get('rpcconnect', 'localhost')))

            port = int(conf.get(f'{network_id}.rpcport',
                                conf.get('rpcport', port or service_port)))
            service_url = ('%s://%s:%d' % ('http', host, port))

            cookie_dir = conf.get(f'{network_id}.datadir',
                                  conf.get('datadir',
                                           None if conf_file is None
                                           else os.path.dirname(conf_file)))
            io_err = None
            if cookie_dir is not None:
                cookie_dir = os.path.join(cookie_dir, extraname)
                cookie_file = os.path.join(cookie_dir, ".cookie")
                try:
                    with open(cookie_file, 'r') as fd:
                        authpair = fd.read()
                except IOError as err:
                    io_err = err

            if authpair is None:
                if f'{network_id}.rpcpassword' in conf:
                    authpair = "%s:%s" % (
                        conf.get(f'{network_id}.rpcuser', ''),
                        conf[f'{network_id}.rpcpassword'])
                elif 'rpcpassword' in conf:
                    authpair = "%s:%s" % (conf.get('rpcuser', ''),
                                          conf['rpcpassword'])
                elif io_err is None:
                    raise ValueError(
                        'Cookie dir is not known and rpcpassword is not '
                        'specified in conf_file_contents')
                else:
                    raise ValueError(
                        'Cookie file unusable (%s) and rpcpassword '
                        'not specified in the configuration file: %r'
                        % (io_err, conf_file))
        else:
            url = urllib.parse.urlparse(service_url)
            authpair = "%s:%s" % (url.username, url.password)

        self.__service_url = service_url
        self.__url = urllib.parse.urlparse(service_url)

        if self.__url.scheme not in ('http',):
            raise ValueError('Unsupported URL scheme %r' % self.__url.scheme)

        if self.__url.port is None:
            self.__port = service_port or http.client.HTTP_PORT
        else:
            self.__port = self.__url.port

        self.__id_count = 0

        if authpair is None:
            self.__auth_header = None
        else:
            self.__auth_header = (
                "Basic " + base64.b64encode(
                    authpair.encode('utf8')).decode('utf8')
            )

        self.connect(connection=connection)

    def connect(self, connection: Optional[HTTPClient_Type] = None) -> None:
        if connection:
            self.__conn = connection
        else:
            self.__conn = http.client.HTTPConnection(
                self.__url.hostname or '', port=self.__port,
                timeout=self.__timeout)

    def _call(self, service_name: str, *args: Any) -> Any:

        if self.__conn is None:
            raise RuntimeError('connection is not configured')

        self.__id_count += 1

        postdata = json.dumps({'version': '1.1',
                               'method': service_name,
                               'params': args,
                               'id': self.__id_count},
                              cls=DecimalJSONEncoder)

        headers = {
            'Host': self.__url.hostname or '',
            'User-Agent': DEFAULT_USER_AGENT,
            'Content-type': 'application/json',
        }

        if self.__auth_header is not None:
            headers['Authorization'] = self.__auth_header

        self.__conn.request('POST', self.__url.path, postdata, headers)

        response = self._get_response()
        err = response.get('error')
        if err is not None:
            if isinstance(err, dict):
                raise JSONRPCError(
                    {'code': err.get('code', -345),
                     'message': err.get('message',
                                        'error message not specified')})
            raise JSONRPCError({'code': -344, 'message': str(err)})
        elif 'result' not in response:
            raise JSONRPCError({
                'code': -343, 'message': 'missing JSON-RPC result'})
        else:
            return response['result']

    def _batch(self, rpc_call_list: Iterable[Any]) -> Any:
        if self.__conn is None:
            raise RuntimeError('connection is not configured')

        postdata = json.dumps(list(rpc_call_list), cls=DecimalJSONEncoder)

        headers = {
            'Host': self.__url.hostname or '',
            'User-Agent': DEFAULT_USER_AGENT,
            'Content-type': 'application/json',
        }

        if self.__auth_header is not None:
            headers['Authorization'] = self.__auth_header

        self.__conn.request('POST', self.__url.path, postdata, headers)
        return self._get_response()

    def _get_response(self) -> Any:
        if self.__conn is None:
            raise RuntimeError('connection is not configured')

        http_response = self.__conn.getresponse()
        if http_response is None:
            raise JSONRPCError({
                'code': -342, 'message': 'missing HTTP response from server'})

        rdata = http_response.read().decode('utf8')
        try:
            return json.loads(rdata, parse_float=decimal.Decimal)
        except Exception:
            raise JSONRPCError({
                'code': -342,
                'message': ('non-JSON HTTP response with \'%i %s\' '
                            'from server: \'%.20s%s\''
                            % (http_response.status, http_response.reason,
                               rdata, '...' if len(rdata) > 20 else ''))})

    def close(self) -> None:
        if self.__conn is not None:
            self.__conn.close()

    def __del__(self) -> None:
        if self.__conn is not None:
            self.__conn.close()

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith('__') and name.endswith('__'):
            # Prevent RPC calls for non-existing python internal attribute
            # access. If someone tries to get an internal attribute
            # of RPCCaller instance, and the instance does not have this
            # attribute, we do not want the bogus RPC call to happen.
            raise AttributeError

        # Create a callable to do the actual call
        def f(*args: Any) -> Any:
            return self._call(name, *args)

        # Make debuggers show <function bitcointx.rpc.name>
        # rather than <function bitcointx.rpc.<lambda>>
        f.__name__ = name
        return f


__all__ = (
    'JSONRPCError',
    'ForbiddenBySafeModeError',
    'InvalidAddressOrKeyError',
    'InvalidParameterError',
    'VerifyError',
    'VerifyRejectedError',
    'VerifyAlreadyInChainError',
    'InWarmupError',
    'RPCCaller',
    'HTTPClient_Type',
    'DecimalJSONEncoder',
)
