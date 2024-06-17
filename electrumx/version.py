__version__ = "1.5.0.2"
electrumx_version = f"ElectrumX {__version__}"
electrumx_version_short = __version__

__aip__ = [1, 3]
aip_implemented = __aip__


def get_server_info():
    return {
        "aip_implemented": aip_implemented,
        "version": electrumx_version_short,
    }
