from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("jwt-toolkit")
except PackageNotFoundError:
    __version__ = "1.4.0"
