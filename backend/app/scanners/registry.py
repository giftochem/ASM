from app.scanners.base import ScannerModule
from app.scanners.dns_module import DNSModule
from app.scanners.headers_module import HeadersModule
from app.scanners.port_scanner_module import PortScannerModule
from app.scanners.ssl_module import SSLModule
from app.scanners.technology_module import TechnologyModule
from app.scanners.whois_module import WhoisModule

MODULE_REGISTRY: dict[str, ScannerModule] = {
    module.name: module
    for module in (
        WhoisModule(),
        DNSModule(),
        SSLModule(),
        TechnologyModule(),
        HeadersModule(),
        PortScannerModule(),
    )
}


def get_module(name: str) -> ScannerModule | None:
    return MODULE_REGISTRY.get(name)


def all_module_names() -> list[str]:
    return list(MODULE_REGISTRY.keys())
