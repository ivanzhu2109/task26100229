import ipaddress

from terramesh.model import Protocol
from terramesh.region import Region, subtract


def test_size_tcp_includes_ports():
    region = Region(Protocol.TCP, 0, 1, 0, 3, 80, 82)
    assert region.size() == 2 * 4 * 3


def test_size_icmp_has_no_port_dimension():
    region = Region(Protocol.ICMP, 0, 1, 0, 3)
    assert region.size() == 2 * 4


def test_subtract_disjoint_returns_original():
    region = Region(Protocol.TCP, 0, 3, 0, 3, 0, 9)
    other = Region(Protocol.TCP, 10, 20, 0, 3, 0, 9)
    assert subtract(region, [other]) == [region]


def test_subtract_other_protocol_is_noop():
    region = Region(Protocol.TCP, 0, 3, 0, 3, 0, 9)
    other = Region(Protocol.UDP, 0, 3, 0, 3, 0, 9)
    assert subtract(region, [other]) == [region]


def test_subtract_fully_covered_returns_empty():
    region = Region(Protocol.TCP, 0, 3, 0, 3, 0, 9)
    assert subtract(region, [region]) == []


def test_subtract_partial_cover_preserves_size_and_disjointness():
    region = Region(Protocol.TCP, 0, 9, 0, 9, 0, 9)
    cut = Region(Protocol.TCP, 2, 5, 3, 4, 1, 8)
    pieces = subtract(region, [cut])
    assert sum(p.size() for p in pieces) == region.size() - cut.size()
    for piece in pieces:
        assert piece._intersect(cut) is None


def test_subtract_multiple_others():
    region = Region(Protocol.UDP, 0, 9, 0, 0, 0, 0)
    a = Region(Protocol.UDP, 0, 3, 0, 0, 0, 0)
    b = Region(Protocol.UDP, 6, 9, 0, 0, 0, 0)
    pieces = subtract(region, [a, b])
    assert sum(p.size() for p in pieces) == 2


def test_first_packet():
    region = Region(Protocol.TCP, 0x0A000000, 0x0A0000FF, 0xC0000200, 0xC00002FF, 80, 81)
    packet = region.first_packet()
    assert packet.protocol is Protocol.TCP
    assert packet.source == ipaddress.IPv4Address("10.0.0.0")
    assert packet.destination == ipaddress.IPv4Address("192.0.2.0")
    assert packet.port == 80


def test_first_packet_icmp_has_no_port():
    region = Region(Protocol.ICMP, 0, 1, 0, 1)
    assert region.first_packet().port is None
