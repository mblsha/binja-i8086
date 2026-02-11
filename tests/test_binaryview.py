from __future__ import annotations

from dataclasses import dataclass

from binja_i8086.binaryview import DosComBinaryView


@dataclass
class MockData:
    payload: bytes
    filename: str

    def __post_init__(self) -> None:
        self.file = type("MockFile", (), {"filename": self.filename})()
        self.start = 0

    def read(self, addr: int, length: int) -> bytes:
        chunk = self.payload[addr : addr + length]
        if len(chunk) < length:
            chunk += b"\x00" * (length - len(chunk))
        return chunk

    def __len__(self) -> int:
        return len(self.payload)


def test_is_valid_for_data_accepts_plain_com() -> None:
    data = MockData(b"\x90\x90", "sample.com")
    assert DosComBinaryView.is_valid_for_data(data) is True


def test_is_valid_for_data_rejects_non_com_or_exe_headers() -> None:
    assert DosComBinaryView.is_valid_for_data(MockData(b"\x90", "sample.bin")) is False
    assert DosComBinaryView.is_valid_for_data(MockData(b"MZ\x90\x00", "sample.com")) is False
    assert DosComBinaryView.is_valid_for_data(MockData(b"\xC9\x00", "sample.com")) is False


def test_init_creates_rwx_segment_and_sections() -> None:
    data = MockData(b"\x90\xC3\x00\x00", "test.com")
    bv = DosComBinaryView(data)

    assert bv.init() is True
    assert bv.perform_is_executable() is True
    assert bv.perform_get_entry_point() == 0x0100

    assert len(bv._segments) == 1
    seg = bv._segments[0]
    assert seg["start"] == 0x0100
    assert seg["length"] == len(data)

    names = [s["name"] for s in bv._sections]
    assert ".text" in names
    assert ".data" in names

    assert bv._navigations
    view_name, addr = bv._navigations[-1]
    assert view_name == "Linear:COM"
    assert addr == 0x0100
