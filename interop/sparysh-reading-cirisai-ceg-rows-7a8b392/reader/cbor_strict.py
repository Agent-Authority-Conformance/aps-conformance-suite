"""Strict CBOR decoding and deterministic re-encoding, written for this reading.

Decoding keeps what a generic decoder loses: map pairs in received order
(duplicates kept), tags, simple values, floats and indefinite lengths.
Deterministic encoding follows RFC 8949 Section 4.2.1 as the draft's CDE
reference fixes it: shortest heads, definite lengths, map keys sorted by
the bytewise order of their encodings.
"""
import struct


class DecodeError(Exception):
    pass


class Tag:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"


class Simple:
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Simple) and other.value == self.value

    def __hash__(self):
        return hash(("simple", self.value))

    def __repr__(self):
        return f"Simple({self.value})"


class Float:
    __slots__ = ("value", "width")

    def __init__(self, value, width):
        self.value, self.width = value, width

    def __repr__(self):
        return f"Float({self.value}, w={self.width})"


class Undefined:
    def __repr__(self):
        return "undefined"


UNDEFINED = Undefined()


class CMap:
    """A CBOR map as a list of (key, value) pairs in received order."""
    __slots__ = ("pairs", "indefinite")

    def __init__(self, pairs, indefinite=False):
        self.pairs, self.indefinite = pairs, indefinite

    def keys(self):
        return [k for k, _ in self.pairs]

    def get(self, key, default=None):
        ek = encode(key)
        for k, v in self.pairs:
            if encode(k) == ek:
                return v
        return default

    def has(self, key):
        ek = encode(key)
        return any(encode(k) == ek for k, _ in self.pairs)

    def __repr__(self):
        return "CMap(" + ", ".join(f"{k!r}: {v!r}" for k, v in self.pairs) + ")"


class CArray(list):
    indefinite = False


class CBytes(bytes):
    chunked = False


class CText(str):
    chunked = False


def decode(data):
    """Decode exactly one data item; trailing bytes are an error."""
    item, pos = _decode(memoryview(data), 0)
    if pos != len(data):
        raise DecodeError("trailing bytes")
    return item


def _head(buf, pos):
    if pos >= len(buf):
        raise DecodeError("truncated")
    ib = buf[pos]
    mt, ai = ib >> 5, ib & 31
    pos += 1
    if ai < 24:
        return mt, ai, ai, pos
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if pos + n > len(buf):
            raise DecodeError("truncated")
        val = int.from_bytes(buf[pos:pos + n], "big")
        return mt, ai, val, pos + n
    if ai == 31:
        return mt, ai, None, pos
    raise DecodeError("reserved additional info")


def _decode(buf, pos):
    mt, ai, val, pos = _head(buf, pos)
    if mt == 0:
        if val is None:
            raise DecodeError("indefinite int")
        return val, pos
    if mt == 1:
        if val is None:
            raise DecodeError("indefinite int")
        return -1 - val, pos
    if mt in (2, 3):
        if val is None:
            chunks = []
            while True:
                if pos >= len(buf):
                    raise DecodeError("truncated")
                if buf[pos] == 0xFF:
                    pos += 1
                    break
                cmt, cai, cval, pos = _head(buf, pos)
                if cmt != mt or cval is None:
                    raise DecodeError("bad chunk")
                if pos + cval > len(buf):
                    raise DecodeError("truncated")
                chunks.append(bytes(buf[pos:pos + cval]))
                pos += cval
            raw = b"".join(chunks)
            if mt == 2:
                out = CBytes(raw)
            else:
                out = CText(raw.decode("utf-8"))
            out.chunked = True
            return out, pos
        if pos + val > len(buf):
            raise DecodeError("truncated")
        raw = bytes(buf[pos:pos + val])
        pos += val
        if mt == 2:
            return CBytes(raw), pos
        try:
            return CText(raw.decode("utf-8")), pos
        except UnicodeDecodeError:
            raise DecodeError("invalid utf-8")
    if mt == 4:
        arr = CArray()
        if val is None:
            arr.indefinite = True
            while True:
                if pos >= len(buf):
                    raise DecodeError("truncated")
                if buf[pos] == 0xFF:
                    return arr, pos + 1
                item, pos = _decode(buf, pos)
                arr.append(item)
        for _ in range(val):
            item, pos = _decode(buf, pos)
            arr.append(item)
        return arr, pos
    if mt == 5:
        pairs = []
        if val is None:
            while True:
                if pos >= len(buf):
                    raise DecodeError("truncated")
                if buf[pos] == 0xFF:
                    return CMap(pairs, True), pos + 1
                k, pos = _decode(buf, pos)
                v, pos = _decode(buf, pos)
                pairs.append((k, v))
        for _ in range(val):
            k, pos = _decode(buf, pos)
            v, pos = _decode(buf, pos)
            pairs.append((k, v))
        return CMap(pairs), pos
    if mt == 6:
        if val is None:
            raise DecodeError("indefinite tag")
        item, pos = _decode(buf, pos)
        return Tag(val, item), pos
    # major type 7
    if ai < 24 or ai == 24:
        if val == 20:
            return False, pos
        if val == 21:
            return True, pos
        if val == 22:
            return None, pos
        if val == 23:
            return UNDEFINED, pos
        return Simple(val), pos
    if ai == 25:
        return Float(_half(val), 2), pos
    if ai == 26:
        return Float(struct.unpack(">f", val.to_bytes(4, "big"))[0], 4), pos
    if ai == 27:
        return Float(struct.unpack(">d", val.to_bytes(8, "big"))[0], 8), pos
    raise DecodeError("break outside indefinite item")


def _half(h):
    return struct.unpack(">e", h.to_bytes(2, "big"))[0]


def _enc_head(mt, n):
    if n < 24:
        return bytes([(mt << 5) | n])
    if n < 0x100:
        return bytes([(mt << 5) | 24, n])
    if n < 0x10000:
        return bytes([(mt << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(mt << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(mt << 5) | 27]) + n.to_bytes(8, "big")


def encode(item):
    """Deterministic encoding (RFC 8949 Section 4.2.1)."""
    if isinstance(item, bool):
        return b"\xf5" if item else b"\xf4"
    if item is None:
        return b"\xf6"
    if item is UNDEFINED:
        return b"\xf7"
    if isinstance(item, int):
        if item >= 0:
            return _enc_head(0, item)
        return _enc_head(1, -1 - item)
    if isinstance(item, (bytes, bytearray)):
        return _enc_head(2, len(item)) + bytes(item)
    if isinstance(item, str):
        raw = item.encode("utf-8")
        return _enc_head(3, len(raw)) + raw
    if isinstance(item, list):
        return _enc_head(4, len(item)) + b"".join(encode(x) for x in item)
    if isinstance(item, CMap):
        enc = [(encode(k), encode(v)) for k, v in item.pairs]
        enc.sort(key=lambda kv: kv[0])
        return _enc_head(5, len(enc)) + b"".join(k + v for k, v in enc)
    if isinstance(item, dict):
        enc = [(encode(k), encode(v)) for k, v in item.items()]
        enc.sort(key=lambda kv: kv[0])
        return _enc_head(5, len(enc)) + b"".join(k + v for k, v in enc)
    if isinstance(item, Tag):
        return _enc_head(6, item.tag) + encode(item.value)
    if isinstance(item, Simple):
        if item.value < 24:
            return bytes([0xE0 | item.value])
        return bytes([0xF8, item.value])
    if isinstance(item, Float):
        return _enc_float(item.value)
    raise TypeError(f"cannot encode {type(item)}")


def _enc_float(v):
    # shortest of half, single, double that preserves the value
    import math
    if math.isnan(v):
        return b"\xf9\x7e\x00"
    try:
        h = struct.pack(">e", v)
        if struct.unpack(">e", h)[0] == v:
            return b"\xf9" + h
    except OverflowError:
        pass
    f = struct.pack(">f", v)
    if struct.unpack(">f", f)[0] == v:
        return b"\xfa" + f
    return b"\xfb" + struct.pack(">d", v)


def has_duplicate_keys(m):
    seen = set()
    for k, _ in m.pairs:
        e = encode(k)
        if e in seen:
            return True
        seen.add(e)
    return False


def walk(item):
    """Yield every data item inside item, item included."""
    yield item
    if isinstance(item, list):
        for x in item:
            yield from walk(x)
    elif isinstance(item, CMap):
        for k, v in item.pairs:
            yield from walk(k)
            yield from walk(v)
    elif isinstance(item, Tag):
        yield from walk(item.value)


def is_deterministic(data):
    """True when data decodes and equals its deterministic re-encoding,
    with no duplicate map key and no float."""
    try:
        item = decode(data)
    except DecodeError:
        return False, None
    for x in walk(item):
        if isinstance(x, CMap) and has_duplicate_keys(x):
            return False, item
        if isinstance(x, Float):
            return False, item
    return encode(item) == bytes(data), item
