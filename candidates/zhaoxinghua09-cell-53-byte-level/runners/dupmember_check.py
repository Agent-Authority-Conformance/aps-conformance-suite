#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dupmember_check.py —— 序列化 JSON 重复成员名检测（字节级，转换前），Python 侧

对应草案 REQ-4.1-4：解析器必须在把对象转成普通 map 之前发现重复成员名，
且不得静默接受最后一次出现。

为什么单独做：json.loads(object_pairs_hook=...) 只能看见"已经解码成字符"的键，
且通常只覆盖被 hook 命中的对象；而草案要的是在字节流层面判，包括
`"a"` 与 `"\\u0061"` 这种解码后才相等的写法、以及代理对转义与真实字符的等价。
本实现手写词法扫描，不依赖任何 JSON 库，因此不会被库的"后者覆盖"策略掩盖。

判三个结果：
  ACCEPT           结构合法、同一对象内无重复成员名
  DUPLICATE_MEMBER 同一对象内出现重复成员名（含解码后相等）
  NOT_JSON         词法/结构非法（必须先失败闭合，不得当成"无重复"放行）

用法：
  python dupmember_check.py --vectors <path>
  python dupmember_check.py --json [--vectors <path>]
"""
from __future__ import annotations
import json, os, sys, argparse

WS = " \t\r\n"


def _hex4(s, i):
    if i + 4 > len(s):
        raise ValueError("NOT_JSON:truncated-escape")
    h = s[i:i + 4]
    for ch in h:
        if ch not in "0123456789abcdefABCDEF":
            raise ValueError("NOT_JSON:bad-hex")
    return int(h, 16), i + 4


def _string(s, i):
    """s[i] 必须是开引号；返回 (解码后的字符串, 末端下标)"""
    if i >= len(s) or s[i] != '"':
        raise ValueError("NOT_JSON:expected-string")
    i += 1
    out = []
    while True:
        if i >= len(s):
            raise ValueError("NOT_JSON:unterminated-string")
        ch = s[i]
        if ch == '"':
            return "".join(out), i + 1
        if ch == "\\":
            if i + 1 >= len(s):
                raise ValueError("NOT_JSON:unterminated-escape")
            e = s[i + 1]
            if e == "u":
                cp, i = _hex4(s, i + 2)
                if 0xD800 <= cp <= 0xDBFF:
                    # 高代理：必须跟一个低代理转义，否则不是合法 JSON 标量
                    if i + 1 < len(s) and s[i] == "\\" and s[i + 1] == "u":
                        lo, j = _hex4(s, i + 2)
                        if not (0xDC00 <= lo <= 0xDFFF):
                            raise ValueError("NOT_JSON:lone-surrogate")
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                        i = j
                    else:
                        raise ValueError("NOT_JSON:lone-surrogate")
                elif 0xDC00 <= cp <= 0xDFFF:
                    raise ValueError("NOT_JSON:lone-surrogate")
                out.append(chr(cp))
                continue
            simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
            if e not in simple:
                raise ValueError("NOT_JSON:bad-escape")
            out.append(simple[e])
            i += 2
            continue
        if ord(ch) < 0x20:
            raise ValueError("NOT_JSON:raw-control-in-string")
        out.append(ch)
        i += 1


def _value(s, i, depth, found):
    if depth > 200:
        raise ValueError("NOT_JSON:too-deep")
    while i < len(s) and s[i] in WS:
        i += 1
    if i >= len(s):
        raise ValueError("NOT_JSON:eof")
    ch = s[i]
    if ch == "{":
        return _object(s, i, depth, found)
    if ch == "[":
        return _array(s, i, depth, found)
    if ch == '"':
        return _string(s, i)
    if ch in "-0123456789":
        return _number(s, i)
    for lit, rep in (("true", True), ("false", False), ("null", None)):
        if s.startswith(lit, i):
            return rep, i + len(lit)
    raise ValueError("NOT_JSON:unexpected-char")


def _number(s, i):
    start = i
    if i < len(s) and s[i] == "-":
        i += 1
    if i >= len(s) or s[i] not in "0123456789":
        raise ValueError("NOT_JSON:bad-number")
    if s[i] == "0":
        i += 1
        if i < len(s) and s[i] in "0123456789":
            raise ValueError("NOT_JSON:leading-zero")
    else:
        while i < len(s) and s[i] in "0123456789":
            i += 1
    if i < len(s) and s[i] == ".":
        i += 1
        if i >= len(s) or s[i] not in "0123456789":
            raise ValueError("NOT_JSON:bad-fraction")
        while i < len(s) and s[i] in "0123456789":
            i += 1
    if i < len(s) and s[i] in "eE":
        i += 1
        if i < len(s) and s[i] in "+-":
            i += 1
        if i >= len(s) or s[i] not in "0123456789":
            raise ValueError("NOT_JSON:bad-exponent")
        while i < len(s) and s[i] in "0123456789":
            i += 1
    return s[start:i], i


def _array(s, i, depth, found):
    i += 1
    while i < len(s) and s[i] in WS:
        i += 1
    if i < len(s) and s[i] == "]":
        return [], i + 1
    out = []
    while True:
        v, i = _value(s, i, depth + 1, found)
        out.append(v)
        while i < len(s) and s[i] in WS:
            i += 1
        if i >= len(s):
            raise ValueError("NOT_JSON:eof-in-array")
        if s[i] == ",":
            i += 1
            continue
        if s[i] == "]":
            return out, i + 1
        raise ValueError("NOT_JSON:expected-comma-or-close")


def _object(s, i, depth, found):
    i += 1
    keys = set()
    first = True
    while True:
        while i < len(s) and s[i] in WS:
            i += 1
        if i >= len(s):
            raise ValueError("NOT_JSON:eof-in-object")
        if s[i] == "}":
            if not first:
                raise ValueError("NOT_JSON:trailing-comma")
            return {}, i + 1
        if not first:
            if s[i] != ",":
                raise ValueError("NOT_JSON:expected-comma")
            i += 1
            while i < len(s) and s[i] in WS:
                i += 1
            if i < len(s) and s[i] == "}":
                raise ValueError("NOT_JSON:trailing-comma")
        key, i = _string(s, i)
        if key in keys:
            found.add("DUPLICATE_MEMBER")
        keys.add(key)
        while i < len(s) and s[i] in WS:
            i += 1
        if i >= len(s) or s[i] != ":":
            raise ValueError("NOT_JSON:expected-colon")
        i += 1
        v, i = _value(s, i, depth + 1, found)
        first = False
        while i < len(s) and s[i] in WS:
            i += 1
        if i >= len(s):
            raise ValueError("NOT_JSON:eof-in-object")
        if s[i] == "}":
            return {}, i + 1
        if s[i] != ",":
            raise ValueError("NOT_JSON:expected-comma-or-close")


def decide(case):
    text = case["input"]
    found = set()
    try:
        _, i = _value(text, 0, 0, found)
        while i < len(text) and text[i] in WS:
            i += 1
        if i != len(text):
            raise ValueError("NOT_JSON:trailing-content")
    except ValueError as e:
        code = str(e).split(":", 1)[0]
        return {"id": case["id"], "got": "NOT_JSON", "reasons": [str(e)[:60]], "ok": case["expect"] == "NOT_JSON"}
    if found:
        return {"id": case["id"], "got": "DUPLICATE_MEMBER", "reasons": ["DUPLICATE_MEMBER"],
                "ok": case["expect"] == "DUPLICATE_MEMBER", "duplicate_anywhere": True}
    return {"id": case["id"], "got": "ACCEPT", "reasons": ["ACCEPT"], "ok": case["expect"] == "ACCEPT"}


ALIAS = "dup-member.json"


def resolve(a):
    here = os.path.dirname(os.path.abspath(__file__))
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "dup_vectors.json"),
             os.path.join(os.path.dirname(here), "vectors", ALIAS)]
    return next(p for p in cand if p and os.path.isfile(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    vec = resolve(a)
    cases = json.load(open(vec, encoding="utf-8"))["cases"]
    rows = [decide(c) for c in cases]
    ok = all(r["ok"] for r in rows)
    if a.json:
        print(json.dumps({"rows": rows, "verdict": "PASS" if ok else "FAIL",
                          "passed": sum(1 for r in rows if r["ok"]), "total": len(rows)}, ensure_ascii=False))
        return 0 if ok else 1
    for r in rows:
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(30) + r["got"])
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), sum(1 for r in rows if r["ok"]),
                                         sum(1 for r in rows if not r["ok"])))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
