"""RFC 3339 date-time: section 5.6 syntax plus section 5.7 calendar and range
validation, returning an exact ORDERING KEY. Not a complete RFC 3339
validator, see "Boundary".

    date-time      = full-date "T" full-time    ("T" and "Z" case-insensitive)
    full-time      = partial-time time-offset
    time-secfrac   = "." 1*DIGIT
    time-numoffset = ("+" / "-") time-hour ":" time-minute
    time-offset    = "Z" / time-numoffset

DIGIT is ASCII 0-9 only. The whole string must match (no trailing newline).

Range checks: year 0000-9999, month 01-12, day valid for month and leap
year, hour 00-23, minute 00-59, second 00-60, offset hour 00-23, offset
minute 00-59.

Ordering key: (utc_seconds, leap_flag, frac)
  utc_seconds  integer seconds since 0000-01-01T00:00:00Z in the proleptic
               Gregorian calendar, with the offset applied. Computed with
               integer arithmetic, no datetime, so year 0000 and every
               offset are in range.
  leap_flag    0, or 1 when second == 60. A leap second keys on the :59
               second of its minute with the flag set, so
               23:59:59.999... < 23:59:60 < next day 00:00:00.
  frac         the secfrac digit string with trailing zeros removed. Digit
               strings compare lexicographically, which is numeric order
               for decimal fractions, at any precision.

Boundary
- second == 60 is accepted SYNTACTICALLY. Section 5.7 restricts it to an
  actual leap second; occurrence is not checked against a leap-second table.
- "-00:00" is accepted per the 5.6 grammar and keyed as offset zero. RFC 9557
  unknown-local-offset semantics are not projected.

Returns None if the string is not an RFC 3339 date-time.
"""
import re

_RE = re.compile(
    r'([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})'
    r'(?:\.([0-9]+))?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))')


def _days_in_month(y, m):
    if m in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if m in (4, 6, 9, 11):
        return 30
    return 29 if ((y % 4 == 0 and y % 100 != 0) or y % 400 == 0) else 28


def _days_from_civil(y, m, d):
    """Days since 0000-03-01 shifted so that 0000-01-01 -> 0. Proleptic Gregorian."""
    y2 = y - (1 if m <= 2 else 0)
    era = y2 // 400
    yoe = y2 - era * 400
    mp = (m + 9) % 12
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe
    return days + 306  # 0000-01-01 is 306 days before 0000-03-01


def parse_rfc3339(s):
    if not isinstance(s, str):
        return None
    m = _RE.fullmatch(s)
    if not m:
        return None
    y, mo, d, h, mi, sec, frac, z, sign, oh, om = m.groups()
    y, mo, d, h, mi, sec = int(y), int(mo), int(d), int(h), int(mi), int(sec)
    if not (1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo)):
        return None
    if not (0 <= h <= 23 and 0 <= mi <= 59 and 0 <= sec <= 60):
        return None
    if z:
        off = 0
    else:
        oh, om = int(oh), int(om)
        if not (0 <= oh <= 23 and 0 <= om <= 59):
            return None
        off = (oh * 3600 + om * 60) * (-1 if sign == '-' else 1)
    leap = 1 if sec == 60 else 0
    local = _days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + (59 if leap else sec)
    return (local - off, leap, (frac or '').rstrip('0'))
