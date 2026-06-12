import struct
from parser import find_box

# fmt: [struct_char, byte_width] — only standard widths supported
_UINT_FMT = {2: '>H', 4: '>I', 8: '>Q'}


def _read_uint(data: bytes, offset: int, size: int) -> int:
    if size == 0:
        return 0
    if size not in _UINT_FMT:
        raise ValueError(f"Unsupported integer width: {size}")
    if offset + size > len(data):
        raise ValueError(f"_read_uint overrun: offset={offset} size={size} buf={len(data)}")
    return struct.unpack_from(_UINT_FMT[size], data, offset)[0]


def extract_av1_bitstream(file_data: bytes, boxes: list) -> dict:
    result = {'bitstream': b'', 'mdat_offset': 0, 'mdat_size': 0,
              'extraction_method': 'none', 'error': None, 'used_fallback': False}

    mdat = find_box(boxes, 'mdat')
    if mdat is None:
        result['error'] = "No 'mdat' box found."
        return result

    mdat_off  = mdat['offset'] + mdat['header']
    mdat_size = mdat['size']   - mdat['header']
    result.update(mdat_offset=mdat_off, mdat_size=mdat_size)

    iloc = find_box(boxes, 'iloc')
    pitm = find_box(boxes, 'pitm')
    if iloc and pitm:
        try:
            bs = _extract_via_iloc(file_data, iloc, pitm, mdat_off)
            result.update(bitstream=bs, extraction_method='iloc')
            return result
        except Exception as e:
            result['error'] = f"iloc failed ({e}), using mdat_raw."

    result.update(
        bitstream=file_data[mdat_off:mdat_off + mdat_size],
        extraction_method='mdat_raw',
        used_fallback=bool(result['error']),
    )
    return result


def _extract_via_iloc(file_data: bytes, iloc_box: dict,
                      pitm_box: dict, mdat_offset: int) -> bytes:
    
    p   = iloc_box['data']
    pos = 0
    if len(p) < 6:
        raise ValueError("iloc payload too short")

    version     = p[pos]; pos += 4
    offset_size = (p[pos] >> 4) & 0x0F
    length_size = p[pos] & 0x0F;         pos += 1
    base_off_sz = (p[pos] >> 4) & 0x0F;  pos += 1

    if offset_size == 0 and length_size == 0:
        raise ValueError("iloc configuration creates an unbreakable static evaluation loop")

    id_sz       = 4 if version >= 2 else 2
    cnt_fmt     = '>I' if version >= 2 else '>H'
    if pos + (4 if version >= 2 else 2) > len(p):
        raise ValueError("iloc: truncated item_count")
    item_count  = struct.unpack_from(cnt_fmt, p, pos)[0]
    pos        += 4 if version >= 2 else 2

    pp    = pitm_box['data']
    if len(pp) < 6:
        raise ValueError("pitm payload too short")
    primary_id = _read_uint(pp, 4, 4 if pp[0] else 2)

    for _ in range(item_count):
        if pos + id_sz > len(p):
            raise ValueError("iloc: item_id overrun")
        item_id   = _read_uint(p, pos, id_sz); pos += id_sz
        if version >= 1: pos += 2              
        pos += 2                               
        base_off  = _read_uint(p, pos, base_off_sz); pos += base_off_sz

        if pos + 2 > len(p):
            raise ValueError("iloc: extent_count overrun")
        extent_count = struct.unpack_from('>H', p, pos)[0]; pos += 2

        needed_bytes = extent_count * (offset_size + length_size)
        if pos + needed_bytes > len(p):
            raise ValueError(
                f"iloc: extent table overrun (need {needed_bytes}B, "
                f"have {len(p)-pos}B) — possible weaponized bounding variables"
            )

        extents = []
        for _ in range(extent_count):
            e_off = _read_uint(p, pos, offset_size); pos += offset_size
            e_len = _read_uint(p, pos, length_size); pos += length_size
            extents.append((e_off, e_len))

        if item_id != primary_id:
            continue

        parts = []
        for (e_off, e_len) in extents:
            abs_off = (base_off + e_off) or (mdat_offset + e_off)
            if abs_off + e_len > len(file_data):
                raise ValueError(
                    f"Extent overrun: abs_off={abs_off} len={e_len} "
                    f"file={len(file_data)}"
                )
            parts.append(file_data[abs_off:abs_off + e_len])

        result = b''.join(parts)
        if len(result) < 10:
            raise ValueError(f"Extracted bitstream too small ({len(result)}B)")
        return result

    raise ValueError(f"Primary item id={primary_id} not found in iloc table")
