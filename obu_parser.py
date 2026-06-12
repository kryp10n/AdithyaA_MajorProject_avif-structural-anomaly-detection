import os

_OBU_NAMES = {
    1:'Sequence Header', 2:'Temporal Delimiter', 3:'Frame Header',
    4:'Tile Group',      5:'Metadata',           6:'Frame',
    7:'Redundant Frame Header', 8:'Tile List',   15:'Padding',
}
_OBU_SHORT = {
    1:'seq_hdr', 2:'temp_delim', 3:'frame_hdr', 4:'tile_grp',
    5:'metadata', 6:'frame',     7:'redund_fhdr', 8:'tile_list', 15:'padding',
}
_RESERVED_RANGE = range(9, 15)


def _leb128(data: bytes, offset: int) -> tuple[int, int]:
    val, shift = 0, 0
    for i in range(8):
        if offset + i >= len(data):
            raise ValueError(f"Truncated LEB128 at offset {offset}")
        b    = data[offset + i]
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i + 1
        shift += 7
    raise ValueError(f"LEB128 exceeds 8-byte limit at offset {offset}")


def parse_obus(bitstream: bytes) -> list:
    obus, offset, idx = [], 0, 1
    while offset < len(bitstream):
        start = offset
        if offset >= len(bitstream): break

        hb             = bitstream[offset]; offset += 1
        forbidden      = (hb >> 7) & 1
        obu_type       = (hb >> 3) & 0x0F
        has_ext        = bool((hb >> 2) & 1)
        has_size       = bool((hb >> 1) & 1)
        tid = sid      = 0
        error          = "forbidden_zero_bit set" if forbidden else None
        is_reserved    = obu_type in _RESERVED_RANGE

        if is_reserved:
            error = (error + "; " if error else "") + \
                    f"reserved OBU type {obu_type} (9–14): requires investigation"

        if has_ext:
            if offset >= len(bitstream):
                offset = len(bitstream)
                continue
            eb  = bitstream[offset]; offset += 1
            tid = (eb >> 5) & 0x07
            sid = (eb >> 3) & 0x03

        if has_size:
            try:
                payload_size, n = _leb128(bitstream, offset)
                offset += n
            except ValueError as e:
                obus.append(_obu_dict(idx, obu_type, start, offset-start,
                                      0, has_ext, tid, sid,
                                      bitstream[start:offset], str(e),
                                      is_reserved, not has_size))
                idx += 1
                break
        else:
            payload_size = len(bitstream) - offset

        if offset + payload_size > len(bitstream):
            error = (error + "; " if error else "") + \
                    f"payload overrun (claimed {payload_size}B, " \
                    f"available {len(bitstream)-offset}B)"

        p_end   = min(offset + payload_size, len(bitstream))
        raw     = bitstream[start:p_end]
        obus.append(_obu_dict(idx, obu_type, start, offset-start,
                              p_end-offset, has_ext, tid, sid, raw, error,
                              is_reserved, not has_size))
        idx    += 1
        offset  = p_end
        if not has_size: break

    return obus


def _obu_dict(idx, obu_type, offset, hdr_sz, payload_sz,
              has_ext, tid, sid, raw, error, is_reserved=False, no_size_field=False):
    return {
        'index':          idx,
        'obu_type':       obu_type,
        'type_name':      _OBU_NAMES.get(obu_type, f'Unknown({obu_type})'),
        'offset':         offset,
        'header_size':    hdr_sz,
        'payload_size':   payload_sz,
        'total_size':     hdr_sz + payload_sz,
        'has_extension':  has_ext,
        'temporal_id':    tid,
        'spatial_id':     sid,
        'raw_bytes':      raw,
        'error':          error,
        'is_reserved':    is_reserved,
        'no_size_field':  no_size_field,
    }


def extract_obus_to_disk(obus: list, output_dir: str) -> list:
    os.makedirs(output_dir, exist_ok=True)
    saved = []
    for o in obus:
        short = _OBU_SHORT.get(o['obu_type'], f"type{o['obu_type']}")
        fname = f"obu_{o['index']}_{short}.bin"
        fpath = os.path.join(output_dir, fname)
        try:
            fpath.encode()
            with open(fpath, 'wb') as f: f.write(o['raw_bytes'])
            saved.append({'index': o['index'], 'filename': fname, 'filepath': fpath,
                          'size': len(o['raw_bytes']), 'type_name': o['type_name'], 'error': None})
        except OSError as e:
            saved.append({'index': o['index'], 'filename': fname, 'filepath': fpath,
                          'size': 0, 'type_name': o['type_name'], 'error': str(e)})
    return saved


def decode_sequence_header_basic(obu: dict) -> dict:
    res = {'seq_profile': None, 'still_picture': None, 'reduced_still_picture_header': None}
    payload = obu['raw_bytes'][obu['header_size']:]
    if not payload:
        return res

    window_bytes = payload[:8]
    window       = int.from_bytes(window_bytes.ljust(8, b'\x00'), 'big')
    capacity     = len(window_bytes) * 8
    cursor       = 0

    def read_bits(n: int) -> int | None:
        nonlocal cursor
        if cursor + n > capacity:
            return None
        shift = 64 - cursor - n
        val   = (window >> shift) & ((1 << n) - 1)
        cursor += n
        return val

    sp  = read_bits(3)
    stp = read_bits(1)
    rsp = read_bits(1)

    if sp  is not None: res['seq_profile']                  = sp
    if stp is not None: res['still_picture']                = bool(stp)
    if rsp is not None: res['reduced_still_picture_header'] = bool(rsp)
    return res
