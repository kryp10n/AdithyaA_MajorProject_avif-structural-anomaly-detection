import struct

_CONTAINERS = {b'moov',b'trak',b'mdia',b'minf',b'stbl',b'udta',b'meta',
               b'ilst',b'dinf',b'edts',b'moof',b'traf',b'mfra',b'skip',
               b'sinf',b'rinf',b'schi',b'ipco',b'iprp',b'grpl'}
_FULLBOXES  = {b'meta',b'hdlr',b'pitm',b'ipma',b'ispe',b'colr'}


def parse_boxes(data: bytes, offset: int = 0, end: int = None, depth: int = 0) -> list:
    if end is None: end = len(data)
    boxes, MAX_DEPTH = [], 8
    while offset < end:
        if offset + 8 > end: break
        try:
            box_size_raw = struct.unpack_from('>I', data, offset)[0]
            box_type     = data[offset+4:offset+8]
        except struct.error:
            break

        hdr = 8
        if box_size_raw == 1:
            if offset + 16 > end: break
            box_size, hdr = struct.unpack_from('>Q', data, offset+8)[0], 16
        elif box_size_raw == 0:
            box_size = end - offset
        else:
            box_size = box_size_raw

        if box_size <= 0: break

        available    = end - offset
        truncated    = box_size > available
        actual_size  = min(box_size, available)

        if actual_size < hdr: break

        btype    = box_type.decode('latin-1', errors='replace')
        children = []
        if box_type in _CONTAINERS and depth < MAX_DEPTH:
            cs = offset + hdr + (4 if box_type in _FULLBOXES else 0)
            ce = offset + actual_size
            if cs < ce:
                children = parse_boxes(data, cs, ce, depth+1)

        boxes.append({
            'type': btype, 'offset': offset, 'size': actual_size,
            'declared_size': box_size, 'truncated': truncated,
            'header': hdr, 'data': data[offset+hdr:offset+actual_size],
            'children': children, 'depth': depth,
        })
        offset += actual_size
    return boxes


def find_box(boxes: list, t: str):
    for b in boxes:
        if b['type'] == t: return b
        r = find_box(b.get('children', []), t)
        if r: return r
    return None


def find_all_boxes(boxes: list, t: str) -> list:
    out = []
    for b in boxes:
        if b['type'] == t: out.append(b)
        out.extend(find_all_boxes(b.get('children', []), t))
    return out


def flatten_boxes(boxes: list) -> list:
    out = []
    for b in boxes:
        out.append({'type': b['type'], 'offset': b['offset'], 'size': b['size']})
        out.extend(flatten_boxes(b.get('children', [])))
    return out


def validate_ftyp(b: dict) -> dict:
    p = b.get('data', b'')
    if len(p) < 8:
        return {'major_brand':'','minor_version':0,'compatible_brands':[],'is_avif':False,'is_avis':False}
    major = p[0:4].decode('latin-1', errors='replace')
    compat = [p[i:i+4].decode('latin-1',errors='replace') for i in range(8,len(p),4) if i+4<=len(p)]
    all_brands = [major] + compat
    return {
        'major_brand': major,
        'minor_version': struct.unpack_from('>I', p, 4)[0],
        'compatible_brands': compat,
        'is_avif': 'avif' in all_brands,
        'is_avis': 'avis' in all_brands,
    }
