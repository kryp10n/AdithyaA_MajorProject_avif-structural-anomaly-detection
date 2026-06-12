from parser import find_all_boxes, flatten_boxes

W = {
    'no_ftyp':                2.0, 'duplicate_ftyp':         1.0,
    'wrong_brand':            1.5, 'ftyp_not_first':         1.0,
    'no_meta':                2.0, 'no_mdat':                3.0,
    'multiple_mdat':          1.0, 'suspicious_mdat_size':   1.0,
    'unusual_box_order':      0.5,
    'no_seq_hdr':             3.0, 'multiple_seq_hdr':       2.0,
    'no_frame':               2.5, 'obu_forbidden_bit':      2.0,
    'abnormal_obu_order':     1.5, 'tiny_obu':               0.5,
    'gigantic_obu':           1.0, 'obu_parse_error':        1.5,
    'no_obus':                3.0, 'bitstream_too_small':    1.5,
    'container_bs_gap':       1.0,
    'reserved_obu_type':            2.0,
    'iloc_fallback_used':           1.5,
    'cross_layer_still_mismatch':   2.0,
}


def analyze(file_data: bytes, boxes: list, ftyp_info: dict,
            bitstream_info: dict, obus: list) -> dict:
    c_findings = (
        _rule_ftyp(boxes, ftyp_info) +
        _rule_box_presence(boxes) +
        _rule_box_order(boxes) +
        _rule_mdat(boxes, file_data, bitstream_info)
    )
    k_findings = (
        _rule_bitstream_size(bitstream_info) +
        _rule_obus(obus, bitstream_info)
    )
    x_findings = _rule_cross(boxes, bitstream_info, obus)

    c_score = min(sum(a['weight'] for a in c_findings), 4.0)
    k_score = min(sum(a['weight'] for a in k_findings), 4.0)
    x_score = sum(a['weight'] for a in x_findings)
    score   = min(round(c_score + k_score + x_score, 2), 10.0)
    cls     = 'Highly Suspicious' if score >= 5.0 else ('Suspicious' if score >= 2.5 else 'Normal')
    all_f   = c_findings + k_findings + x_findings
    summary = ('No anomalies detected. File appears well-formed.' if not all_f else
               f"{len(all_f)} anomaly/anomalies detected. Risk: {score}/10. {cls}.")
    return {'anomalies': all_f, 'risk_score': score, 'classification': cls, 'summary': summary}


def _rule_ftyp(boxes, ftyp_info):
    out, top = [], [b['type'] for b in boxes]
    ftypes = [t for t in top if t == 'ftyp']
    if not ftypes:
        return [_f('no_ftyp', 'Missing ftyp box',
                   'Every ISOBMFF file must begin with an ftyp box. Absence indicates structural anomaly.')]
    if len(ftypes) > 1:
        out.append(_f('duplicate_ftyp', f'Duplicate ftyp boxes ({len(ftypes)})',
                      'Only one ftyp box is permitted. Multiple instances require investigation.'))
    if ftyp_info and not ftyp_info.get('is_avif'):
        brands = [ftyp_info.get('major_brand','')] + ftyp_info.get('compatible_brands',[])
        out.append(_f('wrong_brand', f"AVIF brand absent (major: '{ftyp_info.get('major_brand','?')}')",
                      f"Brand list {brands} contains no 'avif'/'avis' marker. "
                      "File may not be a valid AVIF container."))
    return out


def _rule_box_presence(boxes):
    from parser import find_box
    out = []
    if not find_box(boxes, 'meta'):
        out.append(_f('no_meta', "Missing 'meta' box",
                      "The 'meta' box is required in AVIF. Its absence is a structural anomaly."))
    if not find_box(boxes, 'mdat'):
        out.append(_f('no_mdat', "Missing 'mdat' box",
                      "No media data box found. AV1 image data cannot be located."))
    return out


def _rule_box_order(boxes):
    out = []
    top_types = [b['type'] for b in boxes]
    if top_types and top_types[0] != 'ftyp':
        out.append(_f('ftyp_not_first', f"ftyp is not first box (found '{top_types[0]}')",
                      "ISO 14496-12 §4.3 requires ftyp before any variable-length box. "
                      "Non-standard ordering requires investigation."))
    mi = next((i for i,t in enumerate(top_types) if t=='meta'), None)
    di = next((i for i,t in enumerate(top_types) if t=='mdat'), None)
    if mi is not None and di is not None and di < mi:
        out.append(_f('unusual_box_order', "mdat precedes meta box",
                      "Standard ordering places meta before mdat. "
                      "Reversed layout is a non-standard modification."))
    return out


def _rule_mdat(boxes, file_data, bs_info):
    out, mdats = [], find_all_boxes(boxes, 'mdat')
    if len(mdats) > 1:
        out.append(_f('multiple_mdat', f"Multiple mdat boxes ({len(mdats)})",
                      "AVIF still images should have exactly one mdat box. Multiple instances require investigation."))
    if mdats:
        sz, fsz = bs_info.get('mdat_size', 0), len(file_data)
        if 0 < sz < 32:
            out.append(_f('suspicious_mdat_size', f"mdat payload unusually small ({sz}B)",
                          f"A valid AV1 bitstream requires at least a Sequence Header (>10B). {sz}B is insufficient."))
        elif fsz > 0 and sz > fsz * 0.999:
            out.append(_f('suspicious_mdat_size', "mdat consumes virtually entire file",
                          "No room for metadata alongside mdat. Container structure is non-standard."))
    return out


def _rule_bitstream_size(bs_info):
    sz = len(bs_info.get('bitstream', b''))
    if sz == 0:
        return [_f('bitstream_too_small', 'AV1 bitstream empty',
                   'No AV1 data extracted. Decoding is impossible.', 'Codec')]
    if sz < 10:
        return [_f('bitstream_too_small', f'AV1 bitstream abnormally small ({sz}B)',
                   'Minimal Sequence Header alone is ≥10B. Bitstream is incomplete.', 'Codec')]
    return []


def _rule_obus(obus, bs_info):
    if not obus:
        return [_f('no_obus', 'No OBUs parsed',
                   'Bitstream yielded no OBUs. Data may be encrypted, obfuscated, or corrupt.',
                   'Codec')]
    out  = []
    types = [o['obu_type'] for o in obus]
    seq_n = types.count(1)
    has_frame = any(t in (3, 6) for t in types)
    mean_sz   = sum(o['total_size'] for o in obus) / len(obus)

    if seq_n == 0:
        out.append(_f('no_seq_hdr', 'No Sequence Header OBU',
                      'AV1 requires a Sequence Header before any frame data. Absence is a structural anomaly.',
                      'Codec'))
    elif seq_n > 1:
        out.append(_f('multiple_seq_hdr', f'Multiple Sequence Headers ({seq_n})',
                      f'{seq_n} Sequence Header OBUs found. A single still image should contain exactly one.',
                      'Codec'))
    if not has_frame:
        out.append(_f('no_frame', 'No Frame or Frame Header OBU',
                      'Bitstream contains no decodable frame data. Image reconstruction is impossible.',
                      'Codec'))

    if seq_n > 0 and has_frame:
        fi_seq   = next((i for i,t in enumerate(types) if t==1), None)
        fi_frame = next((i for i,t in enumerate(types) if t in (3,6)), None)
        if fi_seq is not None and fi_frame is not None and fi_seq > fi_frame:
            out.append(_f('abnormal_obu_order', 'Frame OBU precedes Sequence Header',
                          'AV1 requires Sequence Header before frame data. '
                          'This ordering is a structural anomaly.',
                          'Codec'))

    for o in obus:
        err = o.get('error') or ''
        if 'forbidden' in err:
            out.append(_f('obu_forbidden_bit', f"OBU #{o['index']}: forbidden_zero_bit set",
                          'First OBU header bit must be 0 per AV1 spec. Set bit indicates header corruption.',
                          'Codec'))
        elif err:
            out.append(_f('obu_parse_error', f"OBU #{o['index']}: {err}",
                          'Parse error encountered. Bitstream may be malformed or non-standard.',
                          'Codec'))
        if o['obu_type'] != 2 and o['payload_size'] < 2:
            out.append(_f('tiny_obu', f"OBU #{o['index']} ({o['type_name']}): {o['payload_size']}B payload",
                          'Near-empty OBU payload (excluding Temporal Delimiter) requires investigation.',
                          'Codec'))
        if mean_sz > 0 and o['total_size'] > mean_sz * 10 and o['total_size'] > 102400:
            out.append(_f('gigantic_obu',
                          f"OBU #{o['index']} ({o['type_name']}): {o['total_size']}B "
                          f"({o['total_size']/mean_sz:.1f}× mean)",
                          'OBU is significantly larger than peers. Requires investigation.',
                          'Codec'))
        if o.get('is_reserved'):
            out.append(_f('reserved_obu_type',
                          f"OBU #{o['index']}: reserved type {o['obu_type']} (range 9–14)",
                          'OBU types 9–14 are undefined in the AV1 specification. '
                          'Presence of reserved types is an anti-forensic indicator '
                          'and may represent data-smuggling or intentional obfuscation.',
                          'Anti-Forensic'))
    return out


def _rule_cross(boxes, bs_info, obus):
    out = []
    mdat_sz = bs_info.get('mdat_size', 0)
    bs_sz   = len(bs_info.get('bitstream', b''))

    if bs_info.get('extraction_method') == 'iloc' and mdat_sz > 0 and bs_sz > 0:
        gap = mdat_sz - bs_sz
        if gap > bs_sz * 0.1:
            out.append(_f('container_bs_gap',
                          f"mdat ({mdat_sz}B) vs primary item ({bs_sz}B): {gap}B gap",
                          'Extra bytes beyond iloc-declared item extents require investigation.',
                          'Cross-Layer'))

    if bs_info.get('used_fallback'):
        out.append(_f('iloc_fallback_used',
                      'iloc extraction failed; mdat_raw fallback used',
                      f"iloc index parsing failed ({bs_info.get('error','')}). "
                      "Structural anomalies in the item location index required recovery "
                      "extraction from raw mdat. This may indicate index tampering or "
                      "non-standard modification.",
                      'Anti-Forensic'))

    from obu_parser import decode_sequence_header_basic
    seq_obus = [o for o in obus if o['obu_type'] == 1]
    for seq_obu in seq_obus:
        fields = decode_sequence_header_basic(seq_obu)
        still  = fields.get('still_picture')
        from parser import find_box
        has_moov = find_box(boxes, 'moov') is not None
        if still is False and not has_moov:
            out.append(_f('cross_layer_still_mismatch',
                          'Sequence Header still_picture=False in static AVIF container',
                          'The AV1 Sequence Header declares still_picture=False (animated), '
                          'but the container has no moov box and represents a static image. '
                          'This architectural discrepancy between codec and container layers '
                          'requires investigation.',
                          'Cross-Layer'))
            break

    return out


def _f(rule_id, title, explanation, category='Structural', weight=None) -> dict:
    return {'rule_id': rule_id, 'title': title, 'explanation': explanation,
            'category': category,
            'weight': W.get(rule_id, 1.0) if weight is None else weight}
