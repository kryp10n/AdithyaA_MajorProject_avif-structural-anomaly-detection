# AVIF Forensic Analyzer ⬡

A lightweight, byte-level desktop media forensics tool developed to perform deep-dive structural validation, bitstream extraction, and cross-layer anomaly heuristics on AVIF (AV1 Image File Format) images.

Instead of relying on abstract high-level imaging libraries (such as Pillow or OpenCV), this engine parses raw binary payloads directly against standard ISO/IEC 14496-12 (ISOBMFF) and AOMedia AV1 bitstream specifications to uncover anti-forensic indicators, data-smuggling vectors, or evasion payloads.

---

## Key Architecture Components

The implementation is modularly separated into five distinct forensic processing layers:

1. **`main.py` (App Entry Point):** Handles application execution and state initialization.
2. **`gui.py` (Presentation Layer):** Implements a responsive, thread-safe desktop UI. Uses an asynchronous background worker thread via Tkinter's `self.after(0, ...)` interface to prevent execution hangs during deep file reads.
3. **`parser.py` (Binary ISOBMFF Parser):** Recursively processes container structures, validates standard `ftyp` box brands, and tracks absolute box depth layers to isolate nesting-bomb denial-of-service exploits.
4. **`bitstream.py` (Dynamic Payload Extractor):** Maps raw media fragments by interpreting packed variable-length metadata fields (`iloc` and `pitm`). Features explicit bounds-checking and dynamic zero-stride loop shields to halt weaponized index offsets.
5. **`obu_parser.py` (AV1 OBU Bit-Decoder):** Implements a localized 64-bit sliding register window bitstream reader to safely extract unaligned payload bits (such as `seq_profile` and `still_picture`) directly across raw AV1 Open Bitstream Unit byte boundaries.
6. **`analyzer.py` (Heuristic Risk Engine):** An automated expert system that cross-examines outer container configurations against the underlying decoded bitstream attributes. Aggregates and classifies flagged anomalies into an analytical matrix covering **Structural, Codec, Cross-Layer,** and **Anti-Forensic** threat vectors.

---

## Container Layout Reference

The following diagram maps out how the analyzer untangles the multi-layered relationship between the outer ISOBMFF metadata file wrapper and the raw underlying media codec streams:

![ISOBMFF Box Layout Structure](iso%20bmff%20box.png)
