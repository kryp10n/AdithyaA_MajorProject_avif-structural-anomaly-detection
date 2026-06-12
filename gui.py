import os, shutil, tempfile, threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import parser  as avif_parser
import bitstream as bs_module
import obu_parser, analyzer

BG   = '#1E2128'; PNL  = '#252932'; FG   = '#D4DAE8'; DIM  = '#7A8299'
ACC  = '#4ECDC4'; ACC2 = '#F7B731'; RED  = '#FF6B6B'; GRN  = '#A8E6CF'
BTN  = '#3A4150'
MONO = ('Courier New', 10); UI = ('Segoe UI', 10); HDR = ('Segoe UI', 11, 'bold')
BIG  = ('Segoe UI', 13, 'bold')


def truncate(v, n=60):
    s = str(v); return s if len(s) <= n else s[:n-3] + '...'


class _SText(tk.Frame):

    def __init__(self, parent, height=6, font=MONO, **kw):
        super().__init__(parent, bg=PNL)
        self.text = tk.Text(self, height=height, wrap=tk.WORD, state=tk.DISABLED,
                            bg=PNL, fg=FG, font=font, relief=tk.FLAT, padx=6, pady=4, **kw)
        sb = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def set(self, txt):
        self.text.configure(state=tk.NORMAL)
        self.text.delete('1.0', tk.END); self.text.insert(tk.END, txt)
        self.text.configure(state=tk.DISABLED)

    def append(self, txt, tag=None):
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, txt, (tag,) if tag else ())
        self.text.configure(state=tk.DISABLED); self.text.see(tk.END)


class _STable(tk.Frame):

    def __init__(self, parent, cols, col_widths=None, **kw):
        super().__init__(parent, bg=PNL)
        s = ttk.Style(); s.theme_use('clam')
        s.configure('F.Treeview', background=PNL, foreground=FG,
                    fieldbackground=PNL, rowheight=24, font=MONO)
        s.configure('F.Treeview.Heading', background=BG, foreground=ACC,
                    relief='flat', font=HDR)
        s.map('F.Treeview', background=[('selected', '#3A4F6A')])

        self.tree = ttk.Treeview(self, columns=cols, show='headings',
                                  style='F.Treeview', **kw)
        vsb = ttk.Scrollbar(self, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(0, weight=1)

        cw = col_widths or {}
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor='w', width=cw.get(c, 120))

    def clear(self):
        for i in self.tree.get_children(): self.tree.delete(i)

    def add(self, values, tag=None):
        kw = {'values': values}
        if tag: kw['tags'] = (tag,)
        self.tree.insert('', tk.END, **kw)

    def tag(self, name, **kw):
        self.tree.tag_configure(name, **kw)


class AVIFForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('AVIF Forensic Analyzer')
        self.geometry('1100x720'); self.minsize(900, 600)
        self.configure(bg=BG)
        self._filepath    = tk.StringVar()
        self._status_var  = tk.StringVar(value='No file loaded.')
        self._results     = {}
        self._obu_dir     = ''
        self.is_analyzing = False      # thread-safety state flag

        self._build_header()
        self._build_notebook()
        self._build_log_panels()
        self._build_statusbar()


    def _build_header(self):
        h = tk.Frame(self, bg=BG, pady=10); h.pack(fill=tk.X)
        tk.Label(h, text='⬡  AVIF FORENSIC ANALYZER', bg=BG, fg=ACC,
                 font=('Courier New', 16, 'bold')).pack(side=tk.LEFT, padx=20)
        ctrl = tk.Frame(h, bg=BG); ctrl.pack(side=tk.RIGHT, padx=20)
        self._btn_browse = tk.Button(ctrl, text='Browse File…', command=self._browse,
                                     bg=BTN, fg='white', activebackground=ACC,
                                     relief=tk.FLAT, padx=14, pady=6, font=UI, cursor='hand2')
        self._btn_analyze = tk.Button(ctrl, text='▶  Analyze', command=self._start,
                                      bg=ACC, fg=BG, activebackground='#38b2ac',
                                      relief=tk.FLAT, padx=14, pady=6,
                                      font=('Segoe UI', 10, 'bold'), cursor='hand2',
                                      state=tk.DISABLED)
        self._btn_browse.pack(side=tk.LEFT, padx=(0, 8))
        self._btn_analyze.pack(side=tk.LEFT)

        pf = tk.Frame(self, bg='#161920', pady=5); pf.pack(fill=tk.X)
        tk.Label(pf, text='File:', bg='#161920', fg=DIM, font=UI).pack(side=tk.LEFT, padx=12)
        tk.Label(pf, textvariable=self._filepath, bg='#161920', fg=ACC2,
                 font=MONO, anchor='w').pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _build_notebook(self):
        s = ttk.Style()
        s.configure('D.TNotebook', background=BG, borderwidth=0)
        s.configure('D.TNotebook.Tab', background=PNL, foreground=DIM,
                    padding=[14, 6], font=UI)
        s.map('D.TNotebook.Tab', background=[('selected', BG)], foreground=[('selected', ACC)])
        self._nb = ttk.Notebook(self, style='D.TNotebook')
        self._nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 0))

        tabs = ['📄  File Info', '📦  Container', '🔬  Bitstream / OBU',
                '💾  Extracted OBUs', '⚠️   Anomalies & Verdict']
        self._tabs = {}
        for title in tabs:
            f = tk.Frame(self._nb, bg=BG)
            self._nb.add(f, text=title)
            self._tabs[title] = f

        self._build_tab_fileinfo()
        self._build_tab_container()
        self._build_tab_bitstream()
        self._build_tab_extracted()
        self._build_tab_verdict()

    def _build_log_panels(self):
        pf = tk.Frame(self, bg=BG); pf.pack(fill=tk.X, padx=10, pady=(4, 0))
        pf.columnconfigure(0, weight=1); pf.columnconfigure(1, weight=1)
        for col, title, attr in ((0, 'Status Log', '_log_box'),
                                  (1, 'Explanation / Details', '_detail_box')):
            f = tk.Frame(pf, bg=BG); f.grid(row=0, column=col, sticky='nsew',
                                              padx=(0,4) if col==0 else (4,0))
            tk.Label(f, text=title, bg=BG, fg=ACC, font=HDR).pack(anchor='w')
            w = _SText(f, height=6); w.pack(fill=tk.BOTH, expand=True)
            setattr(self, attr, w)

    def _build_statusbar(self):
        b = tk.Frame(self, bg='#161920', pady=4); b.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(b, textvariable=self._status_var, bg='#161920', fg=DIM,
                 font=('Segoe UI', 9), anchor='w').pack(side=tk.LEFT, padx=12)

    # ------------------------------------------------------------------ #
    # File Info tab
    # ------------------------------------------------------------------ #

    def _build_tab_fileinfo(self):
        f = self._tabs['📄  File Info']
        self._fi = {}
        c = tk.Frame(f, bg=BG, padx=30, pady=20); c.pack(fill=tk.BOTH, expand=True)
        tk.Label(c, text='FILE INFORMATION', bg=BG, fg=ACC,
                 font=('Courier New', 13, 'bold')).grid(row=0, columnspan=2, sticky='w', pady=(0,16))
        fields = [('Filename','filename'),('Full Path','filepath'),('File Size','filesize'),
                  ('AVIF Brand','avif_brand'),('Major Brand','major_brand'),
                  ('Minor Version','minor_version'),('Compatible Brands','compat_brands'),
                  ('Validation','validation')]
        for i,(label,key) in enumerate(fields, 1):
            tk.Label(c, text=label+':', bg=BG, fg=DIM, font=UI,
                     anchor='e', width=22).grid(row=i, column=0, sticky='e', pady=4, padx=(0,12))
            var = tk.StringVar(value='—')
            lbl = tk.Label(c, textvariable=var, bg=BG, fg=FG, font=MONO, anchor='w')
            lbl.grid(row=i, column=1, sticky='w', pady=4)
            self._fi[key] = (var, lbl)
        c.columnconfigure(1, weight=1)

    def _update_fileinfo(self, filepath, ftyp_info, boxes):
        sz  = os.path.getsize(filepath)
        ok  = ftyp_info.get('is_avif', False)
        vals = {
            'filename': os.path.basename(filepath),
            'filepath': filepath,
            'filesize': f'{sz:,} bytes  ({sz/1024:.1f} KB)',
            'avif_brand': '✅ YES' if ok else '❌ NO',
            'major_brand': ftyp_info.get('major_brand','—'),
            'minor_version': str(ftyp_info.get('minor_version','—')),
            'compat_brands': '  '.join(ftyp_info.get('compatible_brands',[])) or '—',
            'validation': 'Valid AVIF container' if ok else 'NOT a valid AVIF file',
        }
        color = {True: GRN, False: RED}
        for key,(var,lbl) in self._fi.items():
            var.set(vals[key])
            if key in ('avif_brand','validation'):
                lbl.configure(fg=color[ok])

    # ------------------------------------------------------------------ #
    # Container tab
    # ------------------------------------------------------------------ #

    def _build_tab_container(self):
        f = self._tabs['📦  Container']
        tk.Label(f, text='ISOBMFF / HEIF Container Boxes', bg=BG, fg=ACC, font=BIG).pack(anchor='w', padx=16, pady=10)
        self._tbl_container = _STable(f,
            cols=('Box Type','Offset (bytes)','Size (bytes)','Declared','Truncated','Depth'),
            col_widths={'Box Type':160,'Offset (bytes)':140,'Size (bytes)':120,
                        'Declared':120,'Truncated':80,'Depth':60})
        self._tbl_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self._tbl_container.tag('accent', foreground=ACC2)
        self._tbl_container.tag('trunc',  foreground=RED)

    def _update_container(self, boxes):
        self._tbl_container.clear()
        def _add(bl, depth=0):
            for b in bl:
                tag = ('trunc' if b.get('truncated') else ('accent' if depth==0 else '')) or None
                self._tbl_container.add(
                    ('    '*depth + b['type'], b['offset'], f"{b['size']:,}",
                     f"{b.get('declared_size', b['size']):,}",
                     '⚠ YES' if b.get('truncated') else 'No', depth), tag=tag)
                _add(b.get('children',[]), depth+1)
        _add(boxes)

    # ------------------------------------------------------------------ #
    # Bitstream / OBU tab
    # ------------------------------------------------------------------ #

    def _build_tab_bitstream(self):
        f = self._tabs['🔬  Bitstream / OBU']
        self._bs_summary = tk.StringVar(value='No analysis yet.')
        sf = tk.Frame(f, bg=PNL, pady=8, padx=14); sf.pack(fill=tk.X, padx=10, pady=(10,4))
        tk.Label(sf, textvariable=self._bs_summary, bg=PNL, fg=FG, font=UI, justify='left').pack(anchor='w')
        tk.Label(f, text='AV1 Open Bitstream Units', bg=BG, fg=ACC, font=BIG).pack(anchor='w', padx=16, pady=6)
        self._tbl_obu = _STable(f,
            cols=('#','OBU Type','Code','Offset','Hdr','Payload','Total','Ext','Note'),
            col_widths={'#':40,'OBU Type':170,'Code':55,'Offset':90,'Hdr':55,
                        'Payload':80,'Total':70,'Ext':40,'Note':240})
        self._tbl_obu.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        for name, fg_color in (('seq',ACC),('frm',GRN),('err',RED)):
            self._tbl_obu.tag(name, foreground=fg_color)

    def _update_bitstream(self, bs_info, obus):
        self._bs_summary.set(
            f"Bitstream: {len(bs_info.get('bitstream',b'')):,}B  |  "
            f"Method: {bs_info.get('extraction_method','—')}  |  "
            f"OBUs: {len(obus)}  |  mdat: {bs_info.get('mdat_size',0):,}B")
        self._tbl_obu.clear()
        for o in obus:
            tag = ('seq' if o['obu_type']==1 else
                   'frm' if o['obu_type'] in (3,6) else
                   'err' if o.get('error') else None)
            self._tbl_obu.add(
                (o['index'], o['type_name'], o['obu_type'], o['offset'],
                 o['header_size'], o['payload_size'], o['total_size'],
                 'Y' if o['has_extension'] else 'N',
                 truncate(o.get('error') or '', 80)), tag=tag)

    # ------------------------------------------------------------------ #
    # Extracted OBUs tab
    # ------------------------------------------------------------------ #

    def _build_tab_extracted(self):
        f = self._tabs['💾  Extracted OBUs']
        self._ext_info = tk.StringVar(value='No OBUs extracted yet.')
        tk.Label(f, textvariable=self._ext_info, bg=BG, fg=FG, font=UI).pack(anchor='w', padx=16, pady=10)
        tk.Label(f, text='Extracted OBU Files', bg=BG, fg=ACC, font=BIG).pack(anchor='w', padx=16, pady=(0,6))
        self._tbl_ext = _STable(f,
            cols=('#','Filename','OBU Type','Size (bytes)','Status'),
            col_widths={'#':40,'Filename':280,'OBU Type':180,'Size (bytes)':110,'Status':200})
        self._tbl_ext.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self._tbl_ext.tag('ok',  foreground=GRN)
        self._tbl_ext.tag('err', foreground=RED)
        self._btn_folder = tk.Button(f, text='📂  Open Output Folder',
                                      command=self._open_folder,
                                      bg=BTN, fg='white', relief=tk.FLAT,
                                      padx=12, pady=6, font=UI,
                                      state=tk.DISABLED, cursor='hand2')
        self._btn_folder.pack(anchor='w', padx=16, pady=4)

    def _update_extracted(self, saved, obu_dir):
        self._obu_dir = obu_dir
        self._ext_info.set(f"{len(saved)} OBU file(s) saved to:  {obu_dir}")
        self._tbl_ext.clear()
        for s in saved:
            tag = 'err' if s['error'] else 'ok'
            self._tbl_ext.add(
                (s['index'], truncate(s['filename'],50), s['type_name'],
                 f"{s['size']:,}",
                 'OK' if not s['error'] else truncate(f"Error: {s['error']}",60)),
                tag=tag)
        self._btn_folder.configure(state=tk.NORMAL if saved else tk.DISABLED)

    def _open_folder(self):
        if not (self._obu_dir and os.path.isdir(self._obu_dir)): return
        import subprocess, sys
        {'win32': lambda: os.startfile(self._obu_dir),
         'darwin': lambda: subprocess.Popen(['open', self._obu_dir])
         }.get(sys.platform, lambda: subprocess.Popen(['xdg-open', self._obu_dir]))()

    # ------------------------------------------------------------------ #
    # Anomalies & Verdict tab
    # ------------------------------------------------------------------ #

    def _build_tab_verdict(self):
        f = self._tabs['⚠️   Anomalies & Verdict']
        sf = tk.Frame(f, bg=PNL, pady=14, padx=20); sf.pack(fill=tk.X, padx=10, pady=10)
        self._score_var = tk.StringVar(value='—')
        self._class_var = tk.StringVar(value='—')
        tk.Label(sf, text='Risk Score:',    bg=PNL, fg=DIM,  font=HDR).pack(side=tk.LEFT)
        self._score_lbl = tk.Label(sf, textvariable=self._score_var, bg=PNL, fg=ACC2,
                                   font=('Courier New', 20, 'bold'))
        self._score_lbl.pack(side=tk.LEFT, padx=12)
        tk.Label(sf, text='Classification:', bg=PNL, fg=DIM, font=HDR).pack(side=tk.LEFT, padx=(20,0))
        self._class_lbl = tk.Label(sf, textvariable=self._class_var, bg=PNL, fg=GRN,
                                   font=('Segoe UI', 14, 'bold'))
        self._class_lbl.pack(side=tk.LEFT, padx=12)

        self._summary_var = tk.StringVar()
        tk.Label(f, textvariable=self._summary_var, bg=BG, fg=FG,
                 font=UI, wraplength=900, justify='left').pack(anchor='w', padx=16, pady=(0,6))
        tk.Label(f, text='Detected Anomalies', bg=BG, fg=ACC, font=BIG).pack(anchor='w', padx=16, pady=4)

        self._tbl_anomaly = _STable(f,
            cols=('Rule ID','Category','Title','Weight','Explanation'),
            col_widths={'Rule ID':160,'Category':110,'Title':250,'Weight':55,'Explanation':430})
        self._tbl_anomaly.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        for name, fg_color in (('hi',RED),('med',ACC2),('lo',FG)):
            self._tbl_anomaly.tag(name, foreground=fg_color)
        self._tbl_anomaly.tree.bind('<<TreeviewSelect>>', self._on_anomaly_select)

    def _update_verdict(self, result):
        score, cls = result['risk_score'], result['classification']
        self._score_var.set(f"{score:.1f} / 10.0")
        self._class_var.set(cls)
        cls_fg = {'Highly Suspicious': RED, 'Suspicious': ACC2, 'Normal': GRN}.get(cls, FG)
        self._score_lbl.configure(fg=cls_fg)
        self._class_lbl.configure(fg=cls_fg)
        self._summary_var.set(result.get('summary',''))
        self._tbl_anomaly.clear()
        if not result['anomalies']:
            self._tbl_anomaly.add(('—','—','No anomalies detected.','—','File appears well-formed.'), tag='lo')
        else:
            for a in result['anomalies']:
                w        = a['weight']
                tag      = 'hi' if w >= 2.0 else ('med' if w >= 1.0 else 'lo')
                category = a.get('category', '—')
                self._tbl_anomaly.add(
                    (a['rule_id'], category, a['title'], f"{w:.1f}",
                     truncate(a['explanation'], 80)),
                    tag=tag)

    def _on_anomaly_select(self, _event):
        sel = self._tbl_anomaly.tree.selection()
        if not sel: return
        vals = self._tbl_anomaly.tree.item(sel[0])['values']
        if not vals or len(vals) < 5: return
        rid  = str(vals[0])
        full = next((a['explanation'] for a in self._results.get('anomalies',[])
                     if a['rule_id'] == rid), str(vals[4]))
        self._detail_box.set(full)

    # ------------------------------------------------------------------ #
    # Log / detail helpers
    # ------------------------------------------------------------------ #

    def _log(self, msg, level='INFO'):
        self._log_box.append(f'[{level}] {msg}\n',
                              tag=('err_tag' if level=='ERROR' else None))

    def _set_detail(self, txt):
        self._detail_box.set(txt)

    # ------------------------------------------------------------------ #
    # File / analysis controls
    # ------------------------------------------------------------------ #

    def _browse(self):
        path = filedialog.askopenfilename(
            title='Select AVIF File',
            filetypes=[('AVIF Images','*.avif *.AVIF'),('All Files','*.*')])
        if path:
            self._filepath.set(path)
            self._btn_analyze.configure(state=tk.NORMAL)
            self._status_var.set(f'File selected: {os.path.basename(path)}')
            self._nb.select(0)

    def _start(self):
        if self.is_analyzing:           # thread-safety guard
            messagebox.showinfo('Busy', 'Analysis already running. Please wait.')
            return
        path = self._filepath.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Please select a valid AVIF file first.')
            return
        self.is_analyzing = True
        self._btn_analyze.configure(state=tk.DISABLED, text='Analyzing…')
        self._btn_browse.configure(state=tk.DISABLED)
        self._status_var.set('Running analysis…')
        threading.Thread(target=self._worker, args=(path,), daemon=True).start()

    def _worker(self, path):
        try:
            self._run(path)
        except Exception as e:
            self.after(0, lambda: self._on_error(str(e)))

    def _run(self, filepath):
        """Full analysis pipeline — worker thread."""
        self.after(0, lambda: self._log(f"File loaded: {os.path.basename(filepath)}"))

        with open(filepath, 'rb') as fh:
            raw = fh.read()

        self.after(0, lambda: self._log("Parsing container boxes…"))
        boxes = avif_parser.parse_boxes(raw)
        self.after(0, lambda: self._log(f"  {len(boxes)} top-level box(es) found."))

        ftyp_box  = avif_parser.find_box(boxes, 'ftyp')
        ftyp_info = avif_parser.validate_ftyp(ftyp_box) if ftyp_box else {
            'major_brand':'','minor_version':0,'compatible_brands':[],'is_avif':False,'is_avis':False}
        brand = ftyp_info.get('major_brand','?')
        self.after(0, lambda: self._log(f"  ftyp brand='{brand}'  is_avif={ftyp_info.get('is_avif')}"))

        self.after(0, lambda: self._log("Extracting AV1 bitstream…"))
        bs_info = bs_module.extract_av1_bitstream(raw, boxes)
        bsz, mth = len(bs_info.get('bitstream',b'')), bs_info.get('extraction_method','?')
        self.after(0, lambda: self._log(f"  {bsz}B  ({mth})"))

        self.after(0, lambda: self._log("Parsing AV1 OBUs…"))
        obus = obu_parser.parse_obus(bs_info['bitstream'])
        self.after(0, lambda: self._log(f"  {len(obus)} OBU(s) found."))

        # Filesystem-isolated OBU extraction — never touch user directories
        obu_dir = os.path.join(tempfile.gettempdir(), 'avif_forensic_obus')
        if os.path.isdir(obu_dir):
            shutil.rmtree(obu_dir)   # safe: always our own temp subdir
        self.after(0, lambda: self._log(f"Extracting OBUs → {obu_dir}"))
        saved = obu_parser.extract_obus_to_disk(obus, obu_dir)
        self.after(0, lambda: self._log(f"  {len(saved)} file(s) saved."))

        self.after(0, lambda: self._log("Running anomaly detection & scoring…"))
        result = analyzer.analyze(raw, boxes, ftyp_info, bs_info, obus)
        sc, cl, na = result['risk_score'], result['classification'], len(result['anomalies'])
        self.after(0, lambda: self._log(f"  Score: {sc}/10  |  {cl}  |  {na} anomaly/anomalies."))
        self.after(0, lambda: self._log("Analysis complete."))

        self.after(0, lambda: self._on_complete(
            filepath, boxes, ftyp_info, bs_info, obus, saved, result, obu_dir))

    def _on_complete(self, filepath, boxes, ftyp_info, bs_info, obus, saved, result, obu_dir):
        self._results = result
        self._update_fileinfo(filepath, ftyp_info, boxes)
        self._update_container(boxes)
        self._update_bitstream(bs_info, obus)
        self._update_extracted(saved, obu_dir)
        self._update_verdict(result)
        self._btn_analyze.configure(state=tk.NORMAL, text='▶  Analyze')
        self._btn_browse.configure(state=tk.NORMAL)
        self.is_analyzing = False      # release thread-safety lock
        sc, cl = result['risk_score'], result['classification']
        self._status_var.set(
            f"Done — {len(obus)} OBUs | Risk: {sc:.1f}/10 | {cl}")
        if result['anomalies']:
            self._nb.select(4)

    def _on_error(self, msg):
        self._btn_analyze.configure(state=tk.NORMAL, text='▶  Analyze')
        self._btn_browse.configure(state=tk.NORMAL)
        self.is_analyzing = False      # release thread-safety lock on error path
        self._status_var.set(f'Error: {msg}')
        self._log(msg, level='ERROR')
        messagebox.showerror('Analysis Error', f'An error occurred:\n\n{msg}')
