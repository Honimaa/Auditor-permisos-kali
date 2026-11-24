#!/usr/bin/env python3
"""Interfaz gráfica del auditor de permisos (Tkinter, biblioteca estándar).

La ventana se ejecuta como usuario normal. Cuando se pide una auditoría completa,
solo el escaneo corre con sudo: la interfaz lanza `sudo python3 auditor.py ...`,
y el auditor, como siempre, suelta root después de leer el disco y escribe los
resultados (JSON con permisos 0600) ya como el usuario. Así la interfaz nunca
tiene privilegios de root.

Uso:  python3 auditor_gui.py          (NO usar sudo para abrir la ventana)
Requiere el paquete python3-tk:  sudo apt install python3-tk
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import webbrowser
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover - depende del sistema
    sys.exit("Falta Tkinter. Instálelo con:  sudo apt install python3-tk")

RAIZ = os.path.dirname(os.path.abspath(__file__))
AUDITOR = os.path.join(RAIZ, "auditor.py")

# Paleta: azul petróleo para la estructura y los colores de severidad del reporte HTML.
C = {
    "fondo": "#eef1f4", "panel": "#ffffff", "borde": "#cfd6de", "texto": "#1c2733", "suave": "#5c6b7a",
    "barra": "#16324a", "barra_texto": "#e8f0f7", "acento": "#1f6feb", "acento_osc": "#1858c4",
    "alta": "#c62828", "alta_fondo": "#fdecea", "media": "#b26a00", "media_fondo": "#fff4e0",
    "baja": "#1f6fa8", "baja_fondo": "#e8f2fb", "consola": "#1e1f26", "consola_texto": "#e6e6e6",
}
SEVERIDADES = ("ALTA", "MEDIA", "BAJA")


# ------------------------------------------------------------------ lógica (sin ventana)

def construir_comando(rutas, min_severidad, ruta_json, ruta_html=None, con_sudo=False):
    """Arma el comando del auditor. Con sudo se usa -S para recibir la contraseña por
    la entrada estándar y -p '' para que sudo no imprima su propio mensaje."""
    cmd = [sys.executable, AUDITOR, *rutas, "--min-severidad", min_severidad,
           "--json", ruta_json, "--color", "no"]
    cmd += ["--html", ruta_html] if ruta_html else ["--sin-html"]
    if con_sudo:
        cmd = ["sudo", "-S", "-p", "", *cmd]
    return cmd


def ejecutar_auditoria(rutas, min_severidad, con_sudo, contrasena, ruta_html):
    """Ejecuta el auditor y devuelve (codigo, salida, errores, datos_json o None)."""
    carpeta = tempfile.mkdtemp(prefix="auditor-gui-")      # 0700, del usuario
    ruta_json = os.path.join(carpeta, "resultado.json")
    try:
        cmd = construir_comando(rutas, min_severidad, ruta_json, ruta_html, con_sudo)
        entrada = (contrasena + "\n") if con_sudo else None
        p = subprocess.run(cmd, cwd=RAIZ, input=entrada, capture_output=True, text=True)
        datos = None
        if os.path.exists(ruta_json):
            with open(ruta_json, encoding="utf-8") as f:
                datos = json.load(f)
        return p.returncode, p.stdout, p.stderr, datos
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)


def sudo_sin_contrasena():
    """True si sudo ya tiene la credencial en caché (no hace falta pedir contraseña)."""
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# ------------------------------------------------------------------ ventana

class Aplicacion(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Auditor de permisos")
        self.geometry("1180x720")
        self.minsize(980, 600)
        self.configure(bg=C["fondo"])
        self.datos = None
        self.ruta_html = None
        self._estilos()
        self._encabezado()
        self._opciones()
        self._resumen()
        self._barra_estado()
        self._pestanas()
        if os.geteuid() == 0:
            self.after(300, lambda: messagebox.showwarning(
                "Ejecutando como root",
                "La interfaz no necesita root. Ábrala como usuario normal y marque "
                "'Auditoría completa (sudo)': solo el escaneo usará privilegios."))

    # ---------- estilos
    def _estilos(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        base = ("DejaVu Sans", 10)
        st.configure(".", font=base, background=C["fondo"], foreground=C["texto"])
        st.configure("Panel.TFrame", background=C["panel"])
        st.configure("Panel.TLabel", background=C["panel"])
        st.configure("Suave.TLabel", background=C["panel"], foreground=C["suave"])
        st.configure("TCheckbutton", background=C["panel"])
        st.map("TCheckbutton", background=[("active", C["panel"])])
        st.configure("Primario.TButton", font=("DejaVu Sans", 10, "bold"), foreground="#ffffff",
                     background=C["acento"], borderwidth=0, padding=(18, 8))
        st.map("Primario.TButton", background=[("active", C["acento_osc"]), ("disabled", "#9db7dc")])
        st.configure("TButton", padding=(10, 6))
        st.configure("Treeview", rowheight=24, font=base, background=C["panel"], fieldbackground=C["panel"])
        st.configure("Treeview.Heading", font=("DejaVu Sans", 10, "bold"), background="#e3e8ee")
        st.map("Treeview", background=[("selected", "#cfe0fb")], foreground=[("selected", C["texto"])])
        st.configure("TNotebook", background=C["fondo"], borderwidth=0)
        # Pestañas: la activa es blanca, en negrita y sobresale; las demás quedan grises y más bajas.
        st.configure("TNotebook.Tab", padding=(16, 5), background="#d3d9e0", foreground=C["suave"],
                     bordercolor="#c3cad3", lightcolor="#d3d9e0")
        st.map("TNotebook.Tab",
               background=[("selected", C["panel"]), ("active", "#e2e7ec")],
               foreground=[("selected", C["texto"])],
               lightcolor=[("selected", C["panel"])],
               font=[("selected", ("DejaVu Sans", 10, "bold"))],
               padding=[("selected", (16, 8))],
               expand=[("selected", (2, 3, 2, 0)), ("!selected", (0, 0, 0, 0))])

    # ---------- partes de la ventana
    def _encabezado(self):
        barra = tk.Frame(self, bg=C["barra"], height=50)
        barra.pack(fill="x")
        tk.Label(barra, text="Auditor de permisos", bg=C["barra"], fg=C["barra_texto"],
                 font=("DejaVu Sans", 15, "bold")).pack(side="left", padx=(18, 10), pady=9)
        tk.Label(barra, text="Configuraciones de riesgo en Linux · R01–R07 · solo lectura",
                 bg=C["barra"], fg="#9fb6cc", font=("DejaVu Sans", 10)).pack(side="left", pady=9)
        usuario = os.environ.get("USER") or str(os.getuid())
        tk.Label(barra, text=f"Usuario: {usuario}", bg=C["barra"], fg="#9fb6cc",
                 font=("DejaVu Sans", 10)).pack(side="right", padx=18)

    def _opciones(self):
        marco = ttk.Frame(self, style="Panel.TFrame", padding=(16, 10))
        marco.pack(fill="x", padx=14, pady=(10, 0))
        ttk.Label(marco, text="Carpetas a auditar", style="Panel.TLabel",
                  font=("DejaVu Sans", 10, "bold")).grid(row=0, column=0, sticky="w")
        self.var_rutas = tk.StringVar(value="/opt/lab_auditoria")
        ent = ttk.Entry(marco, textvariable=self.var_rutas, width=60)
        ent.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(marco, text="Agregar carpeta…", command=self._elegir_carpeta).grid(
            row=1, column=1, padx=(8, 18), pady=(4, 0))
        ttk.Label(marco, text="Separe varias carpetas con espacios. Ej.: /etc /home /usr/bin",
                  style="Suave.TLabel").grid(row=2, column=0, sticky="w", pady=(2, 0))

        ttk.Label(marco, text="Severidad mínima", style="Panel.TLabel",
                  font=("DejaVu Sans", 10, "bold")).grid(row=0, column=2, sticky="w")
        self.var_min = tk.StringVar(value="BAJA")
        ttk.Combobox(marco, textvariable=self.var_min, values=("BAJA", "MEDIA", "ALTA"),
                     state="readonly", width=9).grid(row=1, column=2, sticky="w", pady=(4, 0))

        self.var_sudo = tk.BooleanVar(value=True)
        self.var_html = tk.BooleanVar(value=True)
        ttk.Checkbutton(marco, text="Auditoría completa (sudo)", variable=self.var_sudo).grid(
            row=1, column=3, sticky="w", padx=(18, 0), pady=(4, 0))
        ttk.Checkbutton(marco, text="Guardar reporte HTML", variable=self.var_html).grid(
            row=2, column=3, sticky="w", padx=(18, 0))

        self.btn_auditar = ttk.Button(marco, text="Auditar", style="Primario.TButton", command=self._auditar)
        self.btn_auditar.grid(row=1, column=4, padx=(18, 0), pady=(4, 0), sticky="e")
        marco.columnconfigure(0, weight=1)

    def _resumen(self):
        fila = tk.Frame(self, bg=C["fondo"])
        fila.pack(fill="x", padx=14, pady=10)
        self.tarjetas = {}
        defin = [("ALTA", "Altas", C["alta"]), ("MEDIA", "Medias", C["media"]), ("BAJA", "Bajas", C["baja"]),
                 ("archivos", "Archivos revisados", C["texto"]), ("sin_acceso", "Rutas sin acceso", C["texto"]),
                 ("duracion", "Tiempo", C["texto"])]
        for i, (clave, texto, color) in enumerate(defin):
            t = tk.Frame(fila, bg=C["panel"], highlightbackground=C["borde"], highlightthickness=1)
            t.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            tk.Frame(t, bg=color, width=5).pack(side="left", fill="y")
            cuerpo = tk.Frame(t, bg=C["panel"])
            cuerpo.pack(side="left", fill="both", expand=True, padx=12, pady=5)
            num = tk.Label(cuerpo, text="—", bg=C["panel"], fg=color, font=("DejaVu Sans", 18, "bold"))
            num.pack(anchor="w")
            tk.Label(cuerpo, text=texto, bg=C["panel"], fg=C["suave"]).pack(anchor="w")
            self.tarjetas[clave] = num
            fila.columnconfigure(i, weight=1, uniform="t")

    def _pestanas(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14)

        # Pestaña de hallazgos
        tab = ttk.Frame(self.nb, style="Panel.TFrame", padding=10)
        self.nb.add(tab, text="Hallazgos")
        filtros = ttk.Frame(tab, style="Panel.TFrame")
        filtros.pack(fill="x", pady=(0, 8))
        ttk.Label(filtros, text="Mostrar:", style="Panel.TLabel").pack(side="left")
        self.var_filtro = tk.StringVar(value="Todas")
        cb = ttk.Combobox(filtros, textvariable=self.var_filtro, state="readonly", width=10,
                          values=("Todas", "ALTA", "MEDIA", "BAJA"))
        cb.pack(side="left", padx=(6, 16))
        cb.bind("<<ComboboxSelected>>", lambda e: self._llenar_tabla())
        ttk.Label(filtros, text="Buscar en la ruta:", style="Panel.TLabel").pack(side="left")
        self.var_buscar = tk.StringVar()
        self.var_buscar.trace_add("write", lambda *a: self._llenar_tabla())
        ttk.Entry(filtros, textvariable=self.var_buscar, width=36).pack(side="left", padx=6)
        self.btn_html = ttk.Button(filtros, text="Abrir reporte HTML", command=self._abrir_html, state="disabled")
        self.btn_html.pack(side="right")

        cuerpo = ttk.Panedwindow(tab, orient="vertical")
        cuerpo.pack(fill="both", expand=True)
        marco_tabla = ttk.Frame(cuerpo, style="Panel.TFrame")
        cols = ("sev", "regla", "permisos", "ruta")
        self.tabla = ttk.Treeview(marco_tabla, columns=cols, show="headings", selectmode="browse", height=8)
        for col, titulo, ancho, estirar in (("sev", "Severidad", 100, False), ("regla", "Regla", 190, False),
                                            ("permisos", "Permisos", 150, False), ("ruta", "Ruta", 520, True)):
            self.tabla.heading(col, text=titulo)
            self.tabla.column(col, width=ancho, stretch=estirar, anchor="w")
        for sev in SEVERIDADES:
            self.tabla.tag_configure(sev, background=C[sev.lower() + "_fondo"], foreground=C["texto"])
        barra = ttk.Scrollbar(marco_tabla, orient="vertical", command=self.tabla.yview)
        self.tabla.configure(yscrollcommand=barra.set)
        self.tabla.pack(side="left", fill="both", expand=True)
        barra.pack(side="right", fill="y")
        self.tabla.bind("<<TreeviewSelect>>", self._mostrar_detalle)
        cuerpo.add(marco_tabla, weight=3)

        marco_det = ttk.Frame(cuerpo, style="Panel.TFrame", padding=(0, 8, 0, 0))
        self.detalle = tk.Text(marco_det, height=6, wrap="word", relief="flat", bg="#f6f8fa",
                               font=("DejaVu Sans", 10), padx=10, pady=8, state="disabled")
        self.detalle.tag_configure("titulo", font=("DejaVu Sans", 10, "bold"))
        self.detalle.tag_configure("mono", font=("DejaVu Sans Mono", 10))
        self.detalle.pack(side="left", fill="both", expand=True)
        ttk.Button(marco_det, text="Copiar\nrecomendación", command=self._copiar).pack(side="right", padx=(8, 0))
        cuerpo.add(marco_det, weight=2)

        # Pestaña con la salida del auditor (lo mismo que se vería en consola)
        tab2 = ttk.Frame(self.nb, style="Panel.TFrame", padding=10)
        self.nb.add(tab2, text="Salida del auditor")
        self.consola = tk.Text(tab2, wrap="word", bg=C["consola"], fg=C["consola_texto"],
                               insertbackground="#ffffff", font=("DejaVu Sans Mono", 10), padx=10, pady=8)
        self.consola.pack(fill="both", expand=True)
        self._escribir_consola("Elija las carpetas y presione Auditar.\n")

    def _barra_estado(self):
        barra = tk.Frame(self, bg=C["fondo"])
        barra.pack(side="bottom", fill="x", padx=14, pady=(4, 8))
        self.var_estado = tk.StringVar(value="Listo.")
        tk.Label(barra, textvariable=self.var_estado, bg=C["fondo"], fg=C["suave"]).pack(side="left")
        self.progreso = ttk.Progressbar(barra, mode="indeterminate", length=180)
        self.progreso.pack(side="right")

    # ---------- acciones
    def _elegir_carpeta(self):
        carpeta = filedialog.askdirectory(title="Carpeta a auditar", initialdir="/")
        if carpeta:
            actual = self.var_rutas.get().split()
            if carpeta not in actual:
                self.var_rutas.set(" ".join(actual + [carpeta]))

    def _pedir_contrasena(self):
        """Ventana modal para la contraseña de sudo. Se envía a sudo por la entrada
        estándar y no se guarda en ningún archivo."""
        dlg = tk.Toplevel(self)
        dlg.title("Contraseña de sudo")
        dlg.configure(bg=C["panel"])
        dlg.transient(self)
        dlg.resizable(False, False)
        tk.Label(dlg, text="La auditoría completa necesita leer carpetas protegidas.\n"
                           "Escriba su contraseña de sudo:", bg=C["panel"], justify="left").pack(padx=18, pady=(16, 8))
        var = tk.StringVar()
        ent = ttk.Entry(dlg, textvariable=var, show="•", width=32)
        ent.pack(padx=18)
        resultado = {"valor": None}

        def aceptar(_=None):
            resultado["valor"] = var.get()
            dlg.destroy()

        botones = tk.Frame(dlg, bg=C["panel"])
        botones.pack(pady=14)
        ttk.Button(botones, text="Cancelar", command=dlg.destroy).pack(side="left", padx=6)
        ttk.Button(botones, text="Continuar", style="Primario.TButton", command=aceptar).pack(side="left", padx=6)
        ent.bind("<Return>", aceptar)
        ent.focus_set()
        dlg.grab_set()
        self.wait_window(dlg)
        return resultado["valor"]

    def _auditar(self):
        rutas = self.var_rutas.get().split()
        if not rutas:
            messagebox.showinfo("Auditor", "Escriba al menos una carpeta.")
            return
        faltan = [r for r in rutas if not os.path.isdir(r)]
        if faltan:
            messagebox.showerror("Auditor", "Estas carpetas no existen:\n" + "\n".join(faltan))
            return
        con_sudo = self.var_sudo.get() and os.geteuid() != 0
        contrasena = ""
        if con_sudo and not sudo_sin_contrasena():
            contrasena = self._pedir_contrasena()
            if contrasena is None:
                return
        self.ruta_html = None
        if self.var_html.get():
            self.ruta_html = os.path.expanduser(f"~/reporte_auditoria_{datetime.now():%Y-%m-%d_%H%M%S}.html")
        self.btn_auditar.state(["disabled"])
        self.btn_html.state(["disabled"])
        self.progreso.start(12)
        self.var_estado.set("Auditando " + ", ".join(rutas) + ("  (con sudo)" if con_sudo else "  (sin sudo)") + "…")
        self._escribir_consola(f"$ {'sudo ' if con_sudo else ''}python3 auditor.py {' '.join(rutas)} "
                               f"--min-severidad {self.var_min.get()} --json … --color no\n\n", limpiar=True)

        def trabajo():
            try:
                res = ejecutar_auditoria(rutas, self.var_min.get(), con_sudo, contrasena, self.ruta_html)
            except OSError as e:
                res = (3, "", str(e), None)
            self.after(0, lambda: self._terminado(*res))

        threading.Thread(target=trabajo, daemon=True).start()

    def _terminado(self, codigo, salida, errores, datos):
        self.progreso.stop()
        self.btn_auditar.state(["!disabled"])
        self._escribir_consola(salida + (("\n" + errores) if errores else "") + f"\n[código de salida: {codigo}]\n")
        if datos is None:
            if "incorrect password" in errores or "contraseña incorrecta" in errores or "Sorry" in errores:
                msg = "La contraseña de sudo no es correcta."
            else:
                msg = (errores.strip() or "El auditor no entregó resultados.") + f"\n(código de salida {codigo})"
            self.var_estado.set("La auditoría no terminó.")
            messagebox.showerror("Auditor", msg)
            self.nb.select(1)
            return
        self.datos = datos
        r, e = datos["resumen"], datos["estadisticas"]
        self.tarjetas["ALTA"].config(text=r["ALTA"])
        self.tarjetas["MEDIA"].config(text=r["MEDIA"])
        self.tarjetas["BAJA"].config(text=r["BAJA"])
        self.tarjetas["archivos"].config(text=f"{e['archivos']:,}".replace(",", "."))
        self.tarjetas["sin_acceso"].config(text=e["rutas_sin_acceso"])
        self.tarjetas["duracion"].config(text=f"{e['duracion_s']:.2f} s".replace(".", ","))
        self._llenar_tabla()
        if self.ruta_html and os.path.exists(self.ruta_html):
            self.btn_html.state(["!disabled"])
        total = len(datos["hallazgos"])
        self.var_estado.set(f"Listo: {total} hallazgos · listas base: {', '.join(datos['listas_base'])} · "
                            f"{datos['ejecutado_como']}")
        self.nb.select(0)

    def _llenar_tabla(self):
        self.tabla.delete(*self.tabla.get_children())
        if not self.datos:
            return
        filtro, texto = self.var_filtro.get(), self.var_buscar.get().strip().lower()
        for i, h in enumerate(self.datos["hallazgos"]):
            if filtro != "Todas" and h["severidad"] != filtro:
                continue
            if texto and texto not in h["ruta"].lower():
                continue
            self.tabla.insert("", "end", iid=str(i), tags=(h["severidad"],),
                              values=(h["severidad"], h["regla"], h["permisos"], h["ruta"]))
        hijos = self.tabla.get_children()
        if hijos:
            self.tabla.selection_set(hijos[0])
        else:
            self._texto_detalle([("Sin hallazgos para este filtro.", None)])

    def _mostrar_detalle(self, _=None):
        sel = self.tabla.selection()
        if not sel:
            return
        h = self.datos["hallazgos"][int(sel[0])]
        self._texto_detalle([(f"{h['severidad']} · {h['regla']}\n", "titulo"), (h["ruta"] + "\n", "mono"),
                             (h["detalle"] + "\n\n", None), ("Recomendación: ", "titulo"),
                             (h["recomendacion"], "mono")])

    def _texto_detalle(self, partes):
        self.detalle.config(state="normal")
        self.detalle.delete("1.0", "end")
        for texto, tag in partes:
            self.detalle.insert("end", texto, tag)
        self.detalle.config(state="disabled")

    def _copiar(self):
        sel = self.tabla.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.datos["hallazgos"][int(sel[0])]["recomendacion"])
            self.var_estado.set("Recomendación copiada al portapapeles.")

    def _abrir_html(self):
        if self.ruta_html:
            webbrowser.open("file://" + self.ruta_html)

    def _escribir_consola(self, texto, limpiar=False):
        if limpiar:
            self.consola.delete("1.0", "end")
        self.consola.insert("end", texto)
        self.consola.see("end")


if __name__ == "__main__":
    Aplicacion().mainloop()
