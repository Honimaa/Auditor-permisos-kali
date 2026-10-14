"""Salida de resultados: consola (con colores ANSI) y archivo HTML autocontenido."""

import html
import os
import platform
import socket
from collections import Counter
from datetime import datetime
from typing import List

from .modelos import EstadisticasEscaneo, Hallazgo, Severidad

_COLOR = {Severidad.ALTA: "\033[1;31m", Severidad.MEDIA: "\033[1;33m", Severidad.BAJA: "\033[1;36m"}
_RESET = "\033[0m"


def _cortable(texto: str) -> str:
    """Escapa el texto y permite saltos de línea después de cada '/' en rutas largas."""
    return html.escape(texto).replace("/", "/<wbr>")


def ordenar(hallazgos: List[Hallazgo]) -> List[Hallazgo]:
    return sorted(hallazgos, key=lambda h: (-h.severidad, h.regla, h.ruta))


def imprimir_consola(hallazgos: List[Hallazgo], est: EstadisticasEscaneo, color: bool) -> None:
    for h in ordenar(hallazgos):
        etiqueta = f"[{h.severidad.name}]".ljust(8)
        if color:
            etiqueta = f"{_COLOR[h.severidad]}{etiqueta}{_RESET}"
        print(f"{etiqueta} {h.regla:<20} {h.permisos:<18} {h.ruta}")
        print(f"         └─ {h.detalle}")
        print(f"            Recomendación: {h.recomendacion}")
    conteo = Counter(h.severidad for h in hallazgos)
    print()
    print(f"Resumen: {conteo[Severidad.ALTA]} altas · {conteo[Severidad.MEDIA]} medias · "
          f"{conteo[Severidad.BAJA]} bajas")
    print(f"Revisados: {est.archivos} archivos y {est.directorios} directorios en {est.duracion_s:.2f} s "
          f"(omitidos: {est.enlaces_omitidos} enlaces simbólicos, {est.especiales_omitidos} especiales)")
    if est.sin_acceso:
        print(f"Aviso: {len(est.sin_acceso)} rutas no se pudieron leer por falta de permisos "
              f"(ejecute con sudo para una auditoría completa).")


def generar_html(hallazgos: List[Hallazgo], est: EstadisticasEscaneo, rutas: List[str], destino: str) -> str:
    conteo = Counter(h.severidad for h in hallazgos)
    filas = []
    for h in ordenar(hallazgos):
        filas.append(
            f"<tr class='{h.severidad.name.lower()}'><td><span class='sev'>{h.severidad.name}</span></td>"
            f"<td>{html.escape(h.regla)}</td><td class='mono'>{_cortable(h.ruta)}</td>"
            f"<td class='mono'>{html.escape(h.permisos)}</td><td>{html.escape(h.detalle)}</td>"
            f"<td class='mono'>{_cortable(h.recomendacion)}</td></tr>")
    usuario_ejec = "root" if os.geteuid() == 0 else f"UID {os.geteuid()} (sin privilegios)"
    contenido = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Reporte de auditoría de permisos</title>
<style>
 body{{font-family:Arial,Helvetica,sans-serif;font-size:10pt;margin:24px;color:#111;background:#fff}}
 h1{{font-size:15pt;margin:0 0 4px}} .meta{{color:#444;margin-bottom:14px}}
 .tarjetas{{display:flex;gap:10px;margin-bottom:14px}}
 .tarjeta{{border:1px solid #999;padding:8px 14px;min-width:90px}} .tarjeta b{{font-size:16pt;display:block}}
 table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}}
 th{{background:#e6e6e6}} td:nth-child(2),td:nth-child(4){{white-space:nowrap}} .mono{{font-family:'Courier New',monospace;font-size:9pt}}
 .sev{{font-weight:bold;padding:1px 5px;border-radius:3px}}
 tr.alta .sev{{background:#c62828;color:#fff}} tr.media .sev{{background:#f9a825}} tr.baja .sev{{background:#90caf9}}
</style></head><body>
<h1>Reporte de auditoría de permisos</h1>
<div class="meta">Equipo: {html.escape(socket.gethostname())} · {html.escape(platform.platform())} ·
Ejecutado como: {usuario_ejec} · {datetime.now():%Y-%m-%d %H:%M}<br>
Rutas auditadas: {html.escape(', '.join(rutas))} · {est.archivos} archivos, {est.directorios} directorios en {est.duracion_s:.2f} s</div>
<div class="tarjetas">
 <div class="tarjeta"><b>{conteo[Severidad.ALTA]}</b>Altas</div>
 <div class="tarjeta"><b>{conteo[Severidad.MEDIA]}</b>Medias</div>
 <div class="tarjeta"><b>{conteo[Severidad.BAJA]}</b>Bajas</div>
 <div class="tarjeta"><b>{len(est.sin_acceso)}</b>Rutas sin acceso</div>
</div>
<table><tr><th>Severidad</th><th>Regla</th><th>Ruta</th><th>Permisos</th><th>Detalle</th><th>Recomendación</th></tr>
{''.join(filas) or '<tr><td colspan="6">Sin hallazgos.</td></tr>'}
</table></body></html>"""
    with open(destino, "w", encoding="utf-8") as f:
        f.write(contenido)
    return destino
