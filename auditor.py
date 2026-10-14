#!/usr/bin/env python3
"""Punto de entrada (CLI) del auditor de permisos.

Uso:
    sudo python3 auditor.py /etc /home /usr/bin --html reporte.html
"""

import argparse
import os
import sys
from datetime import datetime

from auditor import __version__
from auditor.escaner import EXCLUIDOS_POR_DEFECTO, Escaner
from auditor.modelos import Severidad
from auditor.reglas import Contexto, evaluar, verificar_archivos_sensibles
from auditor.reporte import generar_html, imprimir_consola
from auditor.usuarios import BaseUsuarios


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Auditor de permisos y configuraciones de riesgo en Linux")
    p.add_argument("rutas", nargs="*", default=["/"], help="carpetas a auditar (por defecto /)")
    p.add_argument("--excluir", nargs="*", default=list(EXCLUIDOS_POR_DEFECTO),
                   help="carpetas que no se recorren (por defecto /proc /sys /dev /run)")
    p.add_argument("--profundidad", type=int, default=None, help="profundidad máxima del recorrido")
    p.add_argument("--mismo-fs", action="store_true", help="no cruzar a otros sistemas de archivos montados")
    p.add_argument("--min-severidad", choices=["BAJA", "MEDIA", "ALTA"], default="BAJA",
                   help="mostrar solo hallazgos de esta severidad o mayor")
    p.add_argument("--html", metavar="ARCHIVO", help="ruta del reporte HTML (por defecto reporte_FECHA.html)")
    p.add_argument("--sin-html", action="store_true", help="no generar reporte HTML")
    p.add_argument("--color", choices=["auto", "si", "no"], default="auto")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = construir_parser().parse_args(argv)
    usar_color = args.color == "si" or (args.color == "auto" and sys.stdout.isatty())

    print(f"Auditor de permisos v{__version__} — rutas: {' '.join(args.rutas)}")
    if os.geteuid() != 0:
        print("Aviso: ejecutando sin root; algunas carpetas pueden no ser legibles.\n")
    else:
        print()

    ctx = Contexto(BaseUsuarios())
    escaner = Escaner(args.rutas, excluir=args.excluir, max_profundidad=args.profundidad,
                      mismo_fs=args.mismo_fs)
    hallazgos = []
    for entrada in escaner.recorrer():
        hallazgos.extend(evaluar(entrada, ctx))
    hallazgos.extend(verificar_archivos_sensibles(ctx))

    minimo = Severidad[args.min_severidad]
    hallazgos = [h for h in hallazgos if h.severidad >= minimo]

    imprimir_consola(hallazgos, escaner.estadisticas, usar_color)

    if not args.sin_html:
        destino = args.html or f"reporte_{datetime.now():%Y-%m-%d_%H%M%S}.html"
        generar_html(hallazgos, escaner.estadisticas, args.rutas, destino)
        print(f"Reporte HTML guardado en: {destino}")

    # Código de salida útil para automatizar (cron, CI): 2 = hay altas, 1 = otros hallazgos, 0 = limpio.
    if any(h.severidad == Severidad.ALTA for h in hallazgos):
        return 2
    return 1 if hallazgos else 0


if __name__ == "__main__":
    sys.exit(main())
