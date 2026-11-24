#!/usr/bin/env python3
"""Punto de entrada (CLI) del auditor de permisos.

Uso:
    sudo python3 auditor.py /etc /home /usr/bin --html reporte.html

Orden de ejecución y privilegios (Entregas 3 y 4):
    0. [root]    lectura segura de las listas base de SUID/SGID (auditor/listas_base.conf)
    1. [root]    recorrido del disco y evaluación de reglas (solo lectura)
    2. [root]    registro de la ejecución en /var/log/auditor-permisos.log
    3. [ ---- ]  setgid/setuid al usuario que ejecutó sudo  (sin retorno)
    4. [usuario] escritura del reporte HTML con permisos 0600
"""

import argparse
import os
import sys
from datetime import datetime

from auditor import __version__
from auditor.escaner import EXCLUIDOS_POR_DEFECTO, Escaner
from auditor.listas import RUTA_POR_DEFECTO as LISTAS_POR_DEFECTO, cargar_listas
from auditor.modelos import Severidad
from auditor.registro import registrar_ejecucion, ruta_por_defecto, sha256_texto
from auditor.reglas import Contexto, evaluar, verificar_archivos_sensibles
from auditor.reporte import construir_html, construir_json, imprimir_consola
from auditor.seguridad import (ErrorSeguridad, directorio_inseguro, escribir_archivo_seguro,
                               reducir_privilegios, usuario_invocador)
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
    p.add_argument("--json", metavar="ARCHIVO", help="guardar también los resultados en JSON (lo usa la interfaz gráfica)")
    p.add_argument("--listas", metavar="ARCHIVO", default=LISTAS_POR_DEFECTO,
                   help="archivo con las listas base de SUID/SGID (por defecto auditor/listas_base.conf)")
    p.add_argument("--registro", metavar="ARCHIVO",
                   help="registro de auditoría (por defecto /var/log/auditor-permisos.log si es root)")
    p.add_argument("--mantener-root", action="store_true",
                   help="no soltar privilegios al terminar el escaneo (no recomendado)")
    p.add_argument("--color", choices=["auto", "si", "no"], default="auto")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = construir_parser().parse_args(argv)
    usar_color = args.color == "si" or (args.color == "auto" and sys.stdout.isatty())

    print(f"Auditor de permisos v{__version__} — rutas: {' '.join(args.rutas)}")
    try:
        invocador = usuario_invocador()
    except ErrorSeguridad as e:
        print(f"Error de seguridad: {e}", file=sys.stderr)
        return 3
    if os.geteuid() != 0:
        print("Aviso: ejecutando sin root; algunas carpetas pueden no ser legibles.")
    elif invocador is None and not args.mantener_root:
        print("Aviso: se ejecutó como root directamente (sin sudo); no hay un usuario al cual "
              "bajar privilegios y el reporte se escribirá como root.")

    # 0. Listas base de SUID/SGID según la distribución (Entrega 4)
    try:
        suid_base, sgid_base, secciones = cargar_listas(args.listas)
    except ErrorSeguridad as e:
        print(f"Error de seguridad: {e}", file=sys.stderr)
        return 3
    print(f"Listas base: {args.listas} (secciones: {', '.join(secciones)})\n")

    # 1. Escaneo (única fase que necesita root)
    ctx = Contexto(BaseUsuarios(), suid_esperados=suid_base, sgid_esperados=sgid_base)
    escaner = Escaner(args.rutas, excluir=args.excluir, max_profundidad=args.profundidad,
                      mismo_fs=args.mismo_fs)
    hallazgos = []
    for entrada in escaner.recorrer():
        hallazgos.extend(evaluar(entrada, ctx))
    hallazgos.extend(verificar_archivos_sensibles(ctx))
    minimo = Severidad[args.min_severidad]
    hallazgos = [h for h in hallazgos if h.severidad >= minimo]

    destino = None
    contenido_html = None
    hash_reporte = None
    if not args.sin_html:
        destino = args.html or f"reporte_{datetime.now():%Y-%m-%d_%H%M%S}.html"
        quien = invocador[2] if (invocador and not args.mantener_root) else ("root" if os.geteuid() == 0 else str(os.getuid()))
        contenido_html = construir_html(hallazgos, escaner.estadisticas, args.rutas,
                                        f"escaneo con UID {os.geteuid()}, reporte escrito por {quien}")
        hash_reporte = sha256_texto(contenido_html)

    # 2. Registro de auditoría de la ejecución
    ruta_registro = args.registro or ruta_por_defecto()
    try:
        registrar_ejecucion(ruta_registro, argv, args.rutas, hallazgos, escaner.estadisticas,
                            destino, hash_reporte, __version__)
    except ErrorSeguridad as e:
        print(f"Error de seguridad: {e}", file=sys.stderr)
        return 3

    # 3. Menor privilegio: soltar root antes de escribir cualquier cosa más
    if invocador and not args.mantener_root:
        uid, gid, nombre = invocador
        try:
            reducir_privilegios(uid, gid, nombre)
        except (ErrorSeguridad, OSError) as e:
            print(f"Error de seguridad: no se pudieron reducir privilegios: {e}", file=sys.stderr)
            return 3
        print(f"Privilegios reducidos: el proceso pasó de root a '{nombre}' (UID {uid}) "
              f"y ya no puede volver a root.\n")

    # Resultados en JSON (interfaz gráfica): se arma aquí, ya sin root, y se escribe con 0600
    if args.json:
        quien_json = invocador[2] if (invocador and not args.mantener_root) else ("root" if os.geteuid() == 0 else str(os.getuid()))
        texto_json = construir_json(hallazgos, escaner.estadisticas, args.rutas, secciones,
                                    f"escaneo con UID {0 if invocador else os.geteuid()}, resultados escritos por {quien_json}",
                                    __version__)
        try:
            escribir_archivo_seguro(args.json, texto_json)
        except ErrorSeguridad as e:
            print(f"Error de seguridad: {e}", file=sys.stderr)
            return 3

    imprimir_consola(hallazgos, escaner.estadisticas, usar_color)
    print(f"Ejecución registrada en: {ruta_registro}")

    # 4. Reporte con permisos 0600, escrito con la identidad final del proceso
    if contenido_html is not None:
        if directorio_inseguro(destino):
            print(f"Aviso: la carpeta de '{destino}' es escribible por todos; el archivo se crea "
                  f"igual de forma segura (O_EXCL | O_NOFOLLOW).")
        try:
            escribir_archivo_seguro(destino, contenido_html)
        except ErrorSeguridad as e:
            print(f"Error de seguridad: {e}", file=sys.stderr)
            return 3
        print(f"Reporte HTML guardado en: {destino} (permisos 0600, UID {os.geteuid()})")
        print(f"SHA-256 del reporte: {hash_reporte}")

    # Código de salida útil para automatizar: 3 = error de seguridad, 2 = hay altas,
    # 1 = otros hallazgos, 0 = limpio.
    if any(h.severidad == Severidad.ALTA for h in hallazgos):
        return 2
    return 1 if hallazgos else 0


if __name__ == "__main__":
    sys.exit(main())
