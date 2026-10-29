"""Registro de auditoría de las ejecuciones del propio auditor (Entrega 3).

Cada ejecución agrega una línea JSON con quién la ejecutó, cuándo, sobre qué
rutas, cuántos hallazgos hubo y el hash SHA-256 del reporte generado. Con el
hash se puede comprobar después que un reporte no fue modificado.

El archivo se abre en modo solo-agregar (O_APPEND) y antes de escribir se
verifica que no haya sido alterado: debe ser un archivo regular, del mismo
dueño que el proceso y sin permisos para grupo ni otros. Si algo no cuadra, el
auditor se detiene en lugar de escribir en un registro que no es confiable.
"""

import hashlib
import json
import os
import socket
import stat
from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional

from .modelos import EstadisticasEscaneo, Hallazgo
from .seguridad import ErrorSeguridad

REGISTRO_SISTEMA = "/var/log/auditor-permisos.log"


def ruta_por_defecto() -> str:
    """root escribe en /var/log; un usuario normal, en su propia carpeta."""
    if os.geteuid() == 0:
        return REGISTRO_SISTEMA
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "auditor-permisos", "registro.log")


def sha256_texto(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def _abrir_registro(ruta: str) -> int:
    carpeta = os.path.dirname(ruta)
    if carpeta and not os.path.isdir(carpeta):
        os.makedirs(carpeta, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(ruta, flags, 0o600)
    except OSError as e:
        raise ErrorSeguridad(f"no se pudo abrir el registro '{ruta}': {e.strerror}")
    # Se revisa el archivo ya abierto (fstat sobre el descriptor), no la ruta,
    # para que nadie pueda cambiarlo entre la verificación y la escritura.
    st = os.fstat(fd)
    problema = None
    if not stat.S_ISREG(st.st_mode):
        problema = "no es un archivo regular"
    elif st.st_uid != os.geteuid():
        problema = f"pertenece al UID {st.st_uid} y no al usuario que ejecuta el auditor"
    elif stat.S_IMODE(st.st_mode) & 0o077:
        problema = f"tiene permisos {stat.S_IMODE(st.st_mode):04o}; debe ser 0600"
    if problema:
        os.close(fd)
        raise ErrorSeguridad(f"el registro '{ruta}' {problema}. No se registrará nada en él.")
    return fd


def registrar_ejecucion(ruta_registro: str, argumentos: List[str], rutas: List[str],
                        hallazgos: List[Hallazgo], est: EstadisticasEscaneo,
                        ruta_reporte: Optional[str], hash_reporte: Optional[str], version: str) -> dict:
    conteo = Counter(h.severidad.name for h in hallazgos)
    entrada = {
        "fecha": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "equipo": socket.gethostname(),
        "invocado_por": os.environ.get("SUDO_USER") or _nombre_actual(),
        "uid_real": os.getuid(),
        "uid_efectivo": os.geteuid(),
        "comando": " ".join(["auditor.py"] + argumentos),
        "rutas": rutas,
        "archivos": est.archivos,
        "directorios": est.directorios,
        "rutas_sin_acceso": len(est.sin_acceso),
        "hallazgos": {"ALTA": conteo["ALTA"], "MEDIA": conteo["MEDIA"], "BAJA": conteo["BAJA"]},
        "reporte": os.path.abspath(ruta_reporte) if ruta_reporte else None,
        "sha256_reporte": hash_reporte,
        "version": version,
    }
    fd = _abrir_registro(ruta_registro)
    try:
        os.write(fd, (json.dumps(entrada, ensure_ascii=False) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return entrada


def _nombre_actual() -> str:
    import pwd
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return f"uid {os.getuid()}"
