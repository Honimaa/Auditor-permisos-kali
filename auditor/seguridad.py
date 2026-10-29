"""Mecanismos de seguridad del propio auditor (Entrega 3).

1. Menor privilegio: el auditor necesita root solo para LEER todo el disco.
   Apenas termina el escaneo y el registro de auditoría, suelta root y vuelve
   a la identidad del usuario que ejecutó sudo (SUDO_UID/SUDO_GID). Todo lo que
   escribe después (el reporte) lo escribe como ese usuario.
2. Escritura segura del reporte: el reporte es una lista de debilidades del
   sistema, así que nace con permisos 0600 y se crea con O_EXCL | O_NOFOLLOW
   para que nadie pueda redirigirlo con un enlace simbólico preparado.
"""

import os
import pwd
import stat
from typing import Optional, Tuple


class ErrorSeguridad(Exception):
    """Una verificación de seguridad falló; el programa no debe continuar."""


# ------------------------------------------------------------------ menor privilegio

def usuario_invocador() -> Optional[Tuple[int, int, str]]:
    """Devuelve (uid, gid, nombre) del usuario que ejecutó sudo, o None.

    sudo deja estas variables en el entorno. Solo se aceptan si el proceso es
    root (el único que puede bajar a otro UID) y si el UID existe y no es 0."""
    if os.geteuid() != 0:
        return None
    uid_txt, gid_txt = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid_txt or not gid_txt or not uid_txt.isdigit() or not gid_txt.isdigit():
        return None
    uid, gid = int(uid_txt), int(gid_txt)
    if uid == 0:
        return None
    try:
        nombre = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise ErrorSeguridad(f"SUDO_UID={uid} no corresponde a ningún usuario del sistema")
    return uid, gid, nombre


def reducir_privilegios(uid: int, gid: int, nombre: str) -> None:
    """Cambia el proceso de root al usuario indicado, de forma irreversible.

    El orden importa: primero los grupos suplementarios y el GID (cambiarlos
    requiere seguir siendo root) y al final el UID. os.setuid() ejecutado por
    root cambia el UID real, efectivo y guardado, así que no hay vuelta atrás."""
    if os.geteuid() != 0:
        raise ErrorSeguridad("reducir_privilegios() solo tiene sentido si el proceso es root")
    os.initgroups(nombre, gid)   # grupos suplementarios del usuario, no los de root
    os.setgid(gid)
    os.setuid(uid)
    # Verificación: si el proceso todavía pudiera volver a ser root, se aborta.
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise ErrorSeguridad("el proceso pudo recuperar root: la reducción de privilegios falló")
    if os.getuid() != uid or os.geteuid() != uid or os.getegid() != gid or 0 in os.getgroups():
        raise ErrorSeguridad("la identidad del proceso no quedó como se esperaba")


# ------------------------------------------------------------------ escritura segura

def directorio_inseguro(ruta_archivo: str) -> bool:
    """True si la carpeta destino es escribible por todos (como /tmp): ahí otro
    usuario podría preparar un enlace simbólico con el nombre del reporte."""
    carpeta = os.path.dirname(os.path.abspath(ruta_archivo)) or "."
    try:
        return bool(os.stat(carpeta).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def escribir_archivo_seguro(ruta: str, contenido: str) -> None:
    """Crea `ruta` con permisos 0600 y escribe `contenido`.

    O_CREAT | O_EXCL: falla si el archivo ya existe (incluido un enlace simbólico
    con ese nombre), así que nunca se sobrescribe ni se sigue un enlace.
    O_NOFOLLOW: segunda barrera contra enlaces simbólicos.
    El modo 0600 se pasa en la misma llamada open(), sin una ventana de tiempo
    en la que el archivo exista con permisos más abiertos."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(ruta, flags, 0o600)
    except FileExistsError:
        raise ErrorSeguridad(f"'{ruta}' ya existe (o es un enlace simbólico); no se sobrescribe")
    except OSError as e:
        raise ErrorSeguridad(f"no se pudo crear '{ruta}': {e.strerror}")
    try:
        os.fchmod(fd, 0o600)  # por si la umask del sistema fuera inusual
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(contenido)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(ruta)
        except OSError:
            pass
        raise
