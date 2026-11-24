"""Reglas de detección. Cada regla recibe una EntradaArchivo y devuelve una
lista (posiblemente vacía) de Hallazgo. Agregar una regla nueva = escribir una
función y registrarla en REGLAS."""

import os
import stat
from typing import Dict, List

from .modelos import EntradaArchivo, Hallazgo, Severidad
from .usuarios import BaseUsuarios

# Las listas de binarios SUID/SGID esperados se leen de auditor/listas_base.conf
# (ver auditor/listas.py). Si un Contexto se crea sin listas, todo SUID/SGID se
# considera fuera de la lista base.

# Permisos máximos aceptables para archivos críticos. El registro de auditoría del
# propio auditor también se incluye: la herramienta se revisa a sí misma.
ARCHIVOS_SENSIBLES: Dict[str, int] = {
    "/etc/passwd": 0o644,
    "/etc/group": 0o644,
    "/etc/shadow": 0o640,
    "/etc/gshadow": 0o640,
    "/etc/sudoers": 0o440,
    "/var/log/auditor-permisos.log": 0o600,
}


def formato_permisos(modo: int) -> str:
    """Ej.: 0o104755 -> 'rwsr-xr-x (4755)'. stat.filemode ya maneja s/S/t/T."""
    return f"{stat.filemode(modo)[1:]} ({stat.S_IMODE(modo):04o})"


class Contexto:
    def __init__(self, usuarios: BaseUsuarios, suid_esperados=frozenset(),
                 sgid_esperados=frozenset(), sensibles=ARCHIVOS_SENSIBLES):
        self.usuarios = usuarios
        self.suid_esperados = suid_esperados
        self.sgid_esperados = sgid_esperados
        self.sensibles = sensibles


# ---------------------------------------------------------------- reglas

def regla_escritura_otros(e: EntradaArchivo, ctx: Contexto) -> List[Hallazgo]:
    """R01/R02: archivo regular con permiso de escritura para 'otros' (incluye 777 y 666)."""
    if e.es_directorio or not (e.modo & stat.S_IWOTH):
        return []
    permisos = stat.S_IMODE(e.modo) & 0o777
    if permisos == 0o777:
        return [Hallazgo("R01-PERMISOS-777", Severidad.ALTA, e.ruta, formato_permisos(e.modo),
                         "Cualquier usuario puede leer, modificar y ejecutar el archivo.",
                         f"chmod 755 '{e.ruta}' (o 750/700 según quién lo use)")]
    return [Hallazgo("R02-ESCRITURA-OTROS", Severidad.MEDIA, e.ruta, formato_permisos(e.modo),
                     "Cualquier usuario del sistema puede modificar el contenido.",
                     f"chmod o-w '{e.ruta}'")]


def regla_directorio_sin_sticky(e: EntradaArchivo, ctx: Contexto) -> List[Hallazgo]:
    """R03: directorio con escritura global SIN sticky bit. Sin el bit 't', cualquier
    usuario puede borrar o renombrar archivos de otros dentro del directorio.
    /tmp (1777) es el caso correcto y no se reporta."""
    if not e.es_directorio or not (e.modo & stat.S_IWOTH) or (e.modo & stat.S_ISVTX):
        return []
    return [Hallazgo("R03-DIR-SIN-STICKY", Severidad.ALTA, e.ruta, formato_permisos(e.modo),
                     "Directorio escribible por todos sin sticky bit: cualquiera puede borrar "
                     "o reemplazar archivos ajenos.",
                     f"chmod o-w '{e.ruta}'  o, si debe ser compartido, chmod +t '{e.ruta}'")]


def regla_suid_sgid(e: EntradaArchivo, ctx: Contexto) -> List[Hallazgo]:
    """R04/R05: binarios con SUID o SGID. Al ejecutarse toman la identidad del
    dueño/grupo del archivo. Tener el bit no significa ser vulnerable (passwd lo
    necesita), por eso los esperados se reportan como BAJA (inventario) y los
    demás como señales que requieren verificar origen y uso."""
    if e.es_directorio:
        return []
    hallazgos = []
    if e.modo & stat.S_ISUID:
        dueno = ctx.usuarios.nombre_usuario(e.uid)
        if e.ruta in ctx.suid_esperados:
            hallazgos.append(Hallazgo("R04-SUID", Severidad.BAJA, e.ruta, formato_permisos(e.modo),
                                      f"SUID esperado del sistema (dueño: {dueno}).",
                                      "Ninguna acción; verificar que siga siendo necesario."))
        else:
            sev = Severidad.ALTA if e.uid == 0 else Severidad.MEDIA
            hallazgos.append(Hallazgo("R04-SUID", sev, e.ruta, formato_permisos(e.modo),
                                      f"SUID activo fuera de la lista base; se ejecuta como '{dueno}'. "
                                      "Tener SUID no prueba una vulnerabilidad: hay que verificar origen y uso.",
                                      f"verificar con dpkg -S '{e.ruta}' si viene de un paquete; "
                                      f"si no se necesita, chmod u-s '{e.ruta}'"))
    if e.modo & stat.S_ISGID and e.ruta not in ctx.sgid_esperados:
        grupo = ctx.usuarios.nombre_grupo(e.gid)
        hallazgos.append(Hallazgo("R05-SGID", Severidad.MEDIA, e.ruta, formato_permisos(e.modo),
                                  f"SGID activo fuera de la lista base; se ejecuta con el grupo '{grupo}'. "
                                  "Requiere verificar su origen antes de considerarlo un riesgo.",
                                  f"verificar con dpkg -S '{e.ruta}' si viene de un paquete; "
                                  f"si no se necesita, chmod g-s '{e.ruta}'"))
    return hallazgos


def regla_sin_dueno(e: EntradaArchivo, ctx: Contexto) -> List[Hallazgo]:
    """R06: UID o GID que no existen en /etc/passwd o /etc/group. Si más adelante
    se crea un usuario con ese UID, heredará estos archivos sin que nadie lo note."""
    hallazgos = []
    if not ctx.usuarios.existe_uid(e.uid):
        hallazgos.append(Hallazgo("R06-SIN-DUENO", Severidad.MEDIA, e.ruta, formato_permisos(e.modo),
                                  f"El UID {e.uid} no corresponde a ningún usuario.",
                                  f"chown <usuario_valido> '{e.ruta}' o eliminar si es residuo"))
    if not ctx.usuarios.existe_gid(e.gid):
        hallazgos.append(Hallazgo("R06-SIN-GRUPO", Severidad.BAJA, e.ruta, formato_permisos(e.modo),
                                  f"El GID {e.gid} no corresponde a ningún grupo.",
                                  f"chgrp <grupo_valido> '{e.ruta}'"))
    return hallazgos


REGLAS = [regla_escritura_otros, regla_directorio_sin_sticky, regla_suid_sgid, regla_sin_dueno]


def evaluar(e: EntradaArchivo, ctx: Contexto) -> List[Hallazgo]:
    resultado = []
    for regla in REGLAS:
        resultado.extend(regla(e, ctx))
    return resultado


def verificar_archivos_sensibles(ctx: Contexto) -> List[Hallazgo]:
    """R07: se ejecuta aparte del recorrido, porque estos archivos se revisan
    siempre, sin importar qué carpetas haya elegido el usuario."""
    hallazgos = []
    for ruta, maximo in ctx.sensibles.items():
        try:
            st = os.lstat(ruta)
        except (FileNotFoundError, PermissionError):
            continue
        actuales = stat.S_IMODE(st.st_mode)
        sobrantes = actuales & ~maximo
        if sobrantes:
            hallazgos.append(Hallazgo("R07-ARCHIVO-SENSIBLE", Severidad.ALTA, ruta, formato_permisos(st.st_mode),
                                      f"Permisos más abiertos que el máximo recomendado ({maximo:04o}).",
                                      f"chmod {maximo:o} '{ruta}'"))
    return hallazgos
