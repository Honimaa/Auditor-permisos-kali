"""Estructuras de datos compartidas por todos los módulos del auditor."""

from dataclasses import dataclass, field
from enum import IntEnum


class Severidad(IntEnum):
    """Nivel de riesgo de un hallazgo. IntEnum permite ordenar y filtrar con < y >."""
    BAJA = 1
    MEDIA = 2
    ALTA = 3


@dataclass(frozen=True)
class EntradaArchivo:
    """Metadatos de un archivo o directorio, tal como los entrega lstat()."""
    ruta: str
    modo: int        # st_mode: tipo de archivo + bits de permisos (incluye SUID/SGID/sticky)
    uid: int         # st_uid: dueño
    gid: int         # st_gid: grupo
    es_directorio: bool


@dataclass
class Hallazgo:
    """Una configuración de riesgo detectada por una regla."""
    regla: str
    severidad: Severidad
    ruta: str
    permisos: str
    detalle: str
    recomendacion: str


@dataclass
class EstadisticasEscaneo:
    """Contadores que el escáner va llenando durante el recorrido."""
    archivos: int = 0
    directorios: int = 0
    enlaces_omitidos: int = 0
    especiales_omitidos: int = 0
    desaparecidos: int = 0
    sin_acceso: list = field(default_factory=list)
    duracion_s: float = 0.0
