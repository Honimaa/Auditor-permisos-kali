"""Recorrido del sistema de archivos.

Usa os.scandir() con una pila explícita (no recursión) para no chocar con el
límite de recursión de Python en árboles profundos. Cada entrada se lee con
lstat (follow_symlinks=False) para obtener los permisos del propio archivo y no
los del destino de un enlace simbólico.
"""

import os
import stat
import time
from typing import Iterable, Iterator, Optional

from .modelos import EntradaArchivo, EstadisticasEscaneo

# Sistemas de archivos virtuales: no son archivos en disco, los genera el kernel
# al vuelo y recorrerlos produce miles de entradas sin sentido para la auditoría.
EXCLUIDOS_POR_DEFECTO = ("/proc", "/sys", "/dev", "/run")


class Escaner:
    def __init__(self, raices: Iterable[str], excluir: Iterable[str] = EXCLUIDOS_POR_DEFECTO,
                 max_profundidad: Optional[int] = None, mismo_fs: bool = False):
        self.raices = [os.path.abspath(r) for r in raices]
        self.excluir = {os.path.abspath(e) for e in excluir}
        self.max_profundidad = max_profundidad
        self.mismo_fs = mismo_fs
        self.estadisticas = EstadisticasEscaneo()

    def _crear_entrada(self, ruta: str, st: os.stat_result) -> EntradaArchivo:
        return EntradaArchivo(ruta=ruta, modo=st.st_mode, uid=st.st_uid, gid=st.st_gid,
                              es_directorio=stat.S_ISDIR(st.st_mode))

    def _iterar_seguro(self, iterador, ruta_dir: str):
        """Itera un os.scandir() tolerando errores en medio de la lectura.

        Abrir el directorio (openat) puede funcionar y aun así fallar la lectura
        de entradas (getdents64): pasa en /proc/<pid>/map_files incluso como
        root. Sin esto, una sola carpeta abortaba toda la auditoría."""
        while True:
            try:
                entrada = next(iterador)
            except StopIteration:
                return
            except OSError as e:
                self.estadisticas.sin_acceso.append(f"{ruta_dir} ({e.strerror})")
                return
            yield entrada

    def recorrer(self) -> Iterator[EntradaArchivo]:
        """Genera una EntradaArchivo por cada archivo regular y directorio encontrado."""
        inicio = time.perf_counter()
        est = self.estadisticas
        for raiz in self.raices:
            try:
                st_raiz = os.lstat(raiz)
            except (FileNotFoundError, PermissionError) as e:
                est.sin_acceso.append(f"{raiz} ({e.strerror})")
                continue
            dispositivo_raiz = st_raiz.st_dev
            yield self._crear_entrada(raiz, st_raiz)
            if not stat.S_ISDIR(st_raiz.st_mode):
                continue
            est.directorios += 1

            pila = [(raiz, 0)]
            while pila:
                ruta_dir, profundidad = pila.pop()
                try:
                    iterador = os.scandir(ruta_dir)
                except PermissionError:
                    # Sin bit x/r sobre el directorio: el kernel niega la lectura.
                    est.sin_acceso.append(ruta_dir)
                    continue
                except FileNotFoundError:
                    est.desaparecidos += 1
                    continue

                with iterador:
                    for entrada in self._iterar_seguro(iterador, ruta_dir):
                        ruta = entrada.path
                        try:
                            if entrada.is_symlink():
                                # lrwxrwxrwx siempre: sus permisos no se usan, cuentan los del destino.
                                est.enlaces_omitidos += 1
                                continue
                            st = entrada.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            # El archivo se borró entre el listado y el stat (ej. archivos temporales).
                            est.desaparecidos += 1
                            continue
                        except PermissionError:
                            est.sin_acceso.append(ruta)
                            continue

                        if stat.S_ISDIR(st.st_mode):
                            if ruta in self.excluir:
                                continue
                            if self.mismo_fs and st.st_dev != dispositivo_raiz:
                                continue
                            est.directorios += 1
                            yield self._crear_entrada(ruta, st)
                            if self.max_profundidad is None or profundidad + 1 < self.max_profundidad:
                                pila.append((ruta, profundidad + 1))
                        elif stat.S_ISREG(st.st_mode):
                            est.archivos += 1
                            yield self._crear_entrada(ruta, st)
                        else:
                            # Sockets, FIFOs, dispositivos de bloque/caracter.
                            est.especiales_omitidos += 1
        est.duracion_s = time.perf_counter() - inicio
