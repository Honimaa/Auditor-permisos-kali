"""Pruebas unitarias de las reglas. Ejecutar desde la raíz del proyecto:
    python3 -m unittest -v
Las pruebas que necesitan root (chown a UID inexistente) se omiten si no se es root."""

import os
import tempfile
import unittest

from auditor.escaner import Escaner
from auditor.modelos import Severidad
from auditor.reglas import Contexto, evaluar, verificar_archivos_sensibles
from auditor.usuarios import BaseUsuarios


class PruebasReglas(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        os.chmod(self.dir, 0o755)
        self.ctx = Contexto(BaseUsuarios())

    def tearDown(self):
        self.tmp.cleanup()

    def _archivo(self, nombre, modo):
        ruta = os.path.join(self.dir, nombre)
        with open(ruta, "w") as f:
            f.write("x")
        os.chmod(ruta, modo)
        return ruta

    def _auditar(self):
        hallazgos = []
        esc = Escaner([self.dir], excluir=[])
        for e in esc.recorrer():
            hallazgos.extend(evaluar(e, self.ctx))
        return hallazgos, esc.estadisticas

    def _reglas_de(self, hallazgos, ruta):
        return {h.regla for h in hallazgos if h.ruta == ruta}

    def test_777_es_alta(self):
        r = self._archivo("a.sh", 0o777)
        h, _ = self._auditar()
        self.assertIn("R01-PERMISOS-777", self._reglas_de(h, r))
        self.assertTrue(all(x.severidad == Severidad.ALTA for x in h if x.ruta == r))

    def test_666_es_escritura_otros(self):
        r = self._archivo("b.txt", 0o666)
        h, _ = self._auditar()
        self.assertEqual({"R02-ESCRITURA-OTROS"}, self._reglas_de(h, r))

    def test_644_no_genera_hallazgos(self):
        r = self._archivo("c.txt", 0o644)
        h, _ = self._auditar()
        self.assertEqual(set(), self._reglas_de(h, r))

    def test_directorio_777_sin_sticky(self):
        d = os.path.join(self.dir, "compartida"); os.mkdir(d); os.chmod(d, 0o777)
        h, _ = self._auditar()
        self.assertIn("R03-DIR-SIN-STICKY", self._reglas_de(h, d))

    def test_directorio_1777_con_sticky_es_correcto(self):
        d = os.path.join(self.dir, "tmp"); os.mkdir(d); os.chmod(d, 0o1777)
        h, _ = self._auditar()
        self.assertEqual(set(), self._reglas_de(h, d))

    def test_suid_fuera_de_lista_base(self):
        r = self._archivo("bin_suid", 0o4755)
        h, _ = self._auditar()
        self.assertIn("R04-SUID", self._reglas_de(h, r))

    def test_sgid_fuera_de_lista_base(self):
        r = self._archivo("bin_sgid", 0o2755)
        h, _ = self._auditar()
        self.assertIn("R05-SGID", self._reglas_de(h, r))

    def test_enlaces_simbolicos_se_omiten(self):
        destino = self._archivo("real.txt", 0o644)
        enlace = os.path.join(self.dir, "enlace"); os.symlink(destino, enlace)
        h, est = self._auditar()
        self.assertEqual(set(), self._reglas_de(h, enlace))
        self.assertEqual(1, est.enlaces_omitidos)

    @unittest.skipUnless(os.geteuid() == 0, "requiere root para chown")
    def test_uid_inexistente(self):
        r = self._archivo("huerfano", 0o644)
        os.chown(r, 4242, 4242)
        h, _ = self._auditar()
        self.assertTrue({"R06-SIN-DUENO", "R06-SIN-GRUPO"} <= self._reglas_de(h, r))

    def test_archivo_sensible_con_permisos_abiertos(self):
        falso_shadow = self._archivo("shadow", 0o644)
        ctx = Contexto(BaseUsuarios(), sensibles={falso_shadow: 0o640})
        h = verificar_archivos_sensibles(ctx)
        self.assertEqual(1, len(h))
        self.assertEqual("R07-ARCHIVO-SENSIBLE", h[0].regla)

    @unittest.skipIf(os.geteuid() == 0, "root ignora los permisos de lectura")
    def test_directorio_sin_acceso_se_registra(self):
        d = os.path.join(self.dir, "privado"); os.mkdir(d); os.chmod(d, 0o000)
        try:
            _, est = self._auditar()
            self.assertIn(d, est.sin_acceso)
        finally:
            os.chmod(d, 0o755)


if __name__ == "__main__":
    unittest.main()
