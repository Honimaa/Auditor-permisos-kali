# Auditor de permisos y configuraciones de riesgo en sistemas Linux

Proyecto de aula — Sistemas Operacionales, Politécnico Grancolombiano.
Autor: Juan Camilo Bejarano Chacón. Versión del avance: 0.2.0 (Entrega 2).

Herramienta de línea de comandos que recorre el sistema de archivos y reporta
configuraciones de permisos riesgosas, clasificadas por severidad y con una
recomendación de corrección. Solo usa la biblioteca estándar de Python 3.8+.

## Uso

```bash
sudo python3 auditor.py /etc /home /usr/bin            # consola + reporte_FECHA.html
sudo python3 auditor.py / --min-severidad ALTA --sin-html
python3 auditor.py --help
```

Código de salida: `2` = hay hallazgos ALTA, `1` = otros hallazgos, `0` = sin hallazgos.

## Reglas implementadas

| Regla | Detecta | Severidad |
|---|---|---|
| R01 | Archivo con permisos 777 | ALTA |
| R02 | Archivo con escritura para "otros" (ej. 666) | MEDIA |
| R03 | Directorio con escritura global sin sticky bit | ALTA |
| R04 | Binario SUID fuera de la lista base | ALTA (dueño root) / MEDIA; BAJA si es esperado |
| R05 | Binario SGID fuera de la lista base | MEDIA |
| R06 | UID o GID inexistente en /etc/passwd o /etc/group | MEDIA / BAJA |
| R07 | /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow, /etc/sudoers con permisos de más | ALTA |

## Laboratorio de pruebas (solo en una máquina virtual)

```bash
sudo bash lab/preparar_entorno.sh            # crea /opt/lab_auditoria con fallas sembradas
sudo python3 auditor.py /opt/lab_auditoria
sudo bash lab/limpiar_entorno.sh
```

## Pruebas unitarias

```bash
python3 -m unittest -v          # como usuario normal (una prueba requiere no ser root)
sudo python3 -m unittest -v     # como root (la prueba de UID inexistente requiere root)
```

## Estructura

```
auditor.py            CLI: argumentos y orquestación
auditor/escaner.py    recorrido con os.scandir + lstat (pila explícita, sin seguir enlaces)
auditor/reglas.py     reglas R01–R07 y listas base de SUID/SGID
auditor/usuarios.py   UID/GID válidos (pwd, grp)
auditor/reporte.py    salida en consola y HTML
auditor/modelos.py    estructuras de datos compartidas
lab/                  scripts para crear y borrar el laboratorio
tests/                pruebas unitarias
```
