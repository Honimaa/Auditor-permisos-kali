#!/usr/bin/env bash
# Demostración del ataque que evita la escritura segura del reporte (Entrega 3).
#
# Un usuario sin privilegios prepara, en una carpeta donde todos pueden escribir,
# un enlace simbólico con el nombre que tendrá el reporte y que apunta a un
# archivo de root. Un programa que escriba ese nombre como root siguiendo el
# enlace termina sobrescribiendo el archivo de root.
#
# Se usa /opt/lab_auditoria/compartida (777 SIN sticky bit) porque en carpetas
# como /tmp (1777) el kernel ya bloquea seguir enlaces ajenos
# (fs.protected_symlinks=1); en una carpeta sin sticky bit esa protección no aplica.
#
# Uso (en la VM de pruebas, después de lab/preparar_entorno.sh):
#     sudo bash lab/ataque_enlace.sh
set -uo pipefail
[[ $EUID -ne 0 ]] && { echo "Ejecute con sudo"; exit 1; }
USUARIO="${SUDO_USER:-estudiante}"
DIR=/opt/lab_auditoria/compartida
VICTIMA=/opt/lab_auditoria/archivo_de_root.txt
CEBO="$DIR/reporte_trampa.html"
[[ -d "$DIR" ]] || { echo "Primero ejecute: sudo bash lab/preparar_entorno.sh"; exit 1; }

preparar() {
    echo "contenido original de root" > "$VICTIMA"; chmod 600 "$VICTIMA"
    rm -f "$CEBO"
    sudo -u "$USUARIO" ln -s "$VICTIMA" "$CEBO"      # el "atacante" (sin privilegios) crea el enlace
}

echo "== 1) Escritura ingenua como root: open(ruta, 'w') =="
preparar; ls -l "$CEBO"
python3 -c "open('$CEBO', 'w').write('SOBRESCRITO POR EL REPORTE')" && echo "(escritura aceptada)"
echo "Archivo de root después:  $(cat "$VICTIMA")"
echo
echo "== 2) Auditor v0.3 con --mantener-root (peor caso: escribe como root) =="
preparar
python3 "$(dirname "$0")/../auditor.py" /opt/lab_auditoria/datos --html "$CEBO" --mantener-root \
    --color no --registro /root/registro_demo.log 2>&1 | grep -E "Error de seguridad|Reporte HTML"
echo "Archivo de root después:  $(cat "$VICTIMA")"
rm -f "$CEBO" "$VICTIMA" /root/registro_demo.log
