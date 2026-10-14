#!/usr/bin/env bash
# Crea un laboratorio con configuraciones inseguras INTENCIONALES para probar el auditor.
# Ejecutar SOLO en una máquina virtual de pruebas:  sudo bash lab/preparar_entorno.sh
set -euo pipefail

LAB="${1:-/opt/lab_auditoria}"
if [[ $EUID -ne 0 ]]; then echo "Ejecute con sudo (se necesita root para SUID root y chown)"; exit 1; fi

rm -rf "$LAB"
mkdir -p "$LAB"/{scripts,compartida,tmp_correcto,datos,bin}

# --- Casos que DEBEN detectarse -------------------------------------------
echo '#!/bin/bash' > "$LAB/scripts/backup.sh";  chmod 777 "$LAB/scripts/backup.sh"     # R01 777
echo 'notas internas' > "$LAB/datos/notas.txt";  chmod 666 "$LAB/datos/notas.txt"     # R02 escritura otros
chmod 777 "$LAB/compartida"                                                          # R03 dir sin sticky
cp "$(command -v find)" "$LAB/bin/find_copia";  chmod 4755 "$LAB/bin/find_copia"     # R04 SUID root no esperado
cp "$(command -v id)"   "$LAB/bin/id_sgid";     chmod 2755 "$LAB/bin/id_sgid"        # R05 SGID no esperado
echo 'residuo' > "$LAB/datos/huerfano.txt";      chown 4242:4242 "$LAB/datos/huerfano.txt"  # R06 UID/GID inexistentes

# --- Casos que NO deben detectarse (controles) -----------------------------
chmod 1777 "$LAB/tmp_correcto"                                                       # como /tmp: sticky bit OK
echo 'ok' > "$LAB/datos/seguro.txt";             chmod 644 "$LAB/datos/seguro.txt"
ln -sf /etc/shadow "$LAB/datos/enlace_a_shadow"                                      # enlace: lrwxrwxrwx, se omite

echo "Laboratorio creado en $LAB"
ls -la "$LAB"/*
