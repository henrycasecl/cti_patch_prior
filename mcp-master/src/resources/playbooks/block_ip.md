# Playbook: Bloqueo de IP Maliciosa (UFW)

## Objetivo
Reducir el riesgo operativo bloqueando direcciones IP con comportamiento malicioso
detectado por el SOC o herramientas de monitoreo.

## Criterios para bloqueo
- Múltiples intentos fallidos de autenticación
- Enumeración web (404 masivos, fuzzing)
- Tráfico automatizado no autorizado
- Coincidencia con CTI externa confiable

## Procedimiento
1. Validar la IP y el activo afectado
2. Confirmar severidad (media o superior)
3. Ejecutar bloqueo en firewall (UFW)
4. Verificar estado del firewall
5. Registrar la acción en ticket / SIEM

## Comando recomendado
sudo ufw deny from <IP>

## Consideraciones
- Evitar bloquear IPs internas o de gestión
- Revisar falsos positivos
- Documentar siempre la acción

## Rollback
En caso de bloqueo incorrecto:
sudo ufw delete deny from <IP>

