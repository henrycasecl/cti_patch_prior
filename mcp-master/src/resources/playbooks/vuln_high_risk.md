# Playbook: Gestión de Vulnerabilidades de Alto Riesgo (playbook_vuln_high_risk)

## Objetivo
Establecer un flujo de respuesta inmediata para mitigar y remediar vulnerabilidades de severidad **Alta** o **Crítica** (CVSS ≥ 7.0) que pongan en riesgo la continuidad del negocio o la integridad de la información.

## Criterios de Activación
- Detección de vulnerabilidades críticas por scanners (Nessus, OpenVAS, etc.).
- Publicación de un **0-day** con exploit público activo.
- Alerta de compromiso de activos que manejan datos sensibles (PII, PCI, Financieros).
- Vulnerabilidades que permitan **RCE** (Remote Code Execution) o Escalada de Privilegios.

## Procedimiento de Respuesta

### 1. Identificación y Triage
- **Localización:** Identificar todos los activos afectados (IPs, Hostnames, Microservicios).
- **Impacto:** Determinar si el activo es crítico para la operación.
- **Validación:** Descartar falsos positivos mediante pruebas no intrusivas.

### 2. Contención Temporal (Stop-Gap)
*Si no se puede parchear de inmediato, reducir la superficie de ataque:*
- Aplicar reglas de firewall restrictivas (referencia: `block_ip.md`).
- Deshabilitar temporalmente el servicio o puerto vulnerable.
- En caso de ser un sitio Web y contar con controles WAF: Implementar reglas específicas en el WAF (Web Application Firewall).

### 3. Remediación
- **Aplicación de Parches:** Instalar actualizaciones de seguridad oficiales.
- **Workaround:** Aplicar cambios de configuración recomendados por el fabricante si el parche no está disponible.
- **Hardening:** Cerrar vectores secundarios que puedan facilitar la explotación.

### 4. Verificación y Cierre
- Realizar un escaneo de confirmación para asegurar que la vulnerabilidad fue mitigada.
- Revisar logs de seguridad para asegurar que no hubo explotación antes de la remediación.
- Documentar el tiempo de resolución y lecciones aprendidas.

## Comandos de Emergencia

| Acción | Comando Sugerido |
| :--- | :--- |
| **Aislar tráfico entrante** | `sudo ufw default deny incoming` |
| **Listar servicios vulnerables** | `systemctl list-units --type=service` |
| **Actualizar paquete específico** | `sudo apt-get install --only-upgrade <package>` |
| **Ver conexiones establecidas** | `ss -atp` |

## Consideraciones
- **Backup:** Siempre realizar un snapshot o respaldo del sistema antes de aplicar parches críticos.
- **Pre-producción**: De tener disponible, se recomienda generar una prueba rapida en un ambiente Pre Producción.
- **Comunicación:** Notificar a los dueños de los procesos de negocio sobre posibles interrupciones.
- **Ventana de Mantenimiento:** En vulnerabilidades críticas, la ventana de mantenimiento se considera de emergencia.

## Rollback
En caso de que el parche o la mitigación causen inestabilidad:
1. Restaurar sistema desde el último snapshot conocido.
2. Re-aplicar mitigaciones de red (firewall) para mantener el aislamiento mientras se busca una solución alternativa.
3. Escalar con el proveedor de software/servicio.