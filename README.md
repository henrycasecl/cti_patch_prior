# CTI Patch Prioritization System (TMF

Este repositorio contiene la infraestructura y los flujos de trabajo desarrollados para la priorización de parches basada en Inteligencia de Amenazas (CTI). El proyecto integra herramientas de análisis, automatización y bases de datos vectoriales para optimizar la respuesta ante vulnerabilidades.

## 🏗️ Estructura del Proyecto

El proyecto se organiza en los siguientes módulos principales:

* **/elk**: Configuraciones del stack Elasticsearch, Logstash y Kibana para la ingesta y visualización de logs de seguridad.
* **/n8n**: Workflows automatizados para la correlación de feeds de vulnerabilidades y alertas.
* **/qdrant**: Implementación de la base de datos vectorial para el almacenamiento de embeddings y búsqueda semántica de amenazas.
* **/mcp-master**: Controladores y scripts maestros para la gestión del protocolo de contexto.

## 🚀 Componentes Técnicos

* **Automatización:** Orquestación de procesos mediante n8n.
* **Análisis de Datos:** Procesamiento de grandes volúmenes de datos con el stack ELK.
* **IA Agentica:** Integración de agentes de IA para la toma de decisiones en el SOC.
* **Base de Datos:** Qdrant para la gestión eficiente de vectores de amenazas.

## 🛠️ Configuración Rápida

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/henrycasecl/cti_patch_prior.git](https://github.com/henrycasecl/cti_patch_prior.git)
   cd cti_patch_prior
