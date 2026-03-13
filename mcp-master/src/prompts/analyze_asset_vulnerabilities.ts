import { server } from '../server.js';
import { z } from 'zod';

export function registerAnalyzeAssetVulnerabilitiesPrompt() {
  server.registerPrompt(
    'analyze_asset_vulnerabilities',
    {
      title: 'Analyze asset vulnerabilities and take action',
      description:
        'Evalúa vulnerabilidades (CVE) asociadas a un activo, determina el riesgo real y recomienda acciones defensivas.',
      argsSchema: {
        cve_id: z.string().describe('CVE de activo a analizar'),
        asset_description: z.string().describe('Descripción del activo a analizar'),
        reported_severity: z
          .enum(['low', 'medium', 'high', 'critical'])
          .describe('Severidad sugerida del evento')
      }
    },
    async ({ cve_id, asset_description, reported_severity }) => {
      return {
        messages: [
            {
            role: 'user',
            content: {
              type: 'text',
              text: `
Se ha identificado una vulnerabilidad en un activo de la red.

Datos disponibles:
- CVE: ${cve_id}
- Descripción del activo: ${asset_description}
- Severidad reportada: ${reported_severity}

Instrucciones de análisis (obligatorias):
1. Obtén los detalles técnicos del CVE utilizando la herramienta search_cve_by_id
2. Evalúa el impacto y probabilidad utilizando summarize_cve_risk
3. Cruza la información con la matriz de riesgo disponible
4. Ajusta el nivel de riesgo según el contexto del activo
5. Emite una conclusión basada únicamente en evidencia verificable

Restricciones estrictas:
- No asumas información no provista o no obtenida vía herramientas
- No incluyas recomendaciones genéricas sin sustento
- No incluyas texto fuera del JSON final
                                               
IMPORTANTE:                                                                                    
Responde EXCLUSIVAMENTE en JSON valido con el siguiente formato.                               
NO incluyas texto fuera del JSON.
NO incluyas explicaciones. 
Responde en español.  

Formato obligatorio:           

{
  "risk": "Low | Medium | High | Critical",
  "analysis": "análisis técnico y contextual basado en evidencia",
  "reason": "justificación breve y concreta del nivel de riesgo"
}
`
            }
          }
        ],
        tools: [
            {
                name: 'search_cve_by_id',
                description: 'Obtiene información técnica detallada de un CVE específico.',
                args: {
                cve_id
                }
            },
            {
                name: 'summarize_cve_risk',
                description: 'Evalúa impacto, explotabilidad y severidad de un CVE.',
                args: {
                cve_id 
                }
            }
        ],
            resources: [
            {
                uri: 'resource://playbook.vuln_high_risk'
            }
            ]
        };
      }
  );
}