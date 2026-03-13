import { server } from '../server.js';
import { z } from 'zod';

export function registerAnalyzeSuspiciousIpPrompt() {
  server.registerPrompt(
    'analyze_suspicious_ip',
    {
      title: 'Analyze suspicious IP and take action',
      description:
        'Analiza una IP sospechosa usando matriz de riesgo y playbook SOC, y decide si debe ser bloqueada.',
      argsSchema: {
        ip: z.string().describe('IP sospechosa'),
        description: z
          .string()
          .describe('Descripción del evento o alerta observada'),
        severity: z
          .enum(['low', 'medium', 'high', 'critical'])
          .describe('Severidad sugerida del evento')
      }
    },
    async ({ ip, description, severity }, _extra) => {
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `
Actúa como un analista SOC senior.

Debes evaluar riesgos de seguridad y recomendar acciones defensivas basadas en evidencia.

Se detectó la siguiente actividad sospechosa:

IP: ${ip}
Descripción: ${description}
Severidad sugerida: ${severity}

Instrucciones:
- Utiliza la matriz de riesgo (resource://risk.matrix)
- Utiliza el playbook de bloqueo IP (resource://playbook.block_ip)
- Evalúa el riesgo
- Decide si corresponde bloquear la IP
- Si decides bloquearla, indica explícitamente que debe ejecutarse la tool admin.ufw_block_ip

                                               
IMPORTANTE:                                                                                    
Responde EXCLUSIVAMENTE en JSON valido con el siguiente formato.                               
NO incluyas texto fuera del JSON.
NO incluyas explicaciones. 
Responde en español.  

Formato obligatorio:           

{
  "risk": "low|medium|high",
  "block": true|false,
  "reason": "justificación breve basada en evidencia"
}
`
            }
          }
        ],
        tools: [
          {
            name: 'admin.ufw_block_ip',
            description:
              'Bloquea una IP en el firewall UFW del servidor objetivo'
          }
        ],
        resources: [
          { uri: 'resource://risk.matrix' },
          { uri: 'resource://playbook.block_ip' }
        ]
      };
    }
  );
}
