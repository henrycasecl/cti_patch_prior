import { server } from '../server.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// equivalente a __dirname en ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function log(...args: any[]) {
  console.log('[MCP-RESOURCE]', ...args);
}

// resources/ queda copiado a dist/resources
const basePath = path.resolve(__dirname);
log('[MCP] Resources basePath:', basePath);

export function registerResources() {

  server.registerResource(
    'playbook.vuln_high_risk',
    'resource://playbook.vuln_high_risk',
    {
      title: 'Playbook: Gestión de Vulnerabilidad Alta Riesgo',
      description: 'Procedimiento Ciberseguridad para manejo de vulnerabilidades de alto riesgo'
    },
    async () => {
      try {
        log('Handler invoked');
        log('__dirname =', __dirname);

        const filePath = path.join(__dirname, 'playbooks/vuln_high_risk.md');
        log('filePath =', filePath);
        log('exists =', fs.existsSync(filePath));

        if (!fs.existsSync(filePath)) {
          throw new Error(`File not found: ${filePath}`);
        }

        const text = fs.readFileSync(filePath, 'utf-8');
        log('read OK, length =', text.length);

        const resourceUri = 'resource://playbook.vuln_high_risk';
        log('returning resource uri =', resourceUri);

        return {
          contents: [
            {
              uri: resourceUri,
              text,
              mimeType: 'text/markdown'
            }
          ]
        };
      } catch (err) {
        console.error('[MCP-RESOURCE][ERROR]', err);
        throw err; // fuerza que MCP muestre el error real
      }
    }
  );


  server.registerResource(
    'playbook.block_ip',
    'resource://playbook.block_ip',
    {
      title: 'Playbook: Bloqueo de IP',
      description: 'Procedimiento SOC para bloqueo de IPs maliciosas'
    },
    async () => {
      try {
        log('Handler invoked');
        log('__dirname =', __dirname);

        const filePath = path.join(__dirname, 'playbooks/block_ip.md');
        log('filePath =', filePath);
        log('exists =', fs.existsSync(filePath));

        if (!fs.existsSync(filePath)) {
          throw new Error(`File not found: ${filePath}`);
        }

        const stat = fs.statSync(filePath);
        log('file size =', stat.size);

        const text = fs.readFileSync(filePath, 'utf-8');
        log('read OK, length =', text.length);

        const resourceUri = 'resource://playbook.block_ip';
        log('returning resource uri =', resourceUri);

        return {
          contents: [
            {
              uri: resourceUri,
              text,
              mimeType: 'text/markdown'
            }
          ]
        };
      } catch (err) {
        console.error('[MCP-RESOURCE][ERROR]', err);
        throw err; // fuerza que MCP muestre el error real
      }
    }
  );

  server.registerResource(
    'risk.matrix',
    'resource://risk.matrix',
    {
      title: 'Risk Matrix',
      description: 'Matriz de riesgo Ciberseguridad'
    },
    async () => {
      const text = fs.readFileSync(
        path.join(basePath, 'risk/risk_matrix.json'),
        'utf-8'
      );

      return {
        contents: [
          {
            uri: 'resource://risk.matrix',
            text,
            mimeType: 'application/json'
          }
        ]
      };
    }
  );
}

