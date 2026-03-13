import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import http from 'http';
import https from 'https';
import fs from 'fs';

import { server } from './server.js';


import { registerAllTools } from './tools/index.js';
import { registerResources } from './resources/index.js';
import { registerPrompts } from './prompts/index.js';


const HTTP_PORT = Number(process.env.PORT || 3080);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 3443);
const CERT_PATH = process.env.CERT_PATH || '/certs';

// Tools
registerAllTools();
// Carga los recursos como playbook y matriz de riesgo
registerResources();
// carga los prompts
registerPrompts();

// --- HTTP MCP ---
const app = express();
app.use(express.json());

app.post('/mcp', async (req, res) => {

  try {
    const transport = new StreamableHTTPServerTransport({
      enableJsonResponse: true
    });

    res.on('close', () => {
      transport.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);

  } catch (error) {
    console.error('Error handling MCP request:', error);

    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error'
        },
        id: req.body?.id ?? null
      });
    }
  }
});

app.get('/mcp', (_, res) => {
  res.status(405).end();
});

// Health check para el cliente
app.get('/health', (_, res) => res.send('MCP Server Active'));

http.createServer(app).listen(HTTP_PORT, () => {
  console.log(
    `MCP server HTTP escuchando en http://0.0.0.0:${HTTP_PORT}/mcp`
  );
});

// --- HTTPS MCP ---
const httpsOptions = {
  key: fs.readFileSync(`${CERT_PATH}/key.pem`),
  cert: fs.readFileSync(`${CERT_PATH}/cert.pem`)
};

https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
  console.log(
    `MCP server HTTPS escuchando en https://0.0.0.0:${HTTPS_PORT}/mcp`
  );
});

