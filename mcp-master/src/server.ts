import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

export const server = new McpServer({
  name: 'mcp-master',
  version: '1.0'
}, {
  capabilities: {
    prompts: {},   // Esto activa prompts/list
    resources: {}, // Esto activa resources/list
    tools: {}      // Esto activa tools/list
  }
});