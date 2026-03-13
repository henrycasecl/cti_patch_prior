import { registerAdminTools } from './admin/index.js';
import { registerCtiTools } from './cti/index.js';
import { registerThreatIntelLookupTool } from './cti/threat_intel_lookup.js';

export function registerAllTools() {
  registerAdminTools();
  registerCtiTools();
  registerThreatIntelLookupTool();
}