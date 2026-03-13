import { registerSearchCvesByKeywordsTool } from './search_cves_by_keyword.js';
import { registerSummarizeCveRiskTool } from './summarize_cve_risk.js';
import { registerKevLookupTool } from './kev_lookup.js';

export function registerCtiTools() {
  registerSearchCvesByKeywordsTool();
  registerSummarizeCveRiskTool();
  registerKevLookupTool();
}