import { registerAnalyzeAssetVulnerabilitiesPrompt } from './analyze_asset_vulnerabilities.js';
import { registerAnalyzeSuspiciousIpPrompt } from './analyze_suspicious_ip.js';

export function registerPrompts() {
  registerAnalyzeSuspiciousIpPrompt();
  registerAnalyzeAssetVulnerabilitiesPrompt();
}