import { z } from "zod";
import { server } from "../../server.js";

const DEFAULT_BASE_URL = "https://vulnerability.circl.lu/api";

function getBaseUrl() {
  return (process.env.CIRCL_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
}

function normalizeCveId(id: string) {
  return id.trim().toUpperCase();
}

async function fetchJson(url: string, timeoutMs = 15_000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  console.log(`[${new Date().toISOString()}] MCP Request URL CVE ID RISK - URL: ${url}`);

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        "user-agent": "mcp-server/1.0 (cve-tools)",
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(
        `HTTP ${res.status} ${res.statusText}${body ? ` - ${body.slice(0, 200)}` : ""}`
      );
    }

    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

function cvssToSeverityEs(score?: number | null) {
  if (score == null || Number.isNaN(score)) return "desconocida";
  if (score === 0) return "informativa";
  if (score <= 3.9) return "baja";
  if (score <= 6.9) return "media";
  if (score <= 8.9) return "alta";
  return "crítica";
}

function pickFirst<T>(arr: T[] | undefined | null): T | null {
  return Array.isArray(arr) && arr.length ? arr[0] : null;
}

function extractBasics(payload: any) {
  const cna = payload?.containers?.cna;

  const id =
    payload?.cveMetadata?.cveId ??
    payload?.id ??
    payload?.vuln_id ??
    payload?.cve ??
    null;

  const title =
    typeof cna?.title === "string"
      ? cna.title
      : typeof payload?.title === "string"
        ? payload.title
        : null;

  const affected = Array.isArray(cna?.affected) ? cna.affected : [];
  const firstAffected = affected.find((a: any) => a?.vendor || a?.product) ?? null;

  const vendor = typeof firstAffected?.vendor === "string" ? firstAffected.vendor : null;
  const product = typeof firstAffected?.product === "string" ? firstAffected.product : null;

  // descripción (preferir en, si no, primera)
  const descriptions = Array.isArray(cna?.descriptions) ? cna.descriptions : [];
  const description =
    descriptions.find((d: any) => d?.lang === "en")?.value ??
    descriptions.find((d: any) => d?.lang === "es")?.value ??
    //pickFirst(descriptions)?.value ??
    payload?.details ??
    payload?.summary ??
    payload?.description ??
    null;

  // CVSS (CVE JSON 5.2)
  const metrics = Array.isArray(cna?.metrics) ? cna.metrics : [];
  const cvssObj =
    metrics.find((m: any) => m?.cvssV3_1)?.cvssV3_1 ??
    metrics.find((m: any) => m?.cvssV3_0)?.cvssV3_0 ??
    null;

  const cvss =
    typeof cvssObj?.baseScore === "number"
      ? cvssObj.baseScore
      : typeof payload?.cvss === "number"
        ? payload.cvss
        : null;

  const cvssVector =
    typeof cvssObj?.vectorString === "string"
      ? cvssObj.vectorString
      : typeof payload?.cvssVector === "string"
        ? payload.cvssVector
        : null;

  // referencias (recortar para salida SOC)
  const refs: string[] = [];
  const cnaRefs = Array.isArray(cna?.references) ? cna.references : [];
  for (const r of cnaRefs) {
    const url = typeof r === "string" ? r : r?.url;
    if (url) refs.push(url);
  }

  const references = Array.from(new Set(refs)).slice(0, 8);

  return { id, title, vendor, product, description, cvss, cvssVector, references };
}

function parseCvssVector(vector?: string | null) {
  if (!vector || typeof vector !== "string") return null;

  // Ej: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  const cleaned = vector.replace(/^CVSS:\d\.\d\//i, "");
  const parts = cleaned.split("/");

  const map: Record<string, string> = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    if (k && v) map[k] = v;
  }
  return map;
}

function buildSocMessage(input: {
  cveId: string;
  title: string | null;
  vendor: string | null;
  product: string | null;
  cvss: number | null;
  severity: string;
  vector: string | null;
  vectorMap: Record<string, string> | null;
  description: string | null;
}) {
  const target =
    [input.vendor, input.product].filter(Boolean).join(" / ") ||
    input.title ||
    "producto no especificado";

  // Lectura simple del vector
  const av = input.vectorMap?.AV; // N,A,L,P
  const ac = input.vectorMap?.AC; // L,H
  const pr = input.vectorMap?.PR; // N,L,H
  const ui = input.vectorMap?.UI; // N,R
  const c = input.vectorMap?.C;   // N,L,H
  const i = input.vectorMap?.I;   // N,L,H
  const a = input.vectorMap?.A;   // N,L,H

  const alcance =
    av === "N" ? "remoto (red)" : av === "A" ? "red adyacente" : av === "L" ? "local" : av === "P" ? "físico" : "no determinado";

  const complejidad =
    ac === "L" ? "complejidad baja" : ac === "H" ? "complejidad alta" : "no determinada";

  const auth =
    pr === "N" ? "sin privilegios" : pr === "L" ? "privilegios bajos" : pr === "H" ? "privilegios altos" : "no determinado";

  const interacción =
    ui === "N" ? "sin interacción de usuario" : ui === "R" ? "requiere interacción" : "no determinado";

  const confidencialidad =
    c === "N" ? "ninguna perdida de confidencialidad" : c === "L" ? "perdida parcial de confidencialidad" : c === "H" ? "perdida total de confidencialidad" : "no determinada";

  const integridad =
    i === "N" ? "ninguna perdida de integridad" : i === "L" ? "perdida parcial de integridad" : i === "H" ? "perdida total de integridad" : "no determinada";

  const disponibilidad =
    a === "N" ? "ninguna perdida de disponibilidad" : a === "L" ? "perdida parcial de disponibilidad" : a === "H" ? "perdida total de disponibilidad" : "no determinada";

  const scoreTxt = input.cvss != null ? `CVSS ${input.cvss}` : "CVSS no disponible";

  // Mensaje SOC corto (texto plano, apto para Telegram)
  const lines: string[] = [];
  lines.push(`${input.cveId} — Severidad ${input.severity} (${scoreTxt})`);
  lines.push(`Activo/Producto: ${target}`);
  lines.push(`Condiciones: ${alcance}, ${complejidad}, ${auth}, ${interacción}, ${confidencialidad}, ${integridad}, ${disponibilidad}.`);

  if (input.description) {
    const d = input.description.replace(/\s+/g, " ").trim();
    lines.push(`Resumen: ${d.length > 240 ? d.slice(0, 237) + "..." : d}`);
  }

  //lines.push(
  //  "Acción SOC: validar exposición (internet/interno) y versiones afectadas; priorizar parche/mitigación en activos críticos; aumentar monitoreo (WAF/IDS/EDR) y revisar logs del servicio por intentos de explotación hasta remediación."
  //);

  return lines.join("\n");
}

export function registerSummarizeCveRiskTool() {
  server.registerTool(
    "summarize_cve_risk",
    {
      title: "Resumir riesgo de Ciberseguridad de un CVE",
      description:
        "Consulta Vulnerability-Lookup (CIRCL) y devuelve un resumen breve obtenido del análisis del CVE, accionable y orientado a SOC/Blue Team.",
      inputSchema: z.object({
        cve_id: z.string().min(9).describe("Identificador CVE (ej: CVE-2025-12345)."),
      }),
    },
    async (input) => {
      const cveId = normalizeCveId(input.cve_id);
      const base = getBaseUrl();
      const url = `${base}/vulnerability/${encodeURIComponent(cveId)}?with_linked=false&with_sightings=false`;

      try {
        const payload = await fetchJson(url);
        const basics = extractBasics(payload);
        console.log(`[${new Date().toISOString()}] MCP Request CVE RISK - basic: ${JSON.stringify(basics, null, 2)}`);

        const severity = cvssToSeverityEs(basics.cvss);
        const vectorMap = parseCvssVector(basics.cvssVector);

        const message = buildSocMessage({
          cveId,
          title: basics.title,
          vendor: basics.vendor,
          product: basics.product,
          cvss: basics.cvss,
          severity,
          vector: basics.cvssVector,
          vectorMap,
          description: basics.description,
        });

        const result = {
          query: { cve_id: cveId },
          cve: {
            id: basics.id ?? cveId,
            title: basics.title,
            vendor: basics.vendor,
            product: basics.product,
            description: basics.description,
            cvss: basics.cvss,
            severity,
            cvss_vector: basics.cvssVector,
            references: basics.references,
          },
          message, // <- clave para tu output parser: json.message
        };
        console.log(`[${new Date().toISOString()}] MCP Request URL CVE ID RISK - URL: ${JSON.stringify(result, null, 2)}`);

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
        };
      } catch (err: any) {
        const errorPayload = {
          query: { cve_id: cveId },
          error: {
            message: err?.message ?? String(err),
            endpoint: url,
          },
          message: `No fue posible resumir ${cveId}: ${err?.message ?? String(err)}`,
        };

        return {
          content: [{ type: "text", text: JSON.stringify(errorPayload, null, 2) }],
          structuredContent: errorPayload,
        };
      }
    }
  );
}
