import { z } from "zod";
import { server } from "../../server.js";

const VT_API_KEY = process.env.VT_API_KEY;
const VT_BASE_URL = "https://www.virustotal.com/api/v3/collections";

if (!VT_API_KEY) {
    console.warn("[MCP] VT_API_KEY no definida en el entorno");
}

const toDateTime = (ts?: number | null) =>
    ts ? new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) : "No disponible";

const limitText = (s?: string | null, max = 500) =>
    s ? s.replace(/\n+/g, " ").slice(0, max) : "No disponible";

type GtiSource = {
    name?: string | null;
    url?: string | null;
};

export function registerThreatIntelLookupTool() {
    server.registerTool(
        "threat_intel_lookup",
        {
            title: "Consultar inteligencia de amenaza (VirusTotal GTI)",
            description:
                "Consulta VirusTotal GTI para obtener contexto de explotación y riesgo asociado a un CVE.",
            inputSchema: z.object({
                cve_id: z
                    .string()
                    .regex(/^CVE-\d{4}-\d{4,}$/i, "Formato CVE inválido"),
            }),
        },
        async (input) => {
            const cveId = input.cve_id.toUpperCase();
            const collectionId = `vulnerability--${cveId}`;

            if (!VT_API_KEY) {
                return {
                    content: [
                        {
                            type: "text",
                            text: "VT_API_KEY no configurada en el servidor MCP.",
                        },
                    ],
                    structuredContent: {
                        threat_intel: {
                            has_intel: false,
                            source: "virustotal-gti",
                            error: "API_KEY_NOT_CONFIGURED",
                        },
                    },
                };
            }

            try {
                const res = await fetch(`${VT_BASE_URL}/${collectionId}`, {
                    headers: {
                        accept: "application/json",
                        "x-apikey": VT_API_KEY,
                        "user-agent": "mcp-server/1.0 (threat-intel)",
                    },
                });

                if (res.status === 404) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `VirusTotal no posee inteligencia GTI para ${cveId}.`,
                            },
                        ],
                        structuredContent: {
                            threat_intel: {
                                has_intel: false,
                                source: "virustotal-gti",
                            },
                        },
                    };
                }

                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }

                const data = await res.json();
                const attr = data?.data?.attributes;

                if (!attr) {
                    throw new Error("Respuesta GTI sin atributos esperados");
                }

                const tags: string[] = Array.isArray(attr.tags) ? attr.tags : [];

                const isKev = Boolean(attr.cisa_known_exploited);
                const wasZeroDay = tags.includes("was_zero_day");
                const observedInTheWild = tags.includes("observed_in_the_wild");

                console.log(`[${new Date().toISOString()}] MCP Request URL CVE GTI ${cveId}`);

                const creationDate = toDateTime(attr.creation_date);
                const lastModified = toDateTime(attr.last_modification_date);
                const exploitReleaseDate = toDateTime(attr.exploitation?.exploit_release_date);
                const exploitAvailability = attr.exploit_availability ?? "No especificada";
                const hasExploits = attr.tags?.includes("has_exploits") ? "Sí" : "No";
                const executiveSummary = limitText(attr.executive_summary, 600);

                const sources: string[] =
                    Array.isArray(attr.sources)
                        ? (attr.sources as GtiSource[])
                            .filter((s: GtiSource) => s.name || s.url)
                            .slice(0, 5)
                            .map(
                                (s: GtiSource) =>
                                    `- ${s.name ?? "Fuente"}: ${s.url ?? "URL no disponible"}`
                            )
                        : [];

                const contentText = [
                    `Contexto de inteligencia para ${cveId} (VirusTotal GTI):`,
                    ``,
                    `Estado de explotación: ${attr.exploitation_state ?? "No disponible"}`,
                    `Prioridad GTI: ${attr.priority ?? "No definida"}`,
                    `Riesgo GTI: ${attr.risk_rating ?? "No definido"}`,
                    ``,
                    `Exploit disponible públicamente: ${exploitAvailability ?? "No disponible"}`,
                    `Exploit reportado: ${hasExploits ?? "No reportado"}`,
                    `Fecha publicación exploit: ${exploitReleaseDate ?? "No disponible"}`,
                    ``,
                    `EPSS score: ${attr.epss?.score ?? "No disponible"} (percentil ${attr.epss?.percentile ?? "N/A"})`,
                    ``,
                    `Resumen ejecutivo GTI:`,
                    executiveSummary,
                    ``,
                    sources.length > 0 ? `Fuentes relevantes:` : null,
                    ...sources,
                    ``,
                    `Fecha creación registro GTI: ${creationDate}`,
                    `Última actualización GTI: ${lastModified}`,
                    `Fuente: VirusTotal GTI`,
                    `Referencia: https://www.virustotal.com/gui/collection/${collectionId}`,

                ].filter(Boolean).join("\n");

                return {
                    content: [
                        {
                            type: "text",
                            text: contentText,
                        },
                    ],
                    structuredContent: {
                        threat_intel: {
                            has_intel: true,
                            exploitation_state: attr.exploitation_state || "Desconocido",
                            priority: attr.priority || "No definido",
                            risk_rating: attr.risk_rating || "No definido",
                            predicted_risk_rating: attr.predicted_risk_rating || "No definido",
                            epss: attr.epss
                                ? {
                                    score: attr.epss.score,
                                    percentile: attr.epss.percentile,
                                }
                                : null,
                            is_kev: isKev,
                            ransomware_use:
                                attr.cisa_known_exploited?.ransomware_use || "No especificado",
                            was_zero_day: wasZeroDay,
                            observed_in_the_wild: observedInTheWild,
                            tags,
                            source: "virustotal-gti",
                            reference: `https://www.virustotal.com/gui/collection/${collectionId}`,
                        },
                    },
                };
            } catch (err: any) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error consultando VirusTotal GTI: ${err.message}`,
                        },
                    ],
                    structuredContent: {
                        threat_intel: {
                            has_intel: false,
                            source: "virustotal-gti",
                            error: err.message,
                        },
                    },
                };
            }
        }
    );
}
