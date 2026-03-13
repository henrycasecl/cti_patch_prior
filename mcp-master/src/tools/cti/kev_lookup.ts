import { z } from "zod";
import { server } from "../../server.js";
import fs from "fs";
import path from "path";

const KEV_URL =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const DATA_DIR = path.resolve("data");
const KEV_FILE = path.join(DATA_DIR, "kev.json");
const META_FILE = path.join(DATA_DIR, "kev.meta.json");

/* ============================
   Helpers
============================ */
function todayISO() {
    return new Date().toISOString().split("T")[0];
}

function nowISO() {
    return new Date().toISOString();
}

function safeReadJSON(filePath: string): any | null {
    try {
        if (!fs.existsSync(filePath)) return null;
        return JSON.parse(fs.readFileSync(filePath, "utf-8"));
    } catch {
        return null;
    }
}

function writeJSON(filePath: string, data: any) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

async function fetchKevDatabase() {
    const res = await fetch(KEV_URL, {
        headers: {
            accept: "application/json",
            "user-agent": "mcp-server/1.0 (kev-lookup)",
        },
    });

    if (!res.ok) {
        throw new Error(`HTTP ${res.status} al descargar KEV`);
    }

    const json = await res.json();
    return { json, headers: res.headers };
}

function isKevUpToDate(): boolean {
    const meta = safeReadJSON(META_FILE);
    if (!meta) return false;
    return meta.lastUpdated === todayISO();
}

async function ensureKevDatabase() {
    if (fs.existsSync(KEV_FILE) && isKevUpToDate()) {
        return;
    }

    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const { json: kevData, headers } = await fetchKevDatabase();

    // Guardamos metadata útil si existe
    const meta = {
        lastUpdated: todayISO(),
        retrievedAt: nowISO(),
        sourceUrl: KEV_URL,
        etag: headers.get("etag") ?? null,
        lastModified: headers.get("last-modified") ?? null,
    };

    writeJSON(KEV_FILE, kevData);
    writeJSON(META_FILE, meta);
}

/* ============================
   Normalización y plantillas
============================ */

// Shape estable del KEV tool
const KevToolOutputSchema = z.object({
    kev: z.object({
        status: z.enum(["ok", "error"]),
        cve_id: z.string(),
        is_in_kev: z.boolean(),

        // Detalle del entry KEV (si existe)
        entry: z
            .object({
                cisa: z.object({
                    cveID: z.string().nullable(),
                    vendorProject: z.string().nullable(),
                    product: z.string().nullable(),
                    vulnerabilityName: z.string().nullable(),
                    shortDescription: z.string().nullable(),
                    requiredAction: z.string().nullable(),
                    dateAdded: z.string().nullable(),
                    dueDate: z.string().nullable(),
                    knownRansomwareCampaignUse_raw: z.string().nullable(),
                    knownRansomwareCampaignUse_normalized: z.enum(["yes", "no", "unknown"]).nullable(),
                    notes: z.string().nullable(),
                    cwes: z.array(z.any()).nullable(),
                }),
            })
            .nullable(),

        // Metadata y links (siempre presentes)
        meta: z.object({
            source: z.literal("cisa-kev"),
            source_url: z.string(),
            cache_last_updated_local: z.string().nullable(),
            cache_retrieved_at: z.string().nullable(),
            http_etag: z.string().nullable(),
            http_last_modified: z.string().nullable(),
            retrieved_at: z.string(),
        }),

        links: z.object({
            cisa_feed: z.string(),
            nvd: z.string(),
            cve_org: z.string(),
        }),

        // Error info (solo si status=error)
        error_type: z.string().nullable(),
        error_message: z.string().nullable(),
    }),
});

function normalizeRansomwareFlag(raw: unknown): "yes" | "no" | "unknown" {
    if (raw === null || raw === undefined) return "unknown";
    const s = String(raw).trim().toLowerCase();
    if (s === "known" || s === "yes" || s === "true") return "yes";
    if (s === "no" || s === "false") return "no";
    if (s === "unknown") return "unknown";
    // Valores raros -> unknown (pero preservamos raw en structured)
    return "unknown";
}

function buildStructuredKev(
    cveId: string,
    match: any | undefined,
    metaFile: any | null,
    err?: { type: string; message: string }
) {
    const base = {
        kev: {
            status: err ? ("error" as const) : ("ok" as const),
            cve_id: cveId,
            is_in_kev: Boolean(match),

            entry: match
                ? {
                    cisa: {
                        cveID: match?.cveID ?? null,
                        vendorProject: match?.vendorProject ?? null,
                        product: match?.product ?? null,
                        vulnerabilityName: match?.vulnerabilityName ?? null,
                        shortDescription: match?.shortDescription ?? null,
                        requiredAction: match?.requiredAction ?? null,
                        dateAdded: match?.dateAdded ?? null,
                        dueDate: match?.dueDate ?? null,
                        knownRansomwareCampaignUse_raw: match?.knownRansomwareCampaignUse ?? null,
                        knownRansomwareCampaignUse_normalized: normalizeRansomwareFlag(
                            match?.knownRansomwareCampaignUse
                        ),
                        notes: match?.notes ?? null,
                        cwes: Array.isArray(match?.cwes) ? match.cwes : null,
                    },
                }
                : null,

            meta: {
                source: "cisa-kev" as const,
                source_url: KEV_URL,
                cache_last_updated_local: metaFile?.lastUpdated ?? null,
                cache_retrieved_at: metaFile?.retrievedAt ?? null,
                http_etag: metaFile?.etag ?? null,
                http_last_modified: metaFile?.lastModified ?? null,
                retrieved_at: nowISO(),
            },

            links: {
                cisa_feed: KEV_URL,
                nvd: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
                cve_org: `https://www.cve.org/CVERecord?id=${encodeURIComponent(cveId)}`,
            },

            error_type: err?.type ?? null,
            error_message: err?.message ?? null,
        },
    };

    // Validación defensiva: si algo se rompe, prefieres fallar aquí y devolver error controlado
    const parsed = KevToolOutputSchema.safeParse(base);
    if (!parsed.success) {
        // fallback ultra-seguro: no reventar la tool
        return {
            kev: {
                status: "error" as const,
                cve_id: cveId,
                is_in_kev: false,
                entry: null,
                meta: {
                    source: "cisa-kev" as const,
                    source_url: KEV_URL,
                    cache_last_updated_local: metaFile?.lastUpdated ?? null,
                    cache_retrieved_at: metaFile?.retrievedAt ?? null,
                    http_etag: metaFile?.etag ?? null,
                    http_last_modified: metaFile?.lastModified ?? null,
                    retrieved_at: nowISO(),
                },
                links: {
                    cisa_feed: KEV_URL,
                    nvd: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
                    cve_org: `https://www.cve.org/CVERecord?id=${encodeURIComponent(cveId)}`,
                },
                error_type: "schema_validation",
                error_message: "Salida no cumple el esquema esperado (KevToolOutputSchema).",
            },
        };
    }

    return parsed.data;
}

function buildContentFromStructured(structured: z.infer<typeof KevToolOutputSchema>) {
    const k = structured.kev;

    const header = k.is_in_kev
        ? `✅ KEV MATCH: ${k.cve_id} está en el catálogo KEV de CISA (explotación conocida).`
        : `ℹ️ KEV NO MATCH: ${k.cve_id} no aparece en el catálogo KEV de CISA.`;

    const lines: string[] = [];
    lines.push(header);
    lines.push("");

    // Metadata operativa
    lines.push("**Fuente / Metadata**");
    lines.push(`- Fuente: ${k.meta.source}`);
    lines.push(`- URL feed: ${k.meta.source_url}`);
    lines.push(`- Cache (lastUpdated local): ${k.meta.cache_last_updated_local ?? "N/A"}`);
    lines.push(`- Cache (retrievedAt): ${k.meta.cache_retrieved_at ?? "N/A"}`);
    lines.push(`- HTTP ETag: ${k.meta.http_etag ?? "N/A"}`);
    lines.push(`- HTTP Last-Modified: ${k.meta.http_last_modified ?? "N/A"}`);
    lines.push(`- Consulta (retrieved_at): ${k.meta.retrieved_at}`);
    lines.push("");

    // Links útiles
    lines.push("**Links**");
    lines.push(`- NVD: ${k.links.nvd}`);
    lines.push(`- CVE.org: ${k.links.cve_org}`);
    lines.push(`- CISA KEV feed: ${k.links.cisa_feed}`);
    lines.push("");

    if (k.status === "error") {
        lines.push("**Estado**");
        lines.push(`- status: error`);
        lines.push(`- error_type: ${k.error_type ?? "N/A"}`);
        lines.push(`- error_message: ${k.error_message ?? "N/A"}`);
        return lines.join("\n");
    }

    if (!k.is_in_kev || !k.entry) {
        lines.push("**Detalle KEV**");
        lines.push("- Sin entrada KEV para este CVE (según el feed consultado).");
        return lines.join("\n");
    }

    const e = k.entry.cisa;
    lines.push("**Detalle KEV (CISA)**");
    lines.push(`- vendorProject: ${e.vendorProject ?? "N/A"}`);
    lines.push(`- product: ${e.product ?? "N/A"}`);
    lines.push(`- vulnerabilityName: ${e.vulnerabilityName ?? "N/A"}`);
    lines.push(`- dateAdded: ${e.dateAdded ?? "N/A"}`);
    lines.push(`- dueDate: ${e.dueDate ?? "N/A"}`);
    lines.push(
        `- knownRansomwareCampaignUse: ${e.knownRansomwareCampaignUse_normalized ?? "N/A"} (raw: ${e.knownRansomwareCampaignUse_raw ?? "N/A"
        })`
    );
    lines.push(`- requiredAction: ${e.requiredAction ?? "N/A"}`);
    lines.push(`- shortDescription: ${e.shortDescription ?? "N/A"}`);
    lines.push(`- notes: ${e.notes ?? "N/A"}`);
    lines.push(
        `- cwes: ${Array.isArray(e.cwes) ? (e.cwes.length ? JSON.stringify(e.cwes) : "[]") : "N/A"
        }`
    );

    return lines.join("\n");
}

/* ============================
   Tool MCP
============================ */
export function registerKevLookupTool() {
    server.registerTool(
        "kev_lookup",
        {
            title: "Consultar KEV (CISA Known Exploited Vulnerabilities)",
            description:
                "Verifica si un CVE se encuentra en la base de datos KEV de CISA, indicando explotación activa.",
            inputSchema: z.object({
                cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/i, "Formato CVE inválido"),
            }),
        },
        async (input) => {
            const cveId = input.cve_id.toUpperCase();

            try {
                await ensureKevDatabase();

                const kevDb = safeReadJSON(KEV_FILE);
                if (!kevDb) {
                    const structured = buildStructuredKev(
                        cveId,
                        undefined,
                        safeReadJSON(META_FILE),
                        { type: "read_error", message: "No se pudo leer kev.json (JSON inválido o inexistente)." }
                    );
                    return {
                        content: [{ type: "text", text: buildContentFromStructured(structured) }],
                        structuredContent: structured,
                    };
                }

                const vulnerabilities = kevDb?.vulnerabilities ?? [];
                const match = vulnerabilities.find((v: any) => v?.cveID?.toUpperCase() === cveId);

                const metaFile = safeReadJSON(META_FILE);
                const structured = buildStructuredKev(cveId, match, metaFile);

                return {
                    content: [{ type: "text", text: buildContentFromStructured(structured) }],
                    structuredContent: structured,
                };
            } catch (err: any) {
                const structured = buildStructuredKev(
                    cveId,
                    undefined,
                    safeReadJSON(META_FILE),
                    { type: "exception", message: err?.message ?? String(err) }
                );

                return {
                    content: [{ type: "text", text: buildContentFromStructured(structured) }],
                    structuredContent: structured,
                };
            }
        }
    );
}
