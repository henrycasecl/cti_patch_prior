import { z } from "zod";
import { server } from "../../server.js";

const BASE_URL = "https://vulnerability.circl.lu/api";

/* ============================
   Helpers HTTP
============================ */
async function fetchJson(url: string, timeoutMs = 15000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      headers: {
        accept: "application/json",
        "user-agent": "mcp-server/1.0 (cti-tools)",
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

/* ============================
   Normalización y similitud
============================ */
function normalizeName(s: string) {
  return s.toLowerCase().replace(/[\s\-_]/g, "");
}

function suggestClosestProduct(
  requested: string,
  products: string[]
): string | null {
  const req = normalizeName(requested);

  // 1. Coincidencia exacta normalizada
  for (const p of products) {
    if (normalizeName(p) === req)
      console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - Coincide exacto: ${p}`);
    return p;
  }

  // 2. Inclusión (Catalys → Catalyst)
  const includes = products.filter(p => {
    const np = normalizeName(p);
    console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - Inclusión check: ${np} / ${req}`);
    return np.includes(req) || req.includes(np);
  });
  if (includes.length) {
    console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - Coincide lenght: ${includes[0]}`);
    return includes.sort((a, b) => a.length - b.length)[0];
  }

  // 3. Prefijo
  const starts = products.filter(p => {
    const np = normalizeName(p);
    console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - prefijo: ${p}`);
    return np.startsWith(req) || req.startsWith(np);
  });
  if (starts.length) {
    console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - prefijo match: ${starts[0]}`);
    return starts.sort((a, b) => a.length - b.length)[0];
  }
  console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - No hizo match con product`);
  return null;
}

/* ============================
   CVSS → Severidad SOC
============================ */
function cvssToSeverity(score?: number | null) {
  if (score == null) return "desconocida";
  if (score < 4) return "baja";
  if (score < 7) return "media";
  if (score < 9) return "alta";
  return "crítica";
}

/* ============================
   Tool MCP
============================ */
export function registerSearchCvesByKeywordsTool() {
  server.registerTool(
    "search_cves_by_keywords",
    {
      title: "Buscar CVEs por vendor y producto",
      description:
        "Busca CVEs usando vendor y product. Si el producto no coincide exactamente, sugiere automáticamente el más cercano.",
      inputSchema: z.object({
        vendor: z.string().min(2),
        product: z.string().min(2),
        limit: z.number().min(1).max(50).optional(),
      }),
    },
    async (input) => {
      const vendor = input.vendor.toLowerCase();
      const requestedProduct = input.product.toLowerCase();
      const limit = input.limit ?? 10;

      console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - Inputs: ${vendor}, ${requestedProduct}, limit=${limit}`);
      try {
        /* ============================
           1. Descubrir productos del vendor
        ============================ */
        const url = `${BASE_URL}/browse/${vendor}`;
        console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - url browse: ${url}`);

        const products: string[] = await fetchJson(url);
        //console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - product: ${JSON.stringify(products, null, 2)}`);

        if (!Array.isArray(products) || products.length === 0) {
          throw new Error(`Vendor '${vendor}' no encontrado`);
        }

        /* ============================
           2. Resolver producto efectivo
        ============================ */
        const effectiveProduct =
          suggestClosestProduct(requestedProduct, products);

        console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - effective_product: ${JSON.stringify(effectiveProduct, null, 2)}`);

        if (!effectiveProduct) {
          return {
            content: [
              {
                type: "text",
                text: `Producto '${requestedProduct}' no encontrado para vendor '${vendor}'.`,
              },
            ],
            structuredContent: {
              query: { vendor, product: requestedProduct },
              error: "PRODUCT_NOT_FOUND",
              available_products: products.slice(0, 20),
              message: `No se encontró un producto similar a '${requestedProduct}' para el vendor '${vendor}'.`,
            },
          };
        }

        /* ============================
           3. Búsqueda CVEs
        ============================ */
        const searchResult = await fetchJson(
          `${BASE_URL}/vulnerability/search/${vendor}/${effectiveProduct}`
        );
        console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - Result: ${searchResult ? JSON.stringify(searchResult, null, 2) : 'null'}`);

        const rawItems = Array.isArray(searchResult?.results?.cvelistv5)
          ? searchResult.results.cvelistv5
          : [];
        console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - rawItems length: ${rawItems.length}`);

        const items = rawItems.slice(0, limit);
        console.log(`[${new Date().toISOString()}] MCP Request CVE By keywords - items: ${items ? JSON.stringify(items, null, 2) : 'null'}`);

        const cves = items.map(([_, entry]: [string, any]) => {
          const cveId = entry?.cveMetadata?.cveId ?? null;

          const description =
            entry?.containers?.cna?.descriptions?.find((d: any) => d.lang === "en")
              ?.value ?? null;

          const metrics = entry?.containers?.cna?.metrics ?? [];
          const cvss =
            metrics.find((m: any) => m?.cvssV3_1)?.cvssV3_1?.baseScore ??
            metrics.find((m: any) => m?.cvssV3_0)?.cvssV3_0?.baseScore ??
            null;

          return {
            cve_id: cveId,
            title: description ? description.slice(0, 140) : null,
            cvss,
            severity: cvssToSeverity(cvss),
          };
        });

        /* ============================
           4. Mensaje SOC
        ============================ */
        const corrected =
          effectiveProduct.toLowerCase() !== requestedProduct
            ? ` (producto interpretado como '${effectiveProduct}')`
            : "";

        const messageLines = [
          `Búsqueda CVE para ${vendor} / ${requestedProduct}${corrected}`,
          `Resultados encontrados: ${cves.length}`,
          "",
          ...cves.map(
            (c: { cve_id: string | null; severity: string; cvss: number | null }) =>
              `• ${c.cve_id} | ${c.severity.toUpperCase()} | CVSS ${c.cvss ?? "N/A"}`
          ),
        ];

        return {
          content: [
            { type: "text", text: messageLines.join("\n") },
          ],
          structuredContent: {
            query: { vendor, product: requestedProduct },
            resolved_product: effectiveProduct,
            total_results: cves.length,
            cves,
            message: messageLines.join("\n"),
          },
        };
      } catch (err: any) {
        return {
          content: [
            {
              type: "text",
              text: `Error buscando CVEs: ${err.message}`,
            },
          ],
          structuredContent: {
            query: { vendor, product: requestedProduct },
            error: err.message,
            message: `No fue posible completar la búsqueda para ${vendor}/${requestedProduct}.`,
          },
        };
      }
    }
  );
}
