/**
 * websearch-fallback.js
 *
 * Supplementary vulnerability check using the Anthropic API's web_search
 * tool, for items where structured feeds (NVD/OSV/Red Hat/KEV) have poor or
 * no coverage - vendor-specific products (FME, Axway), internal software
 * (NeoDPS), or items with unconfirmed versions (apim-1).
 *
 * IMPORTANT - this is NOT a replacement for the structured sources:
 *   - Results are model-read web content, not a queryable CVE database.
 *     Treat findings here as leads to verify, not authoritative like NVD/KEV.
 *   - Costs money per call: $10 per 1,000 searches (~$0.01/search) plus
 *     standard token costs for the model call. See:
 *     https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool
 *   - Only call this for items explicitly opted in via SOURCE_MAP
 *     (webSearchFallback: true) - do not run it for every item on every
 *     scan, or costs scale with your inventory size for no real benefit on
 *     items NVD already covers well.
 *
 * Env var required: ANTHROPIC_API_KEY (add as a GitHub Actions secret,
 * same pattern as NVD_API_KEY).
 */

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || null;
const ANTHROPIC_MODEL = "claude-sonnet-5";
const MAX_SEARCHES_PER_ITEM = 2; // caps cost per item per scan

const SYSTEM_PROMPT = `You are a security research assistant helping a vulnerability tracker fill gaps that structured CVE databases (NVD, OSV, Red Hat Security Data API) don't cover well - usually because the product is niche, internal, or the disclosure is too recent to have propagated to those feeds yet.

Search for recent, credible security advisories, CVEs, or vulnerability disclosures for the given product and version. Prioritize vendor security bulletins, CISA advisories, and reputable security research over forums or aggregator blogs.

Respond with ONLY a JSON object, no markdown fences, no preamble, no commentary. Schema:
{
  "findings": [
    {
      "id": "CVE-XXXX-XXXXX or a short vendor advisory identifier if no CVE exists",
      "title": "short description",
      "severity": "critical | high | medium | low | unknown",
      "sourceUrl": "the URL you found this at",
      "sourceName": "e.g. 'Vendor security bulletin', 'CISA', 'NVD (pending)'",
      "publishedDate": "YYYY-MM-DD if known, else null",
      "versionAffected": "version string as stated in the advisory, or null if unclear",
      "confidence": "high | medium | low - how confident you are this genuinely applies to the exact product/version given"
    }
  ],
  "searchNote": "one sentence on what you searched for and how confident you are in the completeness of this result"
}
If you find nothing relevant, return {"findings": [], "searchNote": "explanation"}. Do not invent CVE IDs or details you did not find in search results.`;

async function queryWebSearchFallback(productName, version) {
  if (!ANTHROPIC_API_KEY) {
    console.warn("  ANTHROPIC_API_KEY not set - skipping web search fallback");
    return { findings: [], searchNote: "Skipped - ANTHROPIC_API_KEY not configured", skipped: true };
  }

  const userPrompt = version
    ? `Product: ${productName}\nVersion: ${version}\n\nFind recent security vulnerabilities or advisories affecting this specific product and version.`
    : `Product: ${productName}\n\nNo confirmed version is available. Find recent security vulnerabilities or advisories affecting this product in general, and note in searchNote that version-specific applicability could not be checked.`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: ANTHROPIC_MODEL,
        max_tokens: 1500,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: userPrompt }],
        tools: [
          {
            type: "web_search_20250305",
            name: "web_search",
            max_uses: MAX_SEARCHES_PER_ITEM
          }
        ]
      })
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`  Web search fallback HTTP ${res.status}: ${errText}`);
      return { findings: [], searchNote: `API error: HTTP ${res.status}`, error: true };
    }

    const data = await res.json();

    // Concatenate all text blocks (Claude may interleave text and tool_use blocks)
    const textBlocks = (data.content || [])
      .filter((block) => block.type === "text")
      .map((block) => block.text)
      .join("\n");

    const cleaned = textBlocks.replace(/```json\s*|```\s*/g, "").trim();

    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error(`  Could not parse web search fallback response as JSON: ${parseErr.message}`);
      return { findings: [], searchNote: "Response was not valid JSON - see raw output in logs", error: true, raw: cleaned.slice(0, 500) };
    }

    return {
      findings: parsed.findings || [],
      searchNote: parsed.searchNote || null
    };
  } catch (err) {
    console.error(`  Web search fallback failed: ${err.message}`);
    return { findings: [], searchNote: `Request failed: ${err.message}`, error: true };
  }
}

// Normalizes a web-search finding into the same shape used by the other
// source queries (nvd/osv/redhat) so it can be merged into scan.js's
// findings array without special-casing downstream.
function normalizeWebSearchFindings(rawFindings) {
  return rawFindings.map((f) => ({
    id: f.id || `WEBSEARCH-${Math.random().toString(36).slice(2, 8)}`,
    source: "websearch",
    description: f.title || "",
    cvssScore: null,
    cvssSeverity: (f.severity || "unknown").toUpperCase(),
    published: f.publishedDate || null,
    sourceUrl: f.sourceUrl || null,
    sourceName: f.sourceName || null,
    versionAffected: f.versionAffected || null,
    confidence: f.confidence || "unknown"
  }));
}

export { queryWebSearchFallback, normalizeWebSearchFindings };
