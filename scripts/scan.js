#!/usr/bin/env node
/**
 * Vulnerability scan script
 * Reads inventory.json, checks each software item against:
 *   - NVD (CVE search by CPE / keyword)
 *   - CISA KEV (Known Exploited Vulnerabilities catalog)
 *   - EPSS (Exploit Prediction Scoring System)
 *   - OSV (Open Source Vulnerabilities)
 *   - Red Hat Security Data API
 * Writes results back into inventory.json and a timestamped snapshot in runs/.
 *
 * Usage: node scripts/scan.js
 * Env vars (optional): NVD_API_KEY
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const INVENTORY_PATH = path.join(ROOT, "inventory.json");
const RUNS_DIR = path.join(ROOT, "runs");

const NVD_API_KEY = process.env.NVD_API_KEY || null;

// ---------------------------------------------------------------------------
// Mapping table: inventory id -> search terms used for each data source.
// Extend/correct this as you find better CPE strings or package identifiers.
// Entries with "needsMapping: true" are guesses and should be verified.
// ---------------------------------------------------------------------------
const SOURCE_MAP = {
  "neodps": {
    nvdKeyword: null, // internal/custom software - unlikely to be in NVD
    osvEcosystem: null,
    needsMapping: true,
    note: "Appears to be an internal/custom application - no public CVE source likely applies. Confirm before relying on scan results."
  },
  "postgresql-apim": {
    nvdKeyword: "postgresql",
    cpeVendor: "postgresql",
    cpeProduct: "postgresql",
    needsMapping: false
  },
  "apim-1": {
    nvdKeyword: "red hat 3scale",
    cpeVendor: "redhat",
    cpeProduct: "3scale_api_management",
    needsMapping: true,
    note: "Could not confirm exact version this maps to - see needsReview in inventory.json"
  },
  "elasticsearch": {
    nvdKeyword: "elasticsearch",
    cpeVendor: "elastic",
    cpeProduct: "elasticsearch",
    needsMapping: false
  },
  "openshift": {
    nvdKeyword: "openshift container platform",
    cpeVendor: "redhat",
    cpeProduct: "openshift_container_platform",
    needsMapping: false
  },
  "postgresql-mft": {
    nvdKeyword: "postgresql",
    cpeVendor: "postgresql",
    cpeProduct: "postgresql",
    needsMapping: false
  },
  "postgresql-esb-neodps": {
    nvdKeyword: "postgresql",
    cpeVendor: "postgresql",
    cpeProduct: "postgresql",
    needsMapping: false
  },
  "postgresql-fme": {
    nvdKeyword: "postgresql",
    cpeVendor: "postgresql",
    cpeProduct: "postgresql",
    needsMapping: false
  },
  "redhat-sso": {
    nvdKeyword: "keycloak",
    cpeVendor: "redhat",
    cpeProduct: "single_sign_on",
    needsMapping: false
  },
  "apim-2": {
    nvdKeyword: "red hat 3scale",
    cpeVendor: "redhat",
    cpeProduct: "3scale_api_management",
    needsMapping: true,
    note: "No environment/version data was recoverable from source PDF - verify this entry entirely"
  },
  "fme-safe-software": {
    nvdKeyword: "safe software fme",
    cpeVendor: null,
    cpeProduct: null,
    needsMapping: true,
    note: "FME/Safe Software rarely appears in NVD - may need vendor security bulletins instead"
  },
  "axway": {
    nvdKeyword: "axway secure transport",
    cpeVendor: "axway",
    cpeProduct: "secure_transport",
    needsMapping: false
  },
  "amq": {
    nvdKeyword: "red hat amq",
    cpeVendor: "redhat",
    cpeProduct: "amq",
    needsMapping: false
  },
  "redis": {
    nvdKeyword: "redis",
    cpeVendor: "redis",
    cpeProduct: "redis",
    needsMapping: false
  },
  "camel": {
    nvdKeyword: "apache camel",
    cpeVendor: "apache",
    cpeProduct: "camel",
    needsMapping: false
  }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url, options = {}, retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, options);
      if (res.status === 429) {
        const waitMs = 6000 * attempt;
        console.warn(`  Rate limited on ${url}, waiting ${waitMs}ms...`);
        await sleep(waitMs);
        continue;
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} for ${url}`);
      }
      return await res.json();
    } catch (err) {
      if (attempt === retries) {
        console.error(`  Failed after ${retries} attempts: ${url} - ${err.message}`);
        return null;
      }
      await sleep(2000 * attempt);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Data source queries
// ---------------------------------------------------------------------------

async function queryNvd(keyword) {
  if (!keyword) return [];
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("keywordSearch", keyword);
  url.searchParams.set("resultsPerPage", "20");

  const headers = {};
  if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;

  const data = await fetchJson(url.toString(), { headers });
  if (!data || !data.vulnerabilities) return [];

  return data.vulnerabilities.map((v) => {
    const cve = v.cve;
    const metrics = cve.metrics || {};
    let cvssScore = null;
    let cvssSeverity = null;
    const metricSet =
      metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [];
    if (metricSet.length > 0) {
      cvssScore = metricSet[0].cvssData.baseScore;
      cvssSeverity = metricSet[0].cvssData.baseSeverity || metricSet[0].baseSeverity || null;
    }
    return {
      id: cve.id,
      source: "nvd",
      description:
        (cve.descriptions || []).find((d) => d.lang === "en")?.value || "",
      cvssScore,
      cvssSeverity,
      published: cve.published
    };
  });
}

// NVD's official rate limit without a key is ~5 requests / 30s
async function nvdThrottle() {
  await sleep(NVD_API_KEY ? 700 : 6500);
}

let kevCatalogCache = null;
async function loadKevCatalog() {
  if (kevCatalogCache) return kevCatalogCache;
  const data = await fetchJson(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  );
  kevCatalogCache = data?.vulnerabilities || [];
  return kevCatalogCache;
}

async function checkKev(cveIds) {
  const kev = await loadKevCatalog();
  const kevIds = new Set(kev.map((v) => v.cveID));
  return cveIds.filter((id) => kevIds.has(id));
}

async function getEpssScores(cveIds) {
  if (cveIds.length === 0) return {};
  const scores = {};
  // EPSS API allows comma-separated CVE batches
  const chunks = [];
  for (let i = 0; i < cveIds.length; i += 100) {
    chunks.push(cveIds.slice(i, i + 100));
  }
  for (const chunk of chunks) {
    const url = `https://api.first.org/data/v1/epss?cve=${chunk.join(",")}`;
    const data = await fetchJson(url);
    if (data?.data) {
      for (const entry of data.data) {
        scores[entry.cve] = {
          epssScore: parseFloat(entry.epss),
          percentile: parseFloat(entry.percentile)
        };
      }
    }
  }
  return scores;
}

async function queryOsv(ecosystem, packageName) {
  if (!ecosystem || !packageName) return [];
  const url = "https://api.osv.dev/v1/query";
  const data = await fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: { name: packageName, ecosystem } })
  });
  if (!data?.vulns) return [];
  return data.vulns.map((v) => ({
    id: v.id,
    source: "osv",
    description: v.summary || v.details?.slice(0, 300) || "",
    published: v.published
  }));
}

async function queryRedHat(cpeProduct) {
  if (!cpeProduct) return [];
  const url = `https://access.redhat.com/hydra/rest/securitydata/cve.json?product=${encodeURIComponent(
    cpeProduct
  )}&per_page=20`;
  const data = await fetchJson(url);
  if (!Array.isArray(data)) return [];
  return data.map((v) => ({
    id: v.CVE,
    source: "redhat",
    description: v.bugzilla_description || "",
    severity: v.severity,
    published: v.public_date
  }));
}

// ---------------------------------------------------------------------------
// Main scan
// ---------------------------------------------------------------------------

async function scanItem(item) {
  const mapping = SOURCE_MAP[item.id] || {};
  console.log(`Scanning: ${item.name} (${item.id})`);

  const findings = [];

  if (mapping.nvdKeyword) {
    const nvdResults = await queryNvd(mapping.nvdKeyword);
    findings.push(...nvdResults);
    await nvdThrottle();
  }

  if (mapping.osvEcosystem) {
    const osvResults = await queryOsv(mapping.osvEcosystem, item.name);
    findings.push(...osvResults);
  }

  if (mapping.cpeProduct && mapping.cpeVendor === "redhat") {
    const rhResults = await queryRedHat(mapping.cpeProduct);
    findings.push(...rhResults);
  }

  // De-dupe by CVE id, keep first occurrence
  const seen = new Set();
  const deduped = findings.filter((f) => {
    if (!f.id || seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });

  const cveIds = deduped.map((f) => f.id).filter((id) => id?.startsWith("CVE-"));
  const [kevMatches, epssScores] = await Promise.all([
    checkKev(cveIds),
    getEpssScores(cveIds)
  ]);

  const enriched = deduped.map((f) => ({
    ...f,
    knownExploited: kevMatches.includes(f.id),
    epss: epssScores[f.id] || null
  }));

  // Sort: KEV first, then by CVSS score descending
  enriched.sort((a, b) => {
    if (a.knownExploited !== b.knownExploited) return a.knownExploited ? -1 : 1;
    return (b.cvssScore || 0) - (a.cvssScore || 0);
  });

  const highestSeverity = enriched.reduce((max, f) => {
    const score = f.cvssScore || 0;
    return score > max ? score : max;
  }, 0);

  let status = "clear";
  if (enriched.some((f) => f.knownExploited)) status = "critical";
  else if (highestSeverity >= 9) status = "critical";
  else if (highestSeverity >= 7) status = "high";
  else if (highestSeverity >= 4) status = "medium";
  else if (enriched.length > 0) status = "low";

  return {
    vulnerabilityStatus: status,
    vulnerabilityCount: enriched.length,
    highestCvssScore: highestSeverity || null,
    hasKnownExploited: enriched.some((f) => f.knownExploited),
    findings: enriched.slice(0, 15), // cap stored findings per item
    scanNeedsMapping: !!mapping.needsMapping,
    scanNote: mapping.note || null,
    lastScanned: new Date().toISOString()
  };
}

async function main() {
  const raw = await fs.readFile(INVENTORY_PATH, "utf-8");
  const inventory = JSON.parse(raw);

  for (const item of inventory.software) {
    try {
      const result = await scanItem(item);
      item.scan = result;
    } catch (err) {
      console.error(`  Error scanning ${item.id}: ${err.message}`);
      item.scan = {
        vulnerabilityStatus: "error",
        error: err.message,
        lastScanned: new Date().toISOString()
      };
    }
  }

  inventory.metadata = inventory.metadata || {};
  inventory.metadata.lastFullScan = new Date().toISOString();

  // Write updated inventory
  await fs.writeFile(INVENTORY_PATH, JSON.stringify(inventory, null, 2));
  console.log(`\nUpdated ${INVENTORY_PATH}`);

  // Write timestamped snapshot to runs/
  await fs.mkdir(RUNS_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const runPath = path.join(RUNS_DIR, `${stamp}.json`);
  await fs.writeFile(runPath, JSON.stringify(inventory, null, 2));
  console.log(`Wrote snapshot: ${runPath}`);

  // Summary
  const summary = inventory.software.map((i) => ({
    name: i.name,
    status: i.scan?.vulnerabilityStatus,
    count: i.scan?.vulnerabilityCount
  }));
  console.table(summary);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
