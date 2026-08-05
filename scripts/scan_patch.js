#!/usr/bin/env node
/**
 * Vulnerability scan script
 * Reads inventory.json, checks each software item against:
 *   - NVD (CPE-based version-aware match when possible, keyword fallback otherwise)
 *   - CISA KEV (Known Exploited Vulnerabilities catalog)
 *   - EPSS (Exploit Prediction Scoring System)
 *   - OSV (Open Source Vulnerabilities)
 *   - Red Hat Security Data API
 * Writes results back into inventory.json and a timestamped snapshot in runs/.
 *
 * Usage: node scripts/scan.js
 * Env vars (optional): NVD_API_KEY
 *
 * CHANGES vs previous version:
 *   1. Red Hat queries now use `redhatProductName` (the API's real product
 *      display name, e.g. "Red Hat 3scale API Management") instead of the
 *      CPE-style product slug, which the Red Hat API never matched.
 *   2. OSV is now actually wired up for items that have real OSV coverage
 *      (Redis, Camel). Previously every SOURCE_MAP entry left osvEcosystem
 *      unset, so OSV silently never ran for anything.
 *   3. NVD queries prefer a version-aware CPE match (virtualMatchString)
 *      over a bare keyword search, when the item has cpeVendor/cpeProduct
 *      mapped and a usable version string in inventory.json. This avoids
 *      pulling in every CVE ever filed against the product name regardless
 *      of whether the deployed version is affected. Keyword search is kept
 *      as a fallback for items without a clean CPE-matchable version
 *      (FME, Axway, NeoDPS) so we don't lose coverage entirely.
 *   4. Every scan result now records `sourcesAttempted` - which sources
 *      were actually queried for this item - so "no findings" and "we
 *      never checked" are no longer visually identical on the dashboard.
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { queryWebSearchFallback, normalizeWebSearchFindings } from "./websearch-fallback.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const INVENTORY_PATH = path.join(ROOT, "inventory.json");
const RUNS_DIR = path.join(ROOT, "runs");

const NVD_API_KEY = process.env.NVD_API_KEY || null;

// ---------------------------------------------------------------------------
// Mapping table: inventory id -> search terms used for each data source.
// Extend/correct this as you find better CPE strings or package identifiers.
// Entries with "needsMapping: true" are guesses and should be verified.
//
// Fields:
//   nvdKeyword        - fallback keyword search term (used when no clean
//                        CPE+version match is possible)
//   cpeVendor/cpeProduct - NVD CPE 2.3 vendor/product strings, used to build
//                        a version-aware virtualMatchString query
//   redhatProductName  - the REAL Red Hat product display name expected by
//                        access.redhat.com's `product` query param (NOT a
//                        CPE slug - verify against the live API before
//                        trusting a new entry)
//   osvEcosystem/osvPackage - OSV.dev ecosystem + package identifier, only
//                        set where OSV genuinely has coverage
// ---------------------------------------------------------------------------
const SOURCE_MAP = {
  "neodps": {
    nvdKeyword: null, // internal/custom software - unlikely to be in NVD
    osvEcosystem: null,
    needsMapping: true,
    webSearchFallback: true,
    note: "Appears to be an internal/custom application - no public CVE source likely applies. Confirm before relying on scan results."
  },
  "postgresql-apim": {
    nvdKeyword: "postgresql",
    cpeVendor: "postgresql",
    cpeProduct: "postgresql",
    needsMapping: false
  },
  "apim-1": {
    // No environment/version data exists for this instance in the source
    // PDF (EOL 30 Apr 2026) - see inventory.json needsReview note. Leave
    // unmapped until a real version is confirmed; scanning a keyword with
    // no version just re-creates the inflated-count problem.
    nvdKeyword: null,
    cpeVendor: "redhat",
    cpeProduct: "3scale_api_management",
    redhatProductName: "Red Hat 3scale API Management",
    needsMapping: true,
    webSearchFallback: true,
    note: "No confirmed version for this APIM instance - structured scan skipped pending manual version entry. See needsReview in inventory.json."
  },
  "elasticsearch": {
    nvdKeyword: "elasticsearch",
    cpeVendor: "elastic",
    cpeProduct: "elasticsearch",
    needsMapping: true,
    note: "Version 2.15 in inventory.json is flagged as a likely source-data copy/paste error (shares OpenShift's reference text) - verify against Confluence before trusting scan results."
  },
  "openshift": {
    nvdKeyword: "openshift container platform",
    cpeVendor: "redhat",
    cpeProduct: "openshift_container_platform",
    redhatProductName: "OpenShift Container Platform 4",
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
    redhatProductName: "Red Hat Single Sign-On",
    needsMapping: false
  },
  "apim-2": {
    nvdKeyword: "red hat 3scale",
    cpeVendor: "redhat",
    cpeProduct: "3scale_api_management",
    redhatProductName: "Red Hat 3scale API Management",
    needsMapping: false
  },
  "fme-safe-software": {
    nvdKeyword: "safe software fme",
    cpeVendor: null,
    cpeProduct: null,
    needsMapping: true,
    webSearchFallback: true,
    note: "FME/Safe Software rarely appears in NVD - may need vendor security bulletins instead"
  },
  "axway": {
    nvdKeyword: "axway secure transport",
    cpeVendor: "axway",
    cpeProduct: "secure_transport",
    needsMapping: false,
    webSearchFallback: true
  },
  "amq": {
    nvdKeyword: "red hat amq",
    cpeVendor: "redhat",
    cpeProduct: "amq",
    redhatProductName: "Red Hat AMQ",
    needsMapping: false
  },
  "redis": {
    nvdKeyword: "redis",
    cpeVendor: "redis",
    cpeProduct: "redis",
    osvEcosystem: "Debian",
    osvPackage: "redis",
    needsMapping: false
  },
  "camel": {
    nvdKeyword: "apache camel",
    cpeVendor: "apache",
    cpeProduct: "camel",
    redhatProductName: "Red Hat build of Apache Camel",
    osvEcosystem: "Maven",
    osvPackage: "org.apache.camel:camel-core",
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

// Pull the distinct, non-empty version strings out of an item's
// environments array. Most items run the same version everywhere; a few
// (NeoDPS, Axway) run more than one, so we scan each distinct version.
function getDistinctVersions(item) {
  const versions = (item.environments || [])
    .map((e) => e.version)
    .filter((v) => v && v !== "Not applicable");
  return [...new Set(versions)];
}

// Only bother building a CPE match string for versions that look like real
// version numbers (e.g. "14", "2.15", "7.6.6"). Free-text build strings like
// "FME Flow 2023.2.1 Build 23774-win64" won't match NVD's CPE format, so we
// fall back to keyword search for those instead of silently returning
// nothing.
function looksLikeCpeVersion(version) {
  return /^\d+(\.\d+){0,3}$/.test(version.trim());
}

// ---------------------------------------------------------------------------
// Data source queries
// ---------------------------------------------------------------------------

async function queryNvdByKeyword(keyword) {
  if (!keyword) return [];
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("keywordSearch", keyword);
  url.searchParams.set("resultsPerPage", "20");

  const headers = {};
  if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;

  const data = await fetchJson(url.toString(), { headers });
  return parseNvdResponse(data);
}

// Version-aware NVD query: asks NVD "which CVEs have a configuration that
// covers exactly this vendor/product/version", instead of "which CVEs
// mention this product name anywhere". Dramatically cuts down on
// long-since-fixed, irrelevant, or wrong-version CVEs showing up as
// critical findings.
async function queryNvdByCpe(vendor, product, version) {
  if (!vendor || !product || !version) return [];
  const virtualMatchString = `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("virtualMatchString", virtualMatchString);
  url.searchParams.set("resultsPerPage", "20");

  const headers = {};
  if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;

  const data = await fetchJson(url.toString(), { headers });
  return parseNvdResponse(data);
}

function parseNvdResponse(data) {
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

// OSV entries sometimes carry a CVSS vector string in severity[], and
// sometimes a database_specific.severity word (e.g. Debian's "important"/
// "moderate"). Neither is consistently present, so this is best-effort -
// an OSV finding with no score anywhere still returns null and sorts low,
// but at least the cases where OSV *does* tell us won't be wasted.
const OSV_WORD_SEVERITY_SCORE = { critical: 9.5, high: 7.5, moderate: 5, low: 2 };

function extractOsvScore(vuln) {
  const cvssEntry = (vuln.severity || []).find((s) => s.type?.startsWith("CVSS"));
  if (cvssEntry?.score) {
    // score is a vector string like "CVSS:3.1/AV:N/AC:L/..." on some
    // entries, or a bare number on others - only use it if it parses as
    // a plain number, otherwise fall through to the word-based estimate.
    const asNumber = parseFloat(cvssEntry.score);
    if (!Number.isNaN(asNumber) && asNumber <= 10) return asNumber;
  }
  const word = vuln.database_specific?.severity?.toLowerCase();
  return OSV_WORD_SEVERITY_SCORE[word] || null;
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
  return data.vulns.map((v) => {
    const score = extractOsvScore(v);
    return {
      id: v.id,
      source: "osv",
      description: v.summary || v.details?.slice(0, 300) || "",
      cvssScore: score,
      cvssSeverity: score ? null : v.database_specific?.severity?.toUpperCase() || null,
      published: v.published
    };
  });
}

// Red Hat's severity is a word ("critical" / "important" / "moderate" /
// "low"), not a CVSS number. Map it onto the same 0-10 scale NVD uses so it
// competes fairly in sorting/truncation instead of silently scoring 0.
const REDHAT_SEVERITY_SCORE = { critical: 9.5, important: 7.5, moderate: 5, low: 2 };

async function queryRedHat(productName) {
  if (!productName) return [];
  const url = `https://access.redhat.com/hydra/rest/securitydata/cve.json?product=${encodeURIComponent(
    productName
  )}&per_page=20`;
  const data = await fetchJson(url);
  if (!Array.isArray(data)) return [];
  return data.map((v) => ({
    id: v.CVE,
    source: "redhat",
    description: v.bugzilla_description || "",
    severity: v.severity,
    cvssScore: REDHAT_SEVERITY_SCORE[(v.severity || "").toLowerCase()] || null,
    cvssSeverity: v.severity ? v.severity.toUpperCase() : null,
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
  const sourcesAttempted = [];

  // --- NVD: prefer version-aware CPE match, fall back to keyword ---
  const versions = getDistinctVersions(item);
  const cpeEligibleVersions = mapping.cpeVendor && mapping.cpeProduct
    ? versions.filter(looksLikeCpeVersion)
    : [];

  if (cpeEligibleVersions.length > 0) {
    for (const version of cpeEligibleVersions) {
      const results = await queryNvdByCpe(mapping.cpeVendor, mapping.cpeProduct, version);
      findings.push(...results);
      sourcesAttempted.push(`nvd:cpe:${version}`);
      await nvdThrottle();
    }
  } else if (mapping.nvdKeyword) {
    const results = await queryNvdByKeyword(mapping.nvdKeyword);
    findings.push(...results);
    sourcesAttempted.push("nvd:keyword");
    await nvdThrottle();
  }

  // --- OSV ---
  if (mapping.osvEcosystem && mapping.osvPackage) {
    const osvResults = await queryOsv(mapping.osvEcosystem, mapping.osvPackage);
    findings.push(...osvResults);
    sourcesAttempted.push("osv");
  }

  // --- Red Hat Security Data API ---
  if (mapping.redhatProductName) {
    const rhResults = await queryRedHat(mapping.redhatProductName);
    findings.push(...rhResults);
    sourcesAttempted.push("redhat");
  }

  // --- Web search fallback (opt-in only, for structurally poorly-covered items) ---
  let webSearchNote = null;
  if (mapping.webSearchFallback) {
    const versionForSearch = versions[0] || null; // use first known version, if any
    const wsResult = await queryWebSearchFallback(item.name, versionForSearch);
    findings.push(...normalizeWebSearchFindings(wsResult.findings));
    webSearchNote = wsResult.searchNote;
    sourcesAttempted.push(wsResult.skipped ? "websearch:skipped" : "websearch");
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
  sourcesAttempted.push("kev", "epss"); // always run as enrichment on whatever findings exist

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

  // Websearch-sourced findings often have a text severity (e.g. "CRITICAL")
  // but no CVSS score. Map those to an approximate numeric score too, so
  // they still influence status - otherwise a critical websearch-only
  // finding would silently show as "clear".
  const TEXT_SEVERITY_SCORE = { CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5, LOW: 2, UNKNOWN: 0 };
  const highestSeverity = enriched.reduce((max, f) => {
    const score = f.cvssScore || TEXT_SEVERITY_SCORE[f.cvssSeverity] || 0;
    return score > max ? score : max;
  }, 0);

  // Determine scan coverage quality
  const hasVersion = getDistinctVersions(item).length > 0;
  const hasCpeMapping = !!(mapping.cpeVendor && mapping.cpeProduct);
  let scanCoverage = "structured";
  if (!hasVersion && !mapping.redhatProductName) {
    scanCoverage = "blocked-no-version";
  } else if (mapping.needsMapping) {
    scanCoverage = "partial";
  } else if (!hasCpeMapping && mapping.nvdKeyword) {
    scanCoverage = "keyword-only";
  }

  let status = "clear";
  if (scanCoverage === "blocked-no-version") {
    status = "blocked-no-version";
  } else {
    if (enriched.some((f) => f.knownExploited)) status = "critical";
    else if (highestSeverity >= 9) status = "critical";
    else if (highestSeverity >= 7) status = "high";
    else if (highestSeverity >= 4) status = "medium";
    else if (enriched.length > 0) status = "low";
  }

  // EOL lifecycle state — independent of CVE status
  const eolDate = item.eolDate ? new Date(item.eolDate) : null;
  const nowMs = Date.now();
  const daysToEol = eolDate ? Math.floor((eolDate.getTime() - nowMs) / 86400000) : null;
  let eolStatus = "supported";
  if (daysToEol !== null && daysToEol < 0) eolStatus = "past-eol";
  else if (daysToEol !== null && daysToEol <= 90) eolStatus = "eol-within-90-days";

  return {
    vulnerabilityStatus: status,
    eolStatus,
    daysToEol,
    scanCoverage,
    vulnerabilityCount: enriched.length,
    highestCvssScore: highestSeverity || null,
    hasKnownExploited: enriched.some((f) => f.knownExploited),
    findings: enriched.slice(0, 15), // cap stored findings per item
    sourcesAttempted,
    scanNeedsMapping: !!mapping.needsMapping,
    scanNote: mapping.note || null,
    webSearchNote,
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
    count: i.scan?.vulnerabilityCount,
    sources: (i.scan?.sourcesAttempted || []).join(",")
  }));
  console.table(summary);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
