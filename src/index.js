// Cloudflare Worker entry point
// Serves the dashboard static files, and handles /api/inventory itself.
//
// Required environment variables (set in Cloudflare dashboard →
// Workers & Pages → vul-check → Settings → Variables and Secrets):
//   GITHUB_TOKEN  - fine-grained PAT scoped to this repo, with:
//                     - "Contents: Read and write" (commits inventory.json + runs/)
//                     - "Actions: Read" (lets the dashboard poll scan run status)
//                   mark as Secret/Encrypt
//   GITHUB_REPO   - e.g. "sivakatasani/vul-check"
//   GITHUB_BRANCH - e.g. "main"

const INVENTORY_PATH = "inventory.json";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function githubRequest(env, path, options = {}) {
  const url = `https://api.github.com/repos/${env.GITHUB_REPO}${path}`;
  return fetch(url, {
    ...options,
    headers: {
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "User-Agent": "vul-check-dashboard",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {})
    }
  });
}

function isValidInventory(body) {
  if (!body || typeof body !== "object") return false;
  if (!Array.isArray(body.software)) return false;
  for (const item of body.software) {
    if (typeof item.id !== "string" || !item.id.trim()) return false;
    if (typeof item.name !== "string" || !item.name.trim()) return false;
    if (item.environments && !Array.isArray(item.environments)) return false;
  }
  return true;
}

function checkConfig(env) {
  const missing = ["GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH"].filter((k) => !env[k]);
  return missing.length ? `Server not configured: missing ${missing.join(", ")}` : null;
}

async function handleGetInventory(env) {
  const configErr = checkConfig(env);
  if (configErr) return jsonResponse({ error: configErr }, 500);
  const res = await githubRequest(env, `/contents/${INVENTORY_PATH}?ref=${env.GITHUB_BRANCH}`);
  if (!res.ok) return jsonResponse({ error: `GitHub read failed: ${res.status} (repo=${env.GITHUB_REPO}, branch=${env.GITHUB_BRANCH})` }, 502);
  const data = await res.json();
  const content = atob(data.content.replace(/\n/g, ""));
  return jsonResponse(JSON.parse(content));
}

const MAX_HISTORY = 30;

async function handleGetHistoryList(env) {
  const configErr = checkConfig(env);
  if (configErr) return jsonResponse({ error: configErr }, 500);
  const res = await githubRequest(env, `/contents/runs?ref=${env.GITHUB_BRANCH}`);
  if (!res.ok) return jsonResponse({ error: `GitHub read failed: ${res.status}` }, 502);
  const files = await res.json();
  const runs = (Array.isArray(files) ? files : [])
    .filter((f) => f.name.endsWith(".json"))
    .sort((a, b) => b.name.localeCompare(a.name))
    .slice(0, MAX_HISTORY)
    .map((f) => ({ name: f.name.replace(".json", ""), size: f.size }));
  return jsonResponse({ runs });
}

async function handleGetHistorySnapshot(env, filename) {
  const configErr = checkConfig(env);
  if (configErr) return jsonResponse({ error: configErr }, 500);
  // filename comes from the URL path - keep it strictly alphanumeric/dash/colon to avoid path traversal
  if (!/^[\w-]+\.json$/.test(filename)) {
    return jsonResponse({ error: "Invalid snapshot name" }, 400);
  }
  const res = await githubRequest(env, `/contents/runs/${filename}?ref=${env.GITHUB_BRANCH}`);
  if (!res.ok) return jsonResponse({ error: `GitHub read failed: ${res.status}` }, 502);
  const data = await res.json();
  const content = atob(data.content.replace(/\n/g, ""));
  return jsonResponse(JSON.parse(content));
}

// Returns per-item status across the last N runs (oldest to newest) for real trend sparklines.
// Deliberately capped small - each run is a full inventory fetch through the GitHub API.
const TREND_RUNS = 8;

async function handleGetTrends(env) {
  const configErr = checkConfig(env);
  if (configErr) return jsonResponse({ error: configErr }, 500);
  const listRes = await githubRequest(env, `/contents/runs?ref=${env.GITHUB_BRANCH}`);
  if (!listRes.ok) return jsonResponse({ error: `GitHub read failed: ${listRes.status}` }, 502);
  const files = await listRes.json();
  const recent = (Array.isArray(files) ? files : [])
    .filter((f) => f.name.endsWith(".json"))
    .sort((a, b) => a.name.localeCompare(b.name)) // oldest first
    .slice(-TREND_RUNS);

  const trends = {}; // { itemId: [status, status, ...] oldest->newest }

  for (const file of recent) {
    const res = await githubRequest(env, `/contents/runs/${file.name}?ref=${env.GITHUB_BRANCH}`);
    if (!res.ok) continue;
    const data = await res.json();
    let snapshot;
    try {
      snapshot = JSON.parse(atob(data.content.replace(/\n/g, "")));
    } catch {
      continue;
    }
    for (const item of snapshot.software || []) {
      if (!trends[item.id]) trends[item.id] = [];
      trends[item.id].push(item.scan?.vulnerabilityStatus || "clear");
    }
  }

  return jsonResponse({ trends, runsUsed: recent.length });
}

async function handlePostInventory(request, env) {
  const configErr = checkConfig(env);
  if (configErr) return jsonResponse({ error: configErr }, 500);

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400);
  }

  if (!isValidInventory(body)) {
    return jsonResponse(
      { error: "Payload failed validation - each software item needs at least id and name" },
      400
    );
  }

  const currentRes = await githubRequest(env, `/contents/${INVENTORY_PATH}?ref=${env.GITHUB_BRANCH}`);
  if (!currentRes.ok) {
    return jsonResponse({ error: `Could not read current inventory.json: ${currentRes.status}` }, 502);
  }
  const current = await currentRes.json();

  const newContent = btoa(unescape(encodeURIComponent(JSON.stringify(body, null, 2))));
  const commitRes = await githubRequest(env, `/contents/${INVENTORY_PATH}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: `Dashboard edit - ${new Date().toISOString()}`,
      content: newContent,
      sha: current.sha,
      branch: env.GITHUB_BRANCH
    })
  });

  if (!commitRes.ok) {
    const errText = await commitRes.text();
    return jsonResponse({ error: `GitHub commit failed: ${commitRes.status} ${errText}` }, 502);
  }

  const dispatchRes = await githubRequest(env, `/dispatches`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_type: "inventory-updated" })
  });

  return jsonResponse({
    success: true,
    committed: true,
    rescanTriggered: dispatchRes.ok,
    dispatchedAt: new Date().toISOString(),
    warning: dispatchRes.ok ? null : `Commit succeeded but rescan trigger failed: ${dispatchRes.status}`
  });
}

// Lets the dashboard poll whether the scan triggered at `since` has finished,
// by checking GitHub Actions run history for scan.yml.
async function handleGetScanStatus(env, since) {
  const configErr = checkConfig(env);
  if (configErr) return jsonResponse({ error: configErr }, 500);

  const res = await githubRequest(env, `/actions/workflows/scan.yml/runs?per_page=5`);
  if (!res.ok) return jsonResponse({ error: `GitHub read failed: ${res.status}` }, 502);
  const data = await res.json();
  const runs = data.workflow_runs || [];

  // Find the most relevant run: the newest one created at/after the moment we dispatched.
  const sinceTime = since ? new Date(since).getTime() : 0;
  const relevant = runs.find((r) => new Date(r.created_at).getTime() >= sinceTime - 5000) || runs[0];

  if (!relevant) {
    return jsonResponse({ found: false });
  }

  return jsonResponse({
    found: true,
    status: relevant.status,       // "queued" | "in_progress" | "completed"
    conclusion: relevant.conclusion, // "success" | "failure" | null while running
    createdAt: relevant.created_at,
    updatedAt: relevant.updated_at,
    url: relevant.html_url
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/inventory") {
      if (request.method === "GET") return handleGetInventory(env);
      if (request.method === "POST") return handlePostInventory(request, env);
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    if (url.pathname === "/api/history") {
      if (request.method === "GET") return handleGetHistoryList(env);
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    const snapshotMatch = url.pathname.match(/^\/api\/history\/(.+)$/);
    if (snapshotMatch) {
      if (request.method === "GET") return handleGetHistorySnapshot(env, snapshotMatch[1]);
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    if (url.pathname === "/api/trends") {
      if (request.method === "GET") return handleGetTrends(env);
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    if (url.pathname === "/api/scan-status") {
      if (request.method === "GET") return handleGetScanStatus(env, url.searchParams.get("since"));
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    // Everything else falls through to the static dashboard files
    return env.ASSETS.fetch(request);
  }
};
