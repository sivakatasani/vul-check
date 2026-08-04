// Cloudflare Worker entry point
// Serves the dashboard static files, and handles /api/inventory itself.
//
// Required environment variables (set in Cloudflare dashboard →
// Workers & Pages → vul-check → Settings → Variables and Secrets):
//   GITHUB_TOKEN  - fine-grained PAT scoped to this repo, "Contents: Read and write" (mark as Secret/Encrypt)
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
 
async function handleGetInventory(env) {
  const res = await githubRequest(env, `/contents/${INVENTORY_PATH}?ref=${env.GITHUB_BRANCH}`);
  if (!res.ok) return jsonResponse({ error: `GitHub read failed: ${res.status}` }, 502);
  const data = await res.json();
  const content = atob(data.content.replace(/\n/g, ""));
  return jsonResponse(JSON.parse(content));
}
 
async function handlePostInventory(request, env) {
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO || !env.GITHUB_BRANCH) {
    return jsonResponse(
      { error: "Server not configured: missing GITHUB_TOKEN, GITHUB_REPO, or GITHUB_BRANCH" },
      500
    );
  }
 
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
    warning: dispatchRes.ok ? null : `Commit succeeded but rescan trigger failed: ${dispatchRes.status}`
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
 
    // Everything else falls through to the static dashboard files
    return env.ASSETS.fetch(request);
  }
};
