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

async
