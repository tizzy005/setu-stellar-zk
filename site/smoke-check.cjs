const fs = require("fs");
const path = require("path");
const http = require("http");
const { spawn, spawnSync } = require("child_process");

const root = __dirname;
const failures = [];

function ok(message) {
  console.log(`ok   ${message}`);
}

function fail(message) {
  failures.push(message);
  console.error(`FAIL ${message}`);
}

const requiredFiles = [
  "index.html",
  "styles.css",
  "app.js",
  "server.cjs",
  "build-config.cjs",
  "auth-config.example.js",
  "package.json",
  "vercel.json",
  "assets/setu-mark.svg",
  "assets/setu-product.png",
];

const scriptFiles = [
  "app.js",
  "server.cjs",
  "build-config.cjs",
  "auth-config.example.js",
];

function checkRequiredFiles() {
  for (const rel of requiredFiles) {
    if (fs.existsSync(path.join(root, rel))) {
      ok(`file exists: ${rel}`);
    } else {
      fail(`missing file: ${rel}`);
    }
  }
}

function checkSyntax(rel) {
  const result = spawnSync(process.execPath, ["--check", rel], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status === 0) {
    ok(`syntax valid: ${rel}`);
  } else {
    fail(`syntax error in ${rel}\n${(result.stderr || "").trim()}`);
  }
}

function runConfigBuild() {
  const generated = path.join(root, "auth-config.js");
  if (fs.existsSync(generated)) {
    // Do not clobber a developer's local auth config; the build would rewrite it.
    ok("auth-config.js already present, skipping config build");
    return false;
  }
  const result = spawnSync(process.execPath, ["build-config.cjs"], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(`config build failed\n${(result.stderr || result.stdout || "").trim()}`);
    return false;
  }
  if (!fs.existsSync(generated)) {
    fail("config build did not generate auth-config.js");
    return false;
  }
  ok("config build generated auth-config.js");
  return true;
}

function checkHtmlReferences() {
  const htmlPath = path.join(root, "index.html");
  if (!fs.existsSync(htmlPath)) {
    return;
  }
  const html = fs.readFileSync(htmlPath, "utf8");
  const refs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]);
  const seen = new Set();
  for (const ref of refs) {
    if (/^(https?:|\/\/|#|mailto:|data:)/.test(ref)) {
      continue;
    }
    const rel = ref.replace(/^\.\//, "").split(/[?#]/)[0];
    if (!rel || seen.has(rel)) {
      continue;
    }
    seen.add(rel);
    if (fs.existsSync(path.join(root, rel))) {
      ok(`index.html reference resolves: ${ref}`);
    } else {
      fail(`index.html references missing file: ${ref}`);
    }
  }
}

function get(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (response) => {
      let body = "";
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        resolve({ status: response.statusCode, body });
      });
    });
    request.setTimeout(3000, () => {
      request.destroy(new Error("request timed out"));
    });
    request.on("error", reject);
  });
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function checkServer() {
  const port = Number(process.env.SMOKE_PORT || 4180);
  try {
    await get(`http://127.0.0.1:${port}/index.html`);
    // Something already answers on the port; polling it would pass without
    // testing this repo's server at all.
    fail(`port ${port} is already in use; stop that server or set SMOKE_PORT`);
    return;
  } catch {}
  const server = spawn(process.execPath, ["server.cjs"], {
    cwd: root,
    env: { ...process.env, PORT: String(port) },
    stdio: "ignore",
  });
  try {
    let index;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        index = await get(`http://127.0.0.1:${port}/index.html`);
        break;
      } catch {
        await delay(250);
      }
    }
    if (!index) {
      fail(`server.cjs did not start listening on port ${port}`);
      return;
    }
    if (index.status === 200 && index.body.includes("</html>")) {
      ok("server.cjs serves index.html with status 200");
    } else {
      fail(`GET /index.html returned status ${index.status}`);
    }
    const missing = await get(`http://127.0.0.1:${port}/no-such-file.txt`);
    if (missing.status === 404) {
      ok("server.cjs returns 404 for a missing file");
    } else {
      fail(`GET /no-such-file.txt returned status ${missing.status}, expected 404`);
    }
  } finally {
    server.kill();
  }
}

async function main() {
  checkRequiredFiles();
  for (const rel of scriptFiles) {
    if (fs.existsSync(path.join(root, rel))) {
      checkSyntax(rel);
    }
  }
  const generatedConfig = runConfigBuild();
  try {
    if (fs.existsSync(path.join(root, "auth-config.js"))) {
      checkSyntax("auth-config.js");
    }
    checkHtmlReferences();
    await checkServer();
  } finally {
    if (generatedConfig) {
      // A leftover disabled-mode config would shadow server.cjs's env-var
      // fallback on later `npm run dev` runs, so remove what this run created.
      fs.rmSync(path.join(root, "auth-config.js"), { force: true });
    }
  }
  if (failures.length > 0) {
    console.error(`\nsmoke check failed with ${failures.length} problem(s):`);
    for (const message of failures) {
      console.error(`- ${message.split("\n")[0]}`);
    }
    process.exit(1);
  }
  console.log("\nsmoke check passed");
}

main().catch((error) => {
  console.error(`smoke check crashed: ${error.message}`);
  process.exit(1);
});
