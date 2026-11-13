// Proteção para rodar na rede: senha + cookie de sessão assinado, Host permitido,
// Origin igual ao Host em escrita, limite de tentativas de login e cabeçalhos de segurança.
import crypto from "node:crypto";

const SENHA = process.env.APP_PASSWORD || "";
const SEGREDO = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const HOSTS = (process.env.ALLOWED_HOSTS || "").split(",").map(h => h.trim().toLowerCase()).filter(Boolean);
const DIAS = Number(process.env.SESSION_DAYS || 30);
const COOKIE = "cf_sessao";
const SEGURO = process.env.COOKIE_SECURE === "1"; // só atrás de HTTPS

export const CABECALHOS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin", // no-referrer faz o navegador mandar Origin: null no POST do formulário de login
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "content-security-policy": [
    "default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:", "font-src 'self' data:", "connect-src 'self'", "worker-src 'self' blob:",
    "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'",
  ].join("; "),
};

const hmac = v => crypto.createHmac("sha256", SEGREDO).update(v).digest("base64url");
const iguais = (a, b) => {
  const x = crypto.createHash("sha256").update(String(a)).digest(), y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

function sessaoValida(req) {
  const m = (req.headers.cookie || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return false;
  const [exp, sig] = decodeURIComponent(m[1]).split(".");
  return Number(exp) > Date.now() && !!sig && iguais(sig, hmac(exp));
}

// 5 erros em 15 min bloqueiam o IP por 15 min
const tentativas = new Map();
const JANELA = 15 * 60 * 1000;
function bloqueado(ip) {
  const t = tentativas.get(ip);
  if (t && Date.now() - t.inicio > JANELA) { tentativas.delete(ip); return false; }
  return !!t && t.erros >= 5;
}
function falhou(ip) {
  const t = tentativas.get(ip) ?? { erros: 0, inicio: Date.now() };
  t.erros++; tentativas.set(ip, t);
}

const paginaLogin = erro => `<!doctype html><html lang="pt-BR"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Entrar · Tesouraria da Taverna</title>
<link rel="icon" href="logo.svg" type="image/svg+xml"><link rel="stylesheet" href="app.css">
<style>body{display:grid;place-items:center;grid-template-columns:1fr;min-height:100vh;padding:16px}
form{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;width:min(360px,100%);display:grid;gap:14px;box-shadow:var(--sombra)}
.topo{display:flex;align-items:center;gap:10px}h1{font-size:20px;color:var(--brand)}
input{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card-2);color:var(--text)}
button{font:inherit;font-weight:600;padding:10px;border:0;border-radius:8px;background:var(--accent);color:var(--on-accent);cursor:pointer}
button:hover{background:var(--accent-hover)}.erro{color:var(--falta);margin:0}</style>
<form method="post" action="/login"><div class="topo"><img src="logo.svg" width="32" height="32" alt=""><h1>Tesouraria da Taverna</h1></div>
<label>Senha<br><input type="password" name="senha" autocomplete="current-password" required autofocus style="width:100%"></label>
${erro ? `<p class="erro">${erro}</p>` : ""}<button>Entrar</button></form></html>`;

/**
 * Roda antes das rotas. Devolve true quando já respondeu (bloqueou, login, logout).
 * Sem APP_PASSWORD o app recusa tudo, para não ficar aberto na rede por engano.
 */
export async function proteger(req, res, url) {
  for (const [k, v] of Object.entries(CABECALHOS)) res.setHeader(k, v);
  const responder = (status, corpo, extra = {}) => { res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...extra }); res.end(corpo); return true; };

  // Host fora da lista: barra DNS rebinding (site malicioso apontando um domínio para este IP)
  const host = (req.headers.host || "").toLowerCase();
  if (HOSTS.length && !HOSTS.includes(host)) return responder(421, "host não permitido");
  // escrita só vinda da própria página: barra CSRF de outros sites abertos no navegador
  const origem = req.headers.origin;
  if (req.method !== "GET" && req.method !== "HEAD" && origem && origem !== "null" && new URL(origem).host.toLowerCase() !== host)
    return responder(403, "origem não permitida");
  if (req.method !== "GET" && req.method !== "HEAD" && origem === "null") return responder(403, "origem não permitida");

  if (!SENHA) return responder(503, "Defina APP_PASSWORD para usar a Tesouraria da Taverna na rede.");

  const publico = ["/login", "/app.css", "/logo.svg", "/logo.png", "/favicon.png"].includes(url.pathname) || url.pathname.startsWith("/fonts/");
  if (url.pathname === "/logout") return responder(302, "", { location: "/login", "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict` });
  if (url.pathname === "/login" && req.method === "POST") {
    const ip = req.socket.remoteAddress;
    if (bloqueado(ip)) return responder(429, paginaLogin("Muitas tentativas. Espere 15 minutos."));
    let corpo = "";
    for await (const p of req) { corpo += p; if (corpo.length > 4096) return responder(413, "grande demais"); }
    const senha = new URLSearchParams(corpo).get("senha") ?? "";
    if (!iguais(senha, SENHA)) { falhou(ip); return responder(401, paginaLogin("Senha incorreta.")); }
    tentativas.delete(ip);
    const exp = String(Date.now() + DIAS * 864e5);
    return responder(302, "", { location: "/", "set-cookie": `${COOKIE}=${exp}.${hmac(exp)}; Path=/; Max-Age=${DIAS * 86400}; HttpOnly; SameSite=Strict${SEGURO ? "; Secure" : ""}` });
  }
  if (url.pathname === "/login") return sessaoValida(req) ? responder(302, "", { location: "/" }) : responder(200, paginaLogin(""));
  if (publico || sessaoValida(req)) return false;
  if (url.pathname.startsWith("/api/")) {
    res.writeHead(401, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ erro: "faça login" }));
    return true;
  }
  return responder(302, "", { location: "/login" });
}
