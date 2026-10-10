#!/usr/bin/env python3
"""Publie un catalogue de projets et leurs technologies détectées automatiquement.

Lit uniquement les métadonnées GitHub, l'arbre des fichiers et les manifestes
techniques autorisés. Ne clone aucun dépôt, n'exécute aucun code des projets,
et ne publie aucun contenu de fichier source.

Jeton requis : Fine-grained PAT, propriétaire Ibn-1306, All repositories,
Repository permissions Metadata: Read et Contents: Read.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

USERNAME = os.environ.get("GITHUB_USERNAME", "Ibn-1306")
TOKEN = os.environ.get("PROFILE_METADATA_TOKEN", "").strip()
API = "https://api.github.com"
README = Path("README.md")
MAX_MANIFEST_BYTES = 150_000
MAX_MANIFESTS_PER_REPO = 12
IGNORED_DIRS = {"node_modules", "vendor", "dist", "build", "target", ".git", ".next", ".nuxt", ".venv", "venv", "coverage", "__pycache__", "tmp", "cache"}


def api_json(path: str):
    if not TOKEN:
        raise RuntimeError("Secret PROFILE_METADATA_TOKEN absent dans GitHub Actions.")
    req = urllib.request.Request(
        API + path,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Ibn-1306-private-portfolio",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        url = path.split("?", 1)[0]
        if e.code in (401, 403, 404):
            raise RuntimeError(
                f"API GitHub HTTP {e.code} sur {url}. Verifier Resource owner, "
                "All repositories, Contents: Read, puis le secret du jeton."
            ) from None
        raise RuntimeError(f"API GitHub HTTP {e.code} sur {url}.") from None


def repo_base(repo: dict) -> str:
    return "/repos/" + "/".join(
        urllib.parse.quote(s, safe="") for s in repo["full_name"].split("/")
    )


def list_owned_repos() -> list[dict]:
    repos = []
    for page in range(1, 102):
        payload = api_json(f"/user/repos?affiliation=owner&visibility=all&per_page=100&page={page}")
        if not isinstance(payload, list):
            raise RuntimeError("Liste des dépôts : réponse GitHub inattendue.")
        repos.extend(r for r in payload if r.get("owner", {}).get("login", "").lower() == USERNAME.lower())
        if len(payload) < 100:
            break
    else:
        raise RuntimeError("Plus de 10 000 dépôts : pagination à adapter.")
    public_account = api_json(f"/users/{urllib.parse.quote(USERNAME, safe='')}")
    expected = public_account.get("public_repos")
    actual = sum(not r.get("private", False) for r in repos)
    if not isinstance(expected, int) or expected != actual:
        raise RuntimeError("Comptage public incomplet : vérifier le propriétaire et All repositories du jeton.")
    return sorted(repos, key=lambda r: r["name"].casefold())


def languages(repo: dict) -> list[str]:
    data = api_json(repo_base(repo) + "/languages")
    if not isinstance(data, dict):
        raise RuntimeError("Réponse GitHub langages inattendue.")
    return sorted(data.keys(), key=lambda k: (-data[k], k.lower()))


def manifest_kind(name: str) -> bool:
    n = name.lower()
    return n in {"package.json", "composer.json", "pyproject.toml", "pipfile", "go.mod", "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "pubspec.yaml"} or (
        n.startswith("requirements") and n.endswith(".txt")
    ) or n.endswith((".csproj", ".fsproj"))


def scan_tree(repo: dict) -> tuple[list[dict], set[str], bool]:
    if not repo.get("default_branch") or repo.get("size", 0) == 0:
        return [], set(), False
    ref = urllib.parse.quote(repo["default_branch"], safe="")
    data = api_json(repo_base(repo) + f"/git/trees/{ref}?recursive=1")
    entries = data.get("tree")
    if not isinstance(entries, list):
        raise RuntimeError("Liste des fichiers GitHub non disponible.")
    names = set()
    manifests = []
    for entry in entries:
        path = entry.get("path", "")
        parts = path.lower().split("/")
        if len(parts) > 5 or any(part in IGNORED_DIRS for part in parts[:-1]):
            continue
        if entry.get("type") != "blob":
            continue
        names.add(path.lower())
        if (manifest_kind(parts[-1]) and isinstance(entry.get("size"), int)
                and entry["size"] <= MAX_MANIFEST_BYTES):
            manifests.append(entry)
    manifests.sort(key=lambda x: (x["path"].count("/"), x["path"].lower()))
    return manifests[:MAX_MANIFESTS_PER_REPO], names, bool(data.get("truncated")) or len(manifests) > MAX_MANIFESTS_PER_REPO


def read_manifest(repo: dict, item: dict) -> str:
    # Le SHA provient de l'arbre GitHub de CE dépôt ; jamais du README.
    sha = item["sha"]
    if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise RuntimeError("Identifiant de manifeste invalide.")
    blob = api_json(repo_base(repo) + "/git/blobs/" + sha)
    if blob.get("encoding") != "base64":
        raise RuntimeError("Encodage du manifeste non pris en charge.")
    raw = base64.b64decode(blob.get("content", ""), validate=False)
    if len(raw) > MAX_MANIFEST_BYTES:
        return ""
    return raw.decode("utf-8", errors="replace")


JS_PACKAGES = {
    "next": "Next.js", "react": "React", "react-dom": "React",
    "@angular/core": "Angular", "vue": "Vue.js", "nuxt": "Nuxt",
    "svelte": "Svelte", "@sveltejs/kit": "SvelteKit", "express": "Express.js",
    "@nestjs/core": "NestJS", "fastify": "Fastify", "typescript": "TypeScript",
    "vite": "Vite", "tailwindcss": "Tailwind CSS", "@tailwindcss/vite": "Tailwind CSS",
    "react-native": "React Native", "expo": "Expo", "electron": "Electron",
    "prisma": "Prisma", "@prisma/client": "Prisma", "drizzle-orm": "Drizzle ORM",
    "mongoose": "MongoDB", "mongodb": "MongoDB", "mysql": "MySQL", "mysql2": "MySQL",
    "pg": "PostgreSQL", "redis": "Redis", "ioredis": "Redis",
    "sequelize": "Sequelize", "socket.io": "Socket.IO", "astro": "Astro",
}
PHP_PACKAGES = {
    "laravel/framework": "Laravel", "symfony/framework-bundle": "Symfony",
    "symfony/symfony": "Symfony", "codeigniter4/framework": "CodeIgniter",
    "livewire/livewire": "Livewire", "filament/filament": "Filament",
    "inertiajs/inertia-laravel": "Inertia.js", "doctrine/orm": "Doctrine ORM",
}
PY_PACKAGES = {
    "django": "Django", "djangorestframework": "Django REST Framework",
    "fastapi": "FastAPI", "flask": "Flask", "starlette": "Starlette",
    "sqlalchemy": "SQLAlchemy", "celery": "Celery", "streamlit": "Streamlit",
    "torch": "PyTorch", "tensorflow": "TensorFlow", "psycopg2": "PostgreSQL",
    "psycopg2-binary": "PostgreSQL", "asyncpg": "PostgreSQL",
    "pymysql": "MySQL", "mysqlclient": "MySQL", "redis": "Redis",
    "pymongo": "MongoDB", "motor": "MongoDB",
}
RUST_PACKAGES = {"actix-web": "Actix Web", "axum": "Axum", "rocket": "Rocket", "tokio": "Tokio"}
GO_PACKAGES = {
    "github.com/gin-gonic/gin": "Gin", "github.com/labstack/echo": "Echo",
    "github.com/gofiber/fiber": "Fiber", "gorm.io/gorm": "GORM",
}


def detect_from_manifest(name: str, content: str) -> set[str]:
    found: set[str] = set()
    low = name.lower()
    try:
        if low == "package.json":
            data = json.loads(content)
            deps = {str(dep).lower() for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
                    for dep in (data.get(key, {}) if isinstance(data.get(key, {}), dict) else {})}
            found.update(label for pkg, label in JS_PACKAGES.items() if pkg in deps)
        elif low == "composer.json":
            data = json.loads(content)
            deps = {str(dep).lower() for key in ("require", "require-dev")
                    for dep in (data.get(key, {}) if isinstance(data.get(key, {}), dict) else {})}
            found.update(label for pkg, label in PHP_PACKAGES.items() if pkg in deps)
        elif low.startswith("requirements") and low.endswith(".txt"):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                match = re.match(r"^([A-Za-z0-9_-]+)", line)
                if match:
                    pkg = match.group(1).lower().replace("_", "-")
                    if pkg in PY_PACKAGES:
                        found.add(PY_PACKAGES[pkg])
        elif low in ("pyproject.toml", "pipfile"):
            data = tomllib.loads(content)
            deps = data.get("project", {}).get("dependencies", [])
            for x in deps if isinstance(deps, list) else []:
                match = re.match(r"^\s*([A-Za-z0-9_-]+)", str(x))
                if match:
                    pkg = match.group(1).lower().replace("_", "-")
                    if pkg in PY_PACKAGES:
                        found.add(PY_PACKAGES[pkg])
            poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for pkg in poetry if isinstance(poetry, dict) else {}:
                label = PY_PACKAGES.get(pkg.lower().replace("_", "-"))
                if label:
                    found.add(label)
            for key in ("packages", "dev-packages"):
                p = data.get(key, {})
                for pkg in p if isinstance(p, dict) else {}:
                    label = PY_PACKAGES.get(pkg.lower().replace("_", "-"))
                    if label:
                        found.add(label)
        elif low == "go.mod":
            for pkg, label in GO_PACKAGES.items():
                if pkg in content:
                    found.add(label)
        elif low == "cargo.toml":
            data = tomllib.loads(content)
            deps = set()
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                d = data.get(key, {})
                if isinstance(d, dict):
                    deps.update(d)
            found.update(v for k, v in RUST_PACKAGES.items() if k in deps)
        elif low == "pom.xml":
            if "spring-boot-starter" in content:
                found.add("Spring Boot")
            if "quarkus" in content:
                found.add("Quarkus")
        elif low in ("build.gradle", "build.gradle.kts"):
            if "org.springframework.boot" in content:
                found.add("Spring Boot")
            if "com.android.application" in content:
                found.add("Android")
        elif low.endswith((".csproj", ".fsproj")):
            found.add(".NET")
            if "Microsoft.NET.Sdk.Web" in content:
                found.add("ASP.NET Core")
            if "Microsoft.EntityFrameworkCore" in content:
                found.add("Entity Framework Core")
        elif low == "gemfile":
            if re.search(r"gem\s*['\"]rails['\"]", content):
                found.add("Ruby on Rails")
        elif low == "pubspec.yaml":
            if re.search(r"(?m)^\s*flutter\s*:", content):
                found.add("Flutter")
    except (ValueError, TypeError, AttributeError):
        # Un manifeste incomplet ne doit pas créer de faux positifs.
        pass
    return found


def detect_technologies(repo: dict) -> tuple[list[str], bool]:
    manifests, paths, partial = scan_tree(repo)
    tech = set()
    basenames = {p.rsplit("/", 1)[-1] for p in paths}
    if "dockerfile" in basenames or "docker-compose.yml" in basenames or "compose.yaml" in basenames or "compose.yml" in basenames:
        tech.add("Docker")
    if "tsconfig.json" in basenames:
        tech.add("TypeScript")
    if "angular.json" in basenames:
        tech.add("Angular")
    if "artisan" in basenames:
        tech.add("Laravel")
    if "manage.py" in basenames:
        tech.add("Django")
    if any(n.startswith("next.config.") for n in basenames):
        tech.add("Next.js")
    if any(n.startswith("nuxt.config.") for n in basenames):
        tech.add("Nuxt")
    if any(n.startswith("vite.config.") for n in basenames):
        tech.add("Vite")
    if any(n.startswith("tailwind.config.") for n in basenames):
        tech.add("Tailwind CSS")
    if "vercel.json" in basenames:
        tech.add("Vercel")
    if "netlify.toml" in basenames:
        tech.add("Netlify")
    if "firebase.json" in basenames:
        tech.add("Firebase")
    if any(p.endswith(("/kustomization.yaml", "/kustomization.yml")) or p in ("kustomization.yaml", "kustomization.yml") for p in paths):
        tech.add("Kubernetes")
    if "terraform.tf" in basenames or "main.tf" in basenames:
        tech.add("Terraform")
    for item in manifests:
        content = read_manifest(repo, item)
        if content:
            tech.update(detect_from_manifest(item["path"].rsplit("/", 1)[-1], content))
    return sorted(tech, key=str.casefold), partial


def escape_md(value, fallback="Non renseignée") -> str:
    value = " ".join(str(value or "").split()) or fallback
    value = html.escape(value, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~\-])", r"\\\1", value)


def as_code(value: str) -> str:
    return "`" + html.escape(str(value), quote=False).replace("`", "&#96;") + "`"


def catalogue(repos: list[dict]) -> str:
    records = []
    for repo in repos:
        lang = languages(repo)
        tech, partial = detect_technologies(repo)
        topics = repo.get("topics") or []
        description = escape_md(repo.get("description"), "Description non renseignée")
        items = ["**Langages :** " + (", ".join(as_code(l) for l in lang) if lang else "Non détectés")]
        items.append("**Technologies détectées :** " + (", ".join(as_code(t) for t in tech) if tech else "Non identifiées automatiquement"))
        if topics:
            items.append("**Topics :** " + ", ".join(as_code(t) for t in topics))
        if partial:
            items.append("*Analyse partielle (projet volumineux)*")
        records.append((repo, description, " ; ".join(items)))

    output = [
        "### 🔒 Projets privés — informations publiques de présentation", "",
        "Noms, descriptions et technologies publiés volontairement. **Le code source et les fichiers restent privés.**", "",
        "| Dépôt | Description | Stack technique |", "|:--|:--|:--|",
    ]
    privates = [r for r in records if r[0].get("private")]
    for repo, desc, stack in privates:
        output.append(f"| 🔒 {as_code(repo['name'])} | {desc} | {stack} |")
    if not privates:
        output.append("| Aucun dépôt privé | — | — |")
    output.extend(["", "### 🌐 Projets publics", "", "| Dépôt | Description | Stack technique |", "|:--|:--|:--|"])
    publics = [r for r in records if not r[0].get("private")]
    for repo, desc, stack in publics:
        url = "https://github.com/" + "/".join(urllib.parse.quote(p, safe="") for p in repo["full_name"].split("/"))
        output.append(f"| [{escape_md(repo['name'])}]({url}) | {desc} | {stack} |")
    if not publics:
        output.append("| Aucun dépôt public | — | — |")
    return "\n".join(output)


def replace_marked(content: str, tag: str, block: str) -> str:
    start = f"<!-- {tag}:START -->"
    end = f"<!-- {tag}:END -->"
    match = list(re.finditer(re.escape(start) + r".*?" + re.escape(end), content, flags=re.DOTALL))
    if len(match) != 1:
        raise RuntimeError(f"Marqueurs {tag} absents ou dupliqués dans README.md.")
    return content[:match[0].start()] + start + "\n" + block + "\n" + end + content[match[0].end():]


def should_update(old: str, marker: str, date_marker: str, today: date) -> bool:
    if f"<!-- {marker} -->" not in old:
        return True
    m = re.search(r"<!-- " + re.escape(date_marker) + r":(\d{4}-\d{2}-\d{2}) -->", old)
    if not m:
        return True
    try:
        age = (today - date.fromisoformat(m.group(1))).days
    except ValueError:
        return True
    return age < 0 or age >= 30


def main():
    repos = list_owned_repos()
    publics = sum(not r["private"] for r in repos)
    privates = sum(r["private"] for r in repos)
    today = datetime.now(timezone.utc).date()
    source = README.read_text(encoding="utf-8")
    if source.count("<!-- REPO-STATS:START -->") != 1 or source.count("<!-- REPO-STATS:END -->") != 1:
        raise RuntimeError("README.md ne contient pas exactement une paire REPO-STATS.")

    count_mark = f"REPO-COUNTS:{len(repos)},{publics},{privates}"
    old_stats = source.split("<!-- REPO-STATS:START -->")[1].split("<!-- REPO-STATS:END -->")[0]
    if should_update(old_stats, count_mark, "REPO-DATE", today):
        block = (
            "| Indicateur | Nombre |\n|:--|--:|\n"
            f"| **Total de mes dépôts** | **{len(repos)}** |\n"
            f"| Dépôts publics | **{publics}** |\n"
            f"| Dépôts privés | **{privates}** |\n\n"
            "🔒 Le code des dépôts privés reste confidentiel ; leurs informations de présentation sont visibles plus bas.\n\n"
            f"*Dernière synchronisation : {today.isoformat()} (UTC)*\n\n"
            f"<!-- {count_mark} -->\n<!-- REPO-DATE:{today.isoformat()} -->"
        )
        source = replace_marked(source, "REPO-STATS", block)

    if "<!-- REPO-CATALOG:START -->" not in source and "<!-- REPO-CATALOG:END -->" not in source:
        target = "<!-- REPO-STATS:END -->"
        source = source.replace(target, target + "\n\n## 📁 Catalogue automatique de mes projets\n\n<!-- REPO-CATALOG:START -->\nEn attente de synchronisation.\n<!-- REPO-CATALOG:END -->", 1)
    if source.count("<!-- REPO-CATALOG:START -->") != 1 or source.count("<!-- REPO-CATALOG:END -->") != 1:
        raise RuntimeError("README.md ne contient pas exactement une paire REPO-CATALOG.")

    rows = catalogue(repos)
    digest = hashlib.sha256(rows.encode("utf-8")).hexdigest()[:16]
    mark = f"REPO-CATALOG-HASH:{digest}"
    old = source.split("<!-- REPO-CATALOG:START -->")[1].split("<!-- REPO-CATALOG:END -->")[0]
    if should_update(old, mark, "REPO-CATALOG-DATE", today):
        block = rows + f"\n\n*Catalogue actualisé : {today.isoformat()} (UTC)*\n\n<!-- {mark} -->\n<!-- REPO-CATALOG-DATE:{today.isoformat()} -->"
        source = replace_marked(source, "REPO-CATALOG", block)

    # Corrige les anciennes phrases expliquant que seuls les nombres étaient publics.
    source = source.replace("🔒 Les dépôts privés restent confidentiels : seuls leurs nombres sont affichés.", "🔒 Seul le code source privé reste inaccessible aux visiteurs.")
    source = source.replace(
        "🔒 **Mes dépôts privés contiennent des travaux de développement confidentiels.** Leur code source et leurs informations restent protégés.",
        "🔒 **Le code de mes dépôts privés reste confidentiel.** Leurs métadonnées et technologies sont publiées volontairement.",
    )
    if source != README.read_text(encoding="utf-8"):
        README.write_text(source, encoding="utf-8")
        print(f"README actualisé : {len(repos)} dépôts, {publics} publics, {privates} privés.")
    else:
        print("README déjà à jour.")


if __name__ == "__main__":
    main()
