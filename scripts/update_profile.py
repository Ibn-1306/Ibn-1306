#!/usr/bin/env python3
"""Publicise repository metadata only (never file contents) on a GitHub profile.

Requires a fine-grained PAT for the personal account, with access to ALL
repositories and ONLY repository Metadata: Read permissions.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

USERNAME = os.environ.get("GITHUB_USERNAME", "Ibn-1306")
API = "https://api.github.com"
TOKEN = os.environ.get("PROFILE_METADATA_TOKEN", "").strip()
README = Path("README.md")


def api_json(path: str):
    if not TOKEN:
        raise RuntimeError("Secret PROFILE_METADATA_TOKEN manquant dans GitHub Actions.")
    request = urllib.request.Request(
        API + path,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Ibn-1306-public-portfolio",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"GitHub API HTTP {exc.code} sur {path.split('?')[0]}. "
            "Vérifie le jeton, son expiration et ses permissions Metadata: Read."
        ) from None


def list_owned_repos() -> list[dict]:
    owned = []
    page = 1
    while True:
        results = api_json(
            f"/user/repos?affiliation=owner&visibility=all&per_page=100&page={page}"
        )
        if not isinstance(results, list):
            raise RuntimeError("Réponse API inattendue lors de la liste des dépôts.")
        owned.extend(
            item for item in results
            if item.get("owner", {}).get("login", "").lower() == USERNAME.lower()
        )
        if len(results) < 100:
            break
        page += 1
        if page > 100:  # Prevent runaway pagination on unexpected responses.
            raise RuntimeError("Pagination GitHub anormale (>10 000 dépôts).")

    # Detect a common PAT misconfiguration that hides even public owned repos.
    public_account = api_json(f"/users/{urllib.parse.quote(USERNAME, safe='')}")
    expected_public = public_account.get("public_repos")
    actual_public = sum(not repo.get("private", False) for repo in owned)
    if not isinstance(expected_public, int) or actual_public != expected_public:
        raise RuntimeError(
            "Liste des dépôts incomplète. Vérifie 'Resource owner: Ibn-1306' "
            "et 'Repository access: All repositories' sur le nouveau jeton."
        )
    return sorted(owned, key=lambda repo: repo["name"].casefold())


def escaped(text, fallback="Non renseigné") -> str:
    """Escape user-entered metadata so it cannot inject Markdown/HTML into README."""
    text = " ".join(str(text or "").split()) or fallback
    text = html.escape(text, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~\-])", r"\\\1", text)


def code_inline(text: str) -> str:
    # GitHub language names and Topics appear as code, where backslashes are literal.
    return "`" + html.escape(str(text), quote=False).replace("`", "&#96;") + "`"


def get_languages(repo: dict) -> str:
    full_name = repo["full_name"]
    endpoint = "/repos/" + "/".join(
        urllib.parse.quote(part, safe="") for part in full_name.split("/")
    ) + "/languages"
    languages = api_json(endpoint)
    if not isinstance(languages, dict):
        raise RuntimeError(f"Langages indisponibles pour {repo['name']}.")
    names = sorted(languages, key=lambda lang: (-languages[lang], lang.casefold()))
    if not names:
        return "Non détecté"
    return ", ".join(code_inline(language) for language in names)


def get_topics(repo: dict) -> str:
    topics = repo.get("topics", [])
    if not isinstance(topics, list):
        topics = []
    if not topics:
        return "À compléter dans les Topics GitHub"
    return ", ".join(code_inline(topic) for topic in sorted(topics))


def catalog_text(repos: list[dict]) -> str:
    publics = [repo for repo in repos if not repo["private"]]
    privates = [repo for repo in repos if repo["private"]]
    lines = [
        "### 🔒 Projets privés — informations de présentation",
        "",
        "Les noms, descriptions et technologies ci-dessous sont publiés volontairement. "
        "**Le code source et les fichiers restent privés.**",
        "",
        "| Dépôt | Description | Langages et technologies |",
        "|:--|:--|:--|",
    ]
    for repo in privates:
        desc = escaped(repo.get("description"), "Description à renseigner dans GitHub")
        techs = f"**Langages :** {get_languages(repo)} ; **Topics :** {get_topics(repo)}"
        lines.append(f"| 🔒 {code_inline(repo['name'])} | {desc} | {techs} |")
    if not privates:
        lines.append("| Aucun dépôt privé | — | — |")
    lines.extend([
        "", "### 🌐 Projets publics", "",
        "| Dépôt | Description | Langages et technologies |",
        "|:--|:--|:--|",
    ])
    for repo in publics:
        name = escaped(repo["name"])
        # Project URLs are constructed only for public repositories.
        url = "https://github.com/" + "/".join(
            urllib.parse.quote(x, safe="") for x in repo["full_name"].split("/")
        )
        desc = escaped(repo.get("description"), "Description à renseigner dans GitHub")
        techs = f"**Langages :** {get_languages(repo)} ; **Topics :** {get_topics(repo)}"
        lines.append(f"| [{name}]({url}) | {desc} | {techs} |")
    if not publics:
        lines.append("| Aucun dépôt public | — | — |")
    return "\n".join(lines)


def update_section(content: str, tag: str, block: str) -> str:
    start = f"<!-- {tag}:START -->"
    end = f"<!-- {tag}:END -->"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    found = list(pattern.finditer(content))
    if len(found) != 1:
        raise RuntimeError(f"Il faut exactement une paire de marqueurs {tag} dans README.md.")
    return content[:found[0].start()] + start + "\n" + block + "\n" + end + content[found[0].end():]


def needs_refresh(current_section: str, signature: str, date_tag: str, today: date) -> bool:
    previous_signature = re.search(rf"<!-- {re.escape(signature)} -->", current_section)
    previous_date = re.search(rf"<!-- {re.escape(date_tag)}:(\d{{4}}-\d{{2}}-\d{{2}}) -->", current_section)
    if not previous_signature or not previous_date:
        return True
    try:
        age = (today - date.fromisoformat(previous_date.group(1))).days
    except ValueError:
        return True
    return not 0 <= age < 30


def main():
    repos = list_owned_repos()
    public_count = sum(not r["private"] for r in repos)
    private_count = sum(r["private"] for r in repos)
    today = datetime.now(timezone.utc).date()

    source = README.read_text(encoding="utf-8")
    stats_start = "<!-- REPO-STATS:START -->"
    stats_end = "<!-- REPO-STATS:END -->"
    if source.count(stats_start) != 1 or source.count(stats_end) != 1:
        raise RuntimeError("README.md doit contenir exactement une paire REPO-STATS.")
    counts_signature = f"REPO-COUNTS:{len(repos)},{public_count},{private_count}"
    section = source.split(stats_start, 1)[1].split(stats_end, 1)[0]
    if needs_refresh(section, counts_signature, "REPO-DATE", today):
        stats = (
            "| Indicateur | Nombre |\n"
            "|:--|--:|\n"
            f"| **Total de mes dépôts** | **{len(repos)}** |\n"
            f"| Dépôts publics | **{public_count}** |\n"
            f"| Dépôts privés | **{private_count}** |\n\n"
            "🔒 Les dépôts privés gardent leur code source confidentiel. "
            "Leurs noms, descriptions et technologies sont présentés ci-dessous.\n\n"
            f"*Dernière synchronisation : {today.isoformat()} (UTC)*\n\n"
            f"<!-- {counts_signature} -->\n"
            f"<!-- REPO-DATE:{today.isoformat()} -->"
        )
        source = update_section(source, "REPO-STATS", stats)

    catalog_start = "<!-- REPO-CATALOG:START -->"
    catalog_end = "<!-- REPO-CATALOG:END -->"
    if catalog_start not in source and catalog_end not in source:
        insertion = (
            "\n\n## 📁 Catalogue automatique de mes projets\n\n"
            "<!-- REPO-CATALOG:START -->\n"
            "Catalogue en attente de la première synchronisation.\n"
            "<!-- REPO-CATALOG:END -->\n"
        )
        source = source.replace(stats_end, stats_end + insertion, 1)
    if source.count(catalog_start) != 1 or source.count(catalog_end) != 1:
        raise RuntimeError("Marqueurs REPO-CATALOG incomplets ou dupliqués.")

    rows = catalog_text(repos)
    fingerprint = hashlib.sha256(rows.encode("utf-8")).hexdigest()[:16]
    catalog_signature = f"REPO-CATALOG-HASH:{fingerprint}"
    existing_catalog = source.split(catalog_start, 1)[1].split(catalog_end, 1)[0]
    if needs_refresh(existing_catalog, catalog_signature, "REPO-CATALOG-DATE", today):
        catalog = (
            rows + "\n\n"
            f"*Catalogue actualisé : {today.isoformat()} (UTC)*\n\n"
            f"<!-- {catalog_signature} -->\n"
            f"<!-- REPO-CATALOG-DATE:{today.isoformat()} -->"
        )
        source = update_section(source, "REPO-CATALOG", catalog)

    # Correct an older claim: repository metadata is now intentionally public.
    source = source.replace(
        "🔒 **Mes dépôts privés contiennent des travaux de développement confidentiels.** "
        "Leur code source et leurs informations restent protégés.",
        "🔒 **Le code source de mes dépôts privés reste confidentiel.** "
        "Leurs noms, descriptions et technologies sont publiés volontairement dans ce portfolio.",
    )

    previous = README.read_text(encoding="utf-8")
    if source != previous:
        README.write_text(source, encoding="utf-8")
        print(f"README actualisé : {len(repos)} dépôts, dont {public_count} publics et {private_count} privés.")
    else:
        print(f"Aucun changement : {len(repos)} dépôts déjà synchronisés.")


if __name__ == "__main__":
    main()
