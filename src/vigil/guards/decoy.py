"""Decoy endpoints: the cheapest high-confidence signal in the whole system.

Every other detector in this program has to weigh evidence. A request for
``/wp-login.php`` might be a scanner or might be a site that really runs
WordPress; ``/.env`` might be a probe or a legitimate admin checking their own
deployment. That ambiguity is why the HTTP signatures come in two confidence
tiers and why the low tier needs a *window* of hits before it bans: acting on
a single ambiguous request is how this project once banned its own operator
for 24 hours over an icon called ``ico-phpmyadmin.png``.

A decoy removes the ambiguity by construction. The path is:

* **not present** on disk (we check),
* **not referenced** by anything the site serves (we check), and
* **instrumented** with its own nginx location and its own log file.

So a hit is not evidence, it is a conclusion: something requested a path that
does not exist, is linked from nowhere, and only ever appears in attack
tooling. There is no legitimate explanation to weigh, which is why a single
hit is enough to ban -- and why the ban can be long.

The two checks are not decoration. They are the false-positive control that
the automatic-signature literature insists on: Polygraph and Autograph
evaluate candidate signatures against a corpus of known-good traffic and keep
only those that match none of it, and Honeycomb derives signatures only from
traffic that reached a honeypot rather than from live production requests.
The equivalent here is to refuse any decoy whose path exists in the web root
or whose identifying token appears anywhere in the site's own content. A
decoy that fails either test is dropped, not weakened.

What this is *not*: it is not a honeypot that pretends to be a vulnerable
service. It gives an attacker nothing to interact with -- the response is a
dropped connection -- so there is no fake shell to escape and no emulated
service to fingerprint. All it does is make a class of probing unambiguous
and cheap to punish.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..core import detect, shell

CONF_NAME = "vigil-decoy.conf"

#: How much of the site's content to read while screening. Enough to cover a
#: normal web root, bounded so that screening cannot become the slow part of
#: an install.
_CORPUS_CAP = 8 * 1024 * 1024

#: Files worth reading when building the corpus.
_TEXT_EXT = (".html", ".htm", ".php", ".js", ".mjs", ".css", ".json", ".xml",
             ".txt", ".md", ".vue", ".jsx", ".ts", ".tsx", ".twig", ".tpl")

#: The decoys, and why a hit is conclusive.
#:
#: Each is a path that no legitimate visitor of a normal site requests. The
#: token is what gets searched for in the site's own content during
#: screening -- deliberately the shortest distinctive part of the path, so
#: that a link to it is caught even when it is spelled differently (absolute
#: URL, relative, url-encoded, with a query string).
DECOYS: tuple = (
    # -- 由自修正循环于 2026-10-03 采纳：48 个独立来源共请求 104 次，且都不存在（名字像探测）
    ("/wp-admin/install.php", "auto", "自动采纳的新探测路径"),

    ("/.env", "env", "环境变量文件，正常站点不会有人请求它"),
    ("/.git/config", "git/config", "源码仓库配置，泄露后可直接拉走全部代码"),
    ("/.aws/credentials", "aws/credentials", "云平台密钥文件"),
    ("/.ssh/id_rsa", "id_rsa", "SSH 私钥"),
    ("/.svn/entries", "svn/entries", "旧版源码管理元数据"),
    ("/.bash_history", "bash_history", "命令历史"),
    # -- AI 代理 / MCP 接口（2026 年起成批出现的新扫描面）----------------
    # 日志实证：/mcp、/mcp/、/api/mcp、/sse、/api/auth/validate-sso 被 5 个
    # 不同来源成组探测。这类接口一旦暴露，可以直接调用后端的模型与工具链，
    # 比传统 Web 漏洞的影响面更大，而它们此前一条都不在诱饵库里 —— 探了也
    # 不记分、不封禁。
    ("/mcp", "mcp", "MCP（模型上下文协议）接口，暴露后可被用来调用后端工具链"),
    ("/mcp/", "mcp/", "MCP 接口根路径"),
    ("/api/mcp", "api/mcp", "MCP 接口的常见挂载点"),
    ("/sse", "sse", "Server-Sent Events 接口，常与 MCP 配套，暴露后可持续读取服务端事件"),
    ("/api/auth/validate-sso", "validate-sso", "SSO 校验接口，被用来枚举认证实现"),
    ("/.well-known/ai-plugin.json", "ai-plugin", "AI 插件清单，暴露后泄露接口定义"),
    # -- Linux 家目录探测 --------------------------------------------------
    # 这类路径只在「想确认这是一台真实 Linux 主机、并被真人登录过」时才会被
    # 请求。正常访客与爬虫都不会碰，是典型的踩点信号。
    ("/.config/pulse/", "config/pulse", "桌面环境残留，扫描器用它判断是否为真实 Linux 主机"),
    ("/.cache/motd.legal-displayed", "motd", "登录横幅缓存，用于确认主机被真人登录过"),
    ("/.config/", "config/", "用户配置目录，可能含云平台与 Git 凭据"),
    ("/.local/share/", "local/share", "用户数据目录，可能含应用凭据"),
    ("/.wget-hsts", "wget-hsts", "wget 历史，说明主机被用于对外下载"),
    # -- 其它实证高频探测 --------------------------------------------------
    ("/login", "login", "通用登录入口，被用来枚举认证实现"),
    ("/index.php", "index.php", "PHP 入口，本站不是 PHP 应用"),
    ("/admin/config.php", "admin/config.php", "后台配置文件"),
    ("/wp-login.php", "wp-login.php", "WordPress 后台（本站不是 WordPress）"),
    ("/xmlrpc.php", "xmlrpc.php", "WordPress 接口，被用于爆破与反射"),
    ("/adminer.php", "adminer.php", "数据库管理工具"),
    ("/phpmyadmin/index.php", "phpmyadmin", "数据库管理工具"),
    ("/config.php.bak", "config.php.bak", "配置备份文件"),
    ("/backup.sql", "backup.sql", "数据库导出文件"),
    ("/docker-compose.yml", "docker-compose", "部署文件，常含明文口令"),
    ("/Dockerfile", "Dockerfile", "构建文件，泄露内部结构"),
    ("/credentials.txt", "credentials.txt", "口令文件"),
    ("/server-status", "server-status", "Apache 状态页"),
    ("/actuator/env", "actuator/env", "Spring Boot 配置泄露（含数据库口令）"),
    ("/_ignition/execute-solution", "_ignition", "Laravel RCE（CVE-2021-3129）"),
    ("/cgi-bin/luci", "cgi-bin/luci", "路由器漏洞利用"),
    ("/.well-known/security.txt", "security.txt",
     "只在明确需要时才有意义；本站没有发布它"),

    # -- 后台与入口探测 -------------------------------------------------
    # 命名必须「像真的」：`/honeypot.html` 或 `/fake-admin` 这类名字只会
    # 被扫描器一眼识破，而诱饵的全部价值就在于它看起来值得一试。
    ("/admin/", "admin/", "后台目录，自动化扫描的第一站"),
    ("/administrator/", "administrator/", "Joomla 风格后台目录"),
    ("/wp-admin/", "wp-admin/", "WordPress 后台目录（本站不是 WordPress）"),
    ("/manager/html", "manager/html", "Tomcat 管理台，常见弱口令入口"),
    ("/admin.php", "admin.php", "通用后台入口脚本"),
    ("/user/login", "user/login", "通用登录路径"),

    # -- 备份与导出 -----------------------------------------------------
    ("/backup.zip", "backup.zip", "整站备份压缩包"),
    ("/www.zip", "www.zip", "整站备份压缩包"),
    ("/database.sql", "database.sql", "数据库导出"),
    ("/db_backup.tar.gz", "db_backup.tar.gz", "数据库备份"),
    ("/site-backup.zip", "site-backup.zip", "站点备份"),
    ("/dump.sql", "dump.sql", "数据库导出"),

    # -- 配置与凭据 -----------------------------------------------------
    ("/.env.local", ".env.local", "本地环境变量，常含明文口令"),
    ("/.env.production", ".env.production", "生产环境变量"),
    ("/.env.backup", ".env.backup", "环境变量备份"),
    ("/.htpasswd", "htpasswd", "HTTP 基础认证口令文件"),
    ("/.netrc", ".netrc", "FTP/HTTP 自动登录凭据"),
    ("/.npmrc", ".npmrc", "npm 配置，常含发布令牌"),
    ("/.pypirc", ".pypirc", "PyPI 发布凭据"),
    ("/settings.json", "settings.json", "应用配置"),
    ("/config.yml", "config.yml", "应用配置"),
    ("/secrets.json", "secrets.json", "密钥文件"),
    ("/service-account.json", "service-account.json", "GCP 服务账号密钥"),

    # -- 云与容器编排 ---------------------------------------------------
    ("/.kube/config", "kube/config", "Kubernetes 集群凭据"),
    ("/.docker/config.json", "docker/config.json", "镜像仓库登录凭据"),
    ("/.config/gcloud/credentials.db", "gcloud/credentials.db",
     "GCP 凭据库"),
    ("/.azure/azureProfile.json", "azureProfile.json", "Azure 订阅信息"),
    ("/docker-compose.prod.yml", "docker-compose.prod", "生产编排文件"),

    # -- CI/CD 与仓库元数据 ---------------------------------------------
    ("/.gitlab-ci.yml", "gitlab-ci.yml", "CI 配置，常含部署密钥"),
    ("/.github/workflows/deploy.yml", "workflows/deploy.yml", "CI 部署流程"),
    ("/.git-credentials", "git-credentials", "Git 明文凭据"),
    ("/.git/HEAD", "git/HEAD", "Git 仓库头指针"),

    # -- 调试与探针 -----------------------------------------------------
    ("/phpinfo.php", "phpinfo.php", "PHP 环境信息泄露"),
    ("/info.php", "info.php", "PHP 探针"),
    ("/test.php", "test.php", "遗留测试脚本"),
    ("/_profiler/phpinfo", "_profiler", "Symfony 调试器信息泄露"),
    ("/actuator/health", "actuator/health", "Spring Boot 健康端点"),

    # -- API 面 ---------------------------------------------------------
    ("/api/admin/users", "api/admin/users", "未授权访问的后台接口"),
    ("/api/v1/internal/config", "api/v1/internal", "内部配置接口"),
    ("/graphql", "graphql", "GraphQL 端点，常可内省出全部数据结构"),
    ("/swagger-ui.html", "swagger-ui", "接口文档，泄露全部端点"),

    # -- 现代密钥（AI / 云 SDK）-----------------------------------------
    # 这一类是近几年新增的高价值目标：扫描器已经专门在找它们，
    # 而普通站点根本不会有这些文件。
    ("/.claude/settings.json", "claude/settings.json", "AI 助手配置，可能含 API 密钥"),
    ("/.cursor/mcp.json", "cursor/mcp.json", "编辑器 MCP 配置"),
    ("/.env.openai", "env.openai", "OpenAI 密钥"),
    ("/.env.anthropic", "env.anthropic", "Anthropic 密钥"),
)


def learned_decoys() -> list:
    """Decoy candidates produced by the learning pass.

    Kept separate from the curated list so the two are distinguishable in
    the configuration file and in a report. They go through exactly the same
    screening as everything else -- learned does not mean trusted.
    """
    try:
        from . import learning
        tokens = learning.learned_tokens()
    except (ImportError, OSError):
        return []
    # Bound the shape before it reaches the filesystem.
    #
    # A learned candidate is whatever attackers actually requested, and
    # attackers request things like a single 200-character run of `a`. That
    # token went in, and then the screening step did
    # `Path(webroot) / token` and died with `ENAMETOOLONG` -- so `vigil decoy
    # install` crashed because *somebody else* sent a long URL. Two limits:
    # no component over 64 bytes (no real path on this host is close), and no
    # path over 200 bytes. A decoy that no human or tool would ever probe is
    # worthless anyway; what matters is that it looks like something worth
    # probing.
    bounded = []
    for t in tokens:
        parts = [seg for seg in t.strip().split("/") if seg not in ("", ".")]
        if not parts or len(t) > 200:
            continue
        if any(len(seg.encode("utf-8", "ignore")) > 64 for seg in parts):
            continue
        bounded.append("/" + "/".join(parts))
    return [(t, t.lstrip("/"), "自学习：多个独立来源请求过，且从未被成功访问")
            for t in bounded]


def evolve_adopted() -> list:
    """Decoys the self-improvement loop adopted from this host's own traffic.

    Read straight from the state file instead of importing `evolve`: the
    enforcement path must keep working even when the evolve package is absent,
    disabled, or broken. A tripwire that stops being enforced because the thing
    that added it crashed is worse than no tripwire, because nobody is looking
    for it any more.
    """
    import json
    from ..core import paths as _paths
    path = _paths.STATE_STATE / "evolve-adopted.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for entry in (data if isinstance(data, list) else []):
        if not isinstance(entry, dict):
            continue
        p = str(entry.get("path") or "")
        # Same grammar the writer enforces. Re-checked here because this file is
        # on disk and therefore editable by anything that can write to it, and a
        # path with a quote or a brace in it would become nginx config injection.
        if not p.startswith("/") or len(p) > 130:
            continue
        if any(c in p for c in '"\'{}; \t\r\n'):
            continue
        out.append((p, "auto", "自修正循环采纳：%s"
                    % (str(entry.get("why") or "")[:60])))
    return out


#: Paths that are plausibly **real** application routes on some deployment.
#:
#: The curated list contains `/login`, `/graphql`, `/actuator/health` and
#: friends because a scanner asking for them is suspicious on *most* hosts.
#: But a Spring Boot host really serves `/actuator/health`, an OIDC host
#: really serves `/login`, and a GraphQL host really serves `/graphql`. When
#: the screening below cannot prove the path is absent (the template lives
#: outside the webroot, or the webroot is empty), installing `location =`
#: for it turns the operator's own health check or monitoring probe into a
#: seven-day ban on its first request. So these are *observed* rather than
#: punished on sight: repeated hits from one source still ban, a first hit
#: from a monitor does not.
_LIVE_ROUTE_PATTERNS = re.compile(r"""^(?:
      /actuator(?:/|$)
    | /graphql$
    | /login$
    | /user/login$
    | /api/
    | /mcp/?$
    | /sse$
    | /swagger-ui\.html$
    | /wp-login\.php$
    | /wp-admin/
    | /xmlrpc\.php$
    | /admin/?
    | /admin\.php$
    | /administrator/
    | /manager/html$
    | /phpmyadmin/
    | /adminer\.php$
    | /cgi-bin/luci$
    | /index\.php$
    | /server-status$
    | /\.well-known/
)""", re.X)


def live_route_risk(path: str) -> bool:
    """Could this decoy path be somebody's *working* endpoint?"""
    text = str(path or "").split("?")[0].strip()
    return bool(text) and bool(_LIVE_ROUTE_PATTERNS.match(text))


#: `location` directives, in the shapes a vhost actually uses. Regex
#: locations (`~`, `~*`) are skipped: evaluating them is guesswork, and a
#: guess that rejects a decoy is the safe direction anyway.
_LOCATION_RE = re.compile(
    r"^\s*location\s+(?:(=|\^~)\s+)?([^\s{;]+)", re.M)


def parse_locations(text: str) -> set:
    """Path prefixes/exacts declared by `location` in an nginx config."""
    found = set()
    for _mod, token in _LOCATION_RE.findall(str(text or "")):
        token = token.strip()
        if not token.startswith("/"):
            continue                      # regex, named, @prefix -- not a path
        if token in ("/", ""):
            continue                      # the catch-all covers everything
        found.add(token.rstrip("/") or "/")
    return found


def route_covered(routes, path: str) -> bool:
    """Does one of *routes* already serve *path*?

    A prefix location (`location /app/`) covers everything under it; an exact
    location (`location = /health`) covers one path. Anything the site
    actually declares is by definition not a decoy, whatever the disk and the
    site text say.
    """
    want = str(path or "").rstrip("/") or "/"
    for route in routes or ():
        candidate = str(route or "").rstrip("/") or "/"
        if candidate == "/":
            continue
        if want == candidate or want.startswith(candidate + "/"):
            return True
    return False


def candidate_decoys() -> list:
    """Curated decoys, the lure canary, and anything the learning pass adopted.

    The canary is here so that it is enforced exactly like every other decoy
    -- it is a real path with a real `location`, not a marker. What makes it
    special is only where it is *published*: it appears in no other place on
    this host, so a hit on it proves the requester read the lure surfaces.
    """
    # Deduplicated, curated first. The learned list is mined from traffic and
    # routinely re-discovers paths that are already curated (`/.aws/credentials`
    # and `/.env` both appear in it). Two entries for one path means two
    # `location` blocks, and nginx refuses the whole file with
    # `[emerg] duplicate location` -- which is how this was found, by the
    # `nginx -t` guard rolling the install back rather than by a silent
    # breakage. Curated wins because its rationale is written down.
    out, seen = [], set()
    for entry in list(DECOYS) + learned_decoys() + evolve_adopted():
        if entry[0] in seen:
            continue
        seen.add(entry[0])
        out.append(entry)
    try:
        from . import lure
        entry = lure.canary_entry()
        if entry[0] not in seen:
            out.append(entry)
    except (ImportError, OSError):
        # Narrow on purpose: a lure that is merely unavailable (module not
        # importable, state directory unwritable) must not stop the decoys
        # from working, but anything *unexpected* should surface rather than
        # be swallowed -- a canary that silently never exists is worse than
        # a loud failure, because the lure report would still say "armed".
        pass
    return out


def log_path() -> Path:
    """Where decoy hits are recorded. One file, one meaning."""
    ng = detect.nginx() or {}
    conf = str(ng.get("conf", "") or "")
    candidates = []
    if conf:
        candidates.append(Path(conf).parent.parent / "wwwlogs")
    candidates.append(Path("/www/wwwlogs"))
    for base in candidates:
        if base.is_dir():
            return base / "vigil-decoy.log"
    return candidates[0] / "vigil-decoy.log"


def _site(cfg) -> tuple:
    """(domain, webroot) for the site we are protecting."""
    from ..gates import demo
    return demo._site(cfg)


def _ascii(domain: str) -> str:
    """IDN-encode a display domain so it can be matched against nginx config.

    `_site` hands back the form a person types -- a Unicode IDN, because
    that is what belongs in an email and in a log line. Every resolver below
    keys on the punycode form instead, so the conversion has to happen
    somewhere, and this is it.
    """
    text = str(domain or "").strip()
    if not text or text.isascii():
        return text
    try:
        return text.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return text


def _include_dir(domain: str):
    """The directory the protected vhost includes its snippets from.

    Delegated to the same resolver the demo page uses, and for the same
    reason it was written: guessing this wrong is not cosmetic. A
    server-scope `location` written into ``http{}`` makes nginx refuse to
    load at all, which takes every site on the host down.
    """
    from ..gates import demo
    probes = []
    ascii_domain = _ascii(domain)
    if ascii_domain:
        probes.append(ascii_domain)
        # The panel subdomain protects the panel; the snippet has to land on
        # the site people actually reach, which is the registrable domain.
        probes.append(demo._main_site_ascii(ascii_domain))
    for probe in probes:
        if not probe:
            continue
        found = demo._site_include_dir(probe)
        if found:
            return found
    return None


#: Marks vigil's own lure block inside a site file. Everything between the
#: two markers is written by this program, not by the site -- so it must be
#: removed before the site's content is used to judge whether a decoy is
#: referenced. Without this, advertising the decoys in robots.txt would make
#: every advertised decoy fail screening as "referenced by the site", and the
#: lure would delete itself on the next run.
LURE_BEGIN = "# >>> vigil lure (generated; do not edit) >>>"
LURE_END = "# <<< vigil lure <<<"


def _strip_lure_block(text: str) -> str:
    """Drop vigil's generated lure block from a file's text."""
    if LURE_BEGIN not in text:
        return text
    out, inside = [], False
    for line in text.splitlines():
        if line.strip() == LURE_BEGIN:
            inside = True
            continue
        if line.strip() == LURE_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "\n".join(out)


def corpus(webroot: str, cap: int = _CORPUS_CAP) -> str:
    """Everything the site itself says, as one lowercase blob.

    This is the known-good corpus the decoys are tested against. It is read
    once at install time, not per request.
    """
    root = Path(webroot)
    chunks, total = [], 0
    if not root.is_dir():
        return ""
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", "vendor")]
        for name in sorted(filenames):
            if not name.lower().endswith(_TEXT_EXT):
                continue
            full = Path(dirpath) / name
            try:
                if full.stat().st_size > 2 * 1024 * 1024:
                    continue
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            chunks.append(_strip_lure_block(text))
            total += len(text)
            if total >= cap:
                return "\n".join(chunks).lower()
    return "\n".join(chunks).lower()


def screen(webroot: str, candidates=None, text: str = None,
           routes=None) -> tuple:
    """Split candidates into (safe, rejected).

    A decoy is rejected when it is not actually a decoy:

    * the path exists on disk -- then it is a real file, and banning people
      for requesting a real file is a self-inflicted outage;
    * the site's own content mentions it -- then a legitimate link could lead
      a visitor (or a crawler) straight into a ban;
    * the site's nginx config declares a `location` for it -- then it is a
      live route, and the health check or monitor that requests it would be
      banned on its first call. That is the failure this screening exists to
      prevent: a real Spring Boot `/actuator/health`, an OIDC `/login` or a
      `/graphql` endpoint, on a host where the template lives outside the
      webroot so the disk check cannot see it.

    ``routes`` is supplied by the caller (from the site's own configuration)
    rather than read from the host here, so this function stays a pure
    predicate and a test never depends on the machine it runs on.

    Rejected candidates are reported with the reason, never silently dropped:
    "we installed 18 of 20 decoys" is information, "20 decoys" is a claim.
    """
    text = corpus(webroot) if text is None else text
    safe, rejected = [], []
    for entry in (candidates if candidates is not None else
                  candidate_decoys()):
        path, token, why = entry
        on_disk = Path(webroot) / path.lstrip("/")
        try:
            exists = on_disk.exists()
        except OSError:
            # A name the filesystem cannot even represent cannot be a real
            # file on it, so it is safe to use as a decoy. Guarded because an
            # unhandled error here took the whole command down over a name
            # nobody on this host had written.
            exists = False
        if exists:
            rejected.append((path, "磁盘上已存在这个文件"))
            continue
        if token.lower() in text:
            rejected.append((path, "站点内容里引用了它（可能是正常链接）"))
            continue
        if route_covered(routes, path):
            rejected.append((path, "本机 nginx 配置里已有这个 location"
                                   "（是活路由，不是诱饵）"))
            continue
        safe.append(entry)
    return safe, rejected


def site_routes(cfg=None) -> set:
    """`location` paths declared by the site this program is protecting.

    Read from the site's vhost and its include directory. Our own generated
    snippets are skipped: they define `location` for the gate and for the
    decoys themselves, and counting those would make every decoy reject
    itself on the next install.
    """
    texts = []
    domain = ""
    include_dir = None
    try:
        from ..gates import demo
        domain, _webroot = _site(cfg)
        if domain:
            conf = demo._find_site_conf(_ascii(domain))
            if conf:
                texts.append(Path(conf).read_text(encoding="utf-8",
                                                  errors="replace"))
        include_dir = _include_dir(domain) if domain else None
    except Exception:                                       # noqa: BLE001
        return set()
    if include_dir:
        try:
            for path in sorted(Path(include_dir).glob("*.conf")):
                if path.name.startswith("vigil-"):
                    continue                                # ours, not the site's
                try:
                    texts.append(path.read_text(encoding="utf-8",
                                                errors="replace"))
                except OSError:
                    continue
        except OSError:
            pass
    routes = set()
    for text in texts:
        routes |= parse_locations(text)
    return routes


def render(paths) -> str:
    """The nginx snippet: one location per decoy, all writing to one log.

    ``return 444`` closes the connection without a response. A 404 would be
    friendlier to the scanner -- it would tell it the request was understood
    and merely not found -- while an empty reply gives it nothing to parse and
    costs this server one packet instead of a page.

    The response is deliberately identical for every decoy: a scanner cannot
    learn which of its guesses were "closer".
    """
    log = log_path()
    lines = [
        "# vigil 诱饵端点 —— 由 vigil 生成，请勿手工编辑",
        "#",
        "# 这些路径在磁盘上不存在、站点内容里也没有引用，只可能来自扫描器。",
        "# 任何一次命中都记入下面这个日志，并由 vigil-threatd 立即封禁。",
        "#",
        "# 为什么返回 444：不给出任何响应内容，扫描器无从判断请求是否被理解，",
        "# 而本机只付出一个丢包的代价。",
        "",
    ]
    for path, _token, why in paths:
        lines.append("# %s —— %s" % (path, why))
        lines.append("location = %s {" % path)
        lines.append("    access_log %s;" % log)
        lines.append("    return 444;")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


#: How many hits may accumulate before the file is examined for trimming.
#: Checking on every write is what made this quadratic; checking never lets
#: the file grow without bound. This is the amortisation knob, and it is also
#: the size bound: at most `cap + _TRIM_EVERY` records.
_TRIM_EVERY = 500
_HITS_SINCE_TRIM = 0


def hits_path() -> Path:
    from ..core import paths
    return paths.STATE_STATE / "decoy-hits.jsonl"


def note_hit(ip: str, uri: str, when: float = None, cap: int = 5000) -> None:
    """Record one decoy hit for the learning pass.

    Kept as a bounded append-only file rather than in memory: the daemon
    restarts on every upgrade, and the value of these records is precisely
    that they accumulate over weeks.

    Trimming happens rarely, not on every write. The first version read the
    whole file on *each* hit to decide whether it needed trimming -- O(n) per
    hit, so O(n^2) overall. Measured, that capped this at **659 hits/second**
    in the one code path whose entire purpose is to attract a flood: a decoy
    exists to be hammered. Now the file is only examined once every
    :data:`_TRIM_EVERY` hits, which is amortised to nothing and keeps the
    bound exact: at most ``cap + _TRIM_EVERY`` records on disk.
    """
    import json
    import time as _time
    path = hits_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(path), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(
                {"ts": round(when if when is not None else _time.time(), 3),
                 "ip": str(ip), "uri": str(uri)[:300]},
                ensure_ascii=False) + "\n")
    except OSError:
        return
    global _HITS_SINCE_TRIM
    _HITS_SINCE_TRIM += 1
    if _HITS_SINCE_TRIM < _TRIM_EVERY:
        return
    _HITS_SINCE_TRIM = 0
    try:
        if path.stat().st_size > 0:
            with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            if len(lines) > cap:
                with open(str(path), "w", encoding="utf-8") as fh:
                    fh.writelines(lines[-cap:])
    except OSError:
        pass


def read_hits(limit: int = 5000) -> list:
    import json
    out = []
    try:
        with open(str(hits_path()), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh.readlines()[-limit:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def status(cfg=None) -> dict:
    """What is installed right now."""
    from ..core.config import load as load_config
    cfg = cfg or load_config()
    out = {"installed": False, "conf": "", "paths": [], "log": str(log_path()),
           "log_present": log_path().exists(), "enabled": bool(
               cfg.get("threat.decoy.enabled", True))}
    try:
        domain, webroot = _site(cfg)
    except Exception:                                   # noqa: BLE001
        return out
    out["webroot"] = webroot or ""
    include_dir = _include_dir(domain)
    if include_dir:
        target = Path(include_dir) / CONF_NAME
        out["conf"] = str(target)
        out["installed"] = target.is_file()
        if target.is_file():
            try:
                text = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            out["paths"] = re.findall(r"^location = (\S+) \{", text, re.M)
    return out


def _register_and_restart(cfg) -> tuple:
    """Tell the threat daemon to watch the new log, and make it take effect.

    Two separate things have to happen, and skipping either leaves decoys
    that silently catch nothing:

    * the path is written into ``threat.log_sources.decoy``, because the
      daemon resolves its source list once at start-up -- creating the file
      is not enough, the consumer has to be told the file exists;
    * the daemon is restarted, because it is already running with the old
      list. This is the difference between "installed" and "working", and it
      is precisely the gap this program keeps being bitten by: a component
      that looks healthy while doing nothing.
    """
    from ..core import shell

    # `cfg` 可能是 None（调用方没传）—— 那就去读真实配置，而不是让
    # `None.get()` 抛 AttributeError 被下面那个 except 收成一个含糊的
    # "登记监控来源失败"。实测日志里正是这个报错：
    #   [learn] 写入新候选失败：登记监控来源失败：'NoneType' object has no attribute 'get'
    # 一个「看起来是配置问题、其实是没传参数」的报错，比不报错更费时间。
    if cfg is None:
        try:
            from ..core.config import load as _load_cfg
            cfg = _load_cfg()
        except Exception as e:                                     # noqa: BLE001
            return False, "登记监控来源失败：读不到配置（%s）" % e
    try:
        path = str(log_path())
        listed = [p for p in (cfg.get("threat.log_sources.decoy", []) or [])]
        if path not in listed:
            listed.append(path)
            cfg.set("threat.log_sources.decoy", listed)
            cfg.save()
    except (OSError, AttributeError) as e:
        return False, "登记监控来源失败：%s" % e

    if shell.out(["systemctl", "is-active", "vigil-threatd.service"]) != "active":
        return True, "已登记监控来源（vigil-threatd 未运行，启动后自动生效）"
    ok, _out, err = shell.run(["systemctl", "restart", "vigil-threatd.service"],
                              timeout=60)
    if ok:
        return True, "已重启 vigil-threatd，开始监控诱饵日志"
    return False, "重启 vigil-threatd 失败：%s" % (err or "?")


def install(cfg=None, dry_run: bool = False) -> dict:
    """Write the snippet, prove nginx still loads, then keep it."""
    from ..gates import installer as ginstaller

    out = {"ok": False, "written": "", "paths": [], "rejected": [],
           "problems": [], "log": str(log_path())}

    domain, webroot = _site(cfg)
    if not webroot or not Path(webroot).is_dir():
        out["problems"].append("找不到站点根目录，无法确认诱饵路径是否安全")
        return out

    safe, rejected = screen(webroot, routes=site_routes(cfg))
    out["rejected"] = rejected
    out["paths"] = [p for p, _t, _w in safe]
    if not safe:
        out["problems"].append("没有任何诱饵通过安全检查（全部与站点内容冲突）")
        return out

    include_dir = _include_dir(domain)
    if include_dir is None:
        out["problems"].append(
            "找不到站点 include 片段的目录 —— 不猜布局，避免把 server 作用域的 "
            "location 写进 http{}（那会让 nginx 直接拒绝加载）")
        return out

    target = Path(include_dir) / CONF_NAME
    out["written"] = str(target)
    if dry_run:
        out["ok"] = True
        return out

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        ginstaller._atomic_write(target, render(safe))
    except OSError as e:
        out["problems"].append("写入失败：%s" % e)
        return out

    # Prove nginx still accepts its configuration *before* reloading. A
    # snippet that breaks the config would take every site on this host down,
    # which is a far worse outcome than not having decoys.
    ok, msg = _nginx_test()
    if not ok:
        try:
            target.unlink()
        except OSError:
            pass
        out["problems"].append("nginx 拒绝新配置，已撤回诱饵片段：%s" % msg)
        return out

    _nginx_reload()

    # Creating the log is not the same as watching it. Without this the
    # decoys answered requests and recorded them while the daemon -- which
    # resolved its source list before the file existed -- banned nobody.
    registered, note = _register_and_restart(cfg)
    out["watched"] = registered
    out["notes"] = [note]
    if not registered:
        out["problems"].append(note)
        return out

    # Publishing is what turns a set of tripwires into something that
    # actually gets requested. Failure here is reported but does not undo the
    # decoys: they still work against dictionary scanners, which is strictly
    # better than nothing.
    try:
        from . import lure as lure_mod
        lr = lure_mod.install(cfg)
        out["lure"] = {"ok": lr.get("ok"), "advertised": lr.get("advertised"),
                       "robots": lr.get("robots", "")}
        if not lr.get("ok"):
            out["notes"].append("诱导面未发布：%s"
                                % "；".join(lr.get("problems") or ["未知原因"]))
    except Exception as e:                                  # noqa: BLE001
        out["notes"].append("诱导面发布异常：%s" % e)

    out["ok"] = True
    return out


def uninstall(cfg=None) -> dict:
    st = status(cfg)
    out = {"ok": True, "removed": ""}
    if not st.get("installed"):
        return out
    # Take the lure down with the decoys. Leaving robots.txt advertising
    # paths that are no longer trapped would send automated traffic at 404s
    # while telling it the site is full of juicy files.
    try:
        from . import lure as lure_mod
        lr = lure_mod.uninstall(cfg)
        if not lr.get("ok"):
            out.setdefault("problems", []).extend(lr.get("problems") or [])
    except (ImportError, OSError) as e:
        out.setdefault("problems", []).append("撤销诱导面失败：%s" % e)
    target = Path(st["conf"])
    try:
        target.unlink()
        out["removed"] = str(target)
    except OSError as e:
        out["ok"] = False
        out["problems"] = [str(e)]
        return out
    _nginx_reload()
    return out


def _nginx_test() -> tuple:
    binary = _nginx_binary()
    if not binary:
        return True, "找不到 nginx，跳过语法检查"
    ok, out, err = shell.run([binary, "-t"], timeout=20)
    return ok, ("%s %s" % (out or "", err or "")).strip()


def _nginx_reload() -> None:
    binary = _nginx_binary()
    if binary:
        shell.run([binary, "-s", "reload"], timeout=20)


def _nginx_binary() -> str:
    ng = detect.nginx() or {}
    for cand in (ng.get("binary"), "/www/server/nginx/sbin/nginx"):
        if cand and os.path.exists(str(cand)):
            return str(cand)
    import shutil
    return shutil.which("nginx") or ""


def recent_hits(limit: int = 20) -> list:
    """The tail of the decoy log, for `vigil decoy status`."""
    path = log_path()
    try:
        with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
            return [l.rstrip("\n") for l in fh.readlines()[-limit:]]
    except OSError:
        return []


