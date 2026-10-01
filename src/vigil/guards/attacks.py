# -*- coding: utf-8 -*-
"""Attack knowledge base and HTTP signature tables.

This module is deliberately dependency free (standard library only, no other
``vigil`` imports except the shared :class:`ConfigError`).  Both guard daemons
-- :mod:`vigil.guards.threat` and :mod:`vigil.guards.loadshed` -- import it, and
the threat daemon compiles its detectors from it *after* the merged config is
loaded.

Three things live here
----------------------

1. **Built-in signature tables** (:data:`EXPLOIT_HIGH`, :data:`EXPLOIT_LOW`,
   :data:`STATIC_EXT`).  These are the fallback used when the operator has not
   supplied their own patterns in the config file.  They are exposed as
   *compiled* objects because the verification harness and the daemon both use
   them directly; the source strings are kept alongside under
   ``*_PATTERNS`` so that a config file can be seeded from them.

2. :func:`compile_patterns` / :func:`compile_static` -- the helpers the daemon
   calls at start-up so that patterns edited in the config file actually take
   effect.  In the original implementation the tables were compiled from the
   *module default* dict at import time, before the user config was merged, so
   editing ``exploit_high`` in the config file was silently ignored.  Callers
   must compile from the merged config, never from these constants.

3. :data:`ATTACK_EXPLAIN` -- the "what is this IP actually doing and why does
   it matter" knowledge base used to enrich ban alerts.

The explanation texts are user facing, so they are written in Chinese: the
audience is a Chinese speaking sysadmin reading a mail on a phone at 3am.  Code
and comments stay in English.
"""
from __future__ import annotations

import json
import os
import re
from typing import Iterable, List, Sequence, Tuple


class ConfigError(Exception):
    """The merged configuration cannot be trusted.

    Raised (instead of silently falling back to built-in defaults) when the
    config file is unparseable or a security relevant value has the wrong
    type.  A silent fallback can re-enable hardcoded paths or drop a
    protection, which is exactly the failure mode this project exists to
    avoid.
    """


def assert_config_parsable(path) -> None:
    """Refuse to run against a config file we cannot parse.

    ``core.state.read_json`` (used by ``Config``/``Store``) deliberately
    swallows ``ValueError`` and returns the defaults, which is right for
    monitoring state but wrong for a security daemon: a typo in the config
    file would silently re-enable built-in log paths, restore a stale
    whitelist or drop a protection.  A missing file is fine (defaults are
    trustworthy); a present-but-broken file is fatal and loud.
    """
    try:
        exists = os.path.isfile(str(path))
    except OSError:
        return
    if not exists:
        return
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            blob = json.load(fh)
    except ValueError as exc:
        raise ConfigError(
            "配置文件 %s 不是合法 JSON：%s\n"
            "为避免静默回退到内置默认值（可能重新启用硬编码路径或丢失防护），"
            "已拒绝启动。请修复该文件后重试。" % (path, exc))
    except OSError as exc:
        raise ConfigError("配置文件 %s 无法读取：%s" % (path, exc))
    if not isinstance(blob, dict):
        raise ConfigError(
            "配置文件 %s 的顶层必须是 JSON 对象，实际是 %s"
            % (path, type(blob).__name__))


# --------------------------------------------------------------------------
# Signature tables
# --------------------------------------------------------------------------
# High confidence: virtually never legitimate traffic.  A single hit bans.
EXPLOIT_HIGH_PATTERNS: List[str] = [
    r"\.\./\.\./",                       # path traversal
    r"etc/passwd",                       # /etc/passwd read attempt
    r"jndi:",                            # Log4Shell family
    r"%00",                              # null byte injection
    r"union[+%20]*select",               # SQL injection
    r"cmd\.exe",                         # Windows shell
    r"base64_decode\s*\(",               # PHP webshell primitive
    r"eval\s*\(",                        # PHP webshell primitive
    r"wp-config\.php",                   # WordPress credential file
    r"\.aws/credentials",                # AWS key file
    r"\.ssh/id_",                        # SSH private key
    r"config\.php\.(bak|old|save)",      # leaked config backup
    r"\.git/config",                     # source disclosure, unambiguous
    r"\.svn/entries",                    # same, older tooling
    r"phpunit/.*eval-stdin\.php",        # CVE-2017-9841, still scanned daily
    r"_ignition/execute-solution",        # Laravel RCE, CVE-2021-3129
    r"/actuator/(env|heapdump|jolokia)",  # Spring Boot actuator leak
    r"/proc/self/environ",                # LFI escalation
    r"etc/shadow",                        # shadow read attempt
    r"/bin/(ba|z|c)?sh($|[\s?])",         # shell invocation in a path
    r"%2e%2e%2f",                         # url-encoded traversal
    r"%252e%252e",                        # double-encoded traversal
    r"\$\{jndi:",                          # Log4Shell, braced form
]

# Low confidence: these strings legitimately appear in normal paths (a control
# panel loads ``ico-phpmyadmin.png``), so they need several hits inside a window
# and must not be a static asset before they count as probing.
EXPLOIT_LOW_PATTERNS: List[str] = [
    r"\.env($|[\?/])",
    r"/\.git/",
    r"/\.svn/",
    r"wp-login\.php",
    r"xmlrpc\.php",
    r"phpmyadmin",
    r"/pma/",
    r"adminer",
    r"/actuator",
    r"\.DS_Store",
    r"docker-compose",
    r"Dockerfile",
    r"credentials\.txt",
    r"\.bash_history",
    r"/shell($|[\?/])",
    r"cgi-bin/",
    r"\.sql($|\?)",
    # Reconnaissance against panels and appliances that are only ever
    # internet-facing by mistake. Individually weak -- `jenkins` is a word --
    # which is why they live in the low-confidence tier and need a window of
    # hits before they count.
    r"/(server-status|server-info)",
    r"/(jenkins|hudson|zabbix|grafana|kibana|solr)(/|$)",
    r"/owa/auth/logon\.aspx",            # Exchange
    r"/autodiscover/autodiscover\.xml",   # Exchange
    r"/ecp/",                             # Exchange control panel
    r"/remote/(login|fgtl)",              # Fortinet
    r"/cgi-bin/luci",                     # router exploit
    r"/(boaform|GponForm|HNAP1)/",        # IoT botnets
    r"/setup\.cgi",                       # IoT botnets
    r"\.php~",                            # editor backup of live code
    r"/(id_rsa|id_dsa|authorized_keys)($|[\s?])",
    r"/backup\.(sql|zip|tar\.gz)",
    r"/\.well-known/(?!acme-challenge)",  # scanners probing well-known
]

# Static asset suffixes.  A request for one of these is never judged by the
# exploit signatures: panels load icons whose names contain "phpmyadmin" and
# treating that as an attack banned the administrator for 24h in production.
STATIC_EXT_PATTERN: str = (
    r"\.(png|jpe?g|gif|webp|svg|ico|bmp|css|js|mjs|map|woff2?|ttf|eot|otf"
    r"|mp4|webm|mp3|wav|pdf|zip|gz|tar|tgz|rar|7z)(\?|$)"
)

#: Compiled built-ins.  The daemon must *not* use these directly -- it calls
#: :func:`compile_patterns` with the merged config so operator edits apply.
EXPLOIT_HIGH: List[re.Pattern] = [re.compile(p, re.I) for p in EXPLOIT_HIGH_PATTERNS]
EXPLOIT_LOW: List[re.Pattern] = [re.compile(p, re.I) for p in EXPLOIT_LOW_PATTERNS]
STATIC_EXT: re.Pattern = re.compile(STATIC_EXT_PATTERN, re.I)


def compile_patterns(patterns: Iterable[str], flags: int = re.I
                     ) -> Tuple[List[re.Pattern], List[str]]:
    """Compile *patterns*, returning ``(compiled, errors)``.

    A single malformed operator pattern must not take the daemon down, but it
    must be visible: the caller logs every entry in *errors* and refuses to
    start when the resulting table is empty (a detector with no signatures
    silently stops detecting).
    """
    compiled: List[re.Pattern] = []
    errors: List[str] = []
    for pat in patterns or []:
        text = str(pat)
        if not text:
            continue
        try:
            compiled.append(re.compile(text, flags))
        except re.error as exc:
            errors.append("%s (%s)" % (text, exc))
    return compiled, errors


def compile_static(pattern: str, flags: int = re.I):
    """Compile the static-asset pattern.  Returns ``None`` when malformed."""
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def is_static_path(uri: str, pattern=None) -> bool:
    """True when *uri* looks like a static asset (built-in table)."""
    rx = pattern if pattern is not None else STATIC_EXT
    return bool(rx and rx.search(uri or ""))


# --------------------------------------------------------------------------
# Attack explanation knowledge base
# --------------------------------------------------------------------------
# Each entry: (compiled pattern, plain-language explanation).  Order matters:
# the more specific patterns come first so that, for example, a Log4Shell probe
# is explained as Log4Shell rather than as a generic "exploit attempt".
ATTACK_EXPLAIN: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"jndi:|ldap://|ldaps://|log4j|\$\{jndi", re.I),
     "在触发 **Log4Shell（CVE-2021-44228）** 类型的表达式注入：把 ${jndi:ldap://…} "
     "塞进请求，诱使服务器主动去连接攻击者的服务器。一旦被解析，对方可在你的机器上"
     "远程执行命令，风险等级最高。"),

    (re.compile(r"\.\./|%2e%2e|%252e|path.?traversal|目录穿越|跨目录", re.I),
     "在做**目录穿越（Path Traversal）**：用 ../ 跳出网站根目录去读系统文件。"
     "读 /etc/passwd 只是探路，下一步通常是找配置里的数据库口令或写入后门。"),

    (re.compile(r"union[\s+%]*select|information_schema|sqlmap|sleep\s*\(|"
                r"benchmark\s*\(|or\s+1\s*=\s*1|SQL\s*注入|注入点", re.I),
     "在尝试 **SQL 注入**：把 SQL 片段拼进参数，试图绕过登录或直接拖库。"
     "得手后可读取、篡改、删除你数据库里的全部数据。"),

    (re.compile(r"eval\s*\(|base64_decode|shell_exec|passthru|webshell|后门|"
                r"\.php\.(bak|old|save)|cmd\.exe", re.I),
     "在探测或试图写入 **WebShell / 命令执行后门**：这类请求的目标是让服务器"
     "把外部输入当成代码执行，成功后攻击者就等于拿到了一台可长期控制的机器。"),

    (re.compile(r"\.env", re.I),
     "在扫描 **.env 配置文件** —— 这类文件通常存放数据库密码与 API 密钥。"
     "一旦被读取成功，攻击者可直接连上你的数据库、冒充你的服务对外发起请求。"),

    (re.compile(r"\.git", re.I),
     "试图下载 **.git 目录** —— 据此可还原整站源码与全部提交历史，"
     "而历史提交里常有硬编码的账号、密钥（这是最常见的源码泄露途径）。"),

    (re.compile(r"phpmyadmin|/pma/|adminer|/mysql/", re.I),
     "在找暴露在公网的**数据库管理面板**（phpMyAdmin / adminer 等）—— "
     "一旦找到且口令薄弱，即可直接增删改查你的全部数据。"),

    (re.compile(r"wp-login|wp-admin|xmlrpc\.php|wordpress", re.I),
     "针对 **WordPress**：在尝试登录爆破，或滥用 xmlrpc.php 接口做放大攻击、"
     "批量猜解账号口令。"),

    (re.compile(r"\.aws|credentials", re.I),
     "在找 **云服务凭证**文件（AWS 等）—— 得手后可直接操作你的云资源，"
     "**产生真实费用**，并且难以追回。"),

    (re.compile(r"\.ssh|id_rsa|id_ed25519|authorized_keys", re.I),
     "在找 **SSH 私钥 / 授权文件** —— 得手后即可免密登录你的服务器，"
     "且以该密钥登录往往不会触发口令告警。"),

    (re.compile(r"\.sql|\.bak|\.zip|\.tar|\.tgz|backup|/dump|备份", re.I),
     "在找**数据库导出或站点备份**文件 —— 这类文件常被遗忘在网站目录且无访问控制，"
     "下载即等于拿到全部数据。"),

    (re.compile(r"/cgi-bin/luci|/actuator|/console|/manager/html|/solr/|"
                r"/jenkins|/hudson", re.I),
     "在探测**已知漏洞接口**（路由器/IoT 面板、Spring Actuator、Tomcat 管理台、"
     "Solr、Jenkins 等）—— 这些组件的历史漏洞多，是自动化攻击的首选目标。"),

    (re.compile(r"etc/passwd|etc/shadow|/proc/self/environ", re.I),
     "尝试读取 **系统账户文件**（/etc/passwd、/etc/shadow 等）—— "
     "这已经越过网站范围，属于直接攻击操作系统。"),

    (re.compile(r"配置|config|\.yml|\.yaml|\.json|\.ini|\.conf", re.I),
     "在找**配置文件** —— 里面常含数据库连接串、第三方服务密钥，"
     "是横向渗透时最有价值的目标之一。"),

    (re.compile(r"admin|login|manage|后台|管理", re.I),
     "在探测**后台登录入口**，为后续的口令爆破做准备。"),

    (re.compile(r"目录扫描|异常请求|敏感路径扫描|路径探测|路径爆破|probe", re.I),
     "在做**批量路径探测**：拿一份常见路径字典逐条试探，寻找未授权页面、"
     "备份文件或后台入口 —— 属入侵前的踩点行为。"),

    (re.compile(r"SSH.*爆破|认证失败|password|密码爆破|用户名枚举|无效用户", re.I),
     "用常见用户名与密码字典**反复尝试 SSH 登录**，企图猜中服务器口令。"
     "这类攻击常来自僵尸网络，同一批 IP 会持续数小时到数天。"),

    (re.compile(r"请求洪泛|flood|洪泛|请求总数|高频", re.I),
     "以极高频次请求，意图**耗尽服务器资源**，或借此掩盖其他攻击行为。"),

    (re.compile(r"漏洞利用|exploit|RCE|漏洞探测|高危|shell", re.I),
     "尝试**直接利用漏洞**（读取系统文件、远程命令执行等）—— "
     "这已不是踩点，而是实际攻击，风险等级最高。"),

    (re.compile(r"分布式爆破|distributed|僵尸网络|botnet", re.I),
     "检测到**分布式协同爆破**：大量不同来源 IP 同时低频率尝试，"
     "单 IP 阈值抓不到，是典型的僵尸网络行为。"),

    (re.compile(r"非白名单|off.?whitelist", re.I),
     "有**不在白名单内的 IP 成功登录**。这可能是管理员换了网络，"
     "也可能是口令已被攻破 —— 需要人工确认。"),
]


def explain(reason: str, uris: Sequence[str] = ()) -> str:
    """Return the first plain-language explanation matching *reason* / *uris*.

    Empty string when nothing matches; callers omit the explanation section in
    that case rather than printing a useless placeholder.
    """
    hay = "%s %s" % (reason or "", " ".join(str(u) for u in (uris or [])))
    for pattern, text in ATTACK_EXPLAIN:
        if pattern.search(hay):
            return text
    return ""


def explain_all(reason: str, uris: Sequence[str] = (), limit: int = 3) -> List[str]:
    """All matching explanations, most specific first, de-duplicated."""
    hay = "%s %s" % (reason or "", " ".join(str(u) for u in (uris or [])))
    out: List[str] = []
    for pattern, text in ATTACK_EXPLAIN:
        if pattern.search(hay) and text not in out:
            out.append(text)
            if len(out) >= limit:
                break
    return out


#: Remediation hints keyed by a coarse ``reason`` keyword.  Used by the alert
#: builder to tell the operator what to do next, not just what happened.
REMEDIATION: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"SSH|密码爆破|用户名枚举", re.I),
     "建议：确认 sshd 是否必须对公网开放；如非必要，改为仅密钥登录、"
     "禁用密码认证或限制来源网段。"),
    (re.compile(r"洪泛|flood", re.I),
     "建议：确认是否为 CDN/回源流量；必要时启用云端流量清洗，"
     "并检查后端是否已成为反射放大源。"),
    (re.compile(r"漏洞|exploit|扫描|路径|敏感", re.I),
     "建议：核对被请求的路径是否真实存在；若存在旧版本组件或备份文件，"
     "尽快升级并移出网站目录。"),
    (re.compile(r"分布式|distributed", re.I),
     "建议：这是多源协同攻击，单 IP 封禁作用有限，"
     "应考虑临时收紧认证策略或启用上游清洗。"),
    (re.compile(r"成功|登录", re.I),
     "建议：立即执行 `who`、`ss -tnp` 核查在线会话，必要时修改口令并吊销密钥。"),
]


def remediation(reason: str) -> str:
    """Remediation hint for *reason*, or ``""``."""
    for pattern, text in REMEDIATION:
        if pattern.search(reason or ""):
            return text
    return ""
