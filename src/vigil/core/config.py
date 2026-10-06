"""Configuration model.

Design decisions worth stating up front, because they are what make the
project portable and safe to open source:

* **No host data is ever compiled in.** Defaults below are generic
  (loopback-only whitelist, empty recipient list, empty from-address).
  Anything host specific is discovered at install time by
  :mod:`vigil.core.detect` and written to ``config.json``.
* **Secrets live in their own file** (``secrets.json``, mode 0600) so that
  ``vigil config export`` can share a working configuration without
  leaking API keys, and so the config file can be committed by users who
  want to version it.
* **Unknown keys survive a round trip.** Upgrade paths matter more than a
  strict schema; validation warns instead of destroying data.
"""
from __future__ import annotations

import copy
import os
import socket
from typing import Any

from . import paths
from .state import Store, deep_merge, read_json, write_json

# --------------------------------------------------------------------------
# Defaults. Nothing here may reference this or any other specific server.
# --------------------------------------------------------------------------
DEFAULTS: dict = {
    "version": 1,
    "hostname": "",                 # filled at install; display only

    # -- mail ------------------------------------------------------------
    "mail": {
        # Ordered fallback chain. Each entry: {"provider": "<id>", ...params}.
        # The first entry that succeeds wins; on failure the next is tried.
        "providers": [],
        # Where alerts go. Login alerts fall back to this when
        # login_recipients is empty.
        "recipients": [],
        "login_recipients": [],
        "from_address": "",
        "from_name": "Server Monitor",
        "reply_to": "",
        # Hard ceiling on messages sent per UTC day, across all providers.
        # Protects against alert storms draining a metered API quota.
        "daily_quota": 100,
        # Storm control. If more than this many messages have actually been
        # delivered in the window, further non-critical ones are parked and
        # replayed later as a single digest. A real attack can produce
        # hundreds of findings a minute, and one mail each is how the alert
        # channel ends up filtered into a folder nobody opens.
        "storm_threshold": 12,
        "storm_window": 600,
        # Collapse repeated identical alerts within this window (seconds).
        "dedupe_window": 900,
        # When every provider fails, hold the alert and retry later rather
        # than dropping it silently.
        "overflow_max": 200,
        "subject_prefix": "",
        "language": "zh",           # "zh" or "en"
        # How many parked digest files to replay per run. One keeps the
        # replay gentle on a metered provider after an outage.
        "overflow_per_run": 1,
        # 普通事件攒够这么多条就发一次；不足则等到 digest_max_wait 秒再说。
        # 重要事件（SEV_CRIT 或带 immediate 的）不受这两个值约束，立即发出。
        #
        # 这两项**属于 mail 段**，因为决定的是邮件怎么发。它们曾经被写在
        # `threat` 段里，而读取路径一直是 `mail.digest_min_items` —— 于是
        # `vigil config` 展示一个永远没人读的 `threat.digest_min_items`，
        # 真正生效的 `mail.*` 反而看不见。展示得出来却没人读的键比缺一个键
        # 更坏：它让人以为配上了。展示的键必须就是读取的键。
        "digest_min_items": 5,
        "digest_max_wait": 1800,
        # Inbound mailbox for the reply-command channel. Left empty, it is
        # inferred from the SMTP channel (the mailbox that sends the alerts
        # is almost always the one that receives the replies).
        "imap": {
            "host": "",
            "port": 993,
            "username": "",
            "password": "",
        },
    },

    # -- alert policy ----------------------------------------------------
    "alerts": {
        # "attacks" (default): email only findings that are an attack or
        #   evidence that a security control was switched off -- plus any
        #   CRIT, any login from an address you did not whitelist, and
        #   everything the threat daemon decides to ban.
        # "all": the old behaviour. Every file change, every port change,
        #   every successful login and every recovery is emailed too.
        #
        # Drift is never *hidden*: it is logged, kept in the health history
        #   and printed by `vigil health` / `vigil status`.
        "mode": "attacks",
        # 抖动迟滞（hysteresis）。某项检查从异常恢复后，这么多秒内再次
        #   变坏不重新发告警信 —— 「异常→恢复→异常」的抖动只在第一次异常
        #   和抖动真正结束时各发一封。恢复通知也推迟到状态稳定之后才发。
        #   静默期内异常仍然被记录：`vigil health` 看得到，退出码也为 1。
        #   静默期一过、异常仍在，就照常告警 —— 不会把持续异常吞掉。
        #   0 表示关闭迟滞（恢复即告警、再坏即告警）。
        "recovery_quiet_seconds": 600,
        # 重复提醒间隔（秒）。同一个**未发生变化**的异常最多这么久再提醒
        #   一次；一旦异常项新增或严重度上升，立即提醒，不等这个窗口。
        #   这一项替代了旧的 cooldown：旧值（1800 秒）其实是「多久重复一次」
        #   而不是「多久内不重复」，所以一个持续一天多的误报会每 30 分钟发
        #   一封一模一样的信，连续 55 封也没有被挡住。
        "renotify_seconds": 21600,
    },

    # -- backups ---------------------------------------------------------
    "backup": {
        # `vigil backup` writes here. Deliberately outside /var/lib/vigil so
        # that restoring over the live state cannot delete the archive being
        # restored from. `checks.backup.globs` is pointed at this directory
        # by the first backup, which is what makes the `backup_age`
        # inspection report anything at all.
        "dir": "/var/backups/vigil",
        "keep": 14,
        # Extra paths to include, beyond config, secrets, gate state and
        # baselines. Directories are archived recursively.
        "include": [],
    },

    # -- reply-by-email command channel ----------------------------------
    "commands": {
        "enabled": True,
        # Off by default. Turning this on creates a remote-code-execution
        # surface whose only authentication is the sender address, so it
        # must be a deliberate decision.
        "allow_shell": False,
        "max_per_hour": 30,
        # Hard cap on automatic *replies* per hour, separate from the cap on
        # commands. This channel reads the mailbox it writes to, so an
        # unbounded reply is a loop: on 2026-09-27 a transactional email
        # replied to itself for twenty minutes (#000422..#000447).
        "max_replies_per_hour": 12,
        # Services an inbound `restart <name>` may touch. Empty means the
        # built-in conservative list.
        "restartable": [],
    },

    # -- threat daemon ---------------------------------------------------
    "threat": {
        "enabled": True,
        "poll_interval": 5,
        # Only loopback is trusted by default. The installer offers to add
        # the current admin IP; nothing else is assumed.
        "whitelist": ["127.0.0.1/8", "::1"],
        # Where attacks are observed. Empty means "auto-detect at install".
        "log_sources": {
            "nginx_access": [],
            "auth": [],
            "panel": [],
            # The decoy log, written by the nginx snippet `vigil decoy
            # install` places. Auto-detected when it exists, so installing
            # the decoys is all that is needed to start catching them.
            "decoy": [],
        },
        # -- lure surfaces (robots.txt / sitemap) --------------------------
        # What may happen to /sitemap.xml:
        #   "auto"   -- serve the decoy sitemap only when this site does not
        #               already publish one of its own (default)
        #   "always" -- serve it regardless, shadowing the site's own file
        #   "never"  -- never serve a decoy sitemap
        # The robots.txt block is independent of this: it always lists the
        # same paths, so "auto" does not weaken the lure, it only declines to
        # take a surface the operator is already using.
        "lure": {
            "sitemap": "auto",
        },
        # -- netblock escalation --------------------------------------------
    # Escalating from an address to its network is the most dangerous
    # automatic decision in this program: one host scans you and bystanders
    # on the same /24 lose service. It is enabled because a coordinated
    # sweep from one subnet is exactly what per-address thresholds handle
    # badly, and the safety rails do the work "disabled" would otherwise do:
    # a range is refused outright if it contains a whitelisted address, one
    # of this host's own addresses, or reserved space.
    "netblock": {
        "enabled": True,
        # Distinct addresses, not events: one attacker rotating through a
        # subnet cannot reach this by trying harder.
        "min_ips": 6,
        "window_seconds": 1800,
        "ban_seconds": 86400,
        "max_current": 16,
    },
    # -- attack-driven posture ---------------------------------------
        # Distinct from the load shedder. A slow, patient campaign against
        # an idle machine never moves the load average, so the load-based
        # tightening never fires -- while the attack proceeds at the relaxed
        # threshold. This reacts to attack signals instead.
        "posture": {
            "enabled": True,
            "window_seconds": 300,
            "trigger_bans": 5,
            "hold_seconds": 900,
            "factor": 0.5,
        },
        # -- decoy endpoints (deception) ---------------------------------
        "decoy": {
            # A hit on a decoy path is normally conclusive, not suggestive: the
            # path does not exist on disk, nothing the site serves links to it,
            # and the only clients that ask for it are scanners. So the very
            # first hit already earns a ban measured in weeks.
            #
            # Exception: names that are plausible *real* routes on the right
            # deployment (`/actuator/health`, `/login`, `/graphql`). When the
            # screening cannot prove such a path is absent, a hit is only
            # observed until `soft_hits` requests land inside
            # `soft_window_seconds` -- so a monitor's first probe is not a
            # seven-day ban, while a scanner still bans itself quickly.
            "enabled": True,
            "soft_hits": 3,
            "soft_window_seconds": 300,
            # 7d / 14d / the longest ipset can hold (~24.8 days). ipset
            # stores a timeout as 32-bit milliseconds, so 30d and 90d steps
            # were rejected at enforcement time and the escalation silently
            # did not happen.
            "ban_seconds": [604800, 1209600, 2147483],
        },
        "ssh": {
            "enabled": True,
            "max_failures": 5,
            "window_seconds": 300,
            "ban_seconds": [600, 3600, 21600, 86400],
            # Username enumeration has a different natural rate than
            # password guessing, so it gets its own threshold.
            "invalid_user_threshold": 8,
        },
        "http": {
            "enabled": True,
            "max_attacks": 10,
            "window_seconds": 300,
            "ban_seconds": [600, 3600, 21600, 86400],
            # Sensitive-path probing is low confidence on its own, so it is
            # counted over a window rather than acted on per hit.
            "exploit_low_hits": 10,
            "exploit_low_window": 300,
            "burst_threshold": 100,
            "burst_window": 60,
            # 浏览器到不了的速率。之前的 500/60s（≈8 req/s）低于一个多标签
            # 管理台的正常轮询，实测把一个正在看后台的人判成了攻击者。
            "flood_threshold": 1200,
            "flood_floor": 600,
            "flood_window": 60,
            # NOTE: the built-in signature tables are intentionally NOT
            # listed here. An empty list is indistinguishable from "the
            # operator cleared it", and the daemon correctly refuses to run
            # with no exploit signatures -- so shipping an empty default
            # would make it refuse to start on a fresh install. Set these
            # keys explicitly in config.json if you want to override them;
            # absent means "use the built-in tables".
        },
        "portscan": {
            "enabled": True,
            "max_ports": 30,
            "window_seconds": 120,
            "ban_seconds": [3600, 21600, 86400],
        },
        # Escalation memory: after N bans an address is treated as hostile.
        "recidivist_bans": 3,
        "recidivist_ban_seconds": 604800,
        "notify_bans": True,
        "notify_ssh_success": True,
        "max_bans_per_hour": 60,
        # ipset set name and iptables chain name -- configurable because a
        # host may already use these names for something else.
        "ipset_name": "vigil_threat",
        "chain_name": "VIGIL_SHED",
        # ipset / iptables set and chain names (configurable because a host
        # may already use ours for something else).
        "ipset_set": "vigil_threat",
        "iptables_chain": "INPUT",
        "ipset_program": "ipset",
        "iptables_program": "iptables",
        # Add every local interface address to the whitelist. Prevents the
        # host from banning itself when a local process misbehaves.
        "auto_whitelist_local": True,
        # Minimum ban for a high-severity hit (a proven exploit attempt),
        # regardless of where the escalation ladder currently sits.
        "instant_ban_seconds": 86400,
        "offense_decay": 86400,
        "alert_cooldown": 600,
        "selfheal_interval": 30,
        "housekeeping_interval": 300,
        "min_flush_interval": 30,
        "event_flush_interval": 60,
        "event_queue_max": 1000,
        "strict_flag_ttl": 5,
        "strict_factor": 0.5,
        "max_tracked_ips": 20000,
        "behavior_max_ips": 4000,
        "behavior_max_uris": 8,
        "track_idle_ttl": 3600,
        "distributed": {"window": 300, "min_ips": 15, "min_fails": 20},
        # Mirror the whitelist into fail2ban's ignoreip. Off by default:
        # rewriting another tool's config behind its back produces two
        # divergent lists and a confusing support story.
        "auto_sync_fail2ban": False,

        # -- 可疑进程自动响应 ------------------------------------------------
        # 这是本程序里唯一会**动别的进程**的功能，所以它的护栏比功能本身重要。
        #
        # 取舍写在最前面：**宁可漏处置，也绝不误杀**。一次误判的自动杀进程
        # 会直接把服务器搞挂 —— 那比放过一个攻击者严重得多。所有默认值都是
        # 按这个取舍选的：默认关闭、默认只做可逆的 SIGSTOP、默认先观察。
        "autoresponse": {
            # 默认**关闭**。开启它意味着允许本程序暂停系统上的任意进程，
            # 必须是一个显式的决定。
            "enabled": False,
            # "stop" = SIGSTOP（可逆，默认；随后继续观察，证据被推翻就
            #          SIGCONT 恢复）；"terminate" = 按 terminate_signal 处置。
            "action": "stop",
            # 判定成立后先观察这么久（秒），期间任何豁免信号出现即放弃。
            # 快照一瞬可疑不足以动手：要求可疑特征在时间上持续。
            "observe_seconds": 120,
            # SIGSTOP 之后继续观察这么久（秒），证据被推翻就自动 SIGCONT。
            "resume_window_seconds": 600,
            # 观察期结束后证据仍然成立，且 action=stop 时怎么办：
            #   "hold"      -- 保持暂停，只报告，等操作者决定（默认，最保守）
            #   "terminate" -- 升级为 terminate_signal
            "after_observe": "hold",
            # 直接终止时用的信号。先 SIGTERM 让它自己收尾；SIGKILL 不可挽回，
            # 需要显式配置。
            "terminate_signal": "SIGTERM",
            # 限频：每小时最多处置几个进程，超过只报告并说明已达上限。
            "max_per_hour": 2,
            # 操作者允许清单。命中的进程**永不处置**。与
            # checks.process_anomaly.whitelist（只影响报告）是两件事：
            # 这一条是硬豁免，会写进"永不处置"清单。
            "allowlist": [],
            # 证据落盘目录。内存马一杀证据就没了，所以证据先写盘再动手。
            "evidence_dir": "",
        },
    },

    # -- second enforcement point: the web server -------------------------
    # Renders the active ban list into an nginx snippet, so a ban is
    # enforced even on a host without ipset, and so what is blocked can be
    # read and audited as a file. Off by default: it edits nginx
    # configuration, and that is an operator's decision, not a default.
    #
    # 这一段与 `evolve` 都属于**顶层**，不属于 `threat`：它们的读取路径一直
    # 是 `bouncer.*` / `evolve.*`（bouncer.py、units.py、evolve/*.py）。
    # 早先把它们写在 `threat` 段里，于是 `vigil config` 展示
    # `threat.bouncer.enabled`、代码却读 `bouncer.enabled` —— 一个「看得见、
    # 配了不生效」的键，比缺一个键更坏，因为它让人以为配上了。
    "bouncer": {
        "enabled": False,
        "sync_seconds": 60,
    },

    # -- 自修正循环 --------------------------------------------------------
    # 默认关闭。开启后它会读本机真实流量、采纳新的诱饵路径，并把每次改动写进
    # 台账、改前发邮件、改后上报。
    #
    # 它**不会**随意改源码：只有 `source_root` 指向一个真实的源码检出、且
    # `allow_code_edits` 显式打开时，才允许改动唯一一个被许可的文件（诱饵表），
    # 并且仍有行数上限、每日次数上限、备份与「测试不过就还原」。
    "evolve": {
        "enabled": False,
        "allow_code_edits": False,       # 源码自改总开关，默认关
        "source_root": "",               # 真实源码检出路径；空则无法自改源码
        "run_tests": True,               # 改源码后必须跑测试
        "test_target": "",               # 空 = 全套 discover
        "max_code_edits_per_day": 3,
        "max_patch_lines": 40,
        "max_adopted": 200,              # 运行期采纳的诱饵条数上限
        "max_per_run": 5,                # 单次最多采纳几条
        "min_hits": 8,                   # 证据门槛：至少被请求次数
        "min_ips": 3,                    # 证据门槛：至少几个独立来源
        "memory_pct": 5.0,               # 只取**可用**内存的这个百分比
        "memory_floor_mb": 96,           # 可用内存低于此值就不开工
        "load_ratio": 0.7,               # 负载超过 核数×此值 就不开工
        "time_budget": 120,              # 单次运行的墙钟上限（秒）
        "report_enabled": True,
        # 留空 = 只写本地台账，不外发。指向你自己的收集端即可启用上报。
        "report_url": "",
        # 台账链的 HMAC 密钥。名字里含 "key"，所以 core.config 会把它写进
        # secrets.json（0600）而不是 config.json —— 这正是它有意义的前提：
        # 台账要用来区分「自修正」与「恶意更改」，就必须**不可伪造**，
        # 而没有密钥的哈希链谁都能重算。留空时首次写入自动生成。
        "ledger_mac_key": "",
    },

    # -- load shedding ---------------------------------------------------
    # Engaged only while the host is under enough pressure that dropping
    # requests is better than serving none at all.
    "loadshed": {
        "enabled": True,
        "check_interval": 10,
        "warn_load": 3.0,
        "protect_load": 6.0,
        "protect_conn": 800,
        "release_load": 2.0,
        "release_conn": 200,
        "protect_confirm": 2,
        "release_confirm": 3,
        "connlimit_per_ip": 50,
        "newconn_rate_per_ip": 30,
        "newconn_burst": 60,
        "chain": "VIGIL_SHED",
        "ports": [80, 443],
        "hashlimit_expire_ms": 10000,
        "hashlimit_name": "vigil_shed",
        "alert_cooldown": 600,
    },

    # -- health checks ---------------------------------------------------
    "checks": {
        "enabled": True,
        "interval": 120,
        "cpu": {"warn": 85, "crit": 95, "sustain": 3},
        # 内存阈值同时看**比例**与**绝对量**。
        #
        # 只看比例在小内存机器上是常态误报：一台总内存 2 GB 的机器在做一次
        # 构建时，可用内存很容易掉到 20% 以下，而那台机器一切正常。所以比例
        # 之外还要「可用内存绝对值低于下限」同时成立才报；若整机可用内存本身
        # 就高于 warn_available_mb，无论百分比多低都不报。
        #
        # 下限默认按总内存缩放（见 checks/resource.py::_memory_floor_mb），
        # 也可以在这里显式写死覆盖。
        "memory": {"warn_available_pct": 20, "crit_available_pct": 10,
                   "warn_available_mb": 0, "crit_available_mb": 0},
        "swap": {"warn_pct": 50, "crit_pct": 80},
        "disk": {"warn_pct": 80, "crit_pct": 90, "paths": ["/"]},
        "inode": {"warn_pct": 80, "crit_pct": 90},
        "io_wait": {"warn": 20, "crit": 40},
        "conntrack": {"warn_pct": 70, "crit_pct": 90},
        "zombie": {"warn": 5, "crit": 20},
        "mailq": {"warn": 20, "crit": 100},
        "backup": {"warn_hours": 36, "crit_hours": 72, "globs": []},
        "certificates": {"warn_days": 21, "crit_days": 7, "dirs": []},
        "services": [],             # discovered at install
        "ports": [],                # baseline learned on first run
        # Files whose change must always be reported. Populated at install
        # with our OWN files plus anything the operator adds.
        "watch_files": [],
        "watch_dirs": [],
        "web_roots": [],            # scanned for webshell content
        "web_scan_extra_roots": [],
        "suid_baseline_refresh_days": 30,
        # Per-check tuning. Every one of these has a working built-in
        # default; they are listed here so the schema is discoverable via
        # `vigil config show` instead of being hidden in the code.
        "process_anomaly": {"cpu_warn": 80, "count_warn": 600,
                            # Extra process patterns to exempt, on top of the
                            # built-in set that already covers this project's
                            # own daemons. See BUILTIN_WHITELIST in
                            # guards/checks/process.py.
                            "whitelist": [],
                            # 构建/测试目录：命令行指向这里的进程自动降级，
                            # 因为「正在编译」「正在跑测试」必然高 CPU。
                            # 空表示只用站点根目录与结构判据（见
                            # guards/checks/procresponse.py::runtime_downgrade）。
                            "build_dirs": []},
        "site_availability": {"domain": "", "port": 443, "warn_5xx_pct": 5,
                              "crit_5xx_pct": 20, "log_lines": 200},
        "web_content": {"min_score": 4, "root_thresholds": {},
                        "max_file_bytes": 524288},
        "kernel_errors": {"max_lines": 10},
        "php_config": {"ini_paths": []},
        "outbound_connections": {"safe_ports": [22, 25, 53, 80, 123, 443,
                                                465, 587, 993, 995, 9418,
                                                8080, 8443],
                                 # port@owner-substring: an unusual port that
                                 # is fine when the destination belongs to
                                 # that organisation. A bare port means
                                 # "never report it".
                                 "known_services": ["5228@google",
                                                    "5229@google",
                                                    "5230@google"]},
        "file_permissions": {"files": []},
        # Everything this program generates that an attacker would love to
        # edit: the nginx snippets that decide what reaches the login gate,
        # the gate's own config, the audit rules file. The installed package
        # is always covered and does not need listing. Populated at install.
        #
        # 被删/被改的**生成物**会被自动重建（见 guards/selfheal.py）：那是
        # 本程序自己的输出，重写不会丢操作者的数据。本程序自己的源码与操作者的
        # 文件永不自动还原 —— 静默回滚会掩盖真实入侵，报告必须留给人看。
        "self_integrity": {
            "paths": [],
            # 默认开启：重建本程序自己的文件没有风险，而「发现了却没人去重建」
            # 正是这个功能存在的原因（shield 片段被删后连报 55 次，文件一直是缺的）。
            "auto_recover": True,
            # 限频：同一路径在窗口内最多重建几次，超过后只报警。防的是
            # 「重建→又被删→再重建」的循环：那种循环会烧 CPU、刷满审计日志，
            # 并且掩盖「有东西正在删这个文件」这件本身最值得追查的事。
            "heal_window_seconds": 1800,
            "heal_max_attempts": 3,
            # 归因时间窗口（秒）：台账记录必须**新近**才能为今天的改动背书。
            # 三个月前的一次自修正不该解释今天的改动 —— 那正是「躲在自修正
            # 影子里」的做法。超出窗口的改动按未归因处理。
            "attribution_window_seconds": 86400,
            # `vigil update` 写 deploy.json 前后多久内的源码改动算「部署」。
            # 这是比哈希匹配弱的判据（见代码注释），所以窗口给得保守。
            "deploy_window_seconds": 900,
        },
        "audit_rules": {"rules_file": ""},
        "suid_files": {"extra_dirs": []},
        "reboot": {"min_drop_seconds": 60},
        "oom": {"window_minutes": 10},
    },

    # -- malware ---------------------------------------------------------
    "malware": {
        "engine": "auto",           # auto | maldet | clamav | none
        "monitor_paths": [],
        "exclude_patterns": ["logs", "cache", "runtime", "uploads", ".git",
                             "node_modules", "vendor", "storage"],
        "quarantine": False,        # never auto-delete: a false positive
                                    # would take a site down
        "scan_interval_hours": 24,
    },

    # -- login / gate ----------------------------------------------------
    "gate": {
        "bt_panel": {
            "enabled": False,
            "state_dir": "",
            "webroot": "",
            "cookie": "vigilgate",
            "panel_db": "",
            "auth_log": "",
            "bind_ip": 0,
            "lock_max": 10,
            "lock_secs": 900,
            "max_sessions": 200,
            "panel_dir": "",
            "panel_port": 0,
            "admin_path": "",
            "domain": "",
            "server_name": "",
            "nginx_vhost": "",
            "entry_path": "/__vigil_gate",
            "captcha_ttl": 1800,
            "session_ttl": 43200,
            "nav_cookie": "",
            "strict_nav": 0,
            "lock_backoff": 1,
            "nginx_conf": "",
            "scene_kind": "auto",
            "image_dirs": [],
        },
        # The public playground on the main site. Its picture pool is set
        # separately on purpose: the gates may show anime, but a public page
        # shows scenery only, and inheriting the gates' list would have put
        # 二次元 on the front page of the website.
        "demo": {
            "image_dirs": [],
            "scene_kind": "image",
        },
        "dsh_gate": {
            "enabled": False,
            "state_dir": "",
            "webroot": "",
            "cookie": "vigillogin",
            "auth_log": "",
            "bind_ip": 0,
            "lock_max": 5,
            "lock_secs": 900,
            "max_sessions": 50,
            "domain": "",
            "server_name": "",
            "nginx_vhost": "",
            "entry_path": "/__vigil_login",
            "session_ttl": 1800,
            "abs_ttl": 43200,
            "captcha_ttl": 180,
            "nav_cookie": "",
            "strict_nav": 0,
            "lock_backoff": 1,
            "nginx_conf": "",
            "scene_kind": "auto",
            "image_dirs": [],
        },
        "login_alerts": True,
        # "panel" (default): always notify for panel / login-gate logins,
        #   and for SSH only from addresses you never whitelisted.
        # "offwhitelist": only unexpected addresses, any source.
        # "all": every successful login, including your own SSH sessions.
        "login_notify": "panel",
    },

    # -- auditd ----------------------------------------------------------
    "auditd": {
        "enabled": True,
        "key": "vigil_watch",
        "immutable": True,          # set -e 2 so rules cannot be relaxed
    },

    # -- hygiene (请求卫生片段里的方法白名单) ------------------------------
    # 默认包含 OPTIONS —— 浏览器跨域预检和 REST 接口探测都以它开头，
    # 拒绝它会让正常 API 全部 405。收紧到仅 GET/HEAD/POST 需显式配置。
    "hygiene": {
        "allowed_methods": ["GET", "HEAD", "POST", "OPTIONS"],
    },

    # -- web (自带的状态与反馈页面) ---------------------------------------
    # 默认关闭：这是一个对外可达的页面，装不装由运维决定，不由默认值决定。
    # 只监听本机，由已有的 Web 服务反代对外 —— 让这个进程直接对外就等于
    # 自己实现一遍 TLS，而「差一点」的 TLS 会让它变成全机最薄弱的一环。
    # 账号与密码由使用者在命令行交互设置（`vigil web passwd`）：程序**不
    # 自带默认凭据**，只把 PBKDF2 派生值与随机盐存进 secrets.json。
    # `domain` 默认留空：写死任何域名都会把一台机器的信息带进随包文件。
    "web": {
        "enabled": False,
        "listen": "127.0.0.1",
        "port": 9177,
        "domain": "",
        "username": "",
        "session_minutes": 60,
        # Direct peers whose X-Forwarded-For may be believed when rate-limiting
        # logins. The service listens on loopback and is proxied, so the peer is
        # the proxy: without this, every visitor shares one bucket. Adding an
        # entry is an explicit statement that the address is *our* reverse
        # proxy -- believing the header from anyone else is a bypass.
        "trusted_proxies": ["127.0.0.1/8", "::1"],
    },

    # Filled in at install time; display only.
    "public_ip": "",
    # Which subsystems the operator enabled.
    "features": [],

    "logging": {"level": "INFO", "keep_days": 30},
}

# Keys that must never be written to config.json; they live in secrets.json.
SECRET_KEYS = (
    "api_key", "password", "token", "secret", "smtp_password",
    "auth_code", "webhook_url", "key",
)


class Config:
    """Loaded configuration plus its secrets.

    ``cfg["threat.ssh.max_failures"]`` works; so does ``cfg.get(path, d)``.
    Mutations are staged in memory and committed with :meth:`save`.
    """

    def __init__(self, path=None, secrets_path=None):
        self.path = path or paths.CONFIG
        self.secrets_path = secrets_path or paths.SECRETS
        self._store = Store(self.path, DEFAULTS, mode=0o640)
        self._secrets = Store(self.secrets_path, {}, mode=0o600)

    # -- loading / saving ------------------------------------------------
    @property
    def data(self) -> dict:
        return self._store.data

    @property
    def secrets(self) -> dict:
        return self._secrets.data

    def reload(self) -> "Config":
        self._store.reload()
        self._secrets.reload()
        return self

    def save(self, backup: bool = True) -> bool:
        paths.ensure_dirs()
        if backup and self.path.exists():
            try:
                from shutil import copy2
                copy2(self.path, str(self.path) + ".bak")
            except OSError:
                pass
        ok1 = self._store.save()
        ok2 = self._secrets.save()
        try:
            os.chmod(self.path, 0o640)
            os.chmod(self.secrets_path, 0o600)
        except OSError:
            pass
        return ok1 and ok2

    def exists(self) -> bool:
        return self.path.exists()

    # -- access ----------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        # Secrets shadow config so callers can ask for "provider.api_key"
        # without caring where it is stored.
        secret = self._secrets.get(dotted, _MISSING)
        public = self._store.get(dotted, _MISSING)
        if secret is _MISSING:
            return public if public is not _MISSING else default
        if public is _MISSING:
            return secret
        if isinstance(secret, dict) and isinstance(public, dict):
            # A subtree that happens to contain one secret must not hide its
            # neighbours. `mail.imap` keeps host, port and username in the
            # public store and only the password in the secret one; returning
            # the secret half alone handed callers a dict with no host in it,
            # and the IMAP client would have tried to connect to "".
            return deep_merge(copy.deepcopy(public), secret)
        return secret

    def set(self, dotted: str, value: Any) -> None:
        if _is_secret(dotted):
            self._secrets.set(dotted, value)
        else:
            self._store.set(dotted, value)

    def update(self, patch: dict) -> None:
        self._store.update(patch)

    def __getitem__(self, dotted: str) -> Any:
        val = self.get(dotted, _MISSING)
        if val is _MISSING:
            raise KeyError(dotted)
        return val

    def __contains__(self, dotted: str) -> bool:
        return self.get(dotted, _MISSING) is not _MISSING

    # -- provider helpers -------------------------------------------------
    def providers(self) -> list:
        return list(self.get("mail.providers", []) or [])

    def set_providers(self, chain: list) -> None:
        self._store.set("mail.providers", chain)

    def provider_params(self, provider_id: str) -> dict:
        """Credential blob for *provider_id*.

        Secrets may be stored either inline in the chain entry or in
        ``secrets.json`` under ``providers.<id>``. The latter is preferred;
        the former is accepted so hand written configs keep working.
        """
        merged: dict = {}
        for entry in self.providers():
            if entry.get("provider") == provider_id:
                merged.update({k: v for k, v in entry.items() if k != "provider"})
        stored = self._secrets.get("providers.%s" % provider_id, {}) or {}
        if isinstance(stored, dict):
            merged.update(stored)
        return merged

    def set_provider_params(self, provider_id: str, params: dict) -> None:
        clean_secrets, clean_public = {}, {}
        for k, v in params.items():
            (clean_secrets if _is_secret(k) else clean_public)[k] = v
        self._secrets.set("providers.%s" % provider_id, clean_secrets)
        # keep the public half in the chain entry so it is visible in exports
        chain = []
        found = False
        for entry in self.providers():
            if entry.get("provider") == provider_id:
                chain.append({"provider": provider_id, **clean_public})
                found = True
            else:
                chain.append(entry)
        if not found:
            chain.append({"provider": provider_id, **clean_public})
        self.set_providers(chain)

    # -- recipients -------------------------------------------------------
    def recipients(self, purpose: str = "alert") -> list:
        key = "mail.login_recipients" if purpose == "login" else "mail.recipients"
        got = [r for r in (self.get(key, []) or []) if r]
        # Deliberately NOT derived from the configured sender. A QQ SMTP
        # account is usually a *sending* identity -- alerts come *from* it --
        # and treating the sender as a recipient would quietly start mailing
        # the account its own notifications. Recipients come from the
        # recipient lists or from the alert fallback, and nowhere else.
        if not got:
            got = [r for r in (self.get("mail.recipients", []) or []) if r]
        # de-duplicate, preserving order
        seen, out = set(), []
        for r in got:
            if r.lower() not in seen:
                seen.add(r.lower())
                out.append(r)
        return out

    def add_recipient(self, address: str, purpose: str = "alert") -> None:
        key = "mail.login_recipients" if purpose == "login" else "mail.recipients"
        cur = list(self.get(key, []) or [])
        if address not in cur:
            cur.append(address)
            self._store.set(key, cur)

    def remove_recipient(self, address: str, purpose: str = "alert") -> bool:
        key = "mail.login_recipients" if purpose == "login" else "mail.recipients"
        cur = list(self.get(key, []) or [])
        if address in cur:
            cur.remove(address)
            self._store.set(key, cur)
            return True
        return False

    # -- validation -------------------------------------------------------
    def validate(self) -> list:
        """Return a list of human readable problems. Empty means healthy."""
        problems = []
        m = self.get("mail", {}) or {}
        if m.get("enabled", True) is False:
            pass
        if not m.get("providers"):
            problems.append("mail.providers is empty -- no alert can be sent")
        if not m.get("recipients"):
            problems.append("mail.recipients is empty -- nobody would receive alerts")
        if not m.get("from_address"):
            problems.append("mail.from_address is not set")
        for p in m.get("providers") or []:
            pid = p.get("provider")
            if not pid:
                problems.append("a provider entry is missing its 'provider' id")
        wl = self.get("threat.whitelist", []) or []
        if not wl:
            problems.append("threat.whitelist is empty -- you may lock yourself out")
        for addr in ("127.0.0.1/8", "::1"):
            if addr not in wl:
                problems.append("threat.whitelist is missing %s" % addr)
        if m.get("from_address") and "@" not in str(m.get("from_address")):
            problems.append("mail.from_address does not look like an address")
        return problems

    # -- import / export ---------------------------------------------------
    def export(self, include_secrets: bool = False) -> dict:
        out = copy.deepcopy(self._store.data)
        if include_secrets:
            out["_secrets"] = copy.deepcopy(self._secrets.data)
        else:
            for entry in out.get("mail", {}).get("providers", []) or []:
                for k in list(entry):
                    if _is_secret(k):
                        entry[k] = "<redacted>"
        return out

    def import_(self, blob: dict, merge: bool = True) -> None:
        # Copy before popping: `import_` used to strip `_secrets` out of the
        # caller's dict, so importing the same blob twice silently lost the
        # secrets the second time.
        blob = copy.deepcopy(blob)
        secrets = blob.pop("_secrets", None)
        if merge:
            self._store.data = deep_merge(self._store.data, blob)
        else:
            self._store.data = deep_merge(copy.deepcopy(DEFAULTS), blob)
        if isinstance(secrets, dict):
            self._secrets.data = deep_merge(self._secrets.data, secrets)


class _Missing:
    def __repr__(self):
        return "<missing>"


_MISSING = _Missing()


def _is_secret(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in SECRET_KEYS)


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def load(path=None, secrets_path=None) -> Config:
    return Config(path=path, secrets_path=secrets_path)


def bootstrap_defaults(cfg: Config, host: str = "") -> None:
    """Fill in values that are per-host but need no user input.

    Kept separate from :data:`DEFAULTS` precisely so the defaults stay
    host-agnostic and this file never becomes a place where one machine's
    details leak into a release.
    """
    if not cfg.get("hostname"):
        cfg.set("hostname", host or hostname())
    if not cfg.get("mail.from_name"):
        cfg.set("mail.from_name", "Server Monitor")
