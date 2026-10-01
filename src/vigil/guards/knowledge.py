"""Knowledge base: what a finding *means* and what to do about it.

This is the difference between a monitor and a useful monitor. "File
changed" is noise; "your alert egress script changed, which means you may
never receive another alert" is actionable at 3am by someone who did not
write this software.

Keyed by **stable check id**, never by the human label -- the previous
generation keyed its knowledge off Chinese display strings, so translating
or renaming a check silently orphaned its explanation.
"""
from __future__ import annotations

#: check id -> (what it is, why it is reported, likely consequences, what to do)
ENTRIES: dict = {
    # -- resources -------------------------------------------------------
    "cpu": (
        "CPU 占用率持续过高",
        "计算资源被长期占满，通常是业务增长、程序死循环，或正在被攻击。",
        "请求变慢、超时；如果伴随大量外部连接，很可能是流量型攻击。",
        "先用 `vigil health run --only cpu` 看具体进程；"
        "确认是攻击后风控会自动拦截来源，必要时启用负载保护。",
    ),
    "memory": (
        "可用内存不足",
        "系统可用内存已降到很低的水平。",
        "可能触发 OOM 杀进程，表现是「服务莫名其妙重启」；"
        "切换频繁时整体响应会明显变慢。",
        "检查是否有内存泄漏（常见于长期运行的 Node/PHP 进程），"
        "并为关键服务设置内存上限以便优雅重启。",
    ),
    "swap": (
        "交换分区使用率过高",
        "物理内存不够用，系统开始把内存换出到磁盘。",
        "磁盘 I/O 剧增、响应显著变慢；在 SSD 上还会加速磨损。",
        "增加内存或减少常驻进程；Swap 长期高占用说明内存是真的不够。",
    ),
    "disk": (
        "磁盘空间接近用满",
        "某个分区剩余空间不足。",
        "**写不进去任何东西** —— 数据库停止写入、网站报错、"
        "日志和告警也可能一起失效。",
        "清理日志与备份目录；确认是不是被上传文件或日志撑满的。",
    ),
    "inode": (
        "inode 数量接近用尽",
        "文件数量太多而不是占用空间太大。",
        "同样会导致无法创建新文件，但 `df -h` 看起来还有空间，容易误判。",
        "找出小文件堆积的目录（常见于 session、缓存、邮件队列）。",
    ),
    "disk_io": (
        "磁盘 I/O 等待过高",
        "进程在等待磁盘完成读写。",
        "整体响应变慢；数据库类服务受影响最明显。",
        "确认是正常业务高峰还是异常进程；云盘遇到 I/O 上限需要升配。",
    ),
    "conntrack": (
        "连接跟踪表接近上限",
        "内核记录的连接数接近 `nf_conntrack_max`。",
        "**一旦写满，新连接会被直接丢弃** —— 表现是所有网站同时无法访问，"
        "但服务器本身看起来一切正常。这是被攻击时最先爆掉的资源。",
        "调大 `nf_conntrack_max`，同时用风控封禁攻击来源；"
        "两者要一起做，只调大上限只是把问题推后。",
    ),
    "process_anomaly": (
        "进程数量或单个进程占用异常",
        "总进程数过多，或有进程长期占满 CPU。",
        "可能是程序 fork 失控（僵尸进程的前兆），也可能是被当作矿机。",
        "查看具体进程与父进程；异常增长的进程通常需要重启对应服务。",
    ),
    "zombie": (
        "存在僵尸进程",
        "子进程已结束但父进程没有回收。",
        "短期无害，但持续增长会耗尽进程表，最终无法创建新进程。",
        "找出僵尸进程的父进程并重启它 —— 清理僵尸必须从父进程入手。",
    ),
    "site_availability": (
        "网站不可用或大量 5xx",
        "本地探测没有返回正常状态码，或近期大量请求返回 5xx。",
        "用户无法访问；如果是后端崩溃，还会连带影响同机的其它站点。",
        "先看 PHP/数据库是否存活，再看错误日志的具体报错。",
    ),

    # -- integrity -------------------------------------------------------
    "watch_files": (
        "被监视的关键文件发生了改动",
        "这些文件的内容或被替换（inode 变化）或原地修改。",
        "取决于文件本身：可能是升级，也可能是入侵者留下的后门或改掉的配置。"
        "**邮件里已经写明每个文件的作用和这次改动的含义。**",
        "对照邮件里的「是什么/可能后果」逐项确认；"
        "看归因信息里的进程与父进程，判断是管理员操作还是外部行为。",
    ),
    "listening_ports": (
        "监听端口发生了变化",
        "有新的端口开始监听，或有端口不再监听。",
        "新端口可能是新装的服务，**也可能是后门在监听**；"
        "端口消失则可能是服务崩溃。",
        "确认新端口属于哪个程序（邮件中已给出进程与命令行）；"
        "不认识的一律先封禁再排查。",
    ),
    "suid_files": (
        "出现了新的 SUID / SGID 文件",
        "这类文件以文件属主的权限执行。",
        "**SUID root 文件是本地提权的标准手段** —— 攻击者拿到普通账号后，"
        "常放一个 SUID shell 来获得 root。",
        "确认是不是软件包正常安装带来的；可以用 `rpm -V` / `dpkg -V` 核对，"
        "不属于任何软件包的 SUID 文件应立即处理。",
    ),
    "kernel_modules": (
        "加载了新的内核模块",
        "内核模块运行在内核态，权限高于任何用户进程。",
        "**这是 rootkit 隐藏自身、隐藏进程与文件的常见手段。**",
        "确认模块来源与用途；不认识的模块说明系统可能已被植入。",
    ),
    "cron_entries": (
        "计划任务发生了变化",
        "crontab、/etc/cron.d 或 /var/spool/cron 中的内容有变动。",
        "**计划任务是持久化最常用的位置** —— 攻击者常在这里留下"
        "定时回连或定时下载的条目。",
        "逐条核对你是否认识；注意命令里是否包含 curl/wget 下载、"
        "base64 解码或直接执行远程脚本。",
    ),
    "systemd_units": (
        "systemd 单元发生了变化",
        "新增了服务或定时器单元。",
        "和计划任务一样是持久化手段，而且**重启后依然生效**。",
        "重点看 ExecStart 指向什么程序；不认识的单元应立即禁用并排查。",
    ),
    "firewall_rules": (
        "防火墙规则发生了变化",
        "iptables / ufw 规则与上次基线不一致。",
        "可能是正常封禁（风控、fail2ban 都会改规则），"
        "**也可能是攻击者放开了某个端口或删掉了限制**。",
        "确认变化是否来自本程序的自动封禁；"
        "特别注意是否有「放行」类的新增规则。",
    ),
    "dns_config": (
        "DNS 解析配置发生了变化",
        "/etc/hosts、/etc/resolv.conf 或 nsswitch.conf 被改动。",
        "**改 hosts 可以把你的域名指向攻击者的服务器**，"
        "从而劫持更新、劫持邮件投递。",
        "逐条核对你是否认识这些解析记录；尤其是把外部域名指向内网 IP 的条目。",
    ),
    "audit_rules": (
        "内核审计规则不完整或可被改写",
        "文件里写了规则但内核没有全部加载，或者规则没有置为不可变。",
        "**规则缺失意味着文件被改动时无法追溯到是谁改的** —— "
        "监控看起来正常，实际已经瞎了。规则未置不可变则攻击者可以"
        "运行时删掉审计规则来掩盖行踪。",
        "运行 `vigil audit install` 重新生成；"
        "常见原因是某条规则指向了不存在的路径，会导致其后的规则被整体丢弃。",
    ),

    # -- security --------------------------------------------------------
    "root_accounts": (
        "存在非 root 用户的 uid=0 账号",
        "除 root 外还有账号的 UID 是 0，也就是拥有完全相同的权限。",
        "**这是攻击者最爱的后门账号之一**；也可能是误操作修改 UID 造成的。",
        "立即核对该账号是否为本人创建；不是的话先禁用再排查入侵路径。",
    ),
    "runtime_config": (
        "磁盘上的配置没有生效",
        "本程序生成的 nginx 片段内容已经改变，但加载它们的进程仍早于这次改动 —— "
        "也就是说运行中的服务还在用上一版配置。",
        "**文件是对的，防护却不在**：这是最容易被忽略的一种失效，因为所有表面"
        "都显示成功 —— 配置文件正确、`nginx -t` 通过、命令返回 0、日志无错误。"
        "nginx 在 reload 时拒绝新配置（例如改动了 limit_req_zone 的键变量）就会"
        "这样：master 继续服务旧配置，而后续对同一文件的每一次修改都同样无效。",
        "完整重启使其生效：`systemctl restart nginx`。重启后再跑 "
        "`vigil shield install` 复核，并确认本项恢复 OK。"
        "若频繁出现，说明部署路径没有验证 reload 结果，应检查 "
        "`vigil shield install` 的输出是否报告了 `[emerg]`。",
    ),
    "self_integrity": (
        "安全程序自身或它生成的配置发生了变化",
        "vigil 的代码，或它写出的 nginx 片段／网关配置／审计规则被改动了。"
        "这些文件决定「哪些流量会被送去验证」和「哪些行为会被记录」——"
        "改动它们的收益和改动杀毒软件一样大。",
        "**这是最容易被忽略的一条后门路径**：拿到 root 之后，第一件事往往"
        "不是装木马，而是让防护别再记录它。改掉 nginx 片段可以绕过登录验证，"
        "改掉审计规则可以让后续动作不留痕迹。",
        "对照改动时间与 auditd 记录确认改动者。如果确实是你刚跑过 "
        "`vigil update`，执行 `vigil health rebaseline self_integrity` 接受它；"
        "如果不是，按入侵处理，不要只看这一个文件。",
    ),
    "vigil_watchdog": (
        "本程序的防护没有在运行",
        "vigil 自己的守护进程或定时器不在运行状态，或巡检已经很久没有执行。",
        "**沉默会被误读为安全**：防护停了之后攻击照常发生，只是不再有人报告。"
        "机器看起来一切正常，因为负责报告「正常」的那个东西已经死了。",
        "先看失败原因：`systemctl status vigil-threatd`、"
        "`journalctl -u <失败单元> -n 50`。常见原因是配置写坏、端口或权限冲突、"
        "单元文件被别的程序改过。修好后 `vigil update` 会重新生成全部单元。",
    ),
    "preload": (
        "/etc/ld.so.preload 被设置了内容",
        "该文件会让指定的动态库被**注入到几乎所有进程**中。",
        "**这是最高级别的后门之一** —— 可直接劫持所有程序的系统调用，"
        "用来隐藏文件、隐藏进程、记录密码。正常系统上这个文件应当不存在或为空。",
        "立即查看内容并对照文件是否存在；确认为后门后需要按应急流程处理，"
        "不要只删文件，要找出它是怎么被写进去的。",
    ),
    "suspicious_procs": (
        "发现可疑进程",
        "进程的可执行文件已被删除但仍在运行，或从临时目录运行。",
        "**这是内存马与恶意程序最典型的特征** —— 正常服务不会这样运行。"
        "可执行文件被删除往往是为了让磁盘上查不到样本。",
        "记录 PID 与命令行，检查它的网络连接；"
        "确认为恶意进程后要先断开其对外连接再终止。",
    ),
    "file_permissions": (
        "关键文件的权限过于宽松",
        "系统关键文件允许组或其他用户写入，或有不该被读取的文件可被任意用户读取。",
        "**可写入 /etc/passwd、sudoers 之类文件等于提权。**"
        "shadow 可被普通用户读取则密码哈希面临离线爆破。",
        "按邮件里给出的建议权限修正；用 `chmod` 逐项改回。",
    ),
    "php_config": (
        "PHP 安全配置存在风险项",
        "例如 disable_functions 为空、允许远程包含、未限制 open_basedir。",
        "**一旦网站存在文件包含或上传漏洞，这些配置就是最后的防线**，"
        "配置不当会让小漏洞直接变成服务器沦陷。",
        "禁用危险函数、关闭 allow_url_include、为每个站点设置 open_basedir。",
    ),
    "panel_auth": (
        "面板入口未受认证保护",
        "面板地址在未验证身份的情况下返回了 200。",
        "**控制面板等于服务器的最高权限**，直接暴露意味着可以被持续爆破，"
        "面板一旦有一个漏洞就是整机沦陷。",
        "安装登录防护：`vigil gate install bt_panel --domain 你的面板域名`；"
        "同时确认面板端口没有对全网开放。",
    ),

    # -- network ---------------------------------------------------------
    "outbound_connections": (
        "存在异常的对外连接",
        "有进程主动连接了不常见的远端端口。",
        "服务器**主动外连**通常意味着：反弹 shell、数据外传，"
        "或程序被植入了回连逻辑。正常业务的外连目标是固定的少数几个。",
        "核对邮件中的进程与命令行；确认远端地址是否属于你使用的服务。"
        "不认识的一律先阻断并排查该进程来源。",
    ),

    # -- malware ---------------------------------------------------------
    "webshell_process": (
        "Web 服务进程派生了 shell",
        "nginx / PHP 进程启动了解释器或 shell 子进程。",
        "**这是 WebShell 正在被使用的直接证据** —— "
        "正常的 PHP 请求不会去执行系统命令。",
        "立即定位对应的 PHP 文件并隔离；同时检查该目录下其它文件是否被植入。"
        "邮件里给出了进程链，可以顺藤摸瓜。",
    ),
    "web_content": (
        "网页目录中发现疑似 WebShell 的内容",
        "文件中同时出现了「外部输入」与「代码/命令执行」并且数据确实流到了执行点。",
        "**这意味着网站文件里已经存在后门**，攻击者可以通过浏览器"
        "以网站的身份执行任意命令。",
        "先确认文件是否为你自己的程序（有些正当程序确实会调用外部命令）；"
        "确认为后门后先备份再删除，并排查同目录及最近被改动的文件。",
    ),
    "av_hits": (
        "杀毒引擎检出了恶意文件",
        "本机杀毒引擎的签名库匹配到了已知的恶意样本。",
        "**这是已经落地的恶意文件**，可能是网页后门、挖矿程序或下载器。",
        "核对文件用途；确认为恶意后先备份再删除，"
        "并检查同目录、以及该文件是被哪个进程写进来的。",
    ),

    # -- services & ops ---------------------------------------------------
    "services": (
        "关键服务未运行",
        "受监控的服务当前不是 active 状态。",
        "取决于服务：Web 服务停了网站就打不开，数据库停了业务就中断，"
        "**而监控服务停了你会以为一切正常**。",
        "先看该服务的日志再重启；反复崩溃通常是配置或资源问题。",
    ),
    "mail_queue": (
        "邮件队列积压",
        "本地 MTA 有较多邮件排队等待投递。",
        "**积压通常意味着告警邮件也发不出去** —— 你可能会错过真正的异常通知。",
        "检查 MTA 日志与网络出口；如果 25 端口被封，请改用 API 渠道。",
    ),
    "backup_age": (
        "备份过旧或不存在",
        "最近一次备份的时间超过阈值，或根本没找到备份。",
        "**没有可用备份时，任何一次数据损坏或入侵都无法恢复。**",
        "检查备份脚本是否还在运行、目标磁盘是否写满。",
    ),
    "certificates": (
        "SSL 证书临近到期",
        "证书剩余有效期已低于阈值。",
        "到期后浏览器会直接拦截访问，**而且访问者看到的是一整页安全警告**。",
        "确认自动续期是否正常工作（ACME 续期常因 /.well-known 被拦截而失败）。",
    ),
    "reboot": (
        "检测到系统重启",
        "开机时间比上次记录明显变短。",
        "可能是正常维护，**也可能是被攻击者或云厂商强制重启**；"
        "重启后未持久化的防护规则可能已丢失。",
        "确认是你自己重启的；如果不是，检查系统日志与本次启动前后的事件。",
    ),
    "oom": (
        "发生了 OOM 内存杀进程",
        "内核因内存不足强制结束了进程。",
        "**被杀的进程会毫无征兆地消失**，日志里可能什么都看不到。",
        "找出被杀的是哪个进程并降低其内存占用；长期靠 OOM 杀进程会误伤关键服务。",
    ),
    "kernel_errors": (
        "内核日志中出现错误",
        "dmesg 中有较多 err/crit 级别记录。",
        "可能是硬件故障（磁盘、内存）、驱动问题，或内核被异常操作。",
        "查看具体报错；磁盘类错误要尽快确认数据安全。",
    ),
}

#: Path -> (what it is, what a change means, what to do).
#: Populated for files this program itself owns, because a change there
#: means "your monitoring may have been tampered with", which is exactly
#: the case an operator is least likely to notice.
FILE_ENTRIES: dict = {
    "/etc/vigil/config.json": (
        "本程序的主配置文件",
        "被改动 = **收件人、告警渠道、白名单、各项阈值可能被修改**。"
        "最危险的是白名单里被加入攻击者 IP，或收件人被改成了别人。",
        "逐项核对收件人与白名单，确认仍然是你自己的设置。",
    ),
    "/etc/vigil/secrets.json": (
        "本程序的凭据文件（邮件 API Key、SMTP 授权码等）",
        "被改动 = 有人读取或替换了发信凭据。",
        "核对凭据是否仍是你配置的；如有异常，立即在服务商侧轮换密钥。",
    ),
    "/etc/passwd": (
        "系统账号数据库",
        "被改动 = **可能新增了后门账号，或修改了某个账号的 UID/家目录/shell**。",
        "核对新增条目；特别注意 uid=0 的账号与 shell 被改为可登录的账号。",
    ),
    "/etc/shadow": (
        "系统密码哈希文件",
        "被改动 = 某个账号的密码被修改，或新增了带密码的账号。",
        "核对最近是否有人改过密码；异常时立即重置关键账号密码。",
    ),
    "/etc/sudoers": (
        "sudo 提权配置",
        "被改动 = **可能有账号被授予了免密 sudo 或完全提权**。",
        "核对每一条授权，确认没有陌生的用户或 NOPASSWD 条目。",
    ),
    "/etc/sudoers.d": (
        "sudo 提权的附加配置目录",
        "被改动 = 可能新增了一个提权文件。这个目录常被攻击者用来"
        "投放后门而不改动主文件。",
        "列出目录内容逐条核对。",
    ),
    "/etc/ssh/sshd_config": (
        "SSH 服务配置",
        "被改动 = **可能被放开了 root 登录、开启了密码认证，"
        "或把端口改成了你不知道的值**。",
        "核对 PermitRootLogin、PasswordAuthentication 与 Port。",
    ),
    "/root/.ssh": (
        "root 的 SSH 密钥目录",
        "被改动 = **可能被加入了攻击者的公钥**，之后无需密码即可登录。",
        "核对 authorized_keys 中每一把公钥。",
    ),
    "/etc/ld.so.preload": (
        "动态库预加载配置 —— 存在即异常",
        "被设置 = **几乎所有进程都会被注入指定的库**，"
        "这是隐藏进程与文件的高级后门手段。",
        "正常系统上该文件应不存在或为空；有内容需按应急流程处理。",
    ),
    "/etc/crontab": (
        "系统级计划任务",
        "被改动 = 可能新增了定时执行的任务（持久化的常见位置）。",
        "核对每一条命令，警惕 curl/wget 下载后执行、base64 解码等特征。",
    ),
    "/etc/cron.d": (
        "计划任务附加目录",
        "被改动 = 可能新增了定时任务文件。",
        "列出目录内容逐条核对。",
    ),
    "/var/spool/cron": (
        "用户计划任务目录",
        "被改动 = 某个用户的 crontab 被修改。",
        "检查各用户的任务列表。",
    ),
}

#: Attack patterns -> plain-language explanation. Matched against the
#: reason text and the request samples of a ban.
ATTACK_PATTERNS: list = [
    (r"\.\./\.\./|\.\.%2f|%2e%2e",
     "目录穿越：试图跳出网站根目录去读取服务器上的其它文件，"
     "目标是配置文件、密钥或 /etc/passwd 之类。"),
    (r"etc/passwd|etc/shadow",
     "直接读取系统账号文件：在试探能否读到服务器的账号与密码哈希。"),
    (r"union.*select|select.*from|or\s+1\s*=\s*1|'\s*or\s*'",
     "SQL 注入：试图通过构造数据库查询来绕过登录或直接拖库。"),
    (r"jndi:|ldap://|rmi://",
     "Java 反序列化/JNDI 注入：利用 Java 组件加载远程代码，"
     "这是 Log4Shell 类漏洞的典型特征。"),
    (r"cmd\.exe|/bin/sh|/bin/bash|shell_exec|system\s*\(|passthru",
     "命令注入：试图让服务器执行系统命令。一旦成功等于服务器沦陷。"),
    (r"eval\s*\(|base64_decode|assert\s*\(|gzinflate",
     "代码注入/WebShell：试图让 PHP 执行经过编码的恶意代码。"),
    (r"wp-config|wp-login|xmlrpc\.php|wp-admin",
     "WordPress 针对性扫描：在寻找 WordPress 的已知弱点与配置文件。"),
    (r"phpmyadmin|/pma/|adminer|/db/",
     "数据库管理工具探测：数据库管理界面一旦被打开就是整库泄露。"),
    (r"\.env|\.git/|\.svn/|\.DS_Store|config\.php\.(bak|old|save)",
     "敏感文件探测：在找被误传到网站目录的配置、源码或备份文件 —— "
     "这类文件里常含数据库密码与密钥。"),
    (r"\.aws/credentials|\.ssh/id_|\.bash_history|credentials\.txt",
     "云凭据与私钥探测：目标是拿到可以横向移动到其它服务器的密钥。"),
    (r"docker-compose|Dockerfile|/actuator|/metrics",
     "基础设施信息探测：在枚举容器与运维接口，为下一步攻击做准备。"),
    (r"ssh.*爆破|密码爆破|Failed password",
     "SSH 暴力破解：用字典持续尝试登录，目标是拿到一个可用的账号密码。"),
    (r"用户名枚举|Invalid user",
     "SSH 用户名枚举：在试探服务器上存在哪些账号，为后续爆破缩小范围。"),
    (r"请求洪泛|flood|请求.*次/秒",
     "请求洪泛：用高频请求耗尽连接数或带宽，目标是让正常用户无法访问。"),
    (r"扫描|scan|多端口|portscan",
     "端口/路径扫描：在枚举服务器上开放了哪些服务与页面，属于攻击前的踩点。"),
    (r"分布式",
     "分布式攻击：来源是大量不同的 IP，单点封禁效果有限，"
     "需要依赖连接数限制与上游清洗。"),
]


def explain(key: str):
    """Look up guidance for a check id, a file path, or an attack reason."""
    if key in ENTRIES:
        what, why, conseq, action = ENTRIES[key]
        return {"key": key, "title": what, "what": what, "why": why,
                "consequence": conseq, "action": action}
    if key in FILE_ENTRIES:
        what, conseq, action = FILE_ENTRIES[key]
        return {"key": key, "title": what, "what": what,
                "consequence": conseq, "action": action}
    return None


def explain_attack(reason: str, samples=None) -> str:
    """Plain-language explanation of what an attacker was trying to do."""
    import re
    blob = "%s %s" % (reason or "", " ".join(samples or []))
    for pattern, text in ATTACK_PATTERNS:
        try:
            if re.search(pattern, blob, re.I):
                return text
        except re.error:
            continue
    return ""


def file_hint(path: str):
    """Guidance for a specific file, falling back to its basename.

    The basename fallback matters because a distribution may place a file
    somewhere we did not predict, and a generic-but-wrong explanation is
    worse than a specific-but-approximate one.
    """
    if path in FILE_ENTRIES:
        return FILE_ENTRIES[path]
    base = str(path).rsplit("/", 1)[-1]
    for known, value in FILE_ENTRIES.items():
        if known.rsplit("/", 1)[-1] == base:
            return value
    return None


def ids() -> list:
    return sorted(set(ENTRIES) | set(FILE_ENTRIES))
