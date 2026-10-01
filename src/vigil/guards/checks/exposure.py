"""Is the sensitive-file ruleset actually in force where it matters?

The ruleset is generated into each site's extension directory, but the
statement that applies it *inside* a `^~` prefix has to live in the site's own
configuration -- and on a panel-managed host that file belongs to the panel.
Measured on the development host, the include vanished from a site config
(it was rewritten by something other than this program) and the subtree went
back to serving files it should refuse.

That is the failure this check exists for: not "is the rule file present"
(which stayed true the whole time) but "is it *wired in*". A check that only
looked at the file would have reported OK throughout.
"""
from __future__ import annotations

from .base import CRIT, OK, WARN, Check, CheckContext, CheckResult, register
from .base import G_SECURITY
from .. import exposure


@register
class ExposurePrefixRules(Check):
    id = "exposure_prefix_rules"
    label = "敏感文件规则接线"
    label_en = "sensitive-file rules wired in"
    group = G_SECURITY
    description = ("检查每个会读磁盘的 `^~` 前缀里是否还挂着敏感文件拒绝规则 ——"
                   "`^~` 会让 nginx 跳过同级正则 location，漏挂等于该子树不设防")

    def run(self, ctx: CheckContext) -> CheckResult:
        confs = exposure.site_confs()
        if not confs:
            return CheckResult(OK, "本机没有需要检查的站点配置")

        checked, holes = 0, []
        for conf in confs:
            if not (conf.parent / "zz-exposure-deny.conf").is_file():
                continue          # 本程序没往这个站点放过规则
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                return CheckResult(WARN, "无法读取 %s：%s" % (conf, exc))
            if "location ^~" not in text:
                continue
            checked += 1
            for b in exposure.audit_conf(text)["uncovered"]:
                holes.append("%s 的 `%s`" % (conf.name, b["prefix"]))

        if not checked:
            return CheckResult(OK, "没有站点使用 `^~` 前缀")
        if not holes:
            return CheckResult(OK, "%d 个站点的 `^~` 前缀都已挂上规则" % checked)
        return CheckResult(
            CRIT,
            "**%d 个 `^~` 前缀没有挂敏感文件拒绝规则**：\n       %s\n"
            "       `^~` 会让 nginx 跳过同级正则 location，因此该子树里的备份、"
            "点文件、源码会重新变成可被公网下载。\n"
            "       修复：`vigil exposure install`（或 `vigil update` 会自动补回）。"
            % (len(holes), "\n       ".join(holes)))
