"""`vigil audit-source` -- run the publish check on this checkout.

Before this package goes anywhere public, the question that has to be answered
is "does it contain any of *my* details?". That question cannot be answered by
reading, and it cannot be answered by a rule list either: the operator's own
site name, project name and customer codes have no shape, so a shipped rule
table cannot name them without publishing them.

So the check has two halves:

  · generic shapes (published IPs, internationalised domains, hosting brands,
    personal mailboxes, date-stamped deployment directories, personal data)
    which are wrong in anybody's copy; and
  · a local list at ``tools/source-forbid.txt``, one ``value[:why]`` per line,
    which .gitignore excludes -- so the operator writes their own names down
    without shipping them.

The same code runs in the test suite, so a fork that passes this command
passes CI.
"""
from __future__ import annotations

from pathlib import Path

from .. import ui
from ..core import sourceaudit


def cmd_audit_source(args) -> int:
    root = Path(getattr(args, "root", "") or ".").resolve()
    findings = sourceaudit.scan(root)
    files = list(sourceaudit.shipped_files(root))

    if args.json:
        import json
        ui.out(json.dumps({"root": str(root), "files_scanned": len(files),
                           "findings": findings}, ensure_ascii=False,
                          indent=2))
        return 1 if findings else 0

    ui.header("发布前自检", "随包文件里有没有属于本机的信息")
    ui.kv("扫描根目录", str(root))
    ui.kv("检查文件数", "%d" % len(files))
    local = sourceaudit.local_forbid(root)
    ui.kv("本地禁止清单",
          "%d 条（%s）" % (len(local), sourceaudit.LOCAL_FORBID)
          if local else "无 —— 建议加上自己的站名/项目名")
    ui.out()

    if not findings:
        ui.success("没有发现宿主机信息，可以发布")
        if not local:
            ui.hint("把自己的站名、项目代号写进 %s（已被 .gitignore 排除）"
                    % sourceaudit.LOCAL_FORBID)
        return 0

    ui.failure("发现 %d 处需要处理" % len(findings))
    ui.out(sourceaudit.summarise(findings))
    ui.out()
    ui.hint("改掉它们，或把属于自己、没有固定形状的名字写进 %s"
            % sourceaudit.LOCAL_FORBID)
    return 1


def register(sub) -> None:
    p = sub.add_parser(
        "audit-source",
        help="发布前自检：随包文件里是否混入了本机的 IP/域名/凭据/个人信息",
        description="扫描所有会被打包发布的文件（源码、测试、文档、示例），"
                    "按「形状」找出属于某一台机器的信息。测试套件跑的是同一份代码。")
    p.add_argument("--root", default="", help="要检查的目录（默认当前目录）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit_source)
