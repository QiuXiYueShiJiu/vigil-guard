"""`vigil config` -- inspect, edit, validate, export and import settings."""
from __future__ import annotations

import json as _json
import os
import subprocess
import sys

from .. import ui
from ..core import paths
from ..core.config import DEFAULTS, load as load_config
from ..core.errors import VigilError


def cmd_show(args) -> int:
    cfg = load_config(args.config or None)
    blob = cfg.export(include_secrets=args.show_secrets) if not args.paths_only \
        else paths.describe()
    if args.json:
        ui.out(_json.dumps(blob, ensure_ascii=False, indent=2))
        return 0
    ui.header("当前配置")
    _render(blob, "")
    ui.out()
    ui.note("凭据单独存放在 %s（权限 600），不会出现在上面的输出里。"
            % cfg.secrets_path)
    return 0


def _render(obj, prefix: str) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                ui.out("  %s%s:" % (" " * 0, ui.bold(k)))
                _render(v, prefix + "  ")
            else:
                ui.kv(_indent_key(k, prefix), _fmt(v))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _render(item, prefix)
            else:
                ui.bullet(_fmt(item))
    else:
        ui.kv(prefix, _fmt(obj))


def _indent_key(k, prefix):
    return ("  " + k) if not prefix else k


def _fmt(v):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "是" if v else "否"
    if v == "":
        return "—"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "—"
    if isinstance(v, dict):
        return "{…}"
    return str(v)


def cmd_get(args) -> int:
    cfg = load_config(args.config or None)
    val = cfg.get(args.key, None)
    if val is None:
        ui.failure("配置项不存在: %s" % args.key)
        ui.hint("运行 `vigil config show` 查看全部配置项")
        return 1
    if args.json:
        ui.out(_json.dumps(val, ensure_ascii=False))
    elif isinstance(val, (dict, list)):
        ui.out(_json.dumps(val, ensure_ascii=False, indent=2))
    else:
        ui.out(str(val))
    return 0


def cmd_set(args) -> int:
    cfg = load_config(args.config or None)
    value = args.value
    # Coerce obvious literals so `vigil config set threat.enabled false`
    # does not silently store the string "false".
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "on"):
            value = True
        elif low in ("false", "no", "off"):
            value = False
        elif low.lstrip("-").isdigit():
            value = int(low)
        elif low in ("null", "none", ""):
            value = None
        else:
            try:
                if value.strip().startswith(("[", "{")):
                    value = _json.loads(value)
            except ValueError:
                pass
    cfg.set(args.key, value)
    if not cfg.save():
        ui.failure("写入配置失败")
        return 1
    ui.success("%s = %s" % (args.key, _json.dumps(value, ensure_ascii=False)))
    ui.note("部分配置需要重启服务才能生效：vigil service restart <服务名>")
    return 0


def cmd_validate(args) -> int:
    cfg = load_config(args.config or None)
    problems = cfg.validate()
    if args.json:
        ui.out(_json.dumps({"ok": not problems, "problems": problems},
                           ensure_ascii=False, indent=2))
        return 0 if not problems else 1
    ui.header("配置校验")
    if not problems:
        ui.success("配置看起来没有问题")
        return 0
    ui.problems_block(problems)
    return 1


def cmd_edit(args) -> int:
    cfg = load_config(args.config or None)
    if not cfg.exists():
        ui.failure("配置文件不存在: %s" % cfg.path)
        ui.hint("先运行 `vigil install`")
        return 1
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "nano"
    ui.note("使用 %s 打开 %s" % (editor, cfg.path))
    ui.note("注意：JSON 格式错误会导致服务拒绝启动（这是有意为之）。")
    try:
        subprocess.call([editor, str(cfg.path)])
    except OSError:
        ui.failure("无法启动编辑器 %s，请设置 $EDITOR" % editor)
        return 1
    return cmd_validate(args)


def cmd_paths(args) -> int:
    if args.json:
        ui.out(_json.dumps(paths.describe(), ensure_ascii=False, indent=2))
        return 0
    ui.header("文件位置")
    for k, v in paths.describe().items():
        exists = os.path.exists(v)
        ui.kv(k, "%s %s" % (v, "" if exists else ui.dim("（尚未创建）")))
    ui.section("其它")
    ui.kv("状态目录", str(paths.VAR))
    ui.kv("日志目录", str(paths.LOG))
    return 0


def cmd_export(args) -> int:
    cfg = load_config(args.config or None)
    blob = cfg.export(include_secrets=args.with_secrets)
    text = _json.dumps(blob, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        os.chmod(args.output, 0o600 if args.with_secrets else 0o644)
        ui.success("已导出到 %s" % args.output)
        if args.with_secrets:
            ui.warning("导出内容包含凭据，请妥善保管")
    else:
        ui.out(text)
    return 0


def cmd_import(args) -> int:
    cfg = load_config(args.config or None)
    try:
        if args.file == "-":
            blob = _json.load(sys.stdin)
        else:
            with open(args.file, "r", encoding="utf-8") as fh:
                blob = _json.load(fh)
    except (OSError, ValueError) as e:
        ui.failure("读取导入文件失败: %s" % e)
        return 1
    if not isinstance(blob, dict):
        ui.failure("导入内容必须是一个 JSON 对象")
        return 1
    cfg.import_(blob, merge=not args.replace)
    if not cfg.save():
        ui.failure("写入配置失败")
        return 1
    ui.success("已导入配置（%s）" % ("替换" if args.replace else "合并"))
    return cmd_validate(args)


def cmd_reset(args) -> int:
    cfg = load_config(args.config or None)
    if not args.yes and not ui.confirm("把所有配置恢复为默认值？", default=False):
        return 0
    cfg.import_({}, merge=False)
    if not cfg.save():
        ui.failure("写入配置失败")
        return 1
    ui.success("已恢复默认配置")
    ui.warning("发件凭据与收件人已被清空，需要重新运行 `vigil mail setup`")
    return 0


def register(sub) -> None:
    p = sub.add_parser("config", help="配置管理：查看、修改、导入导出、校验",
                       description="读写配置文件。凭据存放于单独的文件，"
                                   "不会被普通查看或导出带出。")
    ps = p.add_subparsers(dest="config_action", metavar="<操作>")

    sp = ps.add_parser("show", help="显示当前配置")
    sp.add_argument("--show-secrets", action="store_true", help="同时显示凭据")
    sp.add_argument("--paths-only", action="store_true", help="只显示文件位置")
    sp.set_defaults(func=cmd_show)

    sp = ps.add_parser("get", help="读取单个配置项")
    sp.add_argument("key", help="点分路径，例如 mail.from_address")
    sp.set_defaults(func=cmd_get)

    sp = ps.add_parser("set", help="修改单个配置项")
    sp.add_argument("key", help="点分路径")
    sp.add_argument("value", help="新值")
    sp.set_defaults(func=cmd_set)

    sp = ps.add_parser("validate", help="校验配置")
    sp.set_defaults(func=cmd_validate)

    sp = ps.add_parser("edit", help="用编辑器打开配置文件并校验")
    sp.set_defaults(func=cmd_edit)

    sp = ps.add_parser("paths", help="显示各类文件的位置")
    sp.set_defaults(func=cmd_paths)

    sp = ps.add_parser("export", help="导出配置")
    sp.add_argument("-o", "--output", default="", help="输出文件（默认打印到屏幕）")
    sp.add_argument("--with-secrets", action="store_true",
                    help="导出内容包含凭据（请妥善保管）")
    sp.set_defaults(func=cmd_export)

    sp = ps.add_parser("import", help="导入配置")
    sp.add_argument("file", help="JSON 文件路径，- 表示从标准输入读取")
    sp.add_argument("--replace", action="store_true",
                    help="替换而不是合并已有配置")
    sp.set_defaults(func=cmd_import)

    sp = ps.add_parser("reset", help="恢复默认配置")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.set_defaults(func=cmd_reset)
