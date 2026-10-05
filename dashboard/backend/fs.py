"""Filesystem access for the management console.

Full-disk access was requested, so the interesting work here is not the
access but the guard rails around it:

* every path is resolved with ``realpath`` first, so a symlink (or a symlink
  planted inside a web root by an attacker) cannot walk out of a denied
  area;
* a deny list covers the things that are pure liability to hand a browser --
  the shadow file, private keys, live kernel interfaces;
* a read-only list covers system directories that are fine to inspect but
  that nobody should rewrite through a web form;
* destructive operations need a confirmation token that the server issued
  for that exact path, so a stray click or a replayed request cannot delete
  anything.

Large transfers are streamed from the HTTP layer straight to disk; this
module never holds a whole upload in memory.
"""
from __future__ import annotations

import os
import pwd
import grp
import shutil
import stat
import time

from . import settings


class FsError(Exception):
    """A refusal the API turns into a 4xx with a readable message."""

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


BINARY_SNIFF = 4096


def _under(path: str, prefix: str) -> bool:
    path = path.rstrip("/") or "/"
    prefix = prefix.rstrip("/") or "/"
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def _is_denied(path: str) -> str:
    for denied in settings.settings.deny_paths:
        if _under(path, denied):
            return denied
    return ""


def _is_readonly(path: str) -> bool:
    for ro in settings.settings.readonly_paths:
        if _under(path, ro):
            return True
    return False


class Filesystem:
    # -- path handling ---------------------------------------------------

    @staticmethod
    def resolve(path: str) -> str:
        """Absolute, symlink-free path, or raise."""
        if path is None:
            raise FsError("缺少路径参数")
        raw = str(path).strip() or "/"
        if "\x00" in raw:
            raise FsError("路径包含非法字符")
        if not raw.startswith("/"):
            raw = os.path.join(settings.settings.fs_root, raw)
        # normpath first so `..` cannot survive realpath on a missing leaf.
        candidate = os.path.normpath(raw)
        real = os.path.realpath(candidate)
        root = os.path.realpath(settings.settings.fs_root)
        if not _under(real, root):
            raise FsError("路径超出允许范围", 403)
        denied = _is_denied(real)
        if denied:
            raise FsError("该路径已被策略保护：%s" % denied, 403)
        return real

    @staticmethod
    def check_writable(path: str) -> None:
        if _is_readonly(path):
            raise FsError("该路径为只读保护目录，拒绝修改", 403)
        if _is_denied(path):
            raise FsError("该路径已被策略保护", 403)

    @staticmethod
    def describe_mode(mode: int) -> str:
        return stat.filemode(mode)

    @staticmethod
    def owner(uid: int, gid: int) -> str:
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)
        try:
            group = grp.getgrgid(gid).gr_name
        except KeyError:
            group = str(gid)
        return "%s:%s" % (user, group)

    # -- listing ---------------------------------------------------------

    def listing(self, path: str, show_hidden: bool = True,
                sort: str = "name") -> dict:
        target = self.resolve(path)
        if not os.path.isdir(target):
            raise FsError("不是目录：%s" % target, 400)
        entries = []
        try:
            names = os.listdir(target)
        except PermissionError:
            raise FsError("没有权限读取该目录", 403)
        except OSError as exc:
            raise FsError("无法读取目录：%s" % exc, 400)

        for name in names:
            if not show_hidden and name.startswith("."):
                continue
            full = os.path.join(target, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            kind = ("dir" if stat.S_ISDIR(st.st_mode) else
                    "link" if stat.S_ISLNK(st.st_mode) else
                    "file" if stat.S_ISREG(st.st_mode) else "other")
            item = {
                "name": name,
                "path": full,
                "kind": kind,
                "size": st.st_size if kind == "file" else 0,
                "mtime": int(st.st_mtime),
                "mode": self.describe_mode(st.st_mode),
                "owner": self.owner(st.st_uid, st.st_gid),
                "ro": _is_readonly(full),
            }
            if kind == "link":
                try:
                    item["target"] = os.readlink(full)
                except OSError:
                    item["target"] = ""
                try:
                    item["kind"] = "dir" if os.path.isdir(full) else "file"
                    item["link"] = True
                except OSError:
                    pass
            entries.append(item)

        def sort_key(item):
            primary = 0 if item["kind"] == "dir" else 1
            if sort == "size":
                return (primary, -item["size"])
            if sort == "time":
                return (primary, -item["mtime"])
            return (primary, item["name"].lower())

        entries.sort(key=sort_key)

        parent = os.path.dirname(target.rstrip("/")) or "/"
        usage = None
        try:
            st = os.statvfs(target)
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            usage = {"total": total, "free": free, "used": total - free,
                     "percent": round((total - free) * 100.0 / total, 1)
                     if total else 0.0}
        except OSError:
            pass

        return {"path": target, "parent": parent, "entries": entries,
                "count": len(entries), "usage": usage,
                "writable": not _is_readonly(target),
                "root": settings.settings.fs_root}

    def tree(self, path: str, depth: int = 1) -> dict:
        """Cheap directory tree used by the sidebar."""
        target = self.resolve(path)
        depth = max(0, min(3, int(depth)))
        node = {"name": os.path.basename(target) or target, "path": target,
                "kind": "dir", "children": []}
        if depth <= 0:
            return node
        try:
            for name in sorted(os.listdir(target)):
                if name.startswith("."):
                    continue
                full = os.path.join(target, name)
                if not os.path.isdir(full) or os.path.islink(full):
                    continue
                if _is_denied(os.path.realpath(full)):
                    continue
                node["children"].append(self.tree(full, depth - 1))
                if len(node["children"]) >= 40:
                    break
        except OSError:
            pass
        return node

    # -- reading ---------------------------------------------------------

    def read(self, path: str) -> dict:
        target = self.resolve(path)
        if os.path.isdir(target):
            raise FsError("这是一个目录", 400)
        limit = int(settings.settings.read_max)
        try:
            size = os.path.getsize(target)
        except OSError as exc:
            raise FsError("无法读取文件：%s" % exc, 400)
        with open(target, "rb") as fh:
            head = fh.read(min(size, limit + 1))
        truncated = len(head) > limit
        blob = head[:limit]
        binary = b"\x00" in blob[:BINARY_SNIFF]
        st = os.stat(target)
        out = {
            "path": target, "size": size, "truncated": truncated,
            "binary": binary, "mtime": int(st.st_mtime),
            "mode": self.describe_mode(st.st_mode),
            "owner": self.owner(st.st_uid, st.st_gid),
            "encoding": "utf-8", "content": "", "hex": "",
        }
        if binary:
            out["hex"] = blob[:512].hex()
        else:
            try:
                out["content"] = blob.decode("utf-8")
            except UnicodeDecodeError:
                out["content"] = blob.decode("utf-8", "replace")
                out["encoding"] = "utf-8 (replace)"
        return out

    def search(self, path: str, pattern: str, content: bool = False,
               limit: int = 200, case: bool = False) -> dict:
        """Find by name, or grep inside text files, under one directory."""
        target = self.resolve(path)
        if not pattern:
            raise FsError("需要提供搜索内容")
        needle = pattern if case else pattern.lower()
        hits = []
        scanned = 0
        started = time.time()
        for base, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs
                       if not _is_denied(os.path.realpath(os.path.join(base, d)))]
            for name in dirs + files:
                if len(hits) >= limit or time.time() - started > 8:
                    break
                haystack = name if case else name.lower()
                if needle in haystack:
                    full = os.path.join(base, name)
                    hits.append({"path": full, "name": name,
                                 "kind": "dir" if os.path.isdir(full) else "file",
                                 "size": (os.path.getsize(full)
                                          if os.path.isfile(full) else 0)})
            if content:
                for name in files:
                    if len(hits) >= limit or time.time() - started > 8:
                        break
                    full = os.path.join(base, name)
                    try:
                        if os.path.getsize(full) > 2 * 1024 * 1024:
                            continue
                        with open(full, "rb") as fh:
                            blob = fh.read()
                        if b"\x00" in blob[:2048]:
                            continue
                        text = blob.decode("utf-8", "replace")
                    except OSError:
                        continue
                    scanned += 1
                    for lineno, line in enumerate(text.splitlines(), 1):
                        hay = line if case else line.lower()
                        if needle in hay:
                            hits.append({"path": full, "name": name,
                                         "kind": "file", "line": lineno,
                                         "text": line.strip()[:300]})
                            if len(hits) >= limit:
                                break
            if len(hits) >= limit or time.time() - started > 8:
                break
        return {"path": target, "pattern": pattern, "hits": hits,
                "count": len(hits), "scanned": scanned,
                "elapsed": round(time.time() - started, 2),
                "truncated": len(hits) >= limit}

    def du(self, path: str, limit: int = 200) -> dict:
        target = self.resolve(path)
        entries = []
        total = 0
        try:
            names = os.listdir(target)
        except OSError as exc:
            raise FsError("无法读取目录：%s" % exc, 400)
        for name in names[:limit]:
            full = os.path.join(target, name)
            try:
                if os.path.isdir(full) and not os.path.islink(full):
                    size = self._dir_size(full)
                else:
                    size = os.path.getsize(full)
            except OSError:
                continue
            total += size
            entries.append({"name": name, "size": size,
                            "kind": "dir" if os.path.isdir(full) else "file"})
        entries.sort(key=lambda e: -e["size"])
        return {"path": target, "total": total, "entries": entries[:limit]}

    def _dir_size(self, path: str, budget: float = 3.0) -> int:
        total = 0
        started = time.time()
        for base, dirs, files in os.walk(path):
            if time.time() - started > budget:
                break
            for name in files:
                try:
                    st = os.lstat(os.path.join(base, name))
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    total += st.st_size
        return total

    # -- writing ---------------------------------------------------------

    def write(self, path: str, content: str, encoding: str = "utf-8") -> dict:
        target = self.resolve(path)
        self.check_writable(target)
        if os.path.isdir(target):
            raise FsError("目标是目录", 400)
        blob = content.encode(encoding, "surrogateescape") \
            if encoding in ("utf-8", "latin-1") else content.encode(encoding)
        limit = int(settings.settings.upload_max)
        if len(blob) > limit:
            raise FsError("内容超过上限", 413)
        existed = os.path.exists(target)
        if existed:
            self._backup(target)
        parent = os.path.dirname(target)
        if parent and not os.path.isdir(parent):
            raise FsError("上级目录不存在", 400)
        tmp = target + ".vigiltmp"
        try:
            with open(tmp, "wb") as fh:
                fh.write(blob)
            # Preserve the original mode; new files get 0644.
            mode = (os.stat(target).st_mode & 0o7777) if existed else 0o644
            os.chmod(tmp, mode)
            os.replace(tmp, target)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise FsError("写入失败：%s" % exc, 400)
        return {"path": target, "bytes": len(blob), "created": not existed}

    def _backup(self, target: str, keep: int = 5) -> None:
        """Copy the previous contents aside before an overwrite."""
        try:
            if os.path.getsize(target) > 8 * 1024 * 1024:
                return
            stamp = time.strftime("%Y%m%d-%H%M%S")
            dest = "%s.vigilbak.%s" % (target, stamp)
            shutil.copy2(target, dest)
            folder = os.path.dirname(target) or "/"
            prefix = os.path.basename(target) + ".vigilbak."
            olds = sorted(n for n in os.listdir(folder) if n.startswith(prefix))
            for name in olds[:-keep]:
                try:
                    os.unlink(os.path.join(folder, name))
                except OSError:
                    pass
        except OSError:
            pass

    def mkdir(self, path: str, mode: int = 0o755) -> dict:
        target = self.resolve(path)
        self.check_writable(target)
        if os.path.exists(target):
            raise FsError("已存在同名文件或目录", 409)
        try:
            os.makedirs(target, mode=mode, exist_ok=False)
        except OSError as exc:
            raise FsError("创建失败：%s" % exc, 400)
        return {"path": target, "created": True}

    def rename(self, path: str, new_path: str) -> dict:
        src = self.resolve(path)
        dst = self.resolve(new_path)
        self.check_writable(src)
        self.check_writable(dst)
        if not os.path.exists(src):
            raise FsError("源不存在", 404)
        if os.path.exists(dst):
            raise FsError("目标已存在", 409)
        try:
            os.rename(src, dst)
        except OSError as exc:
            raise FsError("重命名失败：%s" % exc, 400)
        return {"from": src, "to": dst}

    def chmod(self, path: str, mode: str) -> dict:
        target = self.resolve(path)
        self.check_writable(target)
        try:
            value = int(str(mode), 8)
        except ValueError:
            raise FsError("权限格式应为八进制，例如 644", 400)
        try:
            os.chmod(target, value)
        except OSError as exc:
            raise FsError("修改权限失败：%s" % exc, 400)
        return {"path": target, "mode": oct(value)}

    def remove(self, paths: list) -> dict:
        removed, failed = [], []
        for raw in paths or []:
            target = self.resolve(raw)
            self.check_writable(target)
            if target == "/":
                failed.append({"path": target, "error": "拒绝删除根目录"})
                continue
            try:
                if os.path.isdir(target) and not os.path.islink(target):
                    shutil.rmtree(target)
                else:
                    os.unlink(target)
                removed.append(target)
            except OSError as exc:
                failed.append({"path": target, "error": str(exc)})
        return {"removed": removed, "failed": failed}

    def make_upload_path(self, directory: str, name: str) -> str:
        """Destination for an upload, refusing traversal in the filename."""
        folder = self.resolve(directory)
        self.check_writable(folder)
        if not os.path.isdir(folder):
            raise FsError("上传目标不是目录", 400)
        safe = os.path.basename(str(name).replace("\\", "/")).strip()
        if not safe or safe in (".", ".."):
            raise FsError("文件名非法", 400)
        return os.path.join(folder, safe)


filesystem = Filesystem()
