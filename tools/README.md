# tools/

## `source-forbid.txt` — 本机的禁止清单

`vigil audit-source` 与测试套件都会调用 `vigil/core/sourceaudit.py`，它按**形状**
找出随包文件里属于某一台机器的信息：公网 IP、国际化（punycode）域名、主机商品牌、
个人邮箱、带日期的一次性目录、真实个人信息字样。

有一类东西没有形状：你自己的站名、项目代号、客户代码、编辑器插件名。它们看起来
和任何普通单词一样，所以**不能**写进代码里的规则表 —— 那等于把要藏的名字
连同守卫一起发布出去（这个项目早期版本就犯过这个错）。

于是它们写在这里，一行一个：

```
值
值:原因
```

这个文件被 `.gitignore` 排除，不会进入发行包。没有它也完全可以，只是那类
名字不会被拦住。建议在第一次发布前把自己相关的名字都列上，然后：

```sh
vigil audit-source          # 看有没有漏
python3 -m unittest tests.test_vigil.TestNoHardcodedHostData
```
