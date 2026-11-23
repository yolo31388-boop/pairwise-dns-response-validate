# pairwise-dns-response-validate

## 领域

安全

## 主题

DNS 响应校验

## 说明

事务 ID、源端口与附加段过滤。

初始状态下 `security/dns_response_validate.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
