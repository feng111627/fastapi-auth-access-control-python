# FastAPI 认证与访问控制服务

在原有 `GET /` 接口不变的前提下，补上了本地可用的认证（JWT 双令牌）、
基于角色与作用域的访问控制，以及按来源的时间窗限流。

## 本地运行与验证

```bash
uv sync                 # 安装依赖
uv run python main.py   # 启动服务（监听 127.0.0.1 随机端口，可自行改端口）
uv run pytest           # 跑全部测试，-v 输出按业务链路分组的用例与结果
```

预置账号（仅本地开发用）：

| 用户名  | 密码         | 角色    |
| ------- | ------------ | ------- |
| admin   | admin-pass   | admin   |
| editor  | editor-pass  | editor  |
| viewer  | viewer-pass  | viewer  |

快速验证：

```bash
# 登录拿令牌
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pass"}'

# 带令牌访问受保护资源
curl -s localhost:8000/resources/documents \
  -H "Authorization: Bearer <access_token>"

# 轮换刷新令牌（旧令牌立即作废）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 登出（访问令牌与提交的刷新令牌同时失效）
curl -s -X POST localhost:8000/auth/logout \
  -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

## 令牌生命周期与撤销规则

- 登录（`POST /auth/login`）签发一对令牌：
  - **访问令牌**：HS256 JWT，15 分钟有效，携带 `sub/role/jti/type=access`；
  - **刷新令牌**：HS256 JWT，7 天有效，携带 `sub/jti/type=refresh`，
    服务端登记其状态（`active`）。
- 刷新（`POST /auth/refresh`）是**轮换式**的：校验通过后旧刷新令牌被
  原子地标记为 `rotated` 并签发新的一对令牌。旧刷新令牌再次使用会被
  判定为**复用**并拒绝（`refresh_token_reused`），并发轮换时只有一个
  请求能成功。
- 登出（`POST /auth/logout`）与主动撤销（`POST /auth/revoke`）都会让
  对应令牌**立刻失效**：访问令牌进撤销名单，刷新令牌状态置为 `revoked`。
- 令牌校验失败按原因区分，响应体 `detail.code` 分别为：

  | code                   | 含义                           | HTTP |
  | ---------------------- | ------------------------------ | ---- |
  | `not_authenticated`    | 未携带访问令牌                 | 401  |
  | `invalid_credentials`  | 用户名或密码错误               | 401  |
  | `token_expired`        | 令牌已过期                     | 401  |
  | `token_tampered`       | 签名非法、格式错误或类型不符   | 401  |
  | `token_revoked`        | 令牌已被撤销（登出/主动撤销）  | 401  |
  | `refresh_token_reused` | 已轮换过的旧刷新令牌被再次使用 | 401  |
  | `forbidden`            | 已登录但角色权限不足           | 403  |
  | `rate_limited`         | 触发限流                       | 429  |

## 角色与作用域对应关系

作用域形如 `<resource>:<action>`，`manage` 蕴含 `write`，`write` 蕴含
`read`。**默认拒绝**：未在下表明确放行的 (角色, 作用域) 一律 403。

| 角色   | 显式作用域                            | 实际可执行                 |
| ------ | ------------------------------------- | -------------------------- |
| admin  | `documents:manage`                    | 读 / 写 / 管理（删除）     |
| editor | `documents:read`, `documents:write`   | 读 / 写                    |
| viewer | `documents:read`                      | 只读                       |

受保护入口（`documents` 资源）：

| 入口                            | 需要作用域         |
| ------------------------------- | ------------------ |
| `GET /resources/documents`      | `documents:read`   |
| `GET /resources/documents/{id}` | `documents:read`   |
| `POST /resources/documents`     | `documents:write`  |
| `DELETE /resources/documents/{id}` | `documents:manage` |

未登录（401）与已登录但权限不足（403）严格区分。

## 限流口径

- 算法：**固定时间窗计数**，按 `(入口桶, 来源)` 二元组独立计数。
- 来源：优先取 `X-Forwarded-For` 首跳，否则取直连客户端 IP。
- 阈值（见 `app/config.py`）：
  - 登录入口 `POST /auth/login`：60 秒内最多 5 次；
  - 受保护资源入口：60 秒内最多 30 次。
- 超限返回 `429`，响应体 `detail.retry_after` 与响应头 `Retry-After`
  都给出还需等待的秒数。
- 计数在同一把锁内完成"读取 + 自增"，并发下不会漏计或重复扣减；
  不同来源、不同入口桶之间互不影响。

## 测试覆盖

`uv run pytest`（已配置 `-v`）按三条业务链路分组输出每个用例的结果：

- `tests/test_token_lifecycle.py`：登录签发、刷新轮换、旧令牌复用拒绝、
  登出/撤销即刻失效、过期/篡改/类型不符的区分；
- `tests/test_access_control.py`：401 与 403 的区分、三种角色 ×
  读/写/管理的结论矩阵、默认拒绝；
- `tests/test_rate_limit.py`：阈值边界、`retry_after` 告知、来源与
  入口桶隔离、并发下计数准确（200 线程抢 50 额度恰好放行 50）。
