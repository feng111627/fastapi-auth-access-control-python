# FastAPI 认证与访问控制（本地可运行）

在原有 `GET / -> {"Hello": "World"}` 接口不变的前提下，补上了认证、基于角色/作用域的
访问控制与按来源的时间窗限流。全部状态为进程内内存实现，本地零依赖即可运行与验证。

## 快速开始

```bash
uv sync                 # 安装依赖
uv run python main.py   # 启动服务（127.0.0.1，随机端口）
uv run pytest           # 运行全部测试（默认 -v，按业务分组展示用例与结果）
```

内置演示账号（仅本地演示，口令为明文）：

| 用户名  | 口令         | 角色   |
| ------- | ------------ | ------ |
| viewer  | viewer-pass  | viewer |
| editor  | editor-pass  | editor |
| admin   | admin-pass   | admin  |

## 接口一览

| 方法 | 路径                | 说明                       | 所需条件             |
| ---- | ------------------- | -------------------------- | -------------------- |
| GET  | /                   | 原有接口                   | 无                   |
| POST | /auth/login         | 登录，签发令牌对           | 限流（登录口径）     |
| POST | /auth/refresh       | 用刷新令牌轮换新令牌对     | 限流（登录口径）     |
| POST | /auth/logout        | 登出，两种令牌立即失效     | 任意已认证角色       |
| POST | /auth/revoke        | 主动撤销指定令牌           | 任意已认证角色       |
| GET  | /documents          | 读资源                     | `documents:read`     |
| POST | /documents          | 写资源                     | `documents:write`    |
| DELETE | /documents/{id}   | 管理资源                   | `documents:manage`   |

## 令牌生命周期与撤销规则

- **签发**：`POST /auth/login` 成功后返回一对 JWT（HS256）：
  - 访问令牌：默认 300 秒（`access_token_ttl_seconds`）；
  - 刷新令牌：默认 3600 秒（`refresh_token_ttl_seconds`）。
  两者都带唯一 `jti` 与 `type`（`access` / `refresh`）声明。
- **轮换**：`POST /auth/refresh` 校验刷新令牌后签发新令牌对，同时把旧刷新令牌的
  `jti` 登记为"已使用"。旧刷新令牌再次使用即判定为**重放**，返回
  `refresh_token_reused`。
- **登出**：`POST /auth/logout` 把当前访问令牌（Bearer）与请求体中的刷新令牌一起
  撤销，两者**立即**失效。
- **主动撤销**：`POST /auth/revoke` 可撤销任意一个令牌（访问或刷新），立即生效。
- 撤销记录保存在内存登记表中，条目过期后惰性清理；服务重启后状态清空（本地语义）。

### 拒绝原因（均返回 401，`detail.reason` 可区分）

| reason                 | 含义                                   |
| ---------------------- | -------------------------------------- |
| `missing_credentials`  | 未携带 Bearer 令牌                     |
| `token_expired`        | 令牌已过期                             |
| `token_tampered`       | 签名不合法（被篡改 / 伪造）            |
| `token_revoked`        | 令牌已被登出或主动撤销                 |
| `refresh_token_reused` | 已轮换过的旧刷新令牌被重放             |
| `token_wrong_type`     | 拿错令牌类型（如刷新令牌当访问令牌用） |
| `token_malformed`      | 令牌结构无法解析                       |
| `invalid_credentials`  | 登录用户名或密码错误（两者同口径）     |

## 角色与作用域对应关系

作用域命名为 `<资源>:<操作>`，操作分 `read` / `write` / `manage` 三档：

| 角色   | documents:read | documents:write | documents:manage |
| ------ | :------------: | :-------------: | :--------------: |
| viewer | ✔              | ✘               | ✘                |
| editor | ✔              | ✔               | ✘                |
| admin  | ✔              | ✔               | ✔                |

- **默认拒绝**：未知角色没有任何作用域；未在 `ROLE_SCOPES` 中明确放行的作用域对任何
  角色都拒绝。
- **未登录 vs 权限不足**：未携带/携带无效令牌返回 `401`；已认证但作用域不足返回
  `403`，响应体带 `required_scope`。

## 限流口径

- **算法**：固定窗口计数（`FixedWindowRateLimiter`）。
- **维度**：按客户端来源 IP 独立计数，某个来源被限不影响其他来源。
- **两档独立额度**：
  - 登录类入口（`/auth/login`、`/auth/refresh`）：默认 60 秒内 5 次；
  - 受保护入口（`/documents*`、`/auth/logout`、`/auth/revoke`）：默认 60 秒内 10 次。
- **超限响应**：`429`，响应头 `Retry-After` 与响应体
  `detail.retry_after_seconds` 给出还需等待的秒数。
- **并发正确性**：判定与计数在同一把锁内完成，并发下不会重复扣减或漏计
  （有对应的并发用例覆盖）。

以上参数均可在 `app/config.py` 的 `Settings` 中调整，测试通过构造独立 `Settings`
实例覆盖默认值。

## 本地验证

```bash
# 1. 全部单测（输出按业务分组：访问控制 / 限流 / 令牌生命周期，逐用例给出结果）
uv run pytest

# 2. 手工验证（另开一个终端）
uv run uvicorn main:app --port 8000

# 登录拿令牌
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pass"}'

# 用访问令牌读资源（viewer 可读）
curl -s localhost:8000/documents -H "Authorization: Bearer <access_token>"

# viewer 写资源 -> 403 insufficient_scope
curl -s -X POST localhost:8000/documents \
  -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' -d '{"title":"t"}'

# 轮换刷新令牌后，旧刷新令牌再用 -> 401 refresh_token_reused
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<refresh_token>"}'

# 登出后访问令牌立即失效 -> 401 token_revoked
curl -s -X POST localhost:8000/auth/logout \
  -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<refresh_token>"}'
```

## 代码结构

```
app/
  config.py        # 配置：密钥、令牌时效、限流参数
  errors.py        # 可区分的令牌/限流错误类型
  store.py         # 线程安全内存存储：用户、撤销登记、刷新令牌轮换记录
  tokens.py        # JWT 签发 / 校验 / 轮换 / 撤销
  rbac.py          # 角色 -> 作用域映射，默认拒绝
  ratelimit.py     # 固定窗口限流器（锁内判定+计数）
  dependencies.py  # FastAPI 依赖：限流、认证、作用域鉴权
  routes.py        # 认证与受保护资源路由
  main.py          # 应用工厂 create_app
tests/
  test_token_lifecycle.py  # 令牌轮换与撤销链路
  test_access_control.py   # 越权访问与默认拒绝链路
  test_rate_limit.py       # 限流与并发边界链路
```
