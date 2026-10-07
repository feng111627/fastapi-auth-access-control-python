# FastAPI 认证与访问控制服务

在原有 `GET /` 接口不变的前提下，补上了本地可用的认证（JWT 双令牌）、
基于角色与作用域的访问控制，以及按来源的时间窗限流。

本次新增（均向后兼容，原有接口的状态码与错误码含义不变）：

- **账号维度登录保护**：同一账号连续登录失败达到阈值即临时锁定，
  锁定期间换来源、换密码都拒绝，并告知还需等待的秒数；
- **全端撤销与泄露处置**：`POST /auth/revoke-all` 一次性作废本账号
  此前签发的全部令牌；已轮换的旧刷新令牌被复用时按疑似泄露处理，
  整条会话链作废；
- **限流口径与容量补强**：登录/刷新/登出/撤销与文档读/写/管理全部
  纳入时间窗限流；来源以服务端确认的连接对端为准（仅可信代理可
  转发来源）；限流状态有界，过期计数自动回收。

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

# 全端撤销（本账号此前签发的全部令牌立即失效）
curl -s -X POST localhost:8000/auth/revoke-all \
  -H "Authorization: Bearer <access_token>"
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
  | `token_revoked`        | 令牌已被撤销（登出/主动撤销/全端撤销/会话链作废） | 401  |
  | `refresh_token_reused` | 已轮换过的旧刷新令牌被再次使用（疑似泄露） | 401  |
  | `account_locked`       | 账号连续登录失败被临时锁定           | 423  |
  | `forbidden`            | 已登录但角色权限不足           | 403  |
  | `rate_limited`         | 触发限流                       | 429  |

## 账号维度登录保护

与按来源的限流互补：限流防"一个来源打爆接口"，账号锁定防"同一个
账号被来自许多来源轮流猜密码"。规则（阈值见 `app/config.py`）：

- 同一账号在失败计数窗口（默认 300 秒）内连续失败达到阈值
  （默认 5 次），账号被临时锁定（默认 300 秒）；
- 锁定期间无论来源、无论密码对错一律拒绝，返回 `423` +
  `account_locked`，响应体 `detail.retry_after` 与响应头
  `Retry-After` 给出还需等待的秒数；
- 锁定按账号独立计算，不同账号互不影响；到期自动恢复；
- 登录成功后该账号的失败计数清零；
- 计数与状态迁移在同一把锁内完成，并发请求下不会提前解锁或锁死。

## 全端撤销与泄露处置

- `POST /auth/revoke-all`（需持有有效访问令牌，与撤销入口共用限流桶）：
  把本账号此前签发的令牌**一次性全部作废**——通过单调递增的账号令牌
  版本号实现，所有携带旧版本号的访问/刷新令牌立即失效，包括已经由旧
  刷新令牌轮换出来、目前还有效的后继令牌；不影响其他账号；之后重新
  登录可正常拿到新令牌。
- **会话链（family）**：一次登录签发的刷新令牌及其轮换出的全部后继
  同属一条链。已轮换过的旧刷新令牌再次被使用时，按**疑似泄露**处置：
  整条链上的令牌（含当前最新的访问/刷新令牌）立即作废，响应
  `401` + `refresh_token_reused`。该错误码与普通的过期
  （`token_expired`）、主动撤销（`token_revoked`）两两可区分，
  前端可据此决定下一步动作；同一账号的其他会话链不受波及。

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
- 来源：**以服务端确认的连接对端为准**。只有当直连对端属于可信代理
  （`config.TRUSTED_PROXY_HOSTS`，默认含 `127.0.0.1`、`::1` 与本地
  测试客户端）时，才采信其转发的 `X-Forwarded-For` 首跳；其余情况
  一律使用连接对端本身——客户端自带的请求头无法左右判定，也就不能
  借此伪造来源绕过阈值。
- 入口桶与阈值（见 `app/config.py`）：

  | 入口                                  | 桶                | 默认阈值      |
  | ------------------------------------- | ----------------- | ------------- |
  | `POST /auth/login`                    | `login`           | 60 秒 5 次    |
  | `POST /auth/refresh`                  | `refresh`         | 60 秒 10 次   |
  | `POST /auth/logout`                   | `logout`          | 60 秒 10 次   |
  | `POST /auth/revoke`、`/auth/revoke-all` | `revoke`        | 60 秒 10 次   |
  | `GET /resources/documents*`           | `documents:read`  | 60 秒 30 次   |
  | `POST /resources/documents`           | `documents:write` | 60 秒 10 次   |
  | `DELETE /resources/documents/{id}`    | `documents:manage`| 60 秒 10 次   |
- 超限返回 `429`，响应体 `detail.retry_after` 与响应头 `Retry-After`
  都给出还需等待的秒数。
- 计数在同一把锁内完成"读取 + 自增"，并发下不会漏计或重复扣减；
  不同来源、不同入口桶之间互不影响，某来源被限不会牵连其他来源
  或其他账号。
- **状态有界**：追踪键数超过 `RATE_LIMIT_MAX_KEYS`（默认 10 万）时，
  优先回收已过期的窗口，仍超限则淘汰最旧窗口，长期运行、来源很多
  时内存不无限增长。

## 测试覆盖

`uv run pytest`（已配置 `-v`）按业务链路分组输出每个用例的结果：

- `tests/test_token_lifecycle.py`：登录签发、刷新轮换、旧令牌复用拒绝、
  登出/撤销即刻失效、过期/篡改/类型不符的区分；
- `tests/test_access_control.py`：401 与 403 的区分、三种角色 ×
  读/写/管理的结论矩阵、默认拒绝；
- `tests/test_rate_limit.py`：阈值边界、`retry_after` 告知、来源与
  入口桶隔离、并发下计数准确（200 线程抢 50 额度恰好放行 50）；
- `tests/test_login_guard.py`：连续失败锁定与等待秒数告知、锁定期间
  换来源/换密码仍拒绝、账号间隔离、到期自动恢复、成功后计数清零、
  并发下恰好到阈值才锁定；
- `tests/test_revoke_all.py`：全端撤销即刻失效（含轮换出的后继令牌）、
  不牵连其他账号、撤销后重新登录可用、旧刷新令牌复用触发整条会话链
  作废、泄露/过期/撤销三种原因可区分；
- `tests/test_rate_limit_coverage.py`：刷新/登出/撤销与文档写/管理
  入口的限流覆盖、伪造来源不能绕过限流、可信代理口径、限流状态
  有界回收（过期优先、活跃键计数不受回收影响）。

## 兼容性说明

- 原有接口的路径、状态码与错误码含义均未改变，原有用例全部继续通过；
- 新增的拒绝情形只有两类：账号锁定（`423 account_locked`，此前该场景
  会返回 `401 invalid_credentials`）与各入口超限（`429 rate_limited`，
  此前这些入口没有限流）；
- 令牌新增 `fid`（会话链）与 `tv`（令牌版本）声明，不影响旧令牌的
  校验逻辑（缺失时按版本 0、无会话链处理）。
