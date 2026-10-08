# FastAPI 认证与访问控制服务

在原有 `GET /` 接口不变的前提下，提供本地可用的认证（JWT 双令牌）、
基于角色与作用域的访问控制、按来源的时间窗限流，并在此基础上补齐了
生产前需要的三块能力：

1. **账号维度的登录保护**：同一账号短时间连续登录失败达到阈值后临时锁定，
   锁定期间换来源也拒绝并告知剩余秒数；不同账号互不影响、到期自动恢复、
   登录成功计数清零；并发下计数精确。
2. **全端撤销与泄露处置**：`POST /auth/revoke-all` 可把一个账号此前签发的
   访问/刷新令牌（含旧刷新令牌换出的后继令牌）一次性作废，不牵连其他账号，
   作废后重新登录可正常拿新令牌；已轮换的旧刷新令牌再次出现时按
   **疑似泄露**处理，作废整条会话链，并与过期、普通撤销明确区分。
3. **限流口径与容量**：登录/刷新/登出/撤销与文档读/写/管理全部纳入
   时间窗限流；来源只取服务端可确认的连接对端（可配置可信代理才采纳
   `X-Forwarded-For`），客户端自报头无法伪造或绕过；限流与锁定状态都有
   容量上限并回收过期计数，高并发下计数精确。

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

# 全端作废（改密/怀疑泄露；该账号此前所有令牌含后继令牌立即失效）
curl -s -X POST localhost:8000/auth/revoke-all \
  -H "Authorization: Bearer <access_token>"
```

## 令牌生命周期与撤销规则

- 登录（`POST /auth/login`）签发一对令牌，二者都携带会话链标识 `sid`
  与账号令牌代数 `gen`：
  - **访问令牌**：HS256 JWT，15 分钟有效，携带 `sub/role/jti/sid/gen/type=access`；
  - **刷新令牌**：HS256 JWT，7 天有效，携带 `sub/jti/sid/gen/type=refresh`，
    服务端登记其状态（`active`）。
  - 同一次登录及其后续轮换属于**同一条会话链（同一 sid）**；重新登录产生
    一条新链。
- 刷新（`POST /auth/refresh`）是**轮换式**的：校验通过后旧刷新令牌被
  原子地标记为 `rotated` 并签发新的一对令牌（沿用同一 sid 与 gen）。
  并发轮换时只有一个请求能成功。
- 登出（`POST /auth/logout`）与主动撤销单令牌（`POST /auth/revoke`）都会让
  对应令牌**立刻失效**：访问令牌进撤销名单，刷新令牌状态置为 `revoked`。
- **全端作废**（`POST /auth/revoke-all`，需持有有效访问令牌）：用于改密或
  怀疑令牌泄露。账号令牌代数 `gen + 1`，该账号此前签发的访问令牌、刷新
  令牌以及"旧刷新令牌换出来的后继令牌"**全部立即失效**；只作用于当前账号，
  不牵连其他账号；作废后重新登录会拿到新代数令牌，一切正常。
- **疑似泄露处置**：一个早已轮换（`rotated`）的旧刷新令牌又被拿来换新，
  属于异常复用，服务端把**这一条会话链**整条作废（不影响同账号的其他
  登录链）。此后：
  - 再用该旧刷新令牌，返回 `refresh_token_reused`；
  - 该链上尚未到期的访问令牌/后继刷新令牌再被使用，返回
    `session_compromised`，方便前端与日志把它和"普通过期""主动撤销"区分开。
- 令牌校验失败按原因区分，响应体 `detail.code` 分别为：

  | code                   | 含义                                        | HTTP |
  | ---------------------- | ------------------------------------------- | ---- |
  | `not_authenticated`    | 未携带访问令牌                              | 401  |
  | `invalid_credentials`  | 用户名或密码错误                            | 401  |
  | `token_expired`        | 令牌已过期                                  | 401  |
  | `token_tampered`       | 签名非法、格式错误或类型不符                | 401  |
  | `token_revoked`        | 主动撤销/登出/全端作废（旧代数令牌）        | 401  |
  | `refresh_token_reused` | 已轮换的旧刷新令牌被再次使用（疑似泄露触发）| 401  |
  | `session_compromised`  | 会话链因疑似泄露被整条作废                  | 401  |
  | `forbidden`            | 已登录但角色权限不足                        | 403  |
  | `rate_limited`         | 触发来源时间窗限流                          | 429  |
  | `account_locked`       | 账号因连续登录失败被临时锁定                | 429  |

## 账号登录保护

- 同一账号在 `LOGIN_LOCKOUT_WINDOW`（默认 300 秒）内连续失败达到
  `LOGIN_LOCKOUT_THRESHOLD`（默认 5 次）后，账号被临时锁定
  `LOGIN_LOCKOUT_DURATION`（默认 900 秒）。
- 锁定期间**先于密码校验**直接拒绝：即便密码正确、更换来源 IP 也返回
  `429 account_locked`，`detail.retry_after` 与响应头 `Retry-After`
  给出还要等待的秒数。
- 不同账号各自独立计数；锁定到期自动恢复，无需后台清理；本次登录成功后
  该账号失败计数清零。
- 计数与判定在同一把锁内完成，并发失败请求恰好到阈值才锁定，不会提前
  解锁，也不会因竞争把账号永久锁死。
- 账号锁与来源限流是**两道独立的闸**：前者按账号、后者按 `(入口, 来源)`。

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

- 算法：**固定时间窗计数**，按 `(入口桶, 来源)` 二元组独立计数；不同入口
  桶、不同来源互不影响，某来源被限不会拖下水其他来源或其他账号。
- 覆盖入口（阈值见 `app/config.py`，默认窗口均为 60 秒）：

  | 入口桶             | 覆盖接口                                   | 默认上限 |
  | ------------------ | ------------------------------------------ | -------- |
  | `auth:login`       | `POST /auth/login`                         | 5        |
  | `auth:refresh`      | `POST /auth/refresh`                      | 20       |
  | `auth:logout`       | `POST /auth/logout`                       | 20       |
  | `auth:revoke`       | `POST /auth/revoke`、`POST /auth/revoke-all` | 20    |
  | `documents:read`    | `GET /resources/documents[/{id}]`         | 30       |
  | `documents:write`   | `POST /resources/documents`               | 30       |
  | `documents:manage`  | `DELETE /resources/documents/{id}`        | 30       |

- **来源口径（防伪造）**：默认只认真实 TCP 连接对端 `request.client.host`，
  客户端在请求里自带的 `X-Forwarded-For`、`X-Real-IP` 等一律不参与判定，
  因此无法靠每请求换一个伪造头来绕过阈值。只有当直连对端属于
  `config.TRUSTED_PROXIES` 时才采纳 `X-Forwarded-For`，且取**离可信代理
  最近的一跳**（从右向左跳过可信代理地址），部署在反向代理后时把代理地址
  配进 `TRUSTED_PROXIES` 即可。
- 超限返回 `429 rate_limited`，`detail.retry_after` 与响应头 `Retry-After`
  都给出还需等待的秒数；账号锁则返回 `429 account_locked`，两者可区分。
- 计数在同一把锁内完成"读取 + 自增"，高并发下不会漏计或重复扣减。
- **容量有界**：限流窗口与账号锁定状态都设有键数上限（默认 10000），
  超过上限时节流地全量清扫过期窗口/过期账号状态（清扫间隔默认 30 秒），
  锁定中的账号不会被误清。长期运行、来源非常多时内存不会无限增长。

## 与原有行为的兼容性

- 原有接口路径、请求/响应结构、HTTP 状态码与错误码含义保持不变；
  原有 25 个用例全部继续通过。
- 新增的只是**能力与更细的区分**：新错误码 `session_compromised`、
  `account_locked`，新入口 `POST /auth/revoke-all`，令牌中新增
  `sid/gen` 声明（对校验方透明），以及把原先单一的 `api` 桶细化为
  刷新/登出/撤销与文档读/写/管理等独立桶（登录桶阈值与原来一致）。
- 默认 `TRUSTED_PROXIES` 为空，与"只认直连来源"的安全默认一致；
  测试环境通过夹具把 TestClient 的对端 `testclient` 临时加入可信集合，
  以便用 `X-Forwarded-For` 模拟不同来源。

## 测试覆盖

`uv run pytest`（已配置 `-v`）按业务链路分组输出每个用例的名称与结果：

- `tests/test_token_lifecycle.py`：登录签发、刷新轮换、旧令牌复用拒绝、
  登出/撤销即刻失效、过期/篡改/类型不符的区分；
- `tests/test_access_control.py`：401 与 403 的区分、三种角色 ×
  读/写/管理的结论矩阵、默认拒绝；
- `tests/test_rate_limit.py`：登录/接口阈值边界、`retry_after` 告知、
  来源与入口桶隔离、并发下计数准确（200 线程抢 50 额度恰好放行 50）；
- `tests/test_account_lockout.py`（新增）：失败达阈值锁定并告知剩余秒数、
  锁定期跨来源且密码正确也拒绝、账号隔离、到期自动恢复、倒计时递减、
  成功清零、失败窗口滑过重置、与来源限流双闸独立、120 并发失败恰好
  第 50 次起锁定且到期恢复、锁定不影响已签发令牌、海量随机账号名的
  状态回收；
- `tests/test_revocation.py`（新增）：全端作废后访问/刷新即刻失效、
  轮换后继令牌一并失效、不牵连其他账号、作废后重登可正常用、旧代数
  令牌不能借刷新复活、旧刷新令牌复用触发整条链 `session_compromised`、
  泄露处置不影响同账号其他登录链、过期/主动撤销/疑似泄露三者可区分；
- `tests/test_rate_limit_extended.py`（新增）：非可信对端忽略伪造 XFF、
  可信代理取最右侧非可信一跳、伪造首跳无法绕过；刷新/登出/撤销各入口
  独立桶及来源/账号隔离；文档读/写/管理独立桶；过期窗口主动回收、
  超容量清扫、清扫节流、大量来源不堆积；400 线程抢 100 额度精确放行、
  令牌代数并发递增 1..50 不丢账、并发轮换同一旧链只有一张新令牌。

共 65 个用例（原 25 个 + 新增 40 个），原有用例无回归。
