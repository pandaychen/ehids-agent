# eHIDS-Agent 四大核心功能深度分析

---

## 功能一：进程行为检测

### 1.1 源码文件

| 层 | 文件路径 | 职责 |
|---|---|---|
| 内核态 | `kern/proc_kern.c` | kretprobe Hook `copy_process`，采集进程创建事件 |
| 用户态 Probe | `user/probe_proc.go` | 加载 BPF 字节码、注册 Manager、绑定 Map 与解码器 |
| 用户态 Event | `user/event_proc.go` | `ForkProcEvent` 结构体定义、二进制解码、格式化输出 |

### 1.2 Hook 点选择

```
Hook: kretprobe/copy_process
```

- `copy_process()` 是 Linux 内核中 `fork/clone/vfork` 系统调用的核心实现函数（位于 `kernel/fork.c`），负责复制父进程的 `task_struct`，创建子进程
- 使用 **kretprobe**（返回探针），因为需要在函数返回时拿到新创建的子进程 `task_struct` 指针（通过 `PT_REGS_RC(regs)` 获取返回值）
- 相比 Hook `sys_clone/sys_fork`，直接 Hook `copy_process` 能统一拦截所有进程创建路径

### 1.3 实现原理：端到端事件流

```
fork()/clone() 系统调用
       │
       ▼
  copy_process() 内核函数返回
       │
       ▼
  kretprobe_copy_process() ── BPF 程序触发
       │
       ├─ PT_REGS_RC(regs) → 获取子进程 task_struct *
       ├─ BPF_CORE_READ 多级读取：child/parent/grandparent PID
       ├─ bpf_probe_read_user → 读取 mm->arg_start 用户态命令行
       ├─ bpf_ringbuf_reserve → 在 RingBuf 预留空间
       └─ bpf_ringbuf_submit → 提交事件
              │
              ▼
   用户态 ringbufEventReader (imodule.go:180-216)
       │
       ├─ ringbuf.NewReader(em) → 创建 Reader
       ├─ rd.Read() → 阻塞读取
       ├─ ForkProcEvent.Decode(payload) → binary.Read 逐字段解码
       └─ ForkProcEvent.String() → 格式化输出日志
```

### 1.4 关键代码走读

#### 1.4.1 内核态结构体定义 (`kern/proc_kern.c:16-36`)

```c
typedef struct _process_info_t {
    int type;                // 事件类型：EVENT_FORK=1
    pid_t child_pid;         // 子进程 PID（namespace 内）
    pid_t child_tgid;        // 子进程 TGID（线程组 ID）
    pid_t parent_pid;        // 父进程 PID
    pid_t parent_tgid;       // 父进程 TGID
    pid_t grandparent_pid;   // 祖父进程 PID
    pid_t grandparent_tgid;  // 祖父进程 TGID
    uid_t uid;               // 用户 ID
    gid_t gid;               // 组 ID
    int cwd_level;           // CWD 层级（实际未填充）
    u32 uts_inum;            // UTS namespace inode（容器检测）
    __u64 start_time;        // 进程启动时间
    char comm[16];           // 进程名
    char cmdline[128];       // 命令行参数
    char filepath[128];      // 可执行文件路径
} proc_info_t;
```

#### 1.4.2 RingBuf Map 定义 (`kern/proc_kern.c:38-42`)

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB，需页对齐
} ringbuf_proc SEC(".maps");
```

- 选择 RingBuf 而非 PerfEventArray：无需 per-CPU 缓冲区、支持可变长消息、更高效的内存利用
- `1 << 24` = 16 MB 的环形缓冲区

#### 1.4.3 BPF_CORE_READ 三级进程树读取 (`kern/proc_kern.c:76-96`)

```c
// 第 1 级：子进程（当前 task）
ringbuf_process->child_pid  = BPF_CORE_READ(task, pid);        // L76
ringbuf_process->child_tgid = BPF_CORE_READ(task, tgid);       // L77

// 第 2 级：父进程（task->real_parent）
ringbuf_process->parent_pid  = BPF_CORE_READ(task, real_parent, pid);   // L91
ringbuf_process->parent_tgid = BPF_CORE_READ(task, real_parent, tgid);  // L92

// 第 3 级：祖父进程（task->real_parent->real_parent）
ringbuf_process->grandparent_pid  = BPF_CORE_READ(task, real_parent, real_parent, pid);   // L95
ringbuf_process->grandparent_tgid = BPF_CORE_READ(task, real_parent, real_parent, tgid);  // L96
```

`BPF_CORE_READ` 是 CO:RE（Compile Once - Run Everywhere）的核心宏，利用 BTF 信息自动处理不同内核版本的结构体字段偏移。多级嵌套读取（如 `task->real_parent->real_parent->pid`）会被展开为多次安全的 `bpf_probe_read_kernel` 调用。

#### 1.4.4 用户态命令行读取 (`kern/proc_kern.c:80-90`)

```c
long unsigned int args_start = BPF_CORE_READ(task, mm, arg_start);  // L80
long unsigned int args_end   = BPF_CORE_READ(task, mm, arg_end);    // L81
int len = (args_end - args_start) & 0x7F;                          // L82，最大 127 字节
ret = bpf_probe_read_user(ringbuf_process->cmdline, len, (const void *)args_start);  // L83
ret = bpf_probe_read_user_str(ringbuf_process->filepath, 128, (const void *)args_start); // L90
```

- 通过 `task->mm->arg_start/arg_end` 获取用户空间的命令行参数地址范围
- `& 0x7F`：限制长度不超过 127 字节，同时满足 BPF verifier 对 `bpf_probe_read_user` 长度参数的要求（必须是已知边界的常量表达式）
- `bpf_probe_read_user`：读取原始 cmdline（参数之间是 `\0` 分隔）
- `bpf_probe_read_user_str`：读取第一个以 `\0` 结尾的字符串（即 argv[0]，可执行文件路径）

#### 1.4.5 容器感知 (`kern/proc_kern.c:100`)

```c
ringbuf_process->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns).inum;
```

- 读取 UTS namespace 的 inode number，可用于判断进程是否运行在容器中（与宿主机的 UTS inode 比较）

#### 1.4.6 用户态解码 (`user/event_proc.go:36-87`)

`ForkProcEvent.Decode()` 使用 `binary.Read` 逐字段按 LittleEndian 解码。**注意**：Go 侧结构体 (`event_proc.go:9-28`) 省略了内核侧的 `type` 字段（eventType），解码从 `ChildPid` 开始，这意味着实际事件的前 4 字节（type 字段）被跳过——这里存在一个隐含的对齐假设问题。

### 1.5 技术手法总结

| 技术 | 用途 |
|---|---|
| `BPF_CORE_READ` 多级链式读取 | 安全遍历 `task_struct` 进程树，CO:RE 跨内核兼容 |
| `bpf_probe_read_user` | 从用户空间读取命令行参数 |
| `bpf_probe_read_user_str` | 从用户空间读取以 `\0` 结尾的可执行文件路径 |
| `bpf_ringbuf_reserve/submit` | 零拷贝 RingBuf 事件投递 |
| `bpf_get_current_comm` | 获取当前进程 comm 名 |
| UTS namespace inum | 容器环境识别 |

### 1.6 局限性和改进空间

| 问题 | 分析 | 改进建议 |
|---|---|---|
| **cmdline 长度仅 128 字节** | `& 0x7F` 限制最大 127 字节，复杂命令行会被截断（如 Java 启动命令动辄数千字节） | 使用多段读取或更大缓冲区（512-4096），或分多次事件传输 |
| **cmdline 中的 `\0` 分隔符未替换** | 代码 L84-88 的替换逻辑被注释掉了，用户态拿到的 cmdline 是 `\0` 分隔的原始格式，`String()` 打印会截断 | 在用户态 Decode 中将 `\0` 替换为空格 |
| **cwd_level 字段未填充** | `proc_info_t.cwd_level` 在内核态始终为 0，`get_cwd()` 函数 (event_proc.go:102-117) 永远返回空字符串 | 在内核态通过 `task->fs->pwd` 遍历 dentry 填充 CWD |
| **仅检测 fork，缺少 exec/exit** | `EVENT_EXEC=2` 和 `EVENT_EXIT=3` 已定义但未实现 Hook | 增加 `kprobe/exec_binprm` 或 tracepoint `sched_process_exec` |
| **Decode 跳过 type 字段** | Go 侧 `ForkProcEvent.Decode` 实际上是从 payload 的 byte 0 开始读 `ChildPid`，但内核侧 `proc_info_t` 的第一个字段是 `type`(4 bytes)，存在字段错位的 Bug | 在 Decode 中先读取并丢弃 type 字段，或修正结构体对齐 |
| **无 namespace PID 支持** | L78 注释提到获取 nstgid 但未实现，容器内 PID 与宿主机 PID 不一致时难以关联 | 通过 `task_tgid_nr_ns()` 逻辑获取容器内 PID |
| **kretprobe 可能丢事件** | kretprobe 有 `maxactive` 限制（默认 512），高并发 fork 场景可能溢出 | 考虑使用 fentry/fexit (BPF Trampoline) 替代 |

---

## 功能二：TCP 连接追踪

### 2.1 源码文件

| 层 | 文件路径 | 职责 |
|---|---|---|
| 内核态 | `kern/tcp_set_state_kern.c` | kprobe Hook `tcp_set_state`，追踪 TCP 连接生命周期 |
| 用户态 Probe | `user/probe_ktcp.go` | 加载字节码、注册 Manager |
| 用户态 Event | `user/event_tcp.go` | `TCPEvent` 解码、IP 格式化输出 |

### 2.2 Hook 点选择

```
Hook: kprobe/tcp_set_state
```

- `tcp_set_state(struct sock *sk, int state)` 是内核中 TCP 状态迁移的统一入口函数
- 每当一个 TCP socket 的状态发生变化（SYN_SENT → ESTABLISHED → CLOSE 等），都会调用此函数
- **核心优势**：只需一个 Hook 点就能追踪完整的 TCP 连接生命周期

### 2.3 TCP 状态机追踪原理

```
═══════════════════ 出站连接 (OUTBOUND) ═══════════════════

  connect() 调用
       │
       ▼
  tcp_set_state(sk, TCP_SYN_SENT)      ← 创建 conn_t, flags=F_OUTBOUND
       │                                   记录 pid/comm/start_ns
       │                                   存入 conns Map (key=sk指针)
       ▼
  tcp_set_state(sk, TCP_ESTABLISHED)   ← 查到 pconn, flags |= F_CONNECTED
       │                                   更新 conns Map
       ▼
  tcp_set_state(sk, TCP_CLOSE)         ← 读取四元组+流量统计
       │                                   提交 perf event
       │                                   删除 conns Map 条目
       ▼
  用户态收到 TCPEvent

═══════════════════ 入站连接 (INBOUND) ═══════════════════

  accept() 收到 SYN
       │
       ▼
  tcp_set_state(sk, TCP_ESTABLISHED)   ← 首次看到此 sk, 无 pconn
       │                                   创建 conn_t, flags=F_CONNECTED (无 F_OUTBOUND)
       │                                   存入 conns Map
       ▼
  tcp_set_state(sk, TCP_CLOSE)         ← 同上，提交事件
```

### 2.4 关键代码走读

#### 2.4.1 核心数据结构 (`kern/tcp_set_state_kern.c:8-36`)

```c
// 事件输出结构体（提交给用户态）
struct event_t {
    u64 start_ns;   // 连接开始时间（纳秒）
    u64 end_ns;     // 连接结束时间
    u32 pid;        // 进程 PID
    u32 laddr;      // 本地 IPv4 地址
    u16 lport;      // 本地端口
    u32 raddr;      // 远端 IPv4 地址
    u16 rport;      // 远端端口
    u8  flags;      // F_OUTBOUND(0x1) | F_CONNECTED(0x10)
    u64 rx_b;       // 接收字节数
    u64 tx_b;       // 发送字节数
    char task[16];  // 进程名
    u16 family;     // 地址族（AF_INET）
    u32 uid;        // 用户 ID
} __attribute__((packed));

// 连接中间状态（存在 Hash Map 中）
struct conn_t {
    u32 pid;
    u64 start_ns;
    u8  flags;
    char task[16];
};
```

#### 2.4.2 sock 指针作为 Hash Key (`kern/tcp_set_state_kern.c:38-44`)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock *);       // 用 sock 指针地址作 key
    __type(value, struct conn_t);
    __uint(max_entries, 10240);
} conns SEC(".maps");
```

**设计精妙之处**：使用 `struct sock *`（内核指针值）作为 Hash key，因为：
1. 在一个 TCP 连接的整个生命周期中，同一个 `sock` 对象会经历多次 `tcp_set_state` 调用
2. sock 指针在连接生命周期内唯一且不变
3. 无需构造复杂的四元组 key，性能更优

#### 2.4.3 状态机核心逻辑 (`kern/tcp_set_state_kern.c:46-153`)

**SYN_SENT 分支（L61-74）**：出站连接的第一个状态
```c
if (state == TCP_SYN_SENT) {
    if (pconn) bpf_map_delete_elem(&conns, &sk);  // 清理残留
    conn.flags = F_OUTBOUND;
    conn.start_ns = bpf_ktime_get_ns();
    goto attach_pid_and_update_conn;  // 记录 PID + comm，写入 Map
}
```

**ESTABLISHED 分支（L78-99）**：分两种情况
```c
if (!pconn && state == TCP_ESTABLISHED) {
    // 入站连接：首次看到此 sk
    conn.flags |= F_CONNECTED;
    conn.start_ns = bpf_ktime_get_ns();
    goto update_conn;  // 仅更新 Map（入站连接此时无法获取准确的 PID）
}
if (pconn && state == TCP_ESTABLISHED) {
    // 出站连接：从 SYN_SENT 转到 ESTABLISHED
    conn.flags |= F_CONNECTED;
    goto update_conn;
}
```

**CLOSE 分支（L105-144）**：连接关闭时收集所有信息并上报
```c
if (state == TCP_CLOSE) {
    // 过滤：仅 IPv4
    if (data.family != AF_INET) goto delete_conn;
    // 过滤：排除 127.x.x.x 回环地址
    if ((data.laddr & 0xff) == 0x7f && (data.raddr & 0xff) == 0x7f) goto delete_conn;
    // 读取流量统计
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    bpf_probe_read(&data.rx_b, sizeof(data.rx_b), &tp->bytes_received);
    bpf_probe_read(&data.tx_b, sizeof(data.tx_b), &tp->bytes_acked);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
}
```

#### 2.4.4 tcp_sock 流量统计读取 (`kern/tcp_set_state_kern.c:136-138`)

```c
struct tcp_sock *tp = (struct tcp_sock *)sk;
bpf_probe_read(&data.rx_b, sizeof(data.rx_b), &tp->bytes_received);  // L137
bpf_probe_read(&data.tx_b, sizeof(data.tx_b), &tp->bytes_acked);     // L138
```

- `struct tcp_sock` 是 `struct sock` 的扩展（"继承"），内核中 `tcp_sock` 包含 `sock` 作为第一个成员
- `bytes_received`：TCP 连接累计接收的字节数
- `bytes_acked`：TCP 连接累计确认发送的字节数
- 这些字段在 TCP_CLOSE 时读取，反映了整个连接的生命周期流量

#### 2.4.5 回环地址过滤逻辑 (`kern/tcp_set_state_kern.c:120-121`)

```c
if ((data.laddr & 0xff) == 0x7f && (data.raddr & 0xff) == 0x7f)
    goto delete_conn;
```

- 检查 IPv4 地址的第一个字节（小端序下的最低字节）是否为 `0x7f`（即 `127.x.x.x`）
- 仅当**两端**都是回环地址时才过滤，这是为了排除本机进程间通信产生的大量噪音事件

### 2.5 设计决策分析

**仅 IPv4 的设计决策**：
- `kern/tcp_set_state_kern.c:113`: `if (data.family != AF_INET) goto delete_conn;`
- 显式过滤掉 IPv6 连接，简化了地址处理逻辑（IPv4 用 u32，IPv6 需要 128 位）
- `event_t` 结构体中 `laddr/raddr` 均为 `u32`，仅支持 IPv4

**延迟到 CLOSE 才上报的设计**：
- 优点：一次事件包含完整的连接信息（持续时间、流量统计、方向）
- 缺点：长连接（如数据库连接池）可能很久不触发 CLOSE

### 2.6 局限性和改进空间

| 问题 | 分析 | 改进建议 |
|---|---|---|
| **不支持 IPv6** | L113 显式过滤 `AF_INET6`，现代环境中 IPv6 越来越普遍 | 扩展 `event_t` 使用 `__int128` 或 `[16]byte` 存储 IPv6 地址 |
| **仅 CLOSE 时上报** | 长连接（WebSocket、数据库连接池）可能数小时/数天不关闭 | 增加定时器或在 ESTABLISHED 时也发一次事件 |
| **conns Map 可能泄漏** | SYN_SENT 后如果连接在异常路径关闭（如 RST），可能不经过 TCP_CLOSE | 用 BPF timer 或用户态定期扫描 conns Map 清理超时条目 |
| **入站连接 PID 不准确** | INBOUND 连接在 ESTABLISHED 时 `goto update_conn`（不经过 `attach_pid_and_update_conn`），此时 pid=0 | 在 TCP_LAST_ACK 或 CLOSE 时补充 PID 信息 |
| **使用 PerfEventArray 而非 RingBuf** | PerfEventArray 是 per-CPU 的，内存消耗更大 | 迁移到 RingBuf（如 proc 模块所做） |
| **rport 字节序处理** | L134 `data.rport = (u16)(data.rport)` 这行赋值给自身无意义，`skc_dport` 是网络字节序，未调用 `ntohs()` | 应使用 `bpf_ntohs()` 转换端口字节序 |
| **uid 类型不一致** | 内核态 `event_t.uid` 是 `u32`，Go 侧 `TCPEvent.UID` 是 `uint16`，会发生截断 | 统一为 `uint32` |
| **event_t 使用 packed** | `__attribute__((packed))` 避免了编译器插入 padding，但与 Go 侧逐字段读取的方式需要严格对齐 | 需仔细验证两侧的字段偏移一致性 |

---

## 功能三：DNS 查询监控（uprobe 模式）

### 3.1 源码文件

| 层 | 文件路径 | 职责 |
|---|---|---|
| 内核态 | `kern/dns_lookup_kern.c` | uprobe/uretprobe Hook glibc 的 `getaddrinfo()` |
| 用户态 Probe | `user/probe_udns.go` | 加载字节码、绑定到 `/lib/x86_64-linux-gnu/libc.so.6` |
| 用户态 Event | `user/event_udns.go` | `DNSEVENT` 解码，输出 PID/UID/AF/IP/HOST |

### 3.2 Hook 点选择

```
Hook: uprobe/getaddrinfo (entry) + uretprobe/getaddrinfo (return)
目标: /lib/x86_64-linux-gnu/libc.so.6
```

- `getaddrinfo()` 是 POSIX 标准的 DNS 解析函数，几乎所有 C 语言程序（包括 curl、wget、大多数服务端程序）都通过此函数解析域名
- 使用 **uprobe**（用户空间探针）Hook 共享库函数：在函数 entry 时保存入参（域名+结果指针），在 return 时读取解析结果

### 3.3 实现原理：Entry-Return 配对

```
应用程序调用 getaddrinfo(node, service, hints, &res)
       │
       ▼
  uprobe/getaddrinfo (entry)           ← getaddrinfo_entry()
       │
       ├─ PT_REGS_PARM1(ctx) → node 域名字符串
       ├─ (ctx)->cx → res 指针的指针 (第 4 个参数)
       ├─ bpf_map_update(&start, &pid, &val)    → 保存 {pid, host}
       └─ bpf_map_update(&currres, &pid, &res)  → 保存结果指针
              │
              ▼
  glibc 内部执行 DNS 查询...
              │
              ▼
  uretprobe/getaddrinfo (return)       ← getaddrinfo_return()
       │
       ├─ bpf_map_lookup(&start, &pid) → 取回 host
       ├─ bpf_map_lookup(&currres, &pid) → 取回 res 指针
       ├─ 三级指针解引用：res → *res → **res → addrinfo
       ├─ for 循环遍历 addrinfo 链表（最多 9 次）
       │   ├─ 读取 ai_family (AF_INET/AF_INET6)
       │   ├─ 读取 sockaddr_in->sin_addr 或 sockaddr_in6->sin6_addr
       │   └─ bpf_perf_event_output 提交事件
       └─ 清理 start + currres Map
              │
              ▼
   用户态 perfEventReader → DNSEVENT.Decode → 输出
```

### 3.4 关键代码走读

#### 3.4.1 Map 定义（`kern/dns_lookup_kern.c:33-51`）

```c
// 存储 entry 时的上下文（域名+PID）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);              // PID
    __type(value, struct val_t);   // {pid, host[80]}
    __uint(max_entries, 1024);
} start SEC(".maps");

// 存储 getaddrinfo 的第 4 个参数（struct addrinfo **res）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);              // PID
    __type(value, struct addrinfo **);  // 结果指针的指针
    __uint(max_entries, 1024);
} currres SEC(".maps");
```

#### 3.4.2 Entry 函数参数捕获（`kern/dns_lookup_kern.c:53-67`）

```c
SEC("uprobe/getaddrinfo")
int getaddrinfo_entry(struct pt_regs *ctx) {
    if (!(ctx)->di) return 0;  // L55: 检查第 1 个参数（node）非空

    struct val_t val = {};
    bpf_probe_read(&val.host, sizeof(val.host), (void *)PT_REGS_PARM1(ctx));  // L59: 读取域名
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    val.pid = pid;

    struct addrinfo **res = (struct addrinfo **)(ctx)->cx;  // L63: x86_64 第 4 个参数在 rcx 寄存器
    bpf_map_update_elem(&start, &pid, &val, BPF_ANY);
    bpf_map_update_elem(&currres, &pid, &res, BPF_ANY);
    return 0;
}
```

**关键技术点**：
- `PT_REGS_PARM1(ctx)` = rdi 寄存器 = `getaddrinfo()` 的第一个参数 `node`
- `(ctx)->cx` = rcx 寄存器 = 第四个参数 `res`（x86_64 System V ABI：rdi, rsi, rdx, rcx）
- 这里直接用了 `(ctx)->cx` 而非 `PT_REGS_PARM4(ctx)`，功能等价但不够规范

#### 3.4.3 Return 函数三级指针解引用（`kern/dns_lookup_kern.c:69-123`）

```c
// 三级指针解引用：res(存储的是 &res) → *res → **res → struct addrinfo
struct addrinfo ***res;
res = bpf_map_lookup_elem(&currres, &pid);     // L82: res 是 addrinfo*** 类型
struct addrinfo **resx;
bpf_probe_read(&resx, sizeof(resx), (struct addrinfo **)res);   // L89: *res → addrinfo**
struct addrinfo *resxx;
bpf_probe_read(&resxx, sizeof(resxx), (struct addrinfo **)resx); // L91: **res → addrinfo*
```

这是因为 `getaddrinfo` 的签名是 `int getaddrinfo(..., struct addrinfo **res)`，而 Map 中存储的是 `res` 参数的值（一个指向指针的指针），所以需要三级解引用。

#### 3.4.4 有界循环与 ai_next 遍历问题（`kern/dns_lookup_kern.c:93-119`）

```c
for (int i = 0; i < 9; i++) {  // L93: 有界循环，最多 9 次迭代
    struct data_t data = {};
    bpf_probe_read(&data.host, sizeof(data.host), (void *)valp->host);
    bpf_probe_read(&data.af, sizeof(data.af), &resxx->ai_family);

    if (data.af == AF_INET) {
        struct sockaddr_in *daddr;
        bpf_probe_read(&daddr, sizeof(daddr), &resxx->ai_addr);
        bpf_probe_read(&data.ip4addr, sizeof(data.ip4addr), &daddr->sin_addr.s_addr);
    } else if (data.af == AF_INET6) { ... }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    // TODO: 被注释掉的链表遍历
    // if (resxx->ai_next == NULL) { break; }
    // resxx = resxx->ai_next;
    break;  // L118: 直接 break，实际只处理第一个结果！
}
```

**关键问题**：
1. `for` 循环设计为最多遍历 9 个 `addrinfo` 节点（满足 BPF verifier 对循环的有界要求）
2. 但 L113-118 的 `ai_next` 遍历逻辑被注释掉了，紧接着就是 `break`
3. **实际效果**：循环只执行一次，仅返回第一个 DNS 解析结果
4. 被注释的原因可能是：在 uprobe 上下文中对用户空间链表指针进行 `bpf_probe_read` 遍历，BPF verifier 可能因为指针安全性问题拒绝加载

### 3.5 局限性和改进空间

| 问题 | 分析 | 改进建议 |
|---|---|---|
| **ai_next 遍历被注释** | 只能获取第一个 DNS 解析结果，丢失了 CDN 场景下的多 IP 结果 | 修复 verifier 问题：先 `bpf_probe_read` 读取 `ai_next` 到局部变量，判断是否为 NULL |
| **仅 Hook glibc** | 静态编译的 Go 程序、musl libc、自定义 DNS resolver 均无法捕获 | 结合 UDP DNS 报文捕获（功能四）实现互补 |
| **硬编码 libc 路径** | `probe_udns.go:83`: `/lib/x86_64-linux-gnu/libc.so.6` 仅适用于 Debian/Ubuntu x86_64 | 动态探测 libc 路径（如解析 `/proc/self/maps` 或 `ldconfig`） |
| **PID 作为 Map key 不够精确** | 多线程程序中同一 PID 可能并发调用 `getaddrinfo`，后者覆盖前者的 Map 条目 | 使用 `pid_tgid`（完整的 PID+TID 组合）作为 key |
| **host 仅 80 字节** | 超长域名会被截断 | 扩展到 256 字节（DNS 域名最长 253 字符） |
| **缺少延迟统计** | 没有记录 DNS 查询耗时 | 在 entry 记录 `bpf_ktime_get_ns()`，在 return 计算差值 |
| **缺少返回码检查** | `getaddrinfo` 返回非 0 表示失败，当前代码不检查 `PT_REGS_RC(ctx)` | 先检查返回值，失败时上报错误事件 |

---

## 功能四：UDP DNS 报文捕获

### 4.1 源码文件

| 层 | 文件路径 | 职责 |
|---|---|---|
| 内核态 | `kern/udp_lookup_kern.c` | kprobe/kretprobe Hook `udp_recvmsg`，捕获端口 53 的 UDP 报文 |
| 用户态 Probe | `user/probe_kudp.go` | 加载字节码、注册 Manager |
| 用户态 Event | `user/event_kudp.go` | `UDPEvent` 解码，使用 `rawdns` 库解析 DNS 报文 |

### 4.2 Hook 点选择

```
Hook: kprobe/udp_recvmsg (entry) + kretprobe/udp_recvmsg (return)
```

- `udp_recvmsg()` 是内核中 UDP 数据接收的核心函数（`net/ipv4/udp.c`）
- 拦截 DNS 响应报文：DNS 客户端发出查询后，DNS 服务器返回的 UDP 响应会经过 `udp_recvmsg` 传递给应用层

### 4.3 实现原理：Entry-Return 配对

```
DNS 响应 UDP 包到达
       │
       ▼
  recvmsg() 系统调用
       │
       ▼
  kprobe/udp_recvmsg (entry)           ← trace_udp_recvmsg()
       │
       ├─ (ctx)->di → struct sock *sk
       ├─ bpf_probe_read(&dport, ..., &sk->skc_dport) → 读取目的端口
       ├─ dport == 13568 (ntohs(53))？ → 仅捕获 DNS 流量
       └─ 是：保存 msg 指针到 tbl_udp_msg_hdr Map
              │
              ▼
  内核完成 udp_recvmsg 数据拷贝
              │
              ▼
  kretprobe/udp_recvmsg (return)       ← trace_ret_udp_recvmsg()
       │
       ├─ 从 tbl_udp_msg_hdr 查找 msg 指针
       ├─ 读取 msghdr->msg_iter (iov_iter)
       ├─ 检查 iter.type == ITER_IOVEC
       ├─ PT_REGS_RC(ctx) → 获取已接收字节数 (copied)
       ├─ 读取 iov_iter->iov[0] → iov_base (用户态数据缓冲区地址)
       ├─ bpf_map_lookup(&dns_data, &zero) → 从 PerCPU Array 获取缓冲区
       ├─ bpf_probe_read(data->pkt, buflen, iov.iov_base) → 读取 DNS 报文
       └─ bpf_perf_event_output → 提交事件
              │
              ▼
   用户态 perfEventReader
       │
       ├─ UDPEvent.Decode(payload)
       │   ├─ payload[0:4]  → PID
       │   ├─ payload[4:20] → comm
       │   └─ payload[20:]  → DNS 报文原始字节
       │
       └─ rawdns.UnmarshalMessage(packet) → 解析 DNS 协议
           ├─ Questions: QNAME, QCLASS, QTYPE
           └─ Answers: A记录(IP), CNAME记录 等
```

### 4.4 关键代码走读

#### 4.4.1 端口 53 过滤（`kern/udp_lookup_kern.c:39-58`）

```c
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)(ctx)->di;   // L43: 第一个参数
    u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);  // L49

    if (dport == 13568) {  // L52: 13568 = ntohs(53) = 0x3500 小端表示
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);       // L54
        bpf_map_update_elem(&tbl_udp_msg_hdr, &pid_tgid, &msg, BPF_ANY);
    }
    return 0;
}
```

- `skc_dport` 是**网络字节序（大端）**存储的目的端口
- `53` 的网络字节序 = `0x0035`，在小端 CPU 上读出为 `0x3500` = `13568`
- 这个过滤确保只捕获与 DNS 服务器（端口 53）通信的 UDP 报文

#### 4.4.2 PerCPU Array 规避栈限制（`kern/udp_lookup_kern.c:30-36`）

```c
struct dns_data_t {
    u32 pid;
    char comm[16];
    u8 pkt[MAX_PKT];       // 512 字节 DNS 报文缓冲区
};  // 总计 532 字节

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dns_data_t);
    __uint(max_entries, 1);
} dns_data SEC(".maps");
```

**为什么用 PerCPU Array 而非栈变量？**
- BPF 程序栈大小限制为 **512 字节**
- `dns_data_t` 结构体约 532 字节（4 + 16 + 512），超出栈限制
- 使用 `BPF_MAP_TYPE_PERCPU_ARRAY`（max_entries=1）作为"临时变量"：
  - PerCPU：每个 CPU 有独立副本，无需加锁
  - key 始终为 0，相当于一个全局的 per-CPU 缓冲区
  - 通过 `bpf_map_lookup_elem(&dns_data, &zero)` 获取指针，直接在 Map 空间中操作

#### 4.4.3 iov_iter 读取 DNS 报文（`kern/udp_lookup_kern.c:60-121`）

```c
SEC("kretprobe/udp_recvmsg")
int trace_ret_udp_recvmsg(struct pt_regs *ctx) {
    // 1. 查找 entry 时保存的 msg 指针
    struct msghdr **msgpp = bpf_map_lookup_elem(&tbl_udp_msg_hdr, &pid_tgid);

    // 2. 读取 msghdr 的 msg_iter（scatter-gather I/O 迭代器）
    struct iov_iter iter = {};
    bpf_probe_read(&iter, sizeof(iter), &msghdr->msg_iter);  // L72
    if (iter.type != ITER_IOVEC) { ... }  // L73: 仅支持 IOVEC 类型

    // 3. 获取实际接收的字节数
    int copied = (int)PT_REGS_RC(ctx);  // L78
    if (copied < 0 || copied > MAX_PKT) { ... }  // 过滤异常

    // 4. 长度掩码满足 verifier
    u32 buflen = (u32)copied;
    buflen = buflen & 0x1ff;  // L91: 限制最大 511 字节

    // 5. 读取 iov[0] 获取用户态数据缓冲区地址
    struct iovec iov;
    bpf_probe_read(&iov, sizeof(iov), iter.iov);  // L94

    // 6. 从 PerCPU Array 获取输出缓冲区
    u32 zero = 0;
    struct dns_data_t *data = bpf_map_lookup_elem(&dns_data, &zero);  // L101

    // 7. 读取 DNS 报文
    bpf_probe_read(data->pkt, buflen, iov.iov_base);  // L112

    // 8. 提交事件（动态长度）
    bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU,
                          data, 4 + 16 + buflen);  // L116
}
```

**Verifier 满足技巧**：
- L79: `copied < 0 || copied > MAX_PKT` 确保范围在 `[0, 512]`
- L91: `buflen & 0x1ff` 再次限制在 `[0, 511]`（位掩码），双重保障让 verifier 确认 `bpf_probe_read` 的长度参数有界
- L116: `4 + 16 + buflen` 动态长度输出，避免总是发送 532 字节

#### 4.4.4 rawdns 库解析（`user/event_kudp.go:41-74`）

```go
var m dns.Message
err = dns.UnmarshalMessage(e.packet, &m)  // L42: 解析原始 DNS 报文

// 解析查询部分
for i := 0; i < len(m.Questions); i++ {
    q := m.Questions[i]
    e.ask[i] = question{q.QNAME, ...}  // 域名、查询类型、查询类
}

// 解析应答部分
for i := 0; i < len(m.Answers); i++ {
    r := m.Answers[i]
    if r.TYPE == dns.QTypeA {
        // A 记录：IP 地址
        fmt.Sprintf("[A] :%s", net.IP(r.RDATA))
    } else if r.TYPE == dns.QTypeCNAME {
        // CNAME 记录：别名
        fmt.Sprintf("[CNAME] :%s", string(r.RDATA))
    }
}
```

使用第三方库 `github.com/cirocosta/rawdns/lib` 将原始字节解析为结构化的 DNS 消息，支持 Questions、Answers 的解码。

### 4.5 Register 被注释（未激活）的原因分析

```go
// user/probe_kudp.go:138-143
func init() {
    mod := &MUDPProbe{}
    mod.name = "EBPFProbeKUDP"
    mod.mType = PROBE_TYPE_KPROBE
    //Register(mod)        // ← 被注释！模块不会注册到全局 modules Map
}
```

**可能原因分析**：

1. **内核版本兼容性问题**：
   - `iov_iter` 结构体在不同内核版本中变化较大（5.14+ 移除了 `type` 字段，改用 `iter_type`）
   - `kern/udp_lookup_kern.c:73` 的 `iter.type != ITER_IOVEC` 在新内核上可能无法编译
   - `udp_recvmsg` 的函数签名在不同内核版本中参数数量不同（5.19 后去掉了 `addr_len` 参数）

2. **与功能三（uprobe DNS）功能重叠**：
   - 两者都是监控 DNS 查询，uprobe 方式（功能三）更稳定可靠
   - UDP 方式是更底层的补充方案（可以捕获绕过 glibc 的 DNS 查询）

3. **稳定性/测试不足**：
   - BPF verifier 相关的 workaround（如 `buflen & 0x1ff`、PerCPU Array）暗示调试过程艰难
   - 代码中多处 TODO 注释（如 `comm` 字段标注"for debug, remove pls"）

### 4.6 局限性和改进空间

| 问题 | 分析 | 改进建议 |
|---|---|---|
| **模块未激活** | `Register(mod)` 被注释，该功能不会运行 | 修复内核兼容性问题后取消注释 |
| **仅捕获 DNS 响应** | Hook `udp_recvmsg` 只能看到收到的数据（DNS 响应），看不到发出的查询 | 增加 `kprobe/udp_sendmsg` Hook 捕获 DNS 查询 |
| **MAX_PKT=512 字节限制** | RFC 1035 限制 UDP DNS 为 512 字节，但 EDNS0 扩展允许更大报文（最大 4096） | 扩展 `MAX_PKT` 或使用动态大小 |
| **iov_iter 内核兼容性** | `iter.type` 字段在 5.14+ 内核中被重构，直接读取会失败 | 使用 CO:RE 的 `BPF_CORE_READ` + BTF 判断字段存在性 |
| **未处理 TCP DNS** | DNS over TCP（大响应、zone transfer）不会被捕获 | 增加 TCP 53 端口的 Hook |
| **仅 IPv4** | `skc_dport` 的检查对 IPv4/IPv6 均有效，但缺少源/目的 IP 记录 | 在事件中增加 DNS 服务器地址 |
| **rawdns 库限制** | 使用的是较简单的第三方库，可能不支持所有 DNS 记录类型（如 SRV、TXT、AAAA） | 切换到更完善的 DNS 解析库如 `miekg/dns` |
| **pid 字段未正确解码** | `event_kudp.go:33` 读取了 `pid` 但赋值给了局部变量，`e.pid` 实际为 0 | 修复：`e.pid = pid` |

---

## 附录：四个功能的整体架构对比

| 维度 | 进程检测 | TCP 追踪 | DNS uprobe | UDP DNS |
|---|---|---|---|---|
| **Hook 类型** | kretprobe | kprobe | uprobe + uretprobe | kprobe + kretprobe |
| **Hook 目标** | `copy_process` | `tcp_set_state` | `getaddrinfo@libc` | `udp_recvmsg` |
| **事件通道** | RingBuf (16MB) | PerfEventArray | PerfEventArray | PerfEventArray |
| **中间状态 Map** | 无 | Hash (sock* → conn_t) | 2x Hash (pid → val/res) | Hash (pid_tgid → msghdr*) |
| **CO:RE 使用** | 大量 BPF_CORE_READ | bpf_probe_read | bpf_probe_read | bpf_probe_read |
| **是否激活** | ✅ 已注册 | ✅ 已注册 | ✅ 已注册 | ❌ Register 被注释 |
| **用户态解码** | binary.Read 逐字段 | binary.Read 逐字段 | binary.Read 逐字段 | rawdns 协议解析 |
| **模块名** | EBPFProbeProc | EBPFProbeKTCP | EBPFProbeUDNS | EBPFProbeKUDP |
