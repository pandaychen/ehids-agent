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
# eHIDS-Agent 核心功能深度分析（第二部分）

> 功能五 ~ 功能七：Socket 连接监控、Java RASP 命令执行检测、BPF 系统调用追踪

---

## 功能五：Socket 连接监控

### 5.1 整体架构

| 维度 | 说明 |
|------|------|
| **内核侧** | `kern/sec_socket_connect_kern.c` |
| **用户侧 Probe** | `user/probe_ktcp_sec.go` |
| **用户侧 Event** | `user/event_ktcp_sec.go` |
| **Hook 点** | `kprobe/security_socket_connect` |
| **模块名** | `EBPFProbeKTCPSec` |
| **模块类型** | `PROBE_TYPE_KPROBE` |

本模块挂钩 Linux Security Module（LSM）层的 `security_socket_connect` 函数，在 socket `connect()` 系统调用进入安全检查时触发。与直接 hook `tcp_v4_connect` / `tcp_v6_connect` 不同，此 hook 点**覆盖所有协议族**（TCP/UDP/SCTP 等），而非仅 TCP。

### 5.2 内核侧：三路分发逻辑

#### 5.2.1 三种事件结构体

```
kern/sec_socket_connect_kern.c
```

**IPv4 事件** （第 13-23 行）：
```c
struct ipv4_event_t {
    u64 ts_us;          // 时间戳（微秒）
    u32 pid;            // 进程 PID
    u32 uid;            // 用户 UID
    u32 af;             // 地址族 (AF_INET=2)
    u32 laddr;          // 本地 IP 地址
    u16 lport;          // 本地端口
    u32 daddr;          // 目的 IP 地址
    u16 dport;          // 目的端口
    char task[16];      // 进程名
} __attribute__((packed));
```

**IPv6 事件** （第 33-41 行）：
```c
struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 af;
    char task[16];
    unsigned __int128 daddr;   // 128 位 IPv6 地址
    u16 dport;
};
```

**Other 事件** （第 49-55 行）：
```c
struct other_socket_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 af;            // 非 IPv4/IPv6/UNIX/UNSPEC 的地址族编号
    char task[16];
};
```

#### 5.2.2 三个独立 PerfEventArray Map

```c
// kern/sec_socket_connect_kern.c 第 25-60 行
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); } ipv4_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); } ipv6_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); } other_socket_events SEC(".maps");
```

使用 3 个独立 Map 而非一个共享 Map 的原因：**三种事件结构体大小不同**（IPv4 含源/目的地址和端口，IPv6 含 128 位地址，Other 仅含基本信息），使用独立 Map 可以避免在内核侧构造联合体或最大化 padding，减少 perf buffer 带宽浪费。

#### 5.2.3 核心 Hook 函数走读

```c
// kern/sec_socket_connect_kern.c 第 62-131 行
SEC("kprobe/security_socket_connect")
int kprobe__security_socket_connect(struct pt_regs *ctx) {
```

**参数获取**（第 72-79 行）：
```c
struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);    // 第一个参数: socket->sk
struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx); // 第二个参数: 目标地址
```

> **注意**：这里有一个问题。`security_socket_connect` 的函数签名是 `int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)`，第一个参数是 `struct socket *` 而非 `struct sock *`。代码将 `PARM1` 强制转换为 `struct sock *` 是**不正确的**，实际应为 `socket->sk`。但由于后面读取 `skp->__sk_common` 字段时使用了 `bpf_probe_read`，如果偏移量恰好对上，可能碰巧能工作。

**地址族读取与三路分发**（第 81-128 行）：

```c
u32 address_family = 0;
bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family);

if (address_family == AF_INET) {           // IPv4 路径
    // ... 读取 laddr/daddr/lport/dport，过滤 dport==0 后输出到 ipv4_events
}
else if (address_family == AF_INET6) {     // IPv6 路径
    // ... 读取 daddr(128bit)/dport，过滤 dport==0 后输出到 ipv6_events
}
else if (address_family != AF_UNIX && address_family != AF_UNSPEC) {  // Other 路径
    // ... 仅采集基本信息，输出到 other_socket_events
}
```

**排除逻辑**：
- `AF_UNIX (1)`：本地 Unix Domain Socket，无网络安全意义
- `AF_UNSPEC (0)`：未指定地址族，通常是 `disconnect` 操作
- `dport == 0`：过滤无效的连接事件（第 100、118 行）

#### 5.2.4 IPv4 路径详细分析（第 84-103 行）

```c
struct ipv4_event_t data4 = {.pid = pid, .uid = uid, .af = address_family};
data4.ts_us = bpf_ktime_get_ns() / 1000;

// 从 sock 结构体读取地址和端口
bpf_probe_read(&data4.laddr, sizeof(data4.laddr), &skp->__sk_common.skc_rcv_saddr);  // 本地IP
bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &skp->__sk_common.skc_daddr);      // 目的IP
bpf_probe_read(&data4.lport, sizeof(data4.lport), &skp->__sk_common.skc_num);        // 本地端口(host order)
bpf_probe_read(&data4.dport, sizeof(data4.dport), &skp->__sk_common.skc_dport);      // 目的端口(network order)
```

> **字节序问题**：`skc_dport` 是网络字节序（big-endian），`skc_num` 是主机字节序。代码中没有做 `ntohs` 转换，用户态解码时也未处理，会导致**目的端口在小端机器上显示错误**。

#### 5.2.5 IPv6 路径分析（第 104-122 行）

```c
// 从 sockaddr_in6 直接读取目的地址（128 位）
bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32);

// 端口也从 sockaddr_in6 读取（而非 sock 结构体）
u16 dport6 = 0;
bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port);
```

与 IPv4 路径不同，IPv6 路径直接从 `sockaddr_in6`（用户传入的参数）而非 `sock` 结构体读取地址。这种不一致性说明代码可能由不同阶段编写。IPv6 路径**缺少本地地址/端口采集**。

### 5.3 用户侧 Probe 分析

```
user/probe_ktcp_sec.go
```

#### 5.3.1 模块注册（第 160-165 行）

```go
func init() {
    mod := &MTCPSecProbe{}
    mod.name = "EBPFProbeKTCPSec"
    mod.mType = PROBE_TYPE_KPROBE
    Register(mod)
}
```

#### 5.3.2 Manager 配置（第 76-115 行）

```go
func (this *MTCPSecProbe) setupManagers() {
    this.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "kprobe/security_socket_connect",
                EbpfFuncName:     "kprobe__security_socket_connect",
                AttachToFuncName: "security_socket_connect",
            },
        },
        Maps: []*manager.Map{
            {Name: "ipv4_events"},
            {Name: "ipv6_events"},
            {Name: "other_socket_events"},
        },
    }
}
```

仅声明一个 kprobe，但注册 3 个 Map，对应内核侧的 3 个 PerfEventArray。

#### 5.3.3 三路解码函数注册（第 122-154 行）

```go
func (this *MTCPSecProbe) initDecodeFun() error {
    // Map "ipv4_events"  -> EventIPV4{}
    // Map "ipv6_events"  -> EventIPV6{}
    // Map "other_socket_events" -> EventOther{}
}
```

每个 Map 绑定独立的事件解码结构体，通过 `eventFuncMaps` map 实现 **Map → Decoder** 的映射。基类 `Module.readEvents()`（`user/imodule.go` 第 117-136 行）遍历 `Events()` 返回的 3 个 Map，为每个 Map 启动独立的 `perfEventReader` goroutine。

### 5.4 用户侧 Event 解码分析

```
user/event_ktcp_sec.go
```

三种事件结构体均实现 `IEventStruct` 接口（`Decode`、`String`、`Clone`）：

| Go 结构体 | 对应内核结构体 | 特有字段 |
|-----------|--------------|---------|
| `EventIPV4` (第 12-22 行) | `ipv4_event_t` | LAddr, LPort, RAddr, RPort |
| `EventIPV6` (第 66-74 行) | `ipv6_event_t` | RAddr([16]byte), RPort |
| `EventOther` (第 112-118 行) | `other_socket_event_t` | 仅基本字段 |

**结构体对齐问题**：

内核侧 `ipv6_event_t` 中 `af` 字段是 `u32`（4 字节），但用户侧 `EventIPV6.AF` 是 `uint16`（2 字节）。同样 `EventOther.AF` 也是 `uint16`。这会导致 **Decode 时字段偏移错位**，后续字段解析全部出错。这是一个明显的 bug。

### 5.5 与 TCP 模块的互补关系

| 对比维度 | TCP 模块 (kprobe/tcp_v4_connect 等) | Socket Sec 模块 (security_socket_connect) |
|---------|-------------------------------------|------------------------------------------|
| Hook 层级 | 传输层（TCP 协议栈内部） | LSM 安全检查层 |
| 协议覆盖 | 仅 TCP | 所有协议族（TCP/UDP/SCTP/RAW 等） |
| 触发时机 | `connect()` 发起后 TCP 状态机处理时 | `connect()` 进入安全检查时（更早） |
| 信息丰富度 | TCP 状态、连接时延、RTT | 地址族、基本四元组 |
| 适用场景 | TCP 连接质量监控 | 全协议连接安全审计 |

两者形成互补：TCP 模块专注 TCP 连接的深层指标，Socket Sec 模块覆盖**所有协议族**的连接意图审计。

### 5.6 局限性和改进空间

1. **PARM1 类型错误**：`security_socket_connect` 第一个参数是 `struct socket *`，不是 `struct sock *`。正确做法应先从 `socket` 取出 `sk` 字段
2. **字节序未处理**：`skc_dport` 是网络字节序，需 `ntohs` 转换。IPv6 的 `sin6_port` 同理
3. **结构体对齐 bug**：用户侧 `EventIPV6.AF` 和 `EventOther.AF` 用 `uint16` 而内核侧是 `u32`，导致解码偏移错误
4. **IPv6 信息不完整**：IPv6 路径未采集本地地址和端口
5. **缺少连接结果**：hook 在 `connect` 前（kprobe 而非 kretprobe），无法获知连接是否成功
6. **无进程上下文**：仅采集 PID/UID/task_comm，缺少 cmdline、父进程等信息，对安全分析不够
7. **Other 事件信息过于稀疏**：仅有 AF 编号，缺少目的地址，难以分析
8. **无过滤机制**：高并发服务器上所有 connect 都会被采集，缺少 PID/端口白名单过滤

---

## 功能六：Java RASP 命令执行检测

### 6.1 整体架构

| 维度 | 说明 |
|------|------|
| **内核侧** | `kern/java_exec_kern.c` |
| **用户侧 Probe** | `user/probe_ujava_rasp.go` |
| **用户侧 Event** | `user/event_java_rasp.go` |
| **Hook 点** | `uprobe/JDK_execvpe`（偏移 `0x19C30`） |
| **模块名** | `EBPFProbeUJavaRASP` |
| **模块类型** | `PROBE_TYPE_UPROBE` |

本模块通过 uprobe 挂钩 JDK 原生库 `libjava.so` 中的 `JDK_execvpe` 函数，实现对 Java 进程**命令执行**行为的实时检测。这是一种 RASP（Runtime Application Self-Protection）实现方式，能捕获 `Runtime.exec()` / `ProcessBuilder.start()` 最终调用到的 native 层函数。

### 6.2 内核侧分析

```
kern/java_exec_kern.c
```

#### 6.2.1 事件结构体（第 4-10 行）

```c
struct jdk_execvpe {
    u32 pid;          // 进程 PID
    u64 mode;         // exec 模式（fork/vfork/posix_spawn/clone）
    char file[128];   // 要执行的文件路径
} __attribute__((packed));
```

`__attribute__((packed))` 确保无填充，总大小 = 4 + 8 + 128 = **140 字节**。

#### 6.2.2 目标函数原型

```c
// JDK 源码 solaris/native/java/lang/childproc.h
// JDK_execvpe(int mode, const char *file, const char *argv[], const char *const envp[])
```

**mode 参数含义**（对应 JDK 源码中的子进程创建方式）：

| 值 | 常量 | 含义 |
|----|------|------|
| 1 | `MODE_FORK` | 使用 `fork()` 创建子进程后 `exec` |
| 2 | `MODE_POSIX_SPAWN` | 使用 `posix_spawn()` 创建进程 |
| 3 | `MODE_VFORK` | 使用 `vfork()` 创建子进程后 `exec` |
| 4 | `MODE_CLONE` | 使用 `clone()` 系统调用创建进程 |

#### 6.2.3 Hook 函数走读（第 23-54 行）

```c
SEC("uprobe/JDK_execvpe")
int java_JDK_execvpe(struct pt_regs *ctx) {
    // 1. 读取第一个参数 mode
    int *mode = (int *)PT_REGS_PARM1(ctx);
    if (!mode) return 0;

    struct jdk_execvpe val = {};

    // 2. 获取 PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    val.pid = pid_tgid >> 32;

    // 3. mode 直接赋值（指针值当整数用）
    val.mode = (u64)mode;

    // 4. 读取文件路径（用户空间字符串）
    const char *file = (const char *)PT_REGS_PARM2(ctx);
    if (!file) return 0;
    bpf_probe_read_user_str(val.file, sizeof(val.file), file);

    // 5. 读取 argv（仅做 NULL 检查，未实际使用）
    const char (*argv)[];
    if (bpf_probe_read(&argv, sizeof(argv), (const char(*)[])PT_REGS_PARM3(ctx)) != 0)
        return 0;

    // 6. 输出事件
    bpf_perf_event_output(ctx, &jdk_execvpe_events, BPF_F_CURRENT_CPU, &val, sizeof(val));
    return 0;
}
```

**关键技术点**：

1. **`bpf_probe_read_user_str`**（第 45 行）：专门用于读取用户空间字符串的 helper，相比 `bpf_probe_read_str` 更安全，在 5.5+ 内核中专门区分了 user/kernel 地址空间的读取
2. **mode 参数的 trick**（第 37 行）：`val.mode = (u64)mode`——这里 `mode` 被声明为 `int *` 指针，但实际上 `PT_REGS_PARM1` 返回的是寄存器值（即 `int mode` 本身），所以 `(u64)mode` 实际就是将 int 值零扩展为 u64。声明为指针是历史遗留写法
3. **argv 读取（第 47-51 行）**：尝试读取第三个参数（`argv` 数组指针），但读取后并未存入事件结构体，仅用于有效性校验。注释中预留了 `argv[128]` 和 `envp[128]` 字段但被注释掉了

### 6.3 用户侧 Probe 分析

```
user/probe_ujava_rasp.go
```

#### 6.3.1 硬编码偏移和二进制路径（第 81-106 行）

```go
func (this *MJavaRasp) setupManagers() {
    this.javaManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "uprobe/JDK_execvpe",
                EbpfFuncName:     "java_JDK_execvpe",
                AttachToFuncName: "JDK_execvpe",
                UprobeOffset:     0x19C30,                                                    // 硬编码偏移
                BinaryPath:       "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so", // 硬编码路径
            },
        },
    }
}
```

**核心问题**：

| 问题 | 详细说明 |
|------|---------|
| **偏移硬编码** | `0x19C30` 是 `JDK_execvpe` 在**特定版本** `libjava.so` 中的偏移。不同 JDK 版本/构建，该偏移完全不同 |
| **路径硬编码** | 仅适用于 `java-8-openjdk-amd64` 的 Debian/Ubuntu 默认安装路径 |
| **MD5 校验** | 注释中记录了 MD5：`38590d0382d776234201996e99487110`，但代码中并未实际校验 |

代码注释（第 84-91 行）明确标注了目标 JDK 版本：
```
openjdk version "1.8.0_292"
OpenJDK Runtime Environment (build 1.8.0_292-8u292-b10-0ubuntu1-b10)
```

#### 6.3.2 事件处理流程

本模块使用标准的 `Module.readEvents()` → `perfEventReader()` → `Decode()` 流程。`initDecodeFun()`（第 152-165 行）将 `jdk_execvpe_events` map 映射到 `JavaJDKExecPeEvent` 解码器。

### 6.4 用户侧 Event 解码分析

```
user/event_java_rasp.go
```

#### 6.4.1 事件结构体与 Mode 常量（第 9-20 行）

```go
const (
    MODE_FORK        = 1
    MODE_POSIX_SPAWN = 2
    MODE_VFORK       = 3
    MODE_CLONE       = 4
)

type JavaJDKExecPeEvent struct {
    Pid  uint32       // 4 bytes
    Mode uint64       // 8 bytes
    File [128]byte    // 128 bytes
}
```

#### 6.4.2 Mode 解析输出（第 38-52 行）

```go
func (ei *JavaJDKExecPeEvent) String() string {
    var m string = "UNKNOW"
    switch ei.Mode {
    case 1: m = "MODE_FORK"
    case 2: m = "MODE_POSIX_SPAWN"
    case 3: m = "MODE_VFORK"
    case 4: m = "MODE_CLONE"
    }
    s := fmt.Sprintf("JAVA RASP exec and fork. PID:%d, command:%s, mode:%s", ei.Pid, ei.File, m)
    return s
}
```

**各 Mode 的安全意义**：

- **MODE_FORK (1)**：经典 `fork()+exec()` 模式，JDK 8 默认方式
- **MODE_VFORK (3)**：`vfork()` 更轻量，父子进程共享地址空间直到 `exec`，JDK 内部优化路径
- **MODE_POSIX_SPAWN (2)**：更高效的进程创建，JDK 9+ 默认倾向使用
- **MODE_CLONE (4)**：Linux 特有的 `clone()` 调用，更细粒度控制

### 6.5 数据流总结

```
Java 应用调用 Runtime.exec("cmd")
  → JNI: ProcessImpl_forkAndExec (libjava.so)
    → JDK_execvpe(mode, file, argv, envp)  // uprobe 在此触发
      → eBPF 程序捕获 mode + file
        → bpf_perf_event_output → jdk_execvpe_events map
          → 用户态 perfEventReader → JavaJDKExecPeEvent.Decode()
            → 输出 "JAVA RASP exec and fork. PID:xxx, command:/bin/sh, mode:MODE_VFORK"
```

### 6.6 局限性和改进空间

1. **JDK 版本适配是最大问题**：
   - 偏移 `0x19C30` 仅对应一个特定 build，升级/打补丁后即失效
   - **改进方案**：运行时通过 `nm` / `objdump` / `readelf` 动态解析符号表获取偏移，或使用 `AttachToFuncName` 配合符号名自动解析（如果 `libjava.so` 没有被 strip）
2. **仅支持 OpenJDK 8 的特定安装路径**：
   - 不支持 Oracle JDK、GraalVM、Zulu、Amazon Corretto 等发行版
   - 不支持 JDK 11/17/21 等版本（`libjava.so` 路径和内部实现均不同）
   - **改进方案**：扫描 `/proc/*/maps` 找到所有已加载的 `libjava.so`，动态 attach
3. **未采集 argv 和 envp**：
   - 内核侧注释掉了 `argv[128]` 和 `envp[128]`，仅能看到执行的文件路径，看不到命令参数
   - **改进方案**：遍历 `argv[]` 数组（需循环 + 边界检查），至少采集前几个参数
4. **缺少进程上下文**：无 UID、父进程信息、容器 ID 等，安全分析价值有限
5. **不支持多 Java 进程**：如果机器上运行多个 Java 进程，uprobe 会 attach 到同一个 `libjava.so` 文件上，无法区分不同应用
6. **File 路径截断**：`char file[128]` 最多 127 字节，长路径会被截断
7. **无 MD5 运行时校验**：虽然注释中记录了目标文件 MD5，但代码未校验，如果 SO 被替换可能 hook 到错误位置导致内核 panic

---

## 功能七：BPF 系统调用追踪

### 7.1 整体架构

| 维度 | 说明 |
|------|------|
| **内核侧** | `kern/bpf_call_kern.c` |
| **用户侧 Probe** | `user/probe_bpf_call.go` |
| **用户侧 Event** | `user/event_bpf_call.go` |
| **BPF 命令枚举** | `user/bpf_cmd.go` |
| **Hook 点** | `tracepoint/syscalls/sys_enter_bpf` |
| **模块名** | `EBPFProbeBPFCall` |
| **模块类型** | `PROBE_TYPE_TP` |

本模块是 eHIDS 中**最复杂、最完善**的模块。它通过 tracepoint 监控所有 `bpf()` 系统调用，采集完整的 3 级进程树信息，用于检测恶意 eBPF 程序加载行为——这对 HIDS 本身的安全防护至关重要（"谁在监控监控者"）。

### 7.2 内核侧深度分析

```
kern/bpf_call_kern.c
```

#### 7.2.1 关键常量定义（第 4-16 行）

```c
#define CWD_BUF_IDX       0    // bufs map 索引：当前工作目录
#define PATH_BUF_IDX      1    // bufs map 索引：路径
#define STRING_BUF_IDX    2    // bufs map 索引：字符串

#define MAX_DEPTH         10
#define UTS_MAX_LEN       64   // 主机名最大长度
#define PATH_MAX_LEN      256  // 路径最大长度
#define TASK_COMM_LEN     16   // 进程名长度
#define MAX_PERCPU_BUFSIZE (1 << 12)  // 4096 字节 percpu buffer
```

#### 7.2.2 四个 Map 的设计（第 38-65 行）

```c
// 1. PerCPU Array: 通用 buffer（用于路径等大数据的临时存储）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buf_t);    // 4096 字节
    __uint(max_entries, 3);         // 3 个 slot
} bufs SEC(".maps");

// 2. LRU Hash: 存储事件上下文（堆内存模式的核心）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);               // pid_tgid 作为 key
    __type(value, struct bpf_context_t);
    __uint(max_entries, 2048);
} bpf_context SEC(".maps");

// 3. Array: 事件模板（仅 1 个元素，用于零值初始化）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct bpf_context_t);
    __uint(max_entries, 1);
} bpf_context_gen SEC(".maps");

// 4. PerfEventArray: 事件输出
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4);
} events SEC(".maps");
```

#### 7.2.3 make_event() 堆内存模式（第 281-289 行）——核心技巧

```c
// 这个函数用来规避512字节栈空间限制，通过在堆上创建内存的方式，避开限制
static __always_inline struct bpf_context_t *make_event() {
    u32 key_gen = 0;
    // 步骤 1: 从 Array map 取出零值模板
    struct bpf_context_t *bpf_ctx = bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx) return 0;

    // 步骤 2: 以 pid_tgid 为 key，将零值模板复制到 LRU_Hash
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);

    // 步骤 3: 从 LRU_Hash 取回指针（现在是堆上的内存）
    return bpf_map_lookup_elem(&bpf_context, &id);
}
```

**为什么需要这个技巧？**

`struct bpf_context_t` 包含 `struct proc_common`，后者大小为：
- 12 个 u32 PID 字段 = 48 bytes
- 4 个 u32 UID/GID 字段 = 16 bytes
- 1 个 u32 uts_inum + 1 个 u32 pending = 8 bytes
- 1 个 u64 start_time = 8 bytes
- comm[16] + cmdline[256] + uts_name[64] = 336 bytes
- **总计约 416 bytes**

加上 `bpf_context_t` 的 `cmd` 和 `pending` 字段（8 bytes），总计约 **424 bytes**。eBPF 程序栈空间限制为 **512 字节**，在函数调用链中加上其他局部变量很容易超限。

**三步法的精妙之处**：
1. `bpf_context_gen`（Array）：提供一个零值初始化的模板，避免在栈上做 `memset`
2. `bpf_map_update_elem`：将模板复制到 `bpf_context`（LRU_Hash）中，数据现在在堆上
3. `bpf_map_lookup_elem`：取回堆上的指针，后续所有写操作都在堆上进行

使用 **LRU_Hash** 而非普通 Hash 的原因：当 map 满时自动淘汰最旧条目，不会因 `BPF_MAP_UPDATE` 返回 `-ENOMEM` 而丢失事件。

#### 7.2.4 proc_common 结构体——完整进程信息（第 193-217 行）

```c
struct proc_common {
    // === 当前进程 ===
    __u32 pid;        // 线程 ID (task->pid)
    __u32 tgid;       // 进程组 ID (task->tgid)，即用户态看到的 PID
    __u32 nspid;      // namespace 内的 PID
    __u32 nstgid;     // namespace 内的 TGID

    // === 父进程 ===
    __u32 ppid;       // 父线程 ID
    __u32 ptgid;      // 父进程组 ID
    __u32 nsppid;     // 父进程 namespace PID
    __u32 nsptgid;    // 父进程 namespace TGID

    // === 祖父进程 ===
    __u32 pppid;      // 祖父线程 ID
    __u32 pptgid;     // 祖父进程组 ID
    __u32 nspppid;    // 祖父 namespace PID
    __u32 nspptgid;   // 祖父 namespace TGID

    // === 身份信息 ===
    __u32 uid;        // 真实 UID
    __u32 euid;       // 有效 UID
    __u32 gid;        // 真实 GID
    __u32 egid;       // 有效 GID

    // === 容器/命名空间信息 ===
    __u32 uts_inum;   // UTS namespace inode number（可标识容器）
    __u32 pending;    // 对齐填充

    // === 时间和名称 ===
    __u64 start_time;        // 进程启动时间
    __u8 comm[16];           // 进程名（task->comm）
    __u8 cmdline[256];       // 完整命令行
    __u8 uts_name[64];       // 主机名/容器名
};
```

**3 级进程树**的安全意义：攻击者通常通过多层 shell 嵌套执行恶意操作，3 级进程树可以追溯到真正的发起者。例如：`sshd → bash → python3 → bpf()` 可以通过 `pppid` 追溯到 `sshd`。

#### 7.2.5 辅助函数详解

**get_task_ns_pid()** （第 84-94 行）——获取 namespace 内的 PID：
```c
static __always_inline u32 get_task_ns_pid(struct task_struct *task) {
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);  // 命名空间嵌套层级
    struct pid *tpid = READ_KERN(task->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);  // 在目标层级的 PID 编号
    return nr;
}
```

这个函数通过遍历 `pid->numbers[]` 数组到对应的 namespace level，获取进程在其 **PID namespace 内**的 PID。对于容器进程，这个值通常是 1（init 进程）或一个较小的数字。

**get_task_ns_tgid()** （第 96-108 行）：与 `get_task_ns_pid` 类似，但通过 `task->group_leader->thread_pid` 获取线程组 leader 的 namespace TGID。

**get_uts_ns_id()** （第 110-114 行）——获取 UTS namespace inode 号：
```c
static __always_inline u32 get_uts_ns_id(struct nsproxy *ns) {
    struct uts_namespace* uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}
```

UTS namespace inode 号可以用来**唯一标识容器**（同一容器内所有进程共享相同的 `uts_inum`）。

**get_task_uts_ns_id()** （第 116-119 行）：组合封装，从 `task_struct` 直接获取 UTS namespace ID。

**get_task_euid() / get_task_gid() / get_task_egid()** （第 121-137 行）：从 `task->real_cred` 读取各种 UID/GID，用于判断进程的真实/有效权限。

**get_task_start_time()** （第 139-142 行）：读取 `task->start_time`，可用于进程唯一标识（PID + start_time 组合全局唯一）。

**get_task_uts_name()** （第 144-149 行）——获取主机名：
```c
static __always_inline char *get_task_uts_name(struct task_struct *task) {
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);  // 即容器的 hostname
}
```

**get_proc_cmdline()** （第 171-180 行）——读取完整命令行：
```c
static __always_inline void get_proc_cmdline(struct task_struct *task, char *cmdline, int size) {
    struct mm_struct *mm = READ_KERN(task->mm);
    long unsigned int args_start = READ_KERN(mm->arg_start);
    long unsigned int args_end = READ_KERN(mm->arg_end);
    int len = (args_end - args_start);
    if (len >= size) len = size - 1;
    bpf_probe_read(cmdline, len & (size - 1), (const void *)args_start);
}
```

从 `mm_struct->arg_start` 到 `arg_end` 读取进程的完整命令行参数。`len & (size - 1)` 利用位运算确保不超过 buffer 大小（要求 `size` 是 2 的幂，这里 `PATH_MAX_LEN=256` 满足条件）。

#### 7.2.6 get_common_proc() 完整进程信息采集（第 244-278 行）

```c
static __always_inline void get_common_proc(struct proc_common *procinfo) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // --- 当前进程 ---
    procinfo->pid = internal_get_task_pid(task);
    procinfo->tgid = internal_get_task_tgid(task);
    procinfo->nspid = get_task_ns_pid(task);
    procinfo->nstgid = get_task_ns_tgid(task);
    procinfo->uid = bpf_get_current_uid_gid();
    procinfo->euid = get_task_euid(task);
    procinfo->gid = get_task_gid(task);
    procinfo->egid = get_task_egid(task);
    procinfo->start_time = get_task_start_time(task);
    procinfo->uts_inum = get_task_uts_ns_id(task);

    // --- 父进程（real_parent）---
    procinfo->ppid = internal_get_task_pid(READ_KERN(task->real_parent));
    procinfo->ptgid = internal_get_task_tgid(READ_KERN(task->real_parent));
    procinfo->nsppid = get_task_ns_pid(READ_KERN(task->real_parent));
    procinfo->nsptgid = get_task_ns_tgid(READ_KERN(task->real_parent));

    // --- 祖父进程（real_parent->real_parent）---
    struct task_struct *parent = READ_KERN(task->real_parent);
    procinfo->pppid = internal_get_task_pid(READ_KERN(parent->real_parent));
    procinfo->pptgid = internal_get_task_tgid(READ_KERN(parent->real_parent));
    procinfo->nspppid = get_task_ns_pid(READ_KERN(parent->real_parent));
    procinfo->nspptgid = get_task_ns_tgid(READ_KERN(parent->real_parent));

    // --- 进程名和命令行 ---
    bpf_get_current_comm(procinfo->comm, 16);
    char *uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(procinfo->uts_name, sizeof(procinfo->uts_name), uts_name);
    get_proc_cmdline(task, procinfo->cmdline, sizeof(procinfo->cmdline));
}
```

#### 7.2.7 Tracepoint 参数结构体（第 184-190 行）

```c
struct syscall_bpf_args {
    unsigned long long unused;   // tracepoint 通用头部
    long syscall_nr;             // 系统调用号
    int cmd;                     // BPF 命令（BPF_MAP_CREATE, BPF_PROG_LOAD 等）
    union bpf_attr* uattr;      // 用户传入的属性指针
    unsigned int size;           // 属性大小
};
```

这个结构体对应 `/sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf/format` 中的 tracepoint 格式。

#### 7.2.8 主 Hook 函数（第 301-310 行）

```c
SEC("tracepoint/syscalls/sys_enter_bpf")
int tracepoint_sys_enter_bpf(struct syscall_bpf_args *args) {
    struct bpf_context_t *bpf_context = make_event();  // 堆上分配
    if (!bpf_context) return 0;
    bpf_context->cmd = args->cmd;                      // 记录 BPF 命令
    get_common_proc(&bpf_context->procinfo);            // 采集完整进程信息
    send_event(args, bpf_context);                      // 输出到 perf buffer
    return 0;
}
```

**send_event()** （第 291-297 行）：
```c
static __always_inline void send_event(void *ctx, struct bpf_context_t *context) {
    u64 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &events, cpu, context, sizeof(struct bpf_context_t));
}
```

注意这里使用 `bpf_get_smp_processor_id()` 而非 `BPF_F_CURRENT_CPU` 宏，效果相同。

### 7.3 用户侧 Probe 分析——独特的 PerfMap 回调模式

```
user/probe_bpf_call.go
```

#### 7.3.1 与其他模块不同的事件处理路径

**其他模块**的流程：
```
Module.readEvents() → perfEventReader(goroutine) → child.Decode(em, data) → Module.Write()
```

**BPF Call 模块**的流程（第 52-62 行）：
```go
// perfMap 事件处理函数设定
perfMap, ok := this.bpfManager.GetPerfMap("events")
if !ok {
    return errors.New("couldn't find events perf map")
}

perfMap.PerfMapOptions = manager.PerfMapOptions{
    PerfRingBufferSize: 1 * os.Getpagesize(),
    DataHandler:        this.dataHandler,       // 自定义回调！
    LostHandler:        this.lostEventsHandle,
}
```

BPF Call 模块使用 `ebpfmanager` 库的 **PerfMap 回调模式**而非基类的 `readEvents()` 流程。这是因为：

1. 在 `setupManagers()`（第 100-107 行）中使用了 `PerfMaps` 字段而非 `Maps` 字段
2. `initDecodeFun()` 为空实现（第 152-154 行），不注册任何 Map→Decoder 映射
3. `Events()` 返回空切片，所以基类的 `readEvents()` 不会为此模块启动 goroutine

**自定义回调函数**（第 129-139 行）：
```go
func (this *MBPFCallProbe) dataHandler(cpu int, data []byte, perfmap *manager.PerfMap, manager *manager.Manager) {
    bpfEvent := &BpfCallEvent{}
    err := bpfEvent.Decode(data)
    if err != nil {
        this.logger.Fatalf("decode error:%v", err)
        return
    }
    this.Write(fmt.Sprintf("BPFCALL EVENT CPU:%d, %s", cpu, bpfEvent.String()))
}
```

直接在回调中创建 `BpfCallEvent`、解码并输出，绕过了基类的 Map→Decoder 查找机制。

#### 7.3.2 MapSpecEditors 动态调整（第 120-126 行）

```go
MapSpecEditors: map[string]manager.MapSpecEditor{
    "events": {
        Type:       ebpf.PerfEventArray,
        MaxEntries: uint32(64),
    },
},
```

通过 `MapSpecEditors` 将 `events` map 的 `max_entries` 从内核侧定义的 4 扩大到 64，支持更多 CPU。

### 7.4 用户侧 Event 解码分析

```
user/event_bpf_call.go
```

#### 7.4.1 手动字节偏移解码（第 53-77 行）

与其他模块使用 `binary.Read` 逐字段读取不同，BPF Call 模块采用**直接字节切片**方式解码：

```go
func (this *BpfCallEvent) Decode(data []byte) error {
    cmd := BPFCmd(ByteOrder.Uint32(data[0:4]))     // offset 0: cmd
    this.Type = cmd.String()
    // offset 4-7: pending (跳过)
    this.Pid = uint32(ByteOrder.Uint32(data[8:12]))    // offset 8: pid
    this.Tgid = uint32(ByteOrder.Uint32(data[12:16]))  // offset 12: tgid
    // ... 按照 proc_common 结构体布局逐字段读取 ...
    this.Start_time = uint64(ByteOrder.Uint64(data[80:88]))   // offset 80: start_time
    this.Comm = string(bytes.TrimRight(data[88:104], "\x00"))  // offset 88: comm[16]
    this.Cmdline = string(bytes.Replace(                        // offset 104: cmdline[256]
        bytes.TrimRight(data[104:360], "\x00"),
        []byte("\x00"), []byte("\x20"), -1))                   // \0 分隔符替换为空格
    this.UtsName = string(bytes.TrimRight(data[360:424], "\x00")) // offset 360: uts_name[64]
    return nil
}
```

**内存布局映射**（`bpf_context_t` 总大小 424 bytes）：

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | cmd | BPF 命令编号 |
| 4 | 4 | pending | 填充对齐 |
| 8 | 4 | pid | 线程 ID |
| 12 | 4 | tgid | 进程组 ID |
| 16 | 4 | nspid | NS PID |
| 20 | 4 | nstgid | NS TGID |
| 24 | 4 | ppid | 父线程 ID |
| 28 | 4 | ptgid | 父进程组 ID |
| 32 | 4 | nsppid | 父 NS PID |
| 36 | 4 | nsptgid | 父 NS TGID |
| 40 | 4 | pppid | 祖父线程 ID |
| 44 | 4 | pptgid | 祖父进程组 ID |
| 48 | 4 | nspppid | 祖父 NS PID |
| 52 | 4 | nspptgid | 祖父 NS TGID |
| 56 | 4 | uid | UID |
| 60 | 4 | euid | EUID |
| 64 | 4 | gid | GID |
| 68 | 4 | egid | EGID |
| 72 | 4 | uts_inum | UTS NS inode |
| 76 | 4 | pending | 填充 |
| 80 | 8 | start_time | 启动时间 |
| 88 | 16 | comm | 进程名 |
| 104 | 256 | cmdline | 命令行 |
| 360 | 64 | uts_name | 主机名 |

#### 7.4.2 动态字节序检测（第 10-18 行）

```go
func GetEndian() binary.ByteOrder {
    var i int32 = 0x1
    v := (*[4]byte)(unsafe.Pointer(&i))
    if v[0] == 0 {
        return binary.BigEndian
    } else {
        return binary.LittleEndian
    }
}
```

通过检查整数 `0x1` 在内存中的存储方式判断当前系统的字节序，保证跨平台兼容（虽然 eBPF 主要在 x86_64 Linux 上运行）。

#### 7.4.3 cmdline 特殊处理

```go
this.Cmdline = string(bytes.Replace(
    bytes.TrimRight(data[104:360], "\x00"),
    []byte("\x00"), []byte("\x20"), -1))
```

Linux 的 `/proc/pid/cmdline` 中参数之间用 `\0` 分隔。这里将 `\0` 替换为空格，使输出更可读。例如 `python3\0-c\0import os` → `python3 -c import os`。

### 7.5 BPF 命令枚举

```
user/bpf_cmd.go
```

定义了 **34 个** BPF 系统调用命令（第 9-44 行，编号 0-33）：

| 编号 | 命令 | 安全关注度 | 说明 |
|------|------|-----------|------|
| 0 | `BPF_MAP_CREATE` | **高** | 创建新 Map |
| 5 | `BPF_PROG_LOAD` | **最高** | 加载 BPF 程序（恶意程序注入的关键操作） |
| 8 | `BPF_PROG_ATTACH` | **高** | 将程序 attach 到 hook 点 |
| 17 | `BPF_RAW_TRACEPOINT_OPEN` | **高** | 打开 raw tracepoint |
| 18 | `BPF_BTF_LOAD` | 中 | 加载 BTF 信息 |
| 28 | `BPF_LINK_CREATE` | **高** | 创建 BPF link（新式 attach 方式） |
| 1-4 | `MAP_LOOKUP/UPDATE/DELETE/GET_NEXT_KEY` | 低 | Map 常规操作（频率极高） |

**安全检测策略建议**：应重点关注 `BPF_PROG_LOAD`（命令 5），因为恶意 rootkit 必须通过此命令加载 eBPF 程序。结合 `euid` 和 `cmdline` 可以判断是否为合法操作。

`BPFCmd.String()` 方法（第 90-95 行）使用编译期生成的字符串索引表实现高效的枚举值→名称转换：

```go
const _BPFCmd_name = "BPF_MAP_CREATEBPF_MAP_LOOKUP_ELEM..."
var _BPFCmd_index = [...]uint16{0, 14, 33, ...}

func (i BPFCmd) String() string {
    return _BPFCmd_name[_BPFCmd_index[i]:_BPFCmd_index[i+1]]
}
```

### 7.6 完整数据流

```
用户程序调用 bpf(BPF_PROG_LOAD, attr, size)
  → 内核 sys_enter_bpf tracepoint 触发
    → tracepoint_sys_enter_bpf()
      → make_event()：Array 模板 → LRU_Hash 堆分配
      → 记录 cmd = BPF_PROG_LOAD
      → get_common_proc()：采集 3 级进程树 + NS PID + UID/GID + cmdline + hostname
      → send_event()：bpf_perf_event_output → events PerfMap
        → ebpfmanager PerfMap 回调 → dataHandler()
          → BpfCallEvent.Decode()：字节切片解码
          → Module.Write()：输出日志
            "BPFCALL EVENT CPU:0, Cmd:BPF_PROG_LOAD, PID:1234, UID:0,
             Comm:bpftool, cmdline:bpftool prog load test.o, utsName:docker-abc123"
```

### 7.7 局限性和改进空间

1. **未解析 `bpf_attr` 内容**：
   - 仅记录了 `cmd` 编号，但未读取 `uattr` 指向的 `bpf_attr` 联合体
   - 对于 `BPF_PROG_LOAD`，应提取 `prog_type`、`prog_name`、`insn_cnt` 等关键字段
   - 对于 `BPF_MAP_CREATE`，应提取 `map_type`、`key_size`、`value_size` 等
   - **改进方案**：使用 `bpf_probe_read_user` 读取 `uattr` 中的关键字段

2. **Map 操作噪声过大**：
   - `BPF_MAP_LOOKUP_ELEM`/`UPDATE_ELEM` 等操作频率极高（每次 map 查找都会触发）
   - 会产生大量噪声事件，影响 perf buffer 和用户态处理性能
   - **改进方案**：在内核侧按 cmd 过滤，仅上报高安全价值的命令（`PROG_LOAD`、`PROG_ATTACH`、`LINK_CREATE` 等）

3. **缺少 sys_exit_bpf 配对**：
   - 仅 hook 了 `sys_enter_bpf`（进入），未 hook `sys_exit_bpf`（退出）
   - 无法获知 bpf() 调用是否成功（返回值/fd）
   - **改进方案**：添加 `tracepoint/syscalls/sys_exit_bpf`，通过 pid_tgid 关联进出事件

4. **PerfRingBufferSize 过小**（第 59 行）：
   ```go
   PerfRingBufferSize: 1 * os.Getpagesize(),  // 仅 4KB
   ```
   对于高频 bpf() 调用场景，4KB 的 perf ring buffer 极易溢出导致事件丢失

5. **lostEventsHandle 未实现**（第 142-145 行）：
   ```go
   func (this *MBPFCallProbe) lostEventsHandle(...) {
       // TODO
   }
   ```
   事件丢失无任何统计或告警

6. **`print_debug` 始终启用**（第 230 行）：
   ```c
   #if 1   // 应改为 #if 0 或使用编译宏控制
   ```
   `bpf_trace_printk` 在生产环境会写入 `/sys/kernel/debug/tracing/trace_pipe`，影响性能

7. **`get_proc_cmdline` 的 mm 空指针风险**：内核线程的 `task->mm` 为 NULL，`READ_KERN(task->mm)` 后未做 NULL 检查就访问 `mm->arg_start`，可能导致读取无效地址

8. **READ_KERN 依赖 CO:RE**：使用了 `bpf_core_read` 宏，要求编译时有 BTF 支持，但 `ehids_agent.h` 中的 `#ifndef NOCORE` 分支为空（`// TODO`），非 CO:RE 模式完全不可用

9. **BPF 命令枚举不完整**：截至 Linux 5.15+，已有 `BPF_LINK_DETACH (34)`、`BPF_PROG_BIND_MAP (35)` 等新命令未收录

---

## 三个功能的横向对比

| 维度 | 功能五 Socket Sec | 功能六 Java RASP | 功能七 BPF Call |
|------|-------------------|-----------------|----------------|
| Hook 类型 | kprobe | uprobe | tracepoint |
| 复杂度 | 低 | 中 | 高 |
| 进程信息 | PID/UID/comm | PID | 完整 3 级进程树 |
| 堆内存技巧 | 无 | 无 | make_event() |
| 事件处理 | 基类 readEvents | 基类 readEvents | PerfMap 回调 |
| Map 数量 | 3 个 PerfEventArray | 1 个 PerfEventArray | 4 个（Array+LRU_Hash+PerCPU_Array+PerfEventArray） |
| CO:RE 依赖 | 无 | 无 | 依赖 bpf_core_read |
| 实用程度 | 中（有 bug） | 低（硬编码） | 高（设计精良） |
| 生产就绪 | 需修复对齐和字节序问题 | 需动态偏移解析 | 需过滤噪声和补全 attr 解析 |
