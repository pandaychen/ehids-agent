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
