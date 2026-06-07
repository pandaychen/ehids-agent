# ehids-agent 项目技术深度分析文档

> 分析日期：2026-03-27
> 项目地址：https://github.com/ehids/ehids-agent
> 项目定位：基于 eBPF 内核技术的主机入侵检测系统（HIDS）演示项目，由美团安全工程团队贡献

---

## 目录

- [1. 项目概览](#1-项目概览)
- [2. 项目目录结构](#2-项目目录结构)
- [3. 构建系统分析](#3-构建系统分析)
- [4. 依赖分析](#4-依赖分析)
- [5. 总体架构设计](#5-总体架构设计)
- [6. 核心接口与设计模式](#6-核心接口与设计模式)
- [7. 内核态 eBPF 探针详解](#7-内核态-ebpf-探针详解)
- [8. 用户态 Go 模块详解](#8-用户态-go-模块详解)
- [9. 端到端数据流分析](#9-端到端数据流分析)
- [10. 关键实现技巧](#10-关键实现技巧)
- [11. CO-RE 跨版本兼容机制](#11-co-re-跨版本兼容机制)
- [12. 资源打包与发布](#12-资源打包与发布)
- [13. 性能与安全约束](#13-性能与安全约束)
- [14. 应用场景](#14-应用场景)
- [15. 技术总结](#15-技术总结)

---

## 1. 项目概览

### 1.1 核心功能矩阵

| 功能模块 | 探针类型 | Hook 点 | 捕获内容 |
|---------|---------|---------|---------|
| 进程事件 | kretprobe | `copy_process` | 进程 fork/exec，包含完整进程树 |
| TCP 连接追踪 | kprobe | `tcp_set_state` | TCP 连接生命周期、流量统计 |
| DNS 解析追踪 | uprobe | `getaddrinfo` (libc) | DNS 查询域名与解析结果 |
| UDP DNS 捕获 | kprobe | `udp_recvmsg` | 端口 53 原始 DNS 报文 |
| Socket 连接监控 | kprobe | `security_socket_connect` | IPv4/IPv6/其他 socket 连接 |
| Java RASP | uprobe | `JDK_execvpe` (libjava.so) | Java 进程命令执行 |
| BPF 系统调用追踪 | tracepoint | `syscalls/sys_enter_bpf` | BPF 系统调用详情 |

### 1.2 技术栈

```
┌──────────────────────────────────────────────────┐
│                   用户态 (Go)                     │
│  ┌────────────┐ ┌───────────┐ ┌───────────────┐  │
│  │ ebpfmanager│ │ cilium/   │ │ go-bindata    │  │
│  │   v0.2.2   │ │ ebpf v0.8 │ │ (资源嵌入)    │  │
│  └────────────┘ └───────────┘ └───────────────┘  │
├──────────────────────────────────────────────────┤
│                   内核态 (C/eBPF)                 │
│  ┌────────────┐ ┌───────────┐ ┌───────────────┐  │
│  │ kprobe/    │ │ uprobe/   │ │ tracepoint    │  │
│  │ kretprobe  │ │ uretprobe │ │               │  │
│  └────────────┘ └───────────┘ └───────────────┘  │
│  ┌────────────────────────────────────────────┐  │
│  │  BPF Maps: PerfEvent / RingBuf / HashMap   │  │
│  └────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────┤
│              Linux Kernel (>= 4.14)              │
└──────────────────────────────────────────────────┘
```

---

## 2. 项目目录结构

```
ehids-agent/
├── main.go                              # 程序入口：初始化、模块编排、信号处理
├── go.mod / go.sum                      # Go 模块定义与依赖锁
├── Makefile                             # 主构建脚本（BPF 编译 + 资源打包 + Go 编译）
│
├── kern/                                # ═══ 内核态 eBPF 代码（C 语言）═══
│   ├── common.h                         # 公共宏定义（READ_KERN、debug_bpf_printk 等）
│   ├── ehids_agent.h                    # 主头文件（CO-RE / NOCORE 条件编译分支）
│   ├── vmlinux.h                        # 内核结构体定义（bpftool btf dump 生成）
│   ├── bpf/                             # BPF 辅助库（libbpf 标准头文件）
│   │   ├── bpf_helpers.h               #   BPF 辅助函数声明
│   │   ├── bpf_tracing.h              #   PT_REGS_PARMx 等追踪宏
│   │   ├── bpf_core_read.h            #   CO-RE 字段读取宏
│   │   ├── bpf_endian.h               #   大小端转换
│   │   └── bpf_helper_defs.h          #   辅助函数完整定义
│   │
│   ├── proc_kern.c                      # 进程事件探针（kretprobe/copy_process）
│   ├── tcp_set_state_kern.c             # TCP 状态追踪（kprobe/tcp_set_state）
│   ├── dns_lookup_kern.c               # DNS 解析追踪（uprobe/getaddrinfo）
│   ├── udp_lookup_kern.c               # UDP DNS 报文（kprobe/udp_recvmsg）
│   ├── sec_socket_connect_kern.c        # Socket 连接追踪（kprobe/security_socket_connect）
│   ├── java_exec_kern.c                # Java RASP（uprobe/JDK_execvpe）
│   └── bpf_call_kern.c                 # BPF syscall 追踪（tracepoint/sys_enter_bpf）
│
├── user/                                # ═══ 用户态 Go 代码 ═══
│   ├── imodule.go                       # IModule 接口 + Module 基类（模板方法）
│   ├── ievent.go                        # IEventStruct 接口（事件解码规范）
│   ├── iclose.go                        # IClose 接口（资源清理）
│   ├── register.go                      # 全局模块注册表
│   ├── common.go                        # 公共常量、辅助函数（IP 转换等）
│   ├── bpf_cmd.go                       # BPF 命令枚举定义
│   │
│   ├── probe_proc.go                    # 进程探针加载器
│   ├── event_proc.go                    # 进程事件结构体与解码
│   ├── probe_ktcp.go                    # TCP 探针加载器
│   ├── event_tcp.go                     # TCP 事件结构体与解码
│   ├── probe_udns.go                    # DNS uprobe 探针加载器
│   ├── event_udns.go                    # DNS 事件结构体与解码
│   ├── probe_kudp.go                    # UDP kprobe 探针加载器
│   ├── event_kudp.go                    # UDP 事件结构体与解码
│   ├── probe_ktcp_sec.go               # Socket 连接探针加载器
│   ├── event_ktcp_sec.go               # Socket 连接事件结构体与解码
│   ├── probe_ujava_rasp.go             # Java RASP uprobe 探针加载器
│   ├── event_java_rasp.go              # Java RASP 事件结构体与解码
│   ├── probe_bpf_call.go               # BPF syscall 探针加载器
│   └── event_bpf_call.go               # BPF 事件结构体与解码
│
├── assets/                              # 编译产物（自动生成）
│   └── ebpf_probe.go                    # go-bindata 生成的 BPF 字节码嵌入文件
│
├── bin/                                 # 最终二进制输出
│   └── ehids-agent
│
├── builder/                             # 发布构建脚本
│   └── Makefile.release
│
├── examples/                            # 示例代码
│   └── Main.java                        # Java RASP 测试用例
│
├── images/                              # 文档图片资源
└── .github/workflows/                   # CI/CD 配置
```

---

## 3. 构建系统分析

### 3.1 Makefile 构建流程

```
make all
  │
  ├─ [1] make ebpf          编译 BPF 内核态代码
  │   ├─ 检查 clang >= 9
  │   ├─ 检查 go >= 1.16
  │   └─ 对每个 kern/*.c：
  │       clang -D__TARGET_ARCH_x86 \
  │             -target bpfel \           # 小端序 BPF 目标
  │             -O2 -mcpu=v1 \            # 优化 + BPF v1 ISA
  │             -nostdinc \               # 排除系统头文件
  │             -I./kern \                # 使用项目内头文件
  │             -c kern/xxx_kern.c \
  │             -o user/bytecode/xxx_kern.o
  │
  ├─ [2] make assets         资源嵌入
  │   └─ go-bindata -pkg assets \
  │        -o assets/ebpf_probe.go \
  │        user/bytecode/*.o              # 将 .o 打包为 Go 代码
  │
  └─ [3] make build          编译 Go 二进制
      └─ CGO_ENABLED=0 go build \
           -ldflags "-w -s" \             # 去除调试信息，减小体积
           -o bin/ehids-agent .
```

### 3.2 BPF 编译目标清单

```makefile
TARGETS := kern/sec_socket_connect    # Socket 连接监控
TARGETS += kern/tcp_set_state         # TCP 生命周期
TARGETS += kern/dns_lookup            # DNS 查询 (uprobe)
TARGETS += kern/udp_lookup            # UDP DNS (kprobe)
TARGETS += kern/java_exec             # Java 命令执行
TARGETS += kern/proc                  # 进程创建
TARGETS += kern/bpf_call              # BPF 系统调用
```

### 3.3 CO-RE vs NOCORE 双模式

```makefile
# 默认使用 CO-RE 模式（推荐，需要 kernel >= 5.2 且开启 BTF）
make ebpf

# NOCORE 模式（兼容未开启 BTF 的旧内核）
make ebpf NOCORE=1
# 区别：使用标准 kernel headers 替代 vmlinux.h
```

---

## 4. 依赖分析

### 4.1 go.mod 核心依赖

| 依赖包 | 版本 | 用途 |
|-------|------|------|
| `github.com/cilium/ebpf` | v0.8.1 | 纯 Go eBPF 库，负责加载 BPF 程序、读取 Map |
| `github.com/ehids/ebpfmanager` | v0.2.2 | eBPF 管理器，封装 cilium/ebpf，简化 probe 挂载 |
| `github.com/cirocosta/rawdns` | latest | 原始 DNS 报文解析 |
| `github.com/shuLhan/go-bindata` | v4.0.0 | BPF 目标文件嵌入 Go 二进制 |
| `github.com/pkg/errors` | v0.9.1 | 错误包装 |
| `github.com/tredoe/osutil` | v1.0.6 | 操作系统工具库 |
| `golang.org/x/sys` | latest | 系统调用（rlimit 等） |

### 4.2 依赖关系图

```
ehids-agent
  ├── cilium/ebpf ←── 底层 BPF 加载
  │     ├── perf.Reader       (读取 PerfEventArray)
  │     ├── ringbuf.Reader    (读取 RingBuf)
  │     └── ebpf.Map          (操作 BPF Maps)
  │
  ├── ehids/ebpfmanager ←── 高层 BPF 管理
  │     ├── manager.Manager    (声明式配置)
  │     ├── manager.Probe      (kprobe/uprobe 定义)
  │     └── manager.MapEditor  (Map 操作)
  │
  ├── go-bindata ←── 构建时工具
  │     └── 将 .o 文件转为 Go byte slice
  │
  └── cirocosta/rawdns ←── DNS 报文解析
        └── 解析 UDP 原始 DNS 响应
```

---

## 5. 总体架构设计

### 5.1 分层架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        main.go (编排层)                         │
│  ┌─────────┐  ┌─────────────────────────────────────────────┐  │
│  │ rlimit  │  │  for name, mod := range GetModules() {      │  │
│  │ Remove  │  │      mod.Init(ctx, logger)                  │  │
│  │ Memlock │  │      go mod.Run()    // 独立 goroutine      │  │
│  └─────────┘  │  }                                          │  │
│               │  signal.Notify(sigCh, SIGTERM, SIGINT)      │  │
│               └─────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                     register.go (注册层)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  var modules = map[string]IModule{}                      │  │
│  │  Register(mod IModule)     // 各探针 init() 中调用       │  │
│  │  GetModules() → 所有已注册模块                            │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                    imodule.go (框架层)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Module 基类                                             │  │
│  │  ├── Run()          → Start() + readEvents()             │  │
│  │  ├── readEvents()   → 识别 Map 类型 → 启动对应 reader     │  │
│  │  ├── perfEventReader()    → 读取 PerfEventArray          │  │
│  │  └── ringbufEventReader() → 读取 RingBuf                 │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                   probe_*.go (探针实现层)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Proc     │ │ TCP      │ │ DNS      │ │ BPFCall  │  ...    │
│  │ Probe    │ │ Probe    │ │ Probe    │ │ Probe    │         │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│  各自实现 Start()/Events()/DecodeFun()/Decode()                │
├─────────────────────────────────────────────────────────────────┤
│                   event_*.go (事件解码层)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ ProcEvent│ │ TCPEvent │ │ DNSEvent │ │ BPFEvent │  ...    │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│  各自实现 Decode([]byte)/String()/Clone()                      │
├─────────────────────────────────────────────────────────────────┤
│               ebpfmanager + cilium/ebpf (基础设施层)            │
│  加载 BPF 字节码 → 挂载到 Hook 点 → 创建/管理 Map              │
├─────────────────────────────────────────────────────────────────┤
│                        Linux Kernel                            │
│  BPF 虚拟机 → 验证器 → JIT 编译 → 内核事件触发                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 程序启动时序图

```
main()
  │
  ├─ unix.Setrlimit(RLIMIT_MEMLOCK, &Infinity)   // 移除 eBPF 内存锁限制
  │
  ├─ modules := user.GetModules()                 // 获取 init() 注册的所有模块
  │
  ├─ for _, mod := range modules:
  │   ├─ mod.Init(ctx, logger)                    // 设置上下文和日志
  │   └─ go mod.Run()                             // 每个模块独立 goroutine
  │       │
  │       ├─ child.Start()                        // ← 由子类实现
  │       │   ├─ assets.Asset("bytecode/xxx.o")   //   读取嵌入的 BPF 字节码
  │       │   ├─ bpfManager.InitWithOptions(...)   //   加载到内核
  │       │   ├─ bpfManager.Start()               //   挂载到 Hook 点
  │       │   └─ 初始化 eventMaps/eventFuncMaps   //   关联 Map 与解码函数
  │       │
  │       └─ readEvents()                         // ← 模板方法
  │           ├─ Events() → []*ebpf.Map           //   获取事件 Map 列表
  │           └─ for each map:
  │               ├─ PerfEventArray → go perfEventReader()
  │               └─ RingBuf       → go ringbufEventReader()
  │
  └─ <-sigCh                                      // 阻塞等待退出信号
      └─ cancel() → 各 goroutine 退出
```

---

## 6. 核心接口与设计模式

### 6.1 IModule 接口（模块规范）

```go
type IModule interface {
    Init(ctx context.Context, logger *log.Logger) error  // 初始化上下文
    Name() string                                        // 模块唯一标识
    Run() error                                          // 启动事件监听循环
    Start() error                                        // 加载 BPF 程序到内核
    Stop() error                                         // 停止 BPF 程序
    Close() error                                        // 释放所有资源
    SetChild(module IModule)                             // 设置具体子类引用
    Decode(em *ebpf.Map, b []byte) (string, error)       // 解码原始事件数据
    Events() []*ebpf.Map                                 // 返回待读取的事件 Map
    DecodeFun(p *ebpf.Map) (IEventStruct, bool)          // 返回 Map 对应的解码器
}
```

### 6.2 IEventStruct 接口（事件规范）

```go
type IEventStruct interface {
    Decode(payload []byte) error   // 从原始字节解码到结构体
    String() string                // 格式化为可读字符串
    Clone() IEventStruct           // 创建新实例（用于并发安全）
}
```

### 6.3 Module 基类（模板方法实现）

```go
type Module struct {
    ctx           context.Context
    logger        *log.Logger
    child         IModule                                    // 具体子类引用
    name          string
    mType         uint8                                      // KPROBE / UPROBE 等
    eventMaps     []*ebpf.Map                                // 事件输出 Map
    eventFuncMaps map[*ebpf.Map]IEventStruct                 // Map → 解码器映射
}

// 模板方法：Run() 定义算法骨架，具体步骤由子类实现
func (m *Module) Run() error {
    m.child.Start()      // 子类：加载 BPF 程序
    m.readEvents()       // 基类：事件读取循环
}

// readEvents() 根据 Map 类型自动选择读取策略
func (m *Module) readEvents() {
    for _, event := range m.child.Events() {
        switch event.Type() {
        case ebpf.PerfEventArray:
            go m.perfEventReader(errChan, event)
        case ebpf.RingBuf:
            go m.ringbufEventReader(errChan, event)
        }
    }
}
```

### 6.4 设计模式运用

| 设计模式 | 应用位置 | 说明 |
|---------|---------|------|
| **模板方法** | `Module.Run()` / `readEvents()` | 基类定义流程骨架，子类实现 `Start()`/`Events()`/`DecodeFun()` |
| **策略模式** | `perfEventReader` / `ringbufEventReader` | 根据 Map 类型动态选择读取策略 |
| **工厂注册** | `register.go` + 各 `init()` | 全局注册表 + init() 自动注册，main 统一获取 |
| **适配器** | `ebpfmanager` | 封装 `cilium/ebpf` 底层 API，提供声明式配置 |
| **原型** | `IEventStruct.Clone()` | 每次事件解码使用新实例，避免并发竞争 |

---

## 7. 内核态 eBPF 探针详解

### 7.1 进程事件探针（proc_kern.c）

**Hook 点：** `kretprobe/copy_process`
**触发时机：** 内核创建新进程（fork/clone）返回时
**Map 类型：** RingBuf（高性能环形缓冲区）

**数据结构：**

```c
typedef struct _process_info_t {
    int type;                    // 事件类型（FORK）
    pid_t child_pid;             // 子进程 PID
    pid_t child_tgid;            // 子线程组 ID
    pid_t parent_pid;            // 父进程 PID
    pid_t parent_tgid;           // 父线程组 ID
    pid_t grandparent_pid;       // 祖父进程 PID（进程树回溯）
    pid_t grandparent_tgid;      // 祖父线程组 ID
    uid_t uid;                   // 用户 ID
    gid_t gid;                   // 组 ID
    int cwd_level;               // 当前工作目录深度
    u32 uts_inum;                // UTS namespace ID（容器识别）
    __u64 start_time;            // 进程启动时间戳
    char comm[16];               // 进程名称（task_struct->comm）
    char cmdline[128];           // 完整命令行参数
    char filepath[128];          // 可执行文件路径
} proc_info_t;
```

**关键实现逻辑：**

```c
SEC("kretprobe/copy_process")
int kretprobe_copy_process(struct pt_regs *ctx) {
    // 1. 从返回值获取新创建的 task_struct
    struct task_struct *task = (struct task_struct *)PT_REGS_RC(ctx);

    // 2. 使用 CO-RE 读取进程树信息
    pid_t child_pid  = BPF_CORE_READ(task, pid);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    struct task_struct *gparent = BPF_CORE_READ(parent, real_parent);

    // 3. 读取命令行（从用户空间内存）
    struct mm_struct *mm = READ_KERN(task->mm);
    unsigned long args_start = READ_KERN(mm->arg_start);
    unsigned long args_end = READ_KERN(mm->arg_end);
    bpf_probe_read_user(info->cmdline, len, (void *)args_start);

    // 4. 通过 RingBuf 输出事件
    proc_info_t *info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
    // ... 填充字段 ...
    bpf_ringbuf_submit(info, 0);
}
```

**进程树关系：**

```
grandparent (pppid) → parent (ppid) → child (pid)
       │                    │                │
       └── 完整进程链路追溯，用于检测进程注入/提权攻击
```

---

### 7.2 TCP 连接追踪探针（tcp_set_state_kern.c）

**Hook 点：** `kprobe/tcp_set_state`
**触发时机：** TCP 连接状态每次变更时
**Map 类型：** PerfEventArray
**状态追踪 Map：** BPF_MAP_TYPE_HASH（key = `struct sock *`）

**连接追踪状态机：**

```
出站连接 (OUTBOUND):
  ┌───────────┐   kprobe触发   ┌────────────────┐   kprobe触发   ┌───────────┐
  │ TCP_CLOSE │ ────────────→ │ TCP_SYN_SENT   │ ────────────→ │ TCP_EST.  │
  └───────────┘               │ flags=OUTBOUND │               └───────────┘
                              │ 写入 conns map │                     │
                              └────────────────┘               kprobe触发
                                                                    │
入站连接 (INBOUND):                                                  ▼
  ┌───────────┐   kprobe触发   ┌────────────────┐            ┌───────────┐
  │ TCP_LISTEN│ ────────────→ │ TCP_ESTABLISHED│            │ TCP_CLOSE │
  └───────────┘               │ flags=INBOUND  │            │ 输出事件  │
                              │ 写入 conns map │            │ 删除 map  │
                              └────────────────┘            └───────────┘
```

**事件数据结构：**

```c
struct event_t {
    u64 start_ns;    // 连接建立时间（纳秒精度）
    u64 end_ns;      // 连接关闭时间
    u32 pid;         // 进程 ID
    u32 laddr;       // 本地 IPv4 地址
    u16 lport;       // 本地端口
    u32 raddr;       // 远端 IPv4 地址
    u16 rport;       // 远端端口
    u8  flags;       // F_OUTBOUND(0x01) | F_CONNECTED(0x02)
    u64 rx_b;        // 接收字节数（tcp_sock->bytes_received）
    u64 tx_b;        // 发送字节数（tcp_sock->bytes_acked）
    char task[16];   // 进程名称
    u16 family;      // 地址族（AF_INET）
    u32 uid;         // 用户 ID
};
```

**关键技巧——流量统计：**

```c
// 从 tcp_sock 结构体直接读取内核维护的流量计数器
struct tcp_sock *tp = (struct tcp_sock *)sk;
conn.rx_b = READ_KERN(tp->bytes_received);
conn.tx_b = READ_KERN(tp->bytes_acked);
// 无需在 eBPF 中自行累计，零开销获取精确流量
```

---

### 7.3 DNS 解析追踪探针（dns_lookup_kern.c）

**Hook 点：**
- `uprobe/getaddrinfo` — libc 函数入口
- `uretprobe/getaddrinfo` — libc 函数返回

**追踪流程：**

```
应用程序调用 getaddrinfo("example.com", ...)
                    │
                    ▼
   ┌─── uprobe Entry ───────────────────────────┐
   │ 1. 读取第一个参数：hostname ("example.com") │
   │ 2. 读取第四个参数：addrinfo **res 指针      │
   │ 3. 以 PID 为 key 存入 HashMap               │
   └────────────────────────────────────────────┘
                    │
                    │  getaddrinfo() 执行 DNS 查询...
                    │
                    ▼
   ┌─── uretprobe Return ──────────────────────┐
   │ 1. 用 PID 从 HashMap 恢复上下文            │
   │ 2. 读取 *res → 获取 addrinfo 链表头        │
   │ 3. 遍历链表（最多 9 个条目）：              │
   │    ├─ AF_INET → 提取 IPv4 地址             │
   │    └─ AF_INET6 → 提取 IPv6 地址            │
   │ 4. 输出到 PerfEventArray                    │
   └────────────────────────────────────────────┘
```

**特殊技术难点：**

```c
// 在 eBPF 中遍历用户空间链表（需要 bpf_probe_read）
for (int i = 0; i < 9; i++) {   // 循环次数必须编译期确定
    struct addrinfo ai;
    bpf_probe_read(&ai, sizeof(ai), cursor);

    if (ai.ai_family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read(&sin, sizeof(sin), ai.ai_addr);
        event.addr4[count++] = sin.sin_addr.s_addr;
    }

    if (ai.ai_next == NULL) break;
    cursor = ai.ai_next;
}
```

---

### 7.4 UDP DNS 报文捕获探针（udp_lookup_kern.c）

**Hook 点：**
- `kprobe/udp_recvmsg` — 入口，获取 msghdr 指针
- `kretprobe/udp_recvmsg` — 返回，读取实际数据

**工作原理：**

```c
// Entry: 过滤端口 53 并保存上下文
SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 dport = READ_KERN(inet_sk(sk)->inet_dport);

    if (ntohs(dport) != 53) return 0;  // 只关心 DNS 流量

    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    // 保存到 PerCPU HashMap
}

// Return: 读取 DNS 报文
SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
    // 从 PerCPU HashMap 恢复 msghdr
    // 通过 iov_iter 读取最多 512 字节 DNS 数据
    bpf_probe_read(&data->pkt, len, iov_base);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, ...);
}
```

**用户态解析：**

```go
// 使用 rawdns 库解析原始 DNS 报文
msg, err := rawdns.Decode(event.Pkt[:])
for _, answer := range msg.Answers {
    // 提取域名、IP、TTL 等信息
}
```

---

### 7.5 Socket 连接监控探针（sec_socket_connect_kern.c）

**Hook 点：** `kprobe/security_socket_connect`
**功能：** 捕获所有 `connect()` 系统调用的目标地址

**三种事件类型：**

```c
// IPv4 连接事件
struct ipv4_event_t {
    u64 ts_us;     u32 pid;    u32 uid;     u32 af;
    u32 laddr;     u16 lport;  u32 daddr;   u16 dport;
    char task[16];
};

// IPv6 连接事件
struct ipv6_event_t {
    u64 ts_us;     u32 pid;    u32 uid;     u32 af;
    char task[16];
    unsigned __int128 daddr;    u16 dport;
};

// 其他类型 Socket（排除 Unix Socket）
struct other_socket_event_t {
    u64 ts_us;     u32 pid;    u32 uid;     u32 af;
    char task[16];
};
```

**独立 PerfEventArray：** 每种事件类型对应独立的 Map，用户态分别读取。

---

### 7.6 Java RASP 探针（java_exec_kern.c）

**Hook 点：** `uprobe/JDK_execvpe`
**目标：** libjava.so 中的 `JDK_execvpe` 函数
**偏移量：** `0x19C30`（JDK 8u292 特定，不同版本需调整）

```c
SEC("uprobe/JDK_execvpe")
int java_execvpe(struct pt_regs *ctx) {
    struct jdk_execvpe event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.mode = (u64)PT_REGS_PARM1(ctx);      // fork/vfork/clone/posix_spawn
    bpf_probe_read_user_str(event.file, sizeof(event.file),
                            (void *)PT_REGS_PARM2(ctx));  // 被执行的命令

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}
```

**执行模式枚举：**

| 模式值 | 含义 | 安全风险 |
|-------|------|---------|
| 1 = MODE_FORK | fork + exec | 标准方式 |
| 2 = MODE_POSIX_SPAWN | posix_spawn | 较轻量 |
| 3 = MODE_VFORK | vfork + exec | 共享内存 |
| 4 = MODE_CLONE | clone | 最灵活 |

---

### 7.7 BPF 系统调用追踪探针（bpf_call_kern.c）

**Hook 点：** `tracepoint/syscalls/sys_enter_bpf`
**功能：** 捕获系统中所有 BPF 系统调用，包含完整调用者进程信息
**复杂度：** 本项目中最复杂的探针（309 行）

**数据结构：**

```c
struct proc_common {
    __u32 pid, tgid;              // 当前进程
    __u32 nspid, nstgid;          // Namespace 内 PID（容器场景）
    __u32 ppid, ptgid;            // 父进程
    __u32 nsppid, nsptgid;        // 父进程 Namespace PID
    __u32 pppid, pptgid;          // 祖父进程
    __u32 nspppid, nspptgid;      // 祖父进程 Namespace PID
    __u32 uid, euid;              // 真实/有效用户 ID
    __u32 gid, egid;              // 真实/有效组 ID
    __u32 uts_inum;               // UTS Namespace ID
    __u64 start_time;             // 进程启动时间
    __u8  comm[16];               // 进程名
    __u8  cmdline[256];           // 完整命令行
    __u8  uts_name[64];           // 主机名
};

struct bpf_context_t {
    __u32 cmd;                    // BPF 命令编号
    __u32 pending;                // 状态标记
    struct proc_common procinfo;  // 完整进程上下文
};
```

**关键技巧——规避 512 字节栈限制：**

```c
// eBPF 栈限制为 512 字节，bpf_context_t 远超此限制
// 解决方案：使用 LRU HashMap 作为"堆内存"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct bpf_context_t);
    __uint(max_entries, 2048);
} bpf_context SEC(".maps");

// 同时使用 PerCPU Array 作为临时缓冲区（避免竞争）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct bpf_context_t);
    __uint(max_entries, 1);
} bpf_context_gen SEC(".maps");
```

**Namespace PID 读取（容器感知）：**

```c
static __always_inline u32 get_task_ns_pid(struct task_struct *task) {
    unsigned int level = READ_KERN(task->thread_pid->level);
    return READ_KERN(task->thread_pid->numbers[level].nr);
}

static __always_inline u32 get_uts_ns_id(struct task_struct *task) {
    return READ_KERN(task->nsproxy->uts_ns->ns.inum);
}
```

---

## 8. 用户态 Go 模块详解

### 8.1 模块注册机制

```go
// register.go — 全局注册表
var modules = make(map[string]IModule)

func Register(p IModule) {
    if p == nil { panic("Register: nil module") }
    name := p.Name()
    if _, dup := modules[name]; dup {
        panic(fmt.Sprintf("Register: duplicate module %s", name))
    }
    modules[name] = p
}

func GetModules() map[string]IModule { return modules }
```

```go
// probe_proc.go — 各探针的 init() 自动注册
func init() {
    mod := &MProcProbe{}
    mod.name = "EBPFProbeProc"
    mod.mType = PROBE_TYPE_KPROBE
    Register(mod)
}
```

**注册的全部模块：**

| 模块名 | 文件 | 类型 |
|-------|------|------|
| `EBPFProbeProc` | probe_proc.go | KPROBE |
| `EBPFProbeTCP` | probe_ktcp.go | KPROBE |
| `EBPFProbeUDNS` | probe_udns.go | UPROBE |
| `EBPFProbeKUDP` | probe_kudp.go | KPROBE |
| `EBPFProbeTCPSec` | probe_ktcp_sec.go | KPROBE |
| `EBPFProbeJavaRASP` | probe_ujava_rasp.go | UPROBE |
| `EBPFProbeBPFCall` | probe_bpf_call.go | TRACEPOINT |

### 8.2 探针加载流程（以 TCP 为例）

```go
func (m *MTCPProbe) Start() error {
    // 1. 读取嵌入的 BPF 字节码
    byteBuf, err := assets.Asset("user/bytecode/tcp_set_state_kern.o")

    // 2. 声明式定义 BPF Manager 配置
    m.bpfManager = &manager.Manager{
        Probes: []*manager.Probe{
            {
                Section:          "kprobe/tcp_set_state",
                EbpfFuncName:     "kprobe_tcp_set_state",
                AttachToFuncName: "tcp_set_state",
            },
        },
        Maps: []*manager.Map{
            { Name: "events" },
            { Name: "conns" },
        },
    }

    // 3. 加载 BPF 程序到内核
    err = m.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), manager.Options{
        DefaultKProbeMaxActive: 512,
        VerifierOptions: ebpf.CollectionOptions{
            Programs: ebpf.ProgramOptions{
                LogSize: 2097152,   // 2MB verifier log
            },
        },
    })

    // 4. 启动（挂载到 Hook 点）
    err = m.bpfManager.Start()

    // 5. 关联事件 Map 与解码函数
    m.eventMaps = append(m.eventMaps, eventsMap)
    m.eventFuncMaps[eventsMap] = &TCPEvent{}
}
```

### 8.3 事件解码流程（以 TCP 为例）

```go
type TCPEvent struct {
    StartNS int64       // 连接开始时间
    EndNS   int64       // 连接结束时间
    PID     uint32      // 进程 ID
    LAddr   uint32      // 本地 IPv4（网络序）
    LPort   uint16      // 本地端口
    RAddr   uint32      // 远端 IPv4（网络序）
    RPort   uint16      // 远端端口
    Flags   uint8       // 出站/入站标志
    Rx      uint64      // 接收字节数
    Tx      uint64      // 发送字节数
    Comm    [16]byte    // 进程名
    Family  uint16      // 地址族
    UID     uint32      // 用户 ID
}

func (e *TCPEvent) Decode(payload []byte) error {
    buf := bytes.NewBuffer(payload)
    // 按照 C 结构体在内存中的布局顺序，逐字段读取
    if err := binary.Read(buf, binary.LittleEndian, &e.StartNS); err != nil {
        return err
    }
    if err := binary.Read(buf, binary.LittleEndian, &e.EndNS); err != nil {
        return err
    }
    // ... 其余字段同理
    return nil
}

func (e *TCPEvent) String() string {
    src := inet_ntop(e.LAddr)
    dst := inet_ntop(e.RAddr)
    duration := (e.EndNS - e.StartNS) / 1e6  // 毫秒
    return fmt.Sprintf("PID:%d %s %s:%d → %s:%d (rx:%d tx:%d dur:%dms)",
        e.PID, trimNull(e.Comm), src, e.LPort, dst, e.RPort,
        e.Rx, e.Tx, duration)
}

func (e *TCPEvent) Clone() IEventStruct { return new(TCPEvent) }
```

### 8.4 BPF 命令枚举（bpf_cmd.go）

```go
// 映射 Linux 内核 bpf_cmd 枚举，用于 BPF syscall 追踪事件的可读输出
const (
    BPF_MAP_CREATE          = 0
    BPF_MAP_LOOKUP_ELEM     = 1
    BPF_MAP_UPDATE_ELEM     = 2
    BPF_MAP_DELETE_ELEM     = 3
    BPF_MAP_GET_NEXT_KEY    = 4
    BPF_PROG_LOAD           = 5
    BPF_OBJ_PIN             = 6
    BPF_OBJ_GET             = 7
    BPF_PROG_ATTACH         = 8
    BPF_PROG_DETACH         = 9
    BPF_PROG_TEST_RUN       = 10
    // ... 完整枚举
)
```

---

## 9. 端到端数据流分析

### 9.1 完整数据流路径

```
┌──────────────────────────────────────────────────────────────────────┐
│                          用户应用程序                                │
│                  (curl / wget / java / any process)                 │
└───────┬──────────────────────────────────────────────────────────────┘
        │ 系统调用 (connect / fork / bpf / ...)
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Linux 内核                                   │
│                                                                     │
│  ┌─── eBPF 探针 ────────────────────────────────────────────────┐  │
│  │ kprobe / uprobe / tracepoint 触发                            │  │
│  │                                                               │  │
│  │  1. 读取函数参数（PT_REGS_PARMx）                             │  │
│  │  2. 读取内核结构体（BPF_CORE_READ / bpf_probe_read）         │  │
│  │  3. 读取用户空间内存（bpf_probe_read_user）                   │  │
│  │  4. 填充事件结构体                                            │  │
│  │  5. 输出到 Map                                                │  │
│  │     ├─ bpf_perf_event_output() → PerfEventArray               │  │
│  │     └─ bpf_ringbuf_submit()   → RingBuf                      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                    ┌──────┴──────┐                                  │
│                    │  BPF Maps   │                                  │
│                    │ (共享内存)  │                                  │
│                    └──────┬──────┘                                  │
└───────────────────────────┼─────────────────────────────────────────┘
                            │ 内核→用户态（mmap 零拷贝）
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Go 用户态程序                                    │
│                                                                     │
│  ┌─── perfEventReader / ringbufEventReader ─────────────────────┐  │
│  │                                                               │  │
│  │  1. reader.Read() 阻塞等待事件                                │  │
│  │  2. 获取 RawSample ([]byte)                                   │  │
│  │  3. DecodeFun(map) → 获取对应 IEventStruct                    │  │
│  │  4. event.Clone() → 创建新实例                                │  │
│  │  5. event.Decode(payload) → 二进制解码到结构体                │  │
│  │  6. event.String() → 格式化输出                               │  │
│  │  7. logger.Println() → 写入日志                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                            │                                        │
│                            ▼                                        │
│                    ┌───────────────┐                                │
│                    │  stdout/日志  │                                │
│                    │  (可扩展为    │                                │
│                    │  Kafka/ES等)  │                                │
│                    └───────────────┘                                │
└──────────────────────────────────────────────────────────────────────┘
```

### 9.2 PerfEventArray vs RingBuf 对比

| 特性 | PerfEventArray | RingBuf |
|------|---------------|---------|
| 内核版本要求 | >= 4.14 | >= 5.8 |
| 使用模块 | TCP、DNS、UDP、Socket、Java、BPF | Proc |
| 内存模型 | Per-CPU 独立 buffer | 全局共享 buffer |
| 事件顺序 | 不保证跨 CPU 有序 | 全局有序 |
| 内存效率 | 每个 CPU 独立分配，可能浪费 | 共享使用，更高效 |
| API | `bpf_perf_event_output()` | `bpf_ringbuf_reserve/submit()` |

---

## 10. 关键实现技巧

### 10.1 规避 eBPF 512 字节栈限制

```c
// 问题：大结构体无法放在 eBPF 栈上
// struct bpf_context_t 大小 > 512 字节 → 验证器拒绝

// 解决方案：使用 PerCPU Array 作为"堆内存"
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // 每 CPU 独立，无竞争
    __type(key, u32);
    __type(value, struct bpf_context_t);       // 大结构体存这里
    __uint(max_entries, 1);                    // 只需 1 个条目
} bpf_context_gen SEC(".maps");

// 使用方式
u32 key_gen = 0;
struct bpf_context_t *ctx = bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
if (!ctx) return 0;
// 现在可以安全地操作大结构体了
```

### 10.2 用户空间内存安全读取

```c
// 读取进程命令行参数
struct mm_struct *mm = READ_KERN(task->mm);
long unsigned int args_start = READ_KERN(mm->arg_start);
long unsigned int args_end = READ_KERN(mm->arg_end);

// 计算长度并限制范围
int len = (args_end - args_start);
len = len & 0x7F;  // 位运算代替 min()，验证器更容易接受

bpf_probe_read_user(info->cmdline, len, (const void *)args_start);
```

### 10.3 HashMap 状态追踪模式

```c
// TCP 连接状态追踪典型模式：
// 1. 事件入口：写入临时状态
bpf_map_update_elem(&conns, &sk, &conn, BPF_ANY);

// 2. 后续事件：查找并更新状态
struct conn_t *pconn = bpf_map_lookup_elem(&conns, &sk);
if (pconn) {
    pconn->flags |= F_CONNECTED;
}

// 3. 事件完成：输出并清理
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, pconn, sizeof(*pconn));
bpf_map_delete_elem(&conns, &sk);
```

### 10.4 循环安全（eBPF 验证器约束）

```c
// eBPF 禁止无界循环，必须编译期确定循环次数
// DNS 链表遍历：最多 9 个条目
#define MAX_DNS_ENTRIES 9

for (int i = 0; i < MAX_DNS_ENTRIES; i++) {
    // ... 处理 addrinfo 节点
    if (ai.ai_next == NULL) break;
    cursor = ai.ai_next;
}
// 如果实际链表更长，后续节点将被截断
```

### 10.5 IP 地址转换（Go 侧）

```go
// 将 uint32 网络序转为可读 IP
func inet_ntop(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
```

---

## 11. CO-RE 跨版本兼容机制

### 11.1 条件编译架构

```c
// ehids_agent.h — CO-RE 与 NOCORE 双模式
#ifndef NOCORE
    // CO-RE 模式：使用 BTF 信息实现跨版本兼容
    #include "vmlinux.h"              // bpftool 从运行内核生成
    #include "bpf/bpf_helpers.h"
    #include "bpf/bpf_tracing.h"
    #include "bpf/bpf_core_read.h"

    #define READ_KERN(ptr) BPF_CORE_READ(ptr)
#else
    // NOCORE 模式：使用标准 kernel headers
    #include <linux/kconfig.h>
    #include <linux/sched.h>
    #include <linux/types.h>
    // ...

    #define READ_KERN(ptr) ({ typeof(ptr) _val; bpf_probe_read(&_val, sizeof(_val), &(ptr)); _val; })
#endif
```

### 11.2 CO-RE 工作原理

```
编译时（开发机）:
  ┌──────────────┐     ┌──────────────┐
  │ vmlinux.h    │────→│ BPF 字节码   │
  │ (结构体定义) │     │ + BTF 重定位 │
  └──────────────┘     │   信息       │
                       └──────┬───────┘
                              │
运行时（目标机）:              │
  ┌──────────────┐     ┌──────▼───────┐     ┌──────────────┐
  │ 目标内核 BTF │────→│ BPF 加载器   │────→│ 调整后的     │
  │ (实际偏移量) │     │ (自动重定位) │     │ BPF 程序     │
  └──────────────┘     └──────────────┘     └──────────────┘

示例：
  编译时 task_struct->pid 偏移 = 0x50
  目标机 task_struct->pid 偏移 = 0x58
  → 加载器自动将 0x50 替换为 0x58
```

---

## 12. 资源打包与发布

### 12.1 BPF 字节码嵌入方案

```
┌─ 编译阶段 ─────────────────────────────────────────────────┐
│                                                             │
│  kern/*.c  ──clang──→  user/bytecode/*.o  ──go-bindata──→  │
│                                                             │
│  assets/ebpf_probe.go:                                     │
│    func Asset(name string) ([]byte, error)                 │
│    // 返回指定 .o 文件的字节码                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ 运行阶段 ─────────────────────────────────────────────────┐
│                                                             │
│  byteBuf, _ := assets.Asset("user/bytecode/proc_kern.o")   │
│  bpfManager.InitWithOptions(bytes.NewReader(byteBuf), ...) │
│                                                             │
│  // 最终二进制是完全自包含的，无需额外文件                    │
│  // 单文件部署：scp ehids-agent target:/usr/local/bin/     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 12.2 发布构建

```makefile
# builder/Makefile.release
# 用于 GitHub Actions 自动构建和发布
# 支持 cross-compilation 和版本标记
```

---

## 13. 性能与安全约束

### 13.1 内核版本要求

| 功能 | 最低版本 | 说明 |
|------|---------|------|
| 基础 eBPF | 4.14 | kprobe + PerfEventArray |
| uprobe | 4.17 | 用户态函数追踪 |
| CO-RE | 5.2 | 跨版本兼容（需 BTF） |
| RingBuf | 5.8 | 高性能事件输出 |
| BTF | 5.2+ | 需内核编译时开启 CONFIG_DEBUG_INFO_BTF |

### 13.2 eBPF 验证器约束

| 约束 | 限制值 | 项目应对策略 |
|------|-------|-------------|
| 栈大小 | 512 字节 | 使用 PerCPU Array / LRU HashMap 作为堆 |
| 指令数 | 100万（5.2+） | 拆分为多个独立 BPF 程序 |
| 循环 | 必须有界 | 编译期常量循环次数（如 DNS 最多 9 条） |
| 内存访问 | 需验证安全 | 全部使用 bpf_probe_read / BPF_CORE_READ |

### 13.3 Map 容量配置

| Map 名称 | 类型 | 容量 | 所属模块 |
|---------|------|------|---------|
| `conns` | HashMap | 10240 | TCP 连接追踪 |
| `tuplepid` | HashMap | 1024 | DNS 上下文 |
| `active_dns` | HashMap | 1024 | UDP DNS 上下文 |
| `bpf_context` | LRU HashMap | 2048 | BPF syscall |
| `bpf_context_gen` | PerCPU Array | 1 | BPF syscall（临时缓冲） |

### 13.4 潜在性能瓶颈

1. **PerfEventArray 事件丢失**：高负载时 buffer 可能溢出
2. **HashMap 满**：TCP 连接数超过 10240 时新连接被忽略
3. **用户态处理延迟**：Go GC 暂停可能导致事件堆积
4. **DNS 链表截断**：超过 9 条 DNS 记录的查询会丢失后续结果

---

## 14. 应用场景

### 14.1 主机入侵检测（HIDS）

```
┌─ 检测能力 ─────────────────────────────────────────────┐
│                                                         │
│  进程监控：                                             │
│  ├─ 异常进程创建（反弹 Shell、挖矿程序）               │
│  ├─ 进程树异常（Web 服务 → /bin/sh）                   │
│  └─ 高权限命令执行（uid=0 的敏感操作）                 │
│                                                         │
│  网络监控：                                             │
│  ├─ 异常外联（连接已知恶意 IP）                        │
│  ├─ DNS 隧道检测（异常 DNS 查询模式）                  │
│  └─ 横向移动检测（内网端口扫描）                       │
│                                                         │
│  BPF 攻击检测：                                        │
│  ├─ 未授权 BPF 程序加载                                │
│  └─ BPF rootkit 植入                                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 14.2 容器安全

- **容器逃逸检测**：通过 UTS Namespace ID 识别容器边界
- **Namespace PID 映射**：精确关联容器内外进程
- **容器间通信监控**：追踪跨容器网络连接

### 14.3 Java 应用安全（RASP）

- **命令注入检测**：拦截 Java 应用执行系统命令
- **RCE 漏洞利用感知**：检测 Java 反序列化漏洞利用
- **无侵入式部署**：无需修改 Java 应用代码

---

## 15. 技术总结

### 15.1 架构优势

| 维度 | 设计选择 | 收益 |
|------|---------|------|
| **可扩展性** | 模块注册 + 接口抽象 | 新增探针只需实现接口，无需修改框架 |
| **跨版本** | CO-RE + NOCORE 双模式 | 覆盖 4.14 ~ 最新内核 |
| **部署** | go-bindata 资源嵌入 | 单二进制文件，零依赖部署 |
| **性能** | 内核态过滤 + 零拷贝传输 | 最小化数据拷贝和用户态开销 |
| **安全** | kprobe + uprobe + tracepoint | 多层次、多维度安全事件采集 |

### 15.2 BPF Map 技术矩阵

| Map 类型 | 用途 | 使用场景 |
|---------|------|---------|
| **PerfEventArray** | 内核→用户态事件传输 | 大多数事件输出 |
| **RingBuf** | 高性能事件传输 | 进程事件（需 5.8+） |
| **HashMap** | 状态追踪 / 上下文关联 | TCP 连接、DNS 查询上下文 |
| **LRU HashMap** | 自动淘汰的状态追踪 | BPF syscall 上下文 |
| **PerCPU Array** | 临时缓冲区 / 避免栈溢出 | 大结构体操作 |

### 15.3 代码量统计

| 类别 | 文件数 | 估计行数 | 说明 |
|------|--------|---------|------|
| 内核态 C 代码 | 7 | ~850 | 7 个 eBPF 探针 |
| 内核头文件 | 8 | ~1000 | BPF 辅助库 + 自定义头 |
| 用户态 Go 代码 | 21 | ~2000 | 模块框架 + 事件处理 |
| 构建脚本 | 2 | ~300 | Makefile |
| **总计** | **38+** | **~4150** | — |

### 15.4 扩展方向

1. **文件监控**：hook `vfs_write` / `security_file_open` 实现文件完整性检测
2. **内核模块监控**：hook `do_init_module` 检测内核 rootkit
3. **用户登录监控**：hook PAM 相关函数追踪登录事件
4. **网络包过滤**：使用 TC/XDP 程序实现深度包检测
5. **事件聚合上报**：接入 Kafka / Elasticsearch 构建完整 SIEM 系统
6. **告警引擎**：基于规则或 ML 模型的实时威胁检测

---

> **文档生成说明：** 本文档基于 ehids-agent 源码的完整分析，涵盖架构设计、内核态探针实现、用户态事件处理、构建系统等全部技术细节。
