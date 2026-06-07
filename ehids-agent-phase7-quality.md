# eHIDS-Agent 工程质量与性能深度分析报告

> 分析日期：2026-03-27
> 项目版本：基于 go 1.17 + cilium/ebpf v0.8.1 + ebpfmanager v0.2.2
> 分析范围：全部内核态 eBPF 程序（7个）、用户态 Go 代码（20个文件）、构建系统

---

## 1. 性能评估

### 1.1 每个 eBPF 程序的指令复杂度估算

| eBPF 程序 | Hook 类型 | 估算指令数 | 复杂度等级 | 关键路径分析 |
|-----------|----------|-----------|-----------|------------|
| `sec_socket_connect_kern.c` | kprobe/security_socket_connect | ~80-120 | **低** | 线性执行，3个分支（IPv4/IPv6/Other），每个分支 ~30 条指令，无循环 |
| `tcp_set_state_kern.c` | kprobe/tcp_set_state | ~150-200 | **中** | 状态机逻辑（SYN_SENT→ESTABLISHED→CLOSE），含 map 查找/更新/删除操作，使用 goto 跳转 |
| `dns_lookup_kern.c` | uprobe/getaddrinfo + uretprobe | ~100-150 | **中** | entry 函数 ~40 条，return 函数含有限循环（max 9 次迭代，实际 break 后仅 1 次）|
| `udp_lookup_kern.c` | kprobe/udp_recvmsg + kretprobe | ~120-180 | **中** | kretprobe 路径较长，含多次 map 操作和 verifier 兼容性处理（`buflen & 0x1ff`）|
| `java_exec_kern.c` | uprobe/JDK_execvpe | ~40-60 | **低** | 简单的参数读取和输出，无循环、无 map 状态 |
| `proc_kern.c` | kretprobe/copy_process | ~80-120 | **中** | 大量 BPF_CORE_READ 链式读取（task→real_parent→real_parent），使用 RingBuf |
| `bpf_call_kern.c` | tracepoint/sys_enter_bpf | ~300-500 | **高** | `get_common_proc()` 函数极其复杂，包含 ~20 次 READ_KERN 宏展开，获取三级进程信息（当前/父/祖父），辅助函数链较长 |

**指令复杂度风险评估：**

- `bpf_call_kern.c` 的 `get_common_proc()` 是整个项目中最复杂的 eBPF 函数，每次调用涉及大量内核结构体遍历。在 eBPF 验证器限制（100万条指令，旧内核 4096 条）下存在一定风险。
- `bpf_call_kern.c` 中 `print_debug()` 在 `#if 1` 条件下始终编译，包含 10 次 `bpf_trace_printk` 调用，**这在生产环境中会严重影响性能**。

### 1.2 预估的 CPU 和内存开销

#### CPU 开销

| 模块 | 触发频率（典型服务器） | 单次开销 | 总 CPU 影响 |
|------|---------------------|---------|------------|
| security_socket_connect | 每次 connect() 调用 | ~200-500ns | **中等**，高并发网络服务器上可能达 1-3% |
| tcp_set_state | 每次 TCP 状态变化 | ~300-800ns | **低-中等**，仅在 TCP 建连/断开时触发 |
| udp_recvmsg | 每次 UDP 接收 | ~100ns（非 53 端口直接返回） | **极低**，端口过滤在 kprobe 入口完成 |
| copy_process | 每次 fork/clone | ~500-1000ns | **低**，进程创建频率通常不高 |
| sys_enter_bpf | 每次 bpf() 系统调用 | ~1-3us | **低**，BPF 系统调用频率极低 |
| getaddrinfo (uprobe) | 每次 DNS 解析 | ~300-600ns | **低**，DNS 查询频率通常不高 |
| JDK_execvpe (uprobe) | Java 进程 exec 时 | ~200-400ns | **极低**，仅 Java 进程执行命令时触发 |

#### 内存开销

| 资源类型 | 来源 | 大小估算 |
|---------|------|---------|
| eBPF 程序指令内存 | 7 个 BPF 程序 | ~50-100 KB |
| PerfEvent buffer (默认) | 各模块 `os.Getpagesize()` = 4KB | **极小，存在严重不足风险** |
| RingBuf (proc) | `1 << 24` = 16 MB | 合理 |
| Hash Map (conns) | `max_entries=10240`, 每条 ~37B | ~380 KB |
| Hash Map (tbl_udp_msg_hdr) | `max_entries=10240`, 每条 ~16B | ~164 KB |
| Hash Map (start/currres) | `max_entries=1024`, 每条 ~88B / ~8B | ~90 KB + ~8 KB |
| PERCPU_ARRAY (dns_data) | `max_entries=1`, 每 CPU ~532B | ~532B × CPU数 |
| LRU_HASH (bpf_context) | `max_entries=2048`, 每条 ~424B | ~848 KB |
| PERCPU_ARRAY (bufs) | `max_entries=3`, 每条 4096B | ~12 KB × CPU数 |
| **总计** | | **约 18-20 MB**（不含 per-CPU 缩放） |

### 1.3 在高负载场景下的表现（10000+ 事件/秒）

#### 严重问题：PerfEvent Buffer 严重不足

```go
// imodule.go:139 - perfEventReader
rd, err := perf.NewReader(em, os.Getpagesize())  // 仅 4KB！
```

**这是项目中最严重的性能瓶颈。** 在 10000+ 事件/秒的场景下：

- `ipv4_event_t` 大小约 46 字节 + perf header 约 16 字节 = ~62 字节/事件
- 4KB buffer 仅能容纳约 **65 个事件**
- 在 10000 事件/秒场景下，**每秒将丢失约 99.3% 的事件**
- 即使 1000 事件/秒也会导致大量丢失

唯一例外：`MBPFCallProbe` 使用了 `PerfRingBufferSize: 1 * os.Getpagesize()`（probe_bpf_call.go:59），虽然也仅 4KB，但 BPF 系统调用频率极低，影响不大。

#### 用户态处理瓶颈

```go
// imodule.go:176 - 每个事件都执行 Write
this.Write(result)  // 实际是 logger.Println，同步写入
```

- `Write()` 方法直接调用 `log.Println`，这是同步阻塞操作
- 在高负载下，日志 I/O 会成为反压源，进一步加剧 perf buffer 溢出
- 没有批量处理、异步写入或采样机制

#### 事件读取的 context 检查开销

```go
// imodule.go:146-152
for {
    select {
    case _ = <-this.ctx.Done():  // 每次循环都检查
        return
    default:
    }
    record, err := rd.Read()  // 阻塞读取
```

每次循环都执行 `select` + `ctx.Done()` 检查，在高频事件下增加不必要的开销。更好的做法是使用 `rd.SetDeadline()` 或监听 reader 的 close 信号。

### 1.4 PerfEventArray / RingBuf Buffer 大小配置分析

| Map 名称 | 类型 | 配置大小 | 推荐大小 | 评估 |
|----------|------|---------|---------|------|
| `ipv4_events` | PerfEventArray | 4 KB (1 page) | 256 KB - 1 MB | **严重不足** |
| `ipv6_events` | PerfEventArray | 4 KB | 256 KB - 1 MB | **严重不足** |
| `other_socket_events` | PerfEventArray | 4 KB | 64 KB | **不足** |
| `events` (tcp) | PerfEventArray | 4 KB | 256 KB - 1 MB | **严重不足** |
| `dns_events` | PerfEventArray | 4 KB | 128 KB | **不足** |
| `events` (dns_lookup) | PerfEventArray | 4 KB | 128 KB | **不足** |
| `jdk_execvpe_events` | PerfEventArray | 4 KB | 64 KB | 勉强可接受（频率低） |
| `events` (bpf_call) | PerfEventArray | 4 KB | 64 KB | 可接受（频率极低） |
| `ringbuf_proc` | RingBuf | **16 MB** | 4-16 MB | **合理** |

**关键发现：** `ringbuf_proc` 的 16MB 配置与其他 PerfEvent 的 4KB 配置形成鲜明对比，说明开发者对 RingBuf 有正确认知，但 PerfEvent 的配置可能是疏忽。

### 1.5 Map 内存占用详细估算

| Map 名称 | 类型 | max_entries | Value 大小 | 估算内存 | 风险点 |
|----------|------|------------|-----------|---------|--------|
| `conns` | HASH | 10240 | ~37B | ~380 KB | 长连接多时可能不够 |
| `tbl_udp_msg_hdr` | HASH | 10240 | ~8B | ~80 KB | 合理 |
| `start` | HASH | 1024 | ~84B | ~86 KB | 并发 DNS 查询多时不够 |
| `currres` | HASH | 1024 | ~8B | ~8 KB | 同上 |
| `dns_data` | PERCPU_ARRAY | 1 | 532B | ~532B × nCPU | 合理（Per-CPU 避免竞争） |
| `bpf_context` | LRU_HASH | 2048 | ~424B | ~848 KB | LRU 策略合理 |
| `bpf_context_gen` | ARRAY | 1 | ~424B | ~424B | 合理（模板用途） |
| `bufs` | PERCPU_ARRAY | 3 | 4096B | ~12KB × nCPU | 合理 |
| `ringbuf_proc` | RINGBUF | - | - | 16 MB | 固定开销 |
| **PerfEventArray** (7个) | PerfEvent | nCPU | 4KB | ~28KB × nCPU | 极小但不够 |
| **总计** | | | | **~18-20 MB** (8核机器) | |

---

## 2. 代码质量

### 2.1 代码组织和模块化程度评分：6/10

**优点：**
- 清晰的层次结构：`kern/`（内核态）、`user/`（用户态）、`assets/`（嵌入资源）
- 接口设计合理：`IModule`、`IEventStruct`、`IClose` 三个接口定义清晰
- 模块注册机制（`register.go`）使用 `init()` 函数自动注册，可扩展性好
- 内核态文件命名规范统一：`*_kern.c`

**不足：**
- **用户态存在大量重复代码**：7 个 `probe_*.go` 文件结构几乎完全相同（Init→Start→setupManagers→initDecodeFun→Events→Close），仅 manager 配置不同。应抽取为通用基类或使用工厂模式。
- 事件解码文件（`event_*.go`）中 `Decode()` 方法全部使用逐字段 `binary.Read`，没有利用 `binary.Read` 可以直接读取整个 struct 的能力
- `bpf_call_kern.c` 与 `proc_kern.c` 使用了不同的进程信息获取方式（前者用 `READ_KERN` 宏 + 大量辅助函数，后者用 `BPF_CORE_READ`），缺乏统一性
- `common.h` 中定义了 `event` 和 `tr_file`、`tr_text` 结构体，但实际上**没有任何 eBPF 程序使用它们**

### 2.2 错误处理的完善程度：5/10

**问题清单：**

| 位置 | 问题 | 严重程度 |
|------|------|---------|
| `main.go:39` | 模块初始化失败直接 `panic`，未做优雅降级 | **高** |
| `main.go:44-48` | goroutine 中 `module.Run()` 错误仅日志打印，未影响主流程 | 中 |
| `imodule.go:130-136` | `readEvents()` 的 `errChan` 接收到第一个错误就返回，导致其他正常的 reader 被丢弃 | **高** |
| `imodule.go:139` | `perf.NewReader` 失败后通过 errChan 传递，但无法区分是哪个 map 失败 | 中 |
| `probe_bpf_call.go:133` | `dataHandler` 中 decode 失败调用 `logger.Fatalf` 导致**整个进程退出** | **严重** |
| `event_kudp.go:44` | `Decode` 中使用 `fmt.Printf` 直接打印到 stdout，不符合日志规范 | 低 |
| `bpf_call_kern.c:303` | `make_event()` 返回 0 时直接返回 0，无错误上报 | 低 |
| `proc_kern.c:73` | `bpf_ringbuf_reserve` 失败返回 -1，应返回 0（BPF 程序约定） | 中 |

**缺失的错误处理：**
- 没有 Graceful Shutdown 机制：`main.go` 收到信号后仅 `cancelFun()` + sleep 100ms，未等待所有模块关闭
- `Close()` 方法虽然定义了，但 `main.go` 中从未调用过
- PerfEvent 丢失事件仅打印日志（`imodule.go:163`），无指标统计
- `lostEventsHandle`（probe_bpf_call.go:142）是空实现，有 TODO 注释

### 2.3 资源泄漏风险

| 风险 | 位置 | 严重程度 | 说明 |
|------|------|---------|------|
| **eBPF Manager 未关闭** | `main.go` | **严重** | 主程序退出时未调用任何模块的 `Close()` 方法，eBPF 程序和 map 可能残留在内核中 |
| **Perf Reader 泄漏** | `imodule.go:138-178` | **中** | 虽然有 `defer rd.Close()`，但如果 goroutine 因 panic 退出，defer 可能不执行 |
| **Map 条目未清理** | `dns_lookup_kern.c` | **低** | `getaddrinfo_entry` 写入 `start` 和 `currres` map，如果 `getaddrinfo_return` 未被触发（如进程被 kill），map 条目将泄漏直到 map 满 |
| **同上** | `udp_lookup_kern.c` | **低** | `trace_udp_recvmsg` 写入 `tbl_udp_msg_hdr`，ret 未触发时泄漏 |
| **conns map 残留** | `tcp_set_state_kern.c` | **低** | 如果连接在 SYN_SENT 后未到达 TCP_CLOSE 就被 kill，conn 条目残留 |
| **Module.reader 切片未使用** | `imodule.go:44` | **低** | 定义了 `reader []IClose` 但从未写入或读取，dead code |

### 2.4 命名规范和代码风格一致性：5/10

**不一致问题：**

| 类别 | 问题 |
|------|------|
| Go 接收者命名 | 全部使用 `this` 作为方法接收者，不符合 Go 惯例（应使用类型首字母小写，如 `m *MTCPProbe`） |
| 变量命名 | 变量 `javaBuf` 在非 Java 相关的模块中也使用（如 `probe_ktcp.go:42`），造成误导 |
| 常量重复定义 | `TASK_COMM_LEN` 在 `common.h`、`sec_socket_connect_kern.c`、`tcp_set_state_kern.c`、`udp_lookup_kern.c`、`bpf_call_kern.c` 中重复定义 |
| `AF_INET`/`AF_INET6` | 在 `common.go`、`sec_socket_connect_kern.c`、`tcp_set_state_kern.c`、`dns_lookup_kern.c` 中各自独立定义 |
| 结构体字段风格 | Go 端 `ForkProcEvent` 混用驼峰和下划线（`Cwd_level`、`Start_time`） |
| C 结构体打包 | 部分使用 `__attribute__((packed))`，部分不使用，可能导致对齐问题 |
| 头文件守护宏 | `common.h` 使用 `ECAPTURE_COMMON_H`（疑似从 eCapture 项目复制），应为 `EHIDS_COMMON_H` |
| 错误消息 | `"cant found"` 应为 `"can't find"`（出现 5 次） |

### 2.5 注释和文档质量：4/10

**注释分析：**
- 中英文混合注释，缺乏统一规范
- 部分注释是有用的设计说明（如 `bpf_call_kern.c:280` 解释栈空间限制规避策略）
- 存在大量遗留 TODO 注释未完成：
  - `sec_socket_connect_kern.c:4`: `// TODO`
  - `dns_lookup_kern.c:113-118`: DNS 链表遍历 TODO，直接 break 退出
  - `udp_lookup_kern.c:106-107`: `// TODO: remove this`
  - `probe_bpf_call.go:141-144`: 事件丢失统计 TODO
- `bpf_call_kern.c` 中 `print_debug()` 在 `#if 1` 条件下始终启用，应改为 `#ifdef DEBUG_PRINT`
- 无 README、无 API 文档、无架构图

### 2.6 测试覆盖率：0/10

**项目中不存在任何测试文件（`*_test.go`）。**

缺失的测试：
- 无单元测试：事件 Decode/String 函数是纯函数，非常适合单元测试
- 无集成测试：无模块初始化/启动/停止流程测试
- 无 eBPF 程序测试：无 BPF 程序验证器加载测试
- 无基准测试：无 Decode 性能基准
- 无模糊测试：Decode 函数处理原始 byte 数据，适合 fuzz testing
- Makefile 中有 `make test` target 定义但无实际测试内容

---

## 3. 可维护性

### 3.1 新增 Hook 点的难度

**难度评估：中等**（需修改 5-6 个文件，约 200-300 行代码）

**步骤清单：**

1. **编写内核态 eBPF 程序** `kern/new_hook_kern.c`
   - 定义事件结构体
   - 定义 Map（PerfEventArray 或 RingBuf）
   - 实现 Hook 函数（kprobe/uprobe/tracepoint）
   - 约 50-100 行

2. **更新 Makefile**
   ```makefile
   TARGETS += kern/new_hook   # 添加一行
   ```

3. **编写事件解码** `user/event_new_hook.go`
   - 实现 `IEventStruct` 接口（Decode/String/Clone）
   - 约 40-80 行

4. **编写 Probe 模块** `user/probe_new_hook.go`
   - 复制现有模块结构（如 `probe_ktcp.go`），修改配置
   - 实现 Init/Start/Close/setupManagers/initDecodeFun/Events/DecodeFun
   - 在 `init()` 中调用 `Register(mod)`
   - 约 100-140 行（大量为模板代码）

5. **重新编译**
   ```bash
   make clean && make all
   ```

**痛点：** 步骤 4 中 90% 的代码是从现有模块复制粘贴，这是明显的 DRY 违规。理想情况下应该只需要提供一个配置结构体。

### 3.2 新增检测规则的难度

**当前项目没有检测规则引擎。** 所有事件直接输出到日志，没有：
- 规则定义语言或配置格式
- 事件过滤机制（除了内核态的端口过滤 `dport == 13568`）
- 告警阈值配置
- 白名单/黑名单机制

要新增检测规则，需要：
1. 设计规则引擎（DSL 或配置文件）
2. 在 `Write()` 方法前插入规则匹配逻辑
3. 实现告警输出通道

**当前难度：高**（需要新建整个规则子系统）

### 3.3 内核版本升级的适配成本

| 方面 | 成本评估 | 说明 |
|------|---------|------|
| CO:RE 支持 | **低** | 项目已支持 CO:RE（vmlinux.h + BPF_CORE_READ），`proc_kern.c` 使用了 CO:RE 读取 |
| 非 CO:RE 路径 | **高** | `bpf_call_kern.c` 使用 `READ_KERN` 宏（bpf_core_read），如果结构体偏移变化需手动适配 |
| kprobe 稳定性 | **中-高** | 5 个内核函数 hook（`security_socket_connect`, `tcp_set_state`, `udp_recvmsg`, `copy_process`, `sys_enter_bpf`）中，`security_socket_connect` 和 `tcp_set_state` 是非稳定内核 API |
| 结构体依赖 | **中** | 依赖 `struct sock`, `struct tcp_sock`, `struct task_struct`, `struct msghdr` 等内核结构体，版本间可能变化 |
| `udp_recvmsg` 签名变化 | **高风险** | 内核 5.19+ 修改了 `udp_recvmsg` 的函数签名（移除 `addr_len` 参数），当前代码使用 `PT_REGS_PARM2` 可能失效 |
| `iter.type` 字段 | **高风险** | `udp_lookup_kern.c:73` 检查 `iter.type != ITER_IOVEC`，此字段在内核 6.0+ 中被重命名为 `iter.iter_type` |
| Makefile 内核版本检测 | **低** | 已有 5.2 版本检测机制（`KERNEL_LESS_5_2_FLAGS`）|

### 3.4 代码复用和 DRY 原则遵循程度：3/10

**严重违反 DRY 的区域：**

1. **Probe 模块模板代码**（最严重）
   - `probe_ktcp.go`、`probe_ktcp_sec.go`、`probe_kudp.go`、`probe_proc.go`、`probe_udns.go`、`probe_ujava_rasp.go` 中 `Init()`、`Start()`、`start()`、`Close()` 方法结构完全相同
   - 仅 `setupManagers()` 和 `initDecodeFun()` 的配置不同
   - **建议：** 抽取 `GenericProbe` 基类，通过配置注入差异化部分

2. **Event Decode 模式**
   - 每个 `event_*.go` 的 `Decode()` 方法都是重复的 `binary.Read` 调用
   - **建议：** 对于固定大小结构体，直接使用 `binary.Read(buf, binary.LittleEndian, &event)` 一次性读取

3. **内核态常量重复定义**
   - `TASK_COMM_LEN`、`AF_INET`、`AF_INET6` 等在多个 .c 文件中重复定义
   - **建议：** 统一在 `common.h` 中定义

4. **Manager Options 配置**
   - 每个 probe 都配置相同的 `DefaultKProbeMaxActive: 512`、`LogSize: 2097152`、`RLimit` 值
   - **建议：** 提取默认配置函数

---

## 4. 部署与运维

### 4.1 部署方式分析

**当前部署方式：静态二进制 + 嵌入式 eBPF 字节码**

```makefile
# 编译流程
make ebpf    # clang 编译 .c → .o
make assets  # go-bindata 将 .o 嵌入 Go 代码
make build   # CGO_ENABLED=0 go build → 静态二进制
```

**优点：**
- 单一二进制文件，部署简单（`scp` + `chmod +x` + 运行）
- CGO_ENABLED=0 确保静态链接，无 libc 依赖
- 支持 CO:RE 和非 CO:RE 两种编译模式

**不足：**
- 需要 root 权限运行（eBPF 要求）
- 没有 systemd service 文件
- 没有 Docker/容器化部署方案
- 没有包管理（deb/rpm）
- 没有自动化部署脚本
- 嵌入式字节码方式导致更新 eBPF 程序必须重新编译整个二进制

**架构依赖：**
- 当前仅支持 x86_64 和 arm64
- uprobe（DNS/Java）依赖特定 libc/JDK 路径（硬编码）：
  - `/lib/x86_64-linux-gnu/libc.so.6`（Debian/Ubuntu 特有路径）
  - `/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so`（特定 JDK 版本）

### 4.2 配置管理能力：1/10

**项目几乎没有配置管理能力：**

- 没有配置文件（无 yaml/toml/json 配置）
- 没有命令行参数解析（无 flag/cobra/viper）
- 所有参数硬编码在代码中：
  - Buffer 大小：`os.Getpagesize()`
  - Map 大小：代码中固定
  - uprobe 路径：硬编码
  - 模块启停：通过注释 `Register(mod)` 控制（如 `probe_kudp.go:142`）
  - 调试开关：`main.go:31-33` 中通过注释控制模块过滤

**建议最低配置项：**
```yaml
modules:
  - name: tcp_state
    enabled: true
    buffer_size: 262144
  - name: proc
    enabled: true
  - name: dns_lookup
    enabled: true
    binary_path: "/lib/x86_64-linux-gnu/libc.so.6"
  - name: java_rasp
    enabled: false
    binary_path: "/usr/lib/jvm/..."
output:
  type: stdout  # stdout | file | kafka | grpc
  file_path: "/var/log/ehids.log"
```

### 4.3 日志和调试能力：3/10

**当前日志系统：**
- 使用标准库 `log.Default()`，仅输出到 stdout
- 无日志级别（debug/info/warn/error）
- 无结构化日志（无 JSON 输出）
- 无日志轮转
- 无指标暴露（Prometheus metrics / StatsD）

**调试能力：**
- 内核态：支持 `DEBUG_PRINT` 编译宏启用 `bpf_trace_printk`
- `bpf_call_kern.c` 的 `print_debug()` 始终启用（`#if 1`），非常不当
- 用户态：无 pprof 端点
- 无健康检查接口
- PerfEvent 丢失统计仅打印日志，无累计计数器

**缺失的关键运维能力：**
- 无 `/health` 或 `/ready` 端点
- 无 `/metrics` 端点
- 无事件统计（每秒处理量、丢失量、延迟分布）
- 无 eBPF 程序状态查询能力

### 4.4 升级和回滚策略

**当前状态：完全没有升级和回滚机制。**

- 没有版本管理 API
- 没有热升级能力（eBPF 程序嵌入二进制）
- 没有配置热更新
- 升级需要：停进程 → 替换二进制 → 启动进程
- 停止时 eBPF 程序未被清理（Close() 未调用），可能导致残留

**建议的最小升级策略：**
1. 实现 Graceful Shutdown（确保 eBPF 清理）
2. 使用 systemd 管理（`systemctl restart ehids-agent`）
3. 二进制版本化命名（`ehids-agent-v1.0.0`）
4. 保留前一版本用于回滚

### 4.5 依赖项的维护状态

| 依赖 | 版本 | 最新版本（2026-03） | 状态 | 风险 |
|------|------|-------------------|------|------|
| `cilium/ebpf` | v0.8.1 | v0.17+ | **严重过时** | 缺少大量 bug 修复和性能优化，安全风险 |
| `ehids/ebpfmanager` | v0.2.2 | 未活跃维护 | **高风险** | 项目可能已停止维护 |
| `go-bindata` | v4.0.0 | 已弃用 | **已弃用** | 应迁移到 Go 1.16+ 的 `embed` 包 |
| `cirocosta/rawdns` | 2019-12 | 未更新 | **停止维护** | 超过 6 年未更新 |
| `tredoe/osutil` | v1.0.6 | 不活跃 | **低风险** | |
| `pkg/errors` | v0.9.1 | 不再推荐 | **应迁移** | Go 1.13+ 标准库已有 `fmt.Errorf("%w")` |
| Go 版本 | 1.17 | 1.22+ | **严重过时** | 缺少泛型、安全补丁等 |

**关键建议：**
1. **立即升级** `cilium/ebpf` 到最新稳定版（修复内存泄漏、verifier 兼容性等问题）
2. 将 `go-bindata` 替换为 Go 内置的 `//go:embed` 指令
3. 评估 `ehids/ebpfmanager` 是否还在维护，考虑直接使用 `cilium/ebpf` 的 link 包
4. 升级 Go 版本到 1.21+

---

## 附录：关键问题优先级排序

### P0 - 必须立即修复

| # | 问题 | 影响 |
|---|------|------|
| 1 | PerfEvent buffer 仅 4KB，高负载下丢失 99%+ 事件 | 核心功能失效 |
| 2 | `main.go` 退出时未调用 `Close()`，eBPF 程序残留内核 | 资源泄漏 |
| 3 | `probe_bpf_call.go:133` decode 失败调用 `Fatalf` 导致进程崩溃 | 可用性 |
| 4 | `bpf_call_kern.c` 的 `print_debug()` 始终启用 | 生产性能 |

### P1 - 短期内应修复

| # | 问题 | 影响 |
|---|------|------|
| 5 | 依赖库严重过时（cilium/ebpf v0.8.1，Go 1.17） | 安全和兼容性 |
| 6 | 无配置文件，所有参数硬编码 | 运维困难 |
| 7 | uprobe 路径硬编码，非 Debian 系统无法运行 | 可移植性 |
| 8 | 无 Graceful Shutdown | 可靠性 |
| 9 | 同步日志输出成为高负载瓶颈 | 性能 |

### P2 - 中期改进

| # | 问题 | 影响 |
|---|------|------|
| 10 | 消除 probe 模块间的重复代码 | 可维护性 |
| 11 | 添加单元测试和集成测试 | 质量保证 |
| 12 | 添加 Prometheus 指标暴露 | 可观测性 |
| 13 | 添加结构化日志 | 运维 |
| 14 | 内核版本兼容性处理（udp_recvmsg 签名变化等） | 兼容性 |

---

## 总评

| 维度 | 评分 (1-10) | 说明 |
|------|------------|------|
| **性能** | 3 | PerfEvent buffer 严重不足是致命问题；RingBuf 配置合理；同步日志输出有瓶颈 |
| **代码质量** | 4 | 接口设计合理但实现有大量重复；错误处理不完善；无测试 |
| **可维护性** | 4 | 模块化有基础但 DRY 违反严重；新增 Hook 需修改 5+ 文件 |
| **部署与运维** | 2 | 单二进制部署简单，但几乎无配置/日志/监控/升级能力 |
| **安全性** | 3 | 依赖过时存在安全风险；无输入验证；硬编码路径 |
| **综合** | **3.2** | 作为 PoC/Demo 项目可接受，距离生产就绪差距较大 |

该项目展示了 eBPF HIDS 的核心架构思路，模块注册和接口设计有一定参考价值，但在性能调优、错误处理、配置管理、测试覆盖等工程化方面还需要大量工作才能达到生产级别。
