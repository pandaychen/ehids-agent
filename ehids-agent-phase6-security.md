# ehids-agent 安全分析报告（攻防对抗视角）

> 基于源码全量审计，从红队/蓝队双重视角分析 ehids-agent 的检测能力、绕过方式与自身安全性。

---

## 1. 检测覆盖面

### 1.1 模块与 Hook 点总览

ehids-agent 共包含 **7 个探测模块**，覆盖内核态和用户态两个层面：

| 模块名 | 类型 | Hook 点 | 功能描述 |
|--------|------|---------|---------|
| `EBPFProbeBPFCall` | tracepoint | `sys_enter_bpf` | 监控所有 bpf() 系统调用 |
| `EBPFProbeProc` | kretprobe | `copy_process` | 监控进程创建（fork） |
| `EBPFProbeKTCP` | kprobe | `tcp_set_state` | TCP 连接生命周期追踪 |
| `EBPFProbeKTCPSec` | kprobe | `security_socket_connect` | 出站 socket 连接监控 |
| `EBPFProbeKUDP` | kprobe/kretprobe | `udp_recvmsg` | UDP DNS 响应捕获（**未注册，已注释**） |
| `EBPFProbeUDNS` | uprobe | `getaddrinfo` (libc) | 用户态 DNS 解析监控 |
| `EBPFProbeUJavaRASP` | uprobe | `JDK_execvpe` (libjava.so) | Java 进程命令执行监控 |

### 1.2 MITRE ATT&CK 覆盖映射

#### Execution（执行）

| Technique ID | 技术名称 | 覆盖模块 | 覆盖程度 |
|-------------|---------|---------|---------|
| T1059 | Command and Scripting Interpreter | `EBPFProbeProc` | ⚠️ 部分 — 仅 fork 阶段，缺少 execve 监控 |
| T1059.004 | Unix Shell | `EBPFProbeProc` | ⚠️ 部分 — 无法区分 shell 类型 |
| T1059.007 | JavaScript (Node.js) | `EBPFProbeProc` | ⚠️ 部分 — 仅通过进程创建间接检测 |
| T1203 | Exploitation for Client Execution | `EBPFProbeUJavaRASP` | ⚠️ 仅覆盖 Java（JDK8 特定版本） |
| T1053.003 | Cron | — | ❌ 未覆盖 |

#### Defense Evasion（防御规避）

| Technique ID | 技术名称 | 覆盖模块 | 覆盖程度 |
|-------------|---------|---------|---------|
| T1014 | Rootkit (eBPF Rootkit) | `EBPFProbeBPFCall` | ✅ 可检测 bpf() 系统调用行为 |
| T1055 | Process Injection | — | ❌ 未覆盖 |
| T1140 | Deobfuscate/Decode Files | — | ❌ 未覆盖 |
| T1070 | Indicator Removal | — | ❌ 未覆盖 |
| T1036 | Masquerading | `EBPFProbeProc` | ⚠️ 部分 — 可获取 comm 但无 exe 路径对比 |

#### Discovery（发现）

| Technique ID | 技术名称 | 覆盖模块 | 覆盖程度 |
|-------------|---------|---------|---------|
| T1071.004 | DNS | `EBPFProbeUDNS` / `EBPFProbeKUDP` | ⚠️ 部分 — uprobe 仅覆盖 glibc getaddrinfo |
| T1046 | Network Service Discovery | `EBPFProbeKTCPSec` | ⚠️ 部分 — 可观察连接目的地 |

#### Command and Control（C2）

| Technique ID | 技术名称 | 覆盖模块 | 覆盖程度 |
|-------------|---------|---------|---------|
| T1071.001 | Web Protocols | `EBPFProbeKTCP` / `EBPFProbeKTCPSec` | ⚠️ 部分 — 仅 IP/Port 级别，无 HTTP 层解析 |
| T1071.004 | DNS C2 | `EBPFProbeUDNS` | ⚠️ 部分 — 可捕获 DNS 解析但无异常检测逻辑 |
| T1095 | Non-Application Layer Protocol | `EBPFProbeKTCPSec` | ⚠️ 部分 — 可监控非标准 socket family |
| T1572 | Protocol Tunneling | — | ❌ 未覆盖 |

#### Lateral Movement（横向移动）

| Technique ID | 技术名称 | 覆盖模块 | 覆盖程度 |
|-------------|---------|---------|---------|
| T1021 | Remote Services (SSH等) | `EBPFProbeKTCP` | ⚠️ 部分 — 仅 TCP 连接级别 |

#### Persistence（持久化）

| 覆盖程度 | 说明 |
|---------|------|
| ❌ 全部未覆盖 | 无文件监控（T1543/T1053/T1546等均未覆盖） |

#### Privilege Escalation（权限提升）

| 覆盖程度 | 说明 |
|---------|------|
| ❌ 基本未覆盖 | 无 `setuid`/`capset`/内核模块加载监控 |

### 1.3 已知检测盲区（Critical Gaps）

**严重盲区：**

1. **无 `execve`/`execveat` 监控** — `proc_kern.c` 仅 hook `copy_process`（fork 阶段），完全缺失 exec 阶段检测。攻击者执行的实际命令行、二进制路径在 exec 后才确定，fork 时获取的 cmdline 是**父进程**的信息
2. **无文件系统监控** — 无任何 FIM（File Integrity Monitoring）能力，无法检测 `/etc/crontab`、`/etc/passwd`、`.bashrc`、systemd unit 等关键文件的篡改
3. **无内核模块加载监控** — 未 hook `init_module`/`finit_module`，无法检测 LKM rootkit
4. **无 ptrace/process injection 监控** — 无法检测 T1055 系列进程注入攻击
5. **无权限变更监控** — 未 hook `setuid`/`setgid`/`capset`/`commit_creds`
6. **TCP 模块仅支持 IPv4** — `tcp_set_state_kern.c` 第 113 行 `if (data.family != AF_INET) goto delete_conn` 直接丢弃 IPv6 连接
7. **UDP DNS 模块被禁用** — `probe_kudp.go` 第 142 行 `//Register(mod)` 已被注释

**中等盲区：**

8. **DNS uprobe 仅覆盖 glibc** — 硬编码路径 `/lib/x86_64-linux-gnu/libc.so.6`，musl libc（Alpine 容器）、静态编译程序（Go/Rust）、DoH/DoT 均不覆盖
9. **Java RASP 仅覆盖 JDK8 特定版本** — 硬编码 `UprobeOffset: 0x19C30` 和特定 `.so` 路径，版本变更即失效
10. **无容器运行时感知** — 虽采集 `uts_inum`（UTS namespace inode），但无 cgroup、mount namespace 等容器关键信息

### 1.4 短生命周期进程/容器有效性

**结论：存在严重缺陷**

- `copy_process` 的 kretprobe 可在进程创建瞬间捕获事件，对短生命周期进程的**创建阶段**有效
- 但由于缺失 `execve` hook，无法捕获进程创建后执行的**实际二进制**——这恰恰是短生命周期攻击（如 `curl | bash` 管道命令）的关键信息
- `tcp_set_state` 仅在 `TCP_CLOSE` 时上报，极短连接可能因 map `conns` 容量限制（10240）被挤出而丢失
- 容器快速创建/销毁场景中，uprobe（DNS、Java）因挂载到宿主机特定路径，**不会追踪容器内 libc/JDK 实例**

---

## 2. 逃逸分析

### 2.1 各模块逐一绕过分析

#### 2.1.1 EBPFProbeProc（进程监控）绕过

| 绕过方式 | 难度 | 说明 |
|---------|------|------|
| **使用 execve 替代 fork** | 🟢 低 | 直接 `execve()` 不触发 `copy_process`，完全不在监控范围内 |
| **线程替代进程** | 🟢 低 | `clone(CLONE_THREAD)` 不经过 `copy_process` 的标准路径 |
| **内存执行（memfd_create + fexecve）** | 🟡 中 | fork 后无文件落地执行，即使触发 fork 也无法从 cmdline 获取有意义信息 |
| **篡改 comm 字段** | 🟢 低 | `prctl(PR_SET_NAME)` 可在运行时修改进程名 |
| **cmdline 字段长度限制** | 🟢 低 | `cmdline` 仅 128 字节（`proc_kern.c:35`），超长命令被截断，关键参数丢失 |

#### 2.1.2 EBPFProbeBPFCall（BPF 系统调用监控）绕过

| 绕过方式 | 难度 | 说明 |
|---------|------|------|
| **预加载 eBPF 程序** | 🟡 中 | 在 ehids-agent 启动前加载恶意 eBPF 程序，不会被捕获 |
| **BPF_PROG_LOAD 合法模拟** | 🟢 低 | 使用合法工具名（如伪装为 `bpftool`）的 comm 字段加载恶意程序，无策略引擎区分 |
| **高频洪泛** | 🟡 中 | 大量合法 BPF 操作淹没恶意操作，Perf Buffer 仅 1 页（`PerfRingBufferSize: 1 * os.Getpagesize()`），极易溢出 |
| **通过 pin/bpffs 间接操作** | 🟡 中 | 使用 `BPF_OBJ_GET` 获取已 pin 的程序 fd，修改 map 内容而非加载新程序 |

#### 2.1.3 EBPFProbeKTCP / EBPFProbeKTCPSec（网络监控）绕过

| 绕过方式 | 难度 | 说明 |
|---------|------|------|
| **使用 IPv6** | 🟢 低 | TCP 模块直接丢弃 IPv6 流量 |
| **使用 UDP/ICMP 隧道** | 🟢 低 | TCP 模块不监控 UDP；`security_socket_connect` 仅捕获 connect 调用 |
| **使用 raw socket** | 🟡 中 | `security_socket_connect` 不覆盖 `SOCK_RAW` 直接发包 |
| **UNIX socket 中继** | 🟢 低 | `sec_socket_connect_kern.c` 第 123 行明确跳过 `AF_UNIX` |
| **本地回环通信** | 🟢 低 | `tcp_set_state_kern.c` 第 120 行跳过 loopback `127.x.x.x` 双向通信 |
| **使用 io_uring 网络 IO** | 🟡 中 | io_uring 的 `IORING_OP_CONNECT` 不走标准 syscall 路径 |
| **端口复用/隐蔽通道** | 🟡 中 | 无深度包检测，无法识别 HTTP 上的 C2 信道（如 Domain Fronting） |

#### 2.1.4 EBPFProbeUDNS（DNS 监控）绕过

| 绕过方式 | 难度 | 说明 |
|---------|------|------|
| **静态编译程序** | 🟢 低 | Go/Rust 静态链接不使用 glibc `getaddrinfo` |
| **使用 musl libc** | 🟢 低 | Alpine 容器使用 musl libc，路径不匹配 |
| **直接 socket 发 DNS 请求** | 🟢 低 | 不经过 libc DNS resolver，直接构造 UDP 包发送到 53 端口 |
| **DoH / DoT** | 🟢 低 | DNS over HTTPS/TLS 完全绕过 |
| **使用其他 resolver 库** | 🟢 低 | 如 `c-ares`、`systemd-resolved` 等不经过 `getaddrinfo` |
| **修改 libc 路径** | 🟢 低 | 不同发行版 libc 路径不同（如 `/lib64/libc.so.6`），硬编码路径直接失效 |

#### 2.1.5 EBPFProbeUJavaRASP（Java RASP）绕过

| 绕过方式 | 难度 | 说明 |
|---------|------|------|
| **非 JDK8 版本** | 🟢 低 | 硬编码 `java-8-openjdk-amd64` 路径和偏移量 |
| **使用 ProcessBuilder 不经过 JDK_execvpe** | 🟡 中 | 某些 JDK 实现可能走不同的 native 路径 |
| **使用 JNI 直接调用** | 🟡 中 | 通过 JNI 加载 native 库直接 `execve`，不走 Java 标准 API |
| **反射调用 Runtime.exec 变体** | 🟢 低 | 仅 hook `JDK_execvpe`，无法覆盖所有 native 入口 |

### 2.2 TOCTOU（Time-of-Check to Time-of-Use）风险

**存在明确的 TOCTOU 风险：**

1. **进程监控中的 TOCTOU**：`kretprobe_copy_process` 在 fork 返回时读取子进程 `task_struct`，此时 cmdline/filepath 来自父进程的内存空间（`mm->arg_start`），子进程尚未 exec。攻击者可在 fork 后、exec 前修改参数，使 ehids-agent 记录的信息与实际执行内容不一致。

2. **DNS uprobe 中的 TOCTOU**：`getaddrinfo_entry` 在函数入口读取 hostname，`getaddrinfo_return` 在函数返回时读取结果。中间窗口期内，攻击者可通过多线程修改传入的 hostname 缓冲区。

3. **`security_socket_connect` 中的 TOCTOU**：该函数在 LSM hook 点被调用，位于实际连接之前。读取的 `sockaddr` 信息在理论上可以在 kprobe 执行和实际 connect 之间被用户态修改（尽管窗口极小）。

4. **BPF 调用监控的 TOCTOU**：`tracepoint/sys_enter_bpf` 在系统调用入口捕获 `cmd` 值，但 `uattr` 指向的用户态内存可在系统调用处理过程中被其他线程修改。内核的 `copy_from_user` 会独立再读一次。

### 2.3 Root 权限下的攻击面

**如果攻击者获得 root 权限，可以完全颠覆 ehids-agent：**

| 攻击向量 | 可行性 | 具体方式 |
|---------|-------|---------|
| **卸载 eBPF 程序** | ✅ 确定可行 | `bpftool prog list && bpftool prog detach` 或直接关闭 fd |
| **杀死 agent 进程** | ✅ 确定可行 | `kill -9 <pid>`，无自我保护/watchdog 机制 |
| **篡改 eBPF Map 数据** | ✅ 确定可行 | 通过 `bpf(BPF_MAP_UPDATE_ELEM)` 直接修改 map 内容 |
| **加载对抗性 eBPF 程序** | ✅ 确定可行 | 加载 TC/XDP 程序修改或丢弃网络数据，加载 kprobe 覆盖同一 hook 点 |
| **修改 perf/ring buffer** | ✅ 确定可行 | 通过 mmap 直接修改共享内存区域 |
| **Namespace 逃逸** | ✅ 确定可行 | 利用 `unshare` 进入新 namespace，agent 的 uprobe 不追踪新 namespace 中的 libc |
| **debugfs 禁用 kprobe** | ✅ 确定可行 | `echo 0 > /sys/kernel/debug/kprobes/enabled` |

---

## 3. 自身安全性

### 3.1 eBPF Rootkit 欺骗风险

**ehids-agent 可以被 eBPF Rootkit 欺骗，具体场景：**

1. **BPF_PROG_LOAD 隐藏**：恶意 eBPF 程序可以 hook 同一 tracepoint（`sys_enter_bpf`），通过 `bpf_override_return()` 或 `tail call` 修改 ehids-agent 看到的数据。但 tracepoint 不支持 `bpf_override_return`，所以更实际的方式是：
   - Hook `bpf_perf_event_output` 的上游函数，在数据写入 perf buffer 之前篡改
   - 利用 eBPF 的 `bpf_probe_write_user` 修改 ehids-agent 用户态内存中的事件数据

2. **Map 投毒**：攻击者的 eBPF 程序可以直接修改 ehids-agent 的 BPF Map（如 `conns`、`bpf_context`），注入虚假数据或删除真实记录。这些 Map **未使用 `BPF_F_RDONLY` 或 `BPF_F_WRONLY` 标志位**进行权限控制。

3. **kprobe 优先级竞争**：多个 kprobe 附加到同一函数时执行顺序不确定，恶意 kprobe 可能先于 ehids 的 kprobe 执行并修改上下文。

4. **Phantom Attack**：恶意 eBPF 程序可直接写入 ehids 的 perf_event_array/ringbuf map，注入大量虚假事件制造噪音，使真实告警淹没在海量误报中。

### 3.2 自我完整性保护机制

**结论：完全缺失自我保护**

| 保护能力 | 状态 | 说明 |
|---------|------|------|
| 进程自保护 | ❌ 缺失 | 无 watchdog、无进程守护、无 `PR_SET_DUMPABLE` 限制 |
| eBPF 程序完整性校验 | ❌ 缺失 | 未校验已加载 eBPF 程序的 hash/tag |
| Map 完整性监控 | ❌ 缺失 | 无定期检查 map 内容是否被篡改 |
| 二进制完整性校验 | ❌ 缺失 | ELF 字节码通过 `go-bindata` 内嵌但无签名验证 |
| 心跳/存活检测 | ❌ 缺失 | 无向管控端上报存活状态 |
| 配置防篡改 | ❌ 缺失 | 所有配置硬编码在代码中，无运行时保护 |
| 安全审计日志 | ❌ 缺失 | 仅 `log.Println` 到标准输出，无防篡改日志 |

### 3.3 Ring Buffer / Perf Buffer 溢出处理

**存在严重的事件丢失风险：**

#### Perf Buffer

```go
// imodule.go:163
if record.LostSamples != 0 {
    log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
    continue  // 仅打印日志，不做任何补偿
}
```

- **BPFCall 模块的 Perf Buffer 仅 1 个内存页**（`PerfRingBufferSize: 1 * os.Getpagesize()`，即 4KB），极易溢出
- `lostEventsHandle` 是空函数（`probe_bpf_call.go:142-145`），带有 TODO 注释但未实现
- **无背压机制**：无法告知内核端降速或丢弃低优先级事件
- **无丢失事件补偿**：丢失后不触发全量扫描或快照同步

#### Ring Buffer

```go
// imodule.go:180-215 ringbufEventReader
// 无 LostSamples 等价处理
```

- `ringbuf_proc` 大小为 `1 << 24`（16MB），相对充裕
- 但 Ring Buffer 满时，`bpf_ringbuf_reserve` 返回 NULL，内核端直接丢弃事件（`proc_kern.c:72`），**用户态无感知**
- 没有任何机制通知用户态发生了丢失

#### 攻击者利用方式

攻击者可通过以下方式故意触发 buffer 溢出以掩盖恶意行为：

1. **Fork 炸弹**：快速创建大量进程填满 `ringbuf_proc`
2. **TCP 洪泛**：大量 TCP 连接填满 perf buffer
3. **BPF 操作洪泛**：频繁调用 `bpf()` 填满 BPF Call 的 1 页 perf buffer（最容易触发）

### 3.4 事件处理管线中的安全风险

#### 3.4.1 Decode 函数的边界检查缺失

```go
// event_bpf_call.go:53-78
func (this *BpfCallEvent) Decode(data []byte) error {
    cmd := BPFCmd(ByteOrder.Uint32(data[0:4]))  // 无长度检查
    this.Comm = string(bytes.TrimRight(data[88:104], "\x00"))
    this.Cmdline = string(bytes.TrimRight(data[104:360], "\x00"))
    this.UtsName = string(bytes.TrimRight(data[360:424], "\x00"))
    return nil
}
```

- **无 payload 长度校验**：若内核端发送截断数据（buffer 溢出部分写入场景），直接 `data[360:424]` 会导致 **panic（index out of range）**
- 此 panic 会导致整个 goroutine 崩溃，可能中断该模块的事件处理
- `main.go:43-48` 中 `module.Run()` 在独立 goroutine 中执行，panic 会静默终止该模块

#### 3.4.2 事件输出为纯文本，无结构化保障

```go
// imodule.go:242-245
func (this *Module) Write(result string) {
    s := fmt.Sprintf("probeName:%s, probeTpye:%s, %s", this.name, this.mType, result)
    this.logger.Println(s)
}
```

- 仅输出到 `log.Default()`（标准输出），无持久化存储
- 无加密传输、无签名保护、无 SIEM 集成
- 攻击者可通过修改 stdout 重定向或 `/dev/null` 完全静默化 agent

#### 3.4.3 阻塞式事件读取

```go
// imodule.go:130-136
for {
    select {
    case err := <-errChan:
        return err  // 任一 reader 出错直接返回
    }
}
```

- `readEvents()` 方法在任一 map reader 报错时直接返回，**导致整个模块停止工作**
- 例如 `EBPFProbeKTCPSec` 有 3 个 perf map（ipv4/ipv6/other），任一出错全部停止

#### 3.4.4 Fatal 导致进程退出

```go
// probe_bpf_call.go:133
this.logger.Fatalf("decode error:%v", err)  // Fatalf 会调用 os.Exit(1)
```

- `dataHandler` 中解码失败使用 `Fatalf`，导致**整个 agent 进程退出**
- 攻击者可构造畸形 BPF 调用（如在 perf buffer 溢出边界产生截断数据）触发此 bug

---

## 4. 与同类工具对比

### 4.1 功能对比矩阵

| 能力维度 | ehids-agent | Falco | Tetragon | Tracee | Sysdig |
|---------|-------------|-------|----------|--------|--------|
| **进程创建监控** | ⚠️ 仅 fork | ✅ execve/fork/clone | ✅ 全生命周期 | ✅ 全生命周期 | ✅ 全生命周期 |
| **进程执行监控 (execve)** | ❌ 缺失 | ✅ | ✅ | ✅ | ✅ |
| **文件系统监控** | ❌ 缺失 | ✅ | ✅ | ✅ | ✅ |
| **网络连接监控** | ⚠️ TCP/IPv4 only | ✅ TCP+UDP | ✅ TCP+UDP | ✅ TCP+UDP | ✅ 全协议 |
| **DNS 监控** | ⚠️ glibc only | ✅ 内核级 | ✅ 内核级 | ✅ 内核级 | ✅ 内核级 |
| **容器感知** | ⚠️ 仅 UTS ns | ✅ 深度集成 K8s | ✅ 深度集成 K8s | ✅ 深度集成 K8s | ✅ 深度集成 K8s |
| **策略引擎** | ❌ 无 | ✅ YAML 规则 | ✅ TracingPolicy CRD | ✅ Rego/Signatures | ✅ Chisel/Lua |
| **BPF 系统调用监控** | ✅ | ⚠️ 有限 | ✅ | ✅ | ❌ |
| **Java RASP** | ⚠️ JDK8 only | ❌ | ❌ | ❌ | ❌ |
| **内核模块加载监控** | ❌ | ✅ | ✅ | ✅ | ✅ |
| **权限变更监控** | ❌ | ✅ | ✅ | ✅ | ✅ |
| **Ptrace/注入监控** | ❌ | ✅ | ✅ | ✅ | ✅ |
| **LSM Hook 支持** | ⚠️ 间接 | ❌ | ✅ BPF LSM | ✅ | ❌ |
| **实时告警** | ❌ 仅日志 | ✅ 多渠道 | ✅ 多渠道 | ✅ 多渠道 | ✅ 多渠道 |
| **事件丢失保护** | ❌ | ⚠️ 有限 | ✅ | ✅ | ✅ |
| **自我保护** | ❌ | ⚠️ 有限 | ✅ | ⚠️ 有限 | ⚠️ 有限 |
| **CO:RE 支持** | ✅ | ⚠️ 内核模块模式 | ✅ | ✅ | ❌ 内核模块 |
| **生产就绪度** | ❌ PoC | ✅ 成熟 | ✅ 成熟 | ✅ 成熟 | ✅ 成熟 |

### 4.2 ehids-agent 的独特优势

1. **BPF 系统调用监控**：通过 `tracepoint/sys_enter_bpf` 专门监控 bpf() 系统调用，可检测 eBPF rootkit 的加载行为。同类工具中这不是默认开启的检测点
2. **Java RASP uprobe**：直接 hook JDK native 函数实现命令执行拦截，思路独特（尽管实现上绑定特定版本）
3. **轻量级架构**：Go + eBPF 纯二进制部署，无依赖，代码量小（约 2000 行），启动快速
4. **CO:RE 支持**：使用 `vmlinux.h` + BTF，跨内核版本兼容性较好
5. **祖父进程追踪**：进程监控采集三代进程链（pid → ppid → pppid），有助于攻击链溯源
6. **学习/参考价值**：代码结构清晰，模块化设计良好，适合作为 eBPF HIDS 的教学/PoC 参考

### 4.3 ehids-agent 的核心劣势

1. **PoC 级别项目**：缺失生产级 HIDS 所需的大量关键能力（execve、文件监控、策略引擎、告警系统等）
2. **无策略引擎**：所有事件仅输出日志，无规则匹配、无异常检测、无自动响应
3. **硬编码依赖**：libc 路径、JDK 路径、Uprobe 偏移量均硬编码，无法适配不同环境
4. **单点故障**：无进程守护、无高可用、Fatalf 可导致整体崩溃
5. **无数据持久化/上报**：仅标准输出，无远程数据采集、无 SIEM 集成
6. **事件丢失无感知**：Ring Buffer 满时静默丢弃，Perf Buffer 丢失仅打日志
7. **IPv6 盲区**：TCP 状态追踪完全不支持 IPv6
8. **无自我保护**：root 攻击者可轻松卸载/杀死 agent

---

## 附录：攻击者绕过 ehids-agent 的最小操作清单

以下是一个具有 root 权限的攻击者完全绕过 ehids-agent 所有检测的快速方法：

```bash
# 方法1：直接杀死 agent（无守护进程保护）
kill -9 $(pgrep ehids)

# 方法2：禁用所有 kprobe（全局影响）
echo 0 > /sys/kernel/debug/kprobes/enabled

# 方法3：使用静态编译的 Go 工具（绕过 uprobe）+ IPv6（绕过 TCP 监控）
# + memfd_create 无文件执行（绕过进程监控）
# 这三步组合可在 agent 存活时完全隐身

# 方法4：perf buffer 洪泛（使 BPFCall 模块丢失事件后加载恶意 eBPF）
for i in $(seq 1 10000); do bpftool prog list > /dev/null 2>&1; done &
# 在洪泛窗口加载恶意 eBPF 程序
```

---

*报告生成时间：2026-03-27 | 分析基于 ehids-agent 源码全量审计*
