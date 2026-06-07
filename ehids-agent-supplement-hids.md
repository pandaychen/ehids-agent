# eHIDS-Agent HIDS/运行时安全专项补充分析

> 本文档基于 ehids-agent 源码进行深度 HIDS 专项分析，涵盖系统调用监控覆盖范围、容器感知、策略引擎、执行阻断、事件富化与部署架构六大维度。

---

## 1. 系统调用监控覆盖范围

### 1.1 当前 Hook 点清单

| 模块名 | 内核 C 文件 | Hook 类型 | Hook 函数/点 | 监控目标 |
|--------|------------|----------|-------------|---------|
| EBPFProbeBPFCall | `bpf_call_kern.c` | Tracepoint | `syscalls/sys_enter_bpf` | BPF 系统调用（加载/卸载 eBPF 程序） |
| EBPFProbeProc | `proc_kern.c` | kretprobe | `copy_process` | 进程 fork 创建 |
| EBPFProbeKTCP | `tcp_set_state_kern.c` | kprobe | `tcp_set_state` | TCP 连接状态变迁（建连/断连/流量统计） |
| EBPFProbeKTCPSec | `sec_socket_connect_kern.c` | kprobe | `security_socket_connect` | Socket 出向连接（IPv4/IPv6/Other） |
| EBPFProbeKUDP | `udp_lookup_kern.c` | kprobe/kretprobe | `udp_recvmsg` | UDP DNS 应答报文捕获（端口 53） |
| EBPFProbeUDNS | `dns_lookup_kern.c` | uprobe/uretprobe | `getaddrinfo` (libc) | 用户态 DNS 解析结果 |
| EBPFProbeUJavaRASP | `java_exec_kern.c` | uprobe | `JDK_execvpe` (libjava.so) | Java 进程命令执行（RASP） |

> **注意**：`EBPFProbeKUDP` 在 `probe_kudp.go` 中 `init()` 里 `Register(mod)` 被注释掉，实际未启用。

### 1.2 实际监控的系统调用/内核函数映射

| 系统调用/操作 | 监控方式 | 覆盖程度 |
|-------------|---------|---------|
| `bpf()` | Tracepoint 直接 hook | **完整** |
| `fork/clone` | kretprobe `copy_process`（内核内部函数） | **部分**（仅 fork，缺少 exec/exit） |
| `connect()` | kprobe `security_socket_connect` | **完整**（所有地址族） |
| TCP 连接生命周期 | kprobe `tcp_set_state` | **完整**（含流量统计） |
| DNS 解析 | uprobe `getaddrinfo` + kprobe `udp_recvmsg` | **部分**（仅覆盖 glibc，musl libc 未覆盖；UDP 模块未启用） |
| Java 命令执行 | uprobe `JDK_execvpe` | **部分**（仅 OpenJDK 8 特定版本） |

### 1.3 与主流 HIDS 必须监控的 Syscall 对比

下表列出主流 HIDS（Falco/Tracee/Tetragon/Datadog Security Agent）的核心监控 syscall，并标注 ehids-agent 的覆盖情况：

| 关键 Syscall/Hook | HIDS 用途 | ehids-agent 状态 | 优先级 |
|-------------------|----------|-----------------|--------|
| `execve` / `execveat` | **进程执行监控**（最核心） | **缺失** | **P0 - 必须补充** |
| `open` / `openat` / `openat2` | 文件访问监控 | **缺失** | **P0 - 必须补充** |
| `unlink` / `unlinkat` | 文件删除监控 | **缺失** | P1 |
| `rename` / `renameat` / `renameat2` | 文件篡改检测 | **缺失** | P1 |
| `ptrace` | 进程注入/调试检测 | **缺失** | **P0 - 必须补充** |
| `mount` / `umount2` | 挂载操作监控（容器逃逸） | **缺失** | **P0 - 必须补充** |
| `setuid` / `setgid` / `setreuid` | 权限提升检测 | **缺失** | P1 |
| `init_module` / `finit_module` | 内核模块加载（rootkit） | **缺失** | **P0 - 必须补充** |
| `delete_module` | 内核模块卸载 | **缺失** | P1 |
| `mmap` / `mprotect` | 内存注入/代码注入 | **缺失** | P1 |
| `socket` / `bind` / `listen` / `accept` | 完整网络行为 | **部分**（仅 connect 出向） | P1 |
| `kill` / `tkill` / `tgkill` | 信号发送监控 | **缺失** | P2 |
| `chroot` / `pivot_root` | 容器逃逸检测 | **缺失** | P1 |
| `prctl` | 进程属性变更（如 `PR_SET_NAME`） | **缺失** | P2 |
| `memfd_create` | 无文件攻击检测 | **缺失** | P1 |
| `ioctl` | 设备交互/终端操作 | **缺失** | P2 |
| `exit` / `exit_group` | 进程退出监控 | **缺失** | P1 |
| `setns` / `unshare` | Namespace 操作（容器逃逸） | **缺失** | **P0 - 必须补充** |
| LSM hooks (`bprm_check_security` 等) | 安全决策点 | **缺失** | P1 |

### 1.4 覆盖率评估

```
当前覆盖：  3/20+ 关键 syscall（约 15%）
P0 缺失：  execve, open, ptrace, mount, init_module, setns
核心结论：  当前仅覆盖网络和 BPF 系统调用，进程执行和文件系统两个最核心维度完全缺失
```

### 1.5 建议补充的 Hook 点（按优先级）

#### P0 - 立即补充

```c
// 1. 进程执行监控 —— HIDS 最核心能力
SEC("tracepoint/syscalls/sys_enter_execve")        // 或 kprobe/security_bprm_check
SEC("tracepoint/syscalls/sys_enter_execveat")

// 2. 文件访问监控
SEC("tracepoint/syscalls/sys_enter_openat")
SEC("kprobe/security_file_open")                    // LSM hook，覆盖所有 open 变体

// 3. 进程注入检测
SEC("tracepoint/syscalls/sys_enter_ptrace")

// 4. 容器逃逸相关
SEC("tracepoint/syscalls/sys_enter_mount")
SEC("tracepoint/syscalls/sys_enter_setns")
SEC("tracepoint/syscalls/sys_enter_unshare")

// 5. 内核模块加载
SEC("tracepoint/syscalls/sys_enter_init_module")
SEC("tracepoint/syscalls/sys_enter_finit_module")
```

#### P1 - 近期补充

```c
// 文件完整性
SEC("tracepoint/syscalls/sys_enter_unlinkat")
SEC("tracepoint/syscalls/sys_enter_renameat2")
SEC("kprobe/security_inode_create")

// 权限提升
SEC("tracepoint/syscalls/sys_enter_setuid")
SEC("tracepoint/syscalls/sys_enter_setreuid")
SEC("kprobe/commit_creds")                          // 覆盖所有提权路径

// 无文件攻击
SEC("tracepoint/syscalls/sys_enter_memfd_create")
SEC("tracepoint/syscalls/sys_enter_mprotect")

// 进程退出 —— 完善生命周期
SEC("tracepoint/sched/sched_process_exit")
```

---

## 2. 容器运行时感知机制

### 2.1 当前容器信息采集分析

#### UTS Namespace ID 采集

在 `bpf_call_kern.c` 的 `get_common_proc()` 函数中实现了容器相关信息采集：

```c
// 获取 UTS namespace inode number —— 用于区分容器
static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace* uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

// 获取 namespace 内的 PID
static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct pid *tpid = READ_KERN(task->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
    return nr;
}

// 获取 UTS hostname（容器 hostname）
static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}
```

在 `proc_kern.c` 中也获取了 `uts_inum`：
```c
ringbuf_process->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns).inum;
```

#### 采集的容器相关字段

| 字段 | 来源 | 说明 |
|-----|------|------|
| `uts_inum` | `task->nsproxy->uts_ns->ns.inum` | UTS namespace inode，可区分不同容器 |
| `uts_name` | `task->nsproxy->uts_ns->name.nodename` | 容器 hostname |
| `nspid` | `task->thread_pid->numbers[level].nr` | namespace 内的 PID |
| `nstgid` | 通过 `group_leader` 获取 | namespace 内的 TGID |

### 2.2 容器信息采集的局限性

| 能力 | 状态 | 说明 |
|-----|------|------|
| 区分容器/宿主机进程 | **基础具备** | 通过 `uts_inum` 可判断（与宿主机 init namespace inum 比较） |
| 容器 ID（Docker 64位 hex） | **缺失** | 未从 cgroup 路径提取容器 ID |
| 容器镜像名 | **缺失** | 需要用户态关联 Docker/containerd API |
| Pod Name / Namespace | **缺失** | 需要用户态关联 Kubernetes API |
| 容器运行时类型 | **缺失** | 未区分 Docker/containerd/CRI-O |
| cgroup ID / cgroup path | **缺失** | 未采集 `task->cgroups` 信息 |

### 2.3 容器 ID 获取方案建议

#### 内核态：从 cgroup 提取

```c
// 方案 1：通过 bpf_get_current_cgroup_id() 获取 cgroup v2 ID
u64 cgroup_id = bpf_get_current_cgroup_id();

// 方案 2：读取 cgroup 路径，从中解析容器 ID
// cgroup path 格式（Docker）: /docker/<container_id_64hex>/
// cgroup path 格式（k8s）:    /kubepods/pod<pod_uid>/<container_id>/
static __always_inline void get_cgroup_name(struct task_struct *task, char *buf, int size)
{
    struct css_set *cgroups = READ_KERN(task->cgroups);
    struct cgroup_subsys_state *css = READ_KERN(cgroups->subsys[0]);
    struct cgroup *cgrp = READ_KERN(css->cgroup);
    struct kernfs_node *kn = READ_KERN(cgrp->kn);
    char *name = READ_KERN(kn->name);
    bpf_probe_read_str(buf, size, name);
}
```

#### 用户态：关联容器运行时

```go
// 方案 3：用户态通过 /proc/<pid>/cgroup 获取容器 ID
// 方案 4：通过 containerd/Docker API 建立 cgroup_id -> container_info 映射
// 方案 5：监听容器运行时事件，维护容器信息缓存
```

### 2.4 Kubernetes 集成能力评估

| 集成维度 | 当前状态 | 改进建议 |
|---------|---------|---------|
| Pod 信息关联 | **无** | 通过 K8s Informer 建立 Node 上的 Pod 缓存，用 cgroup ID 关联 |
| K8s 元数据标注 | **无** | 在事件中补充 `pod_name`, `namespace`, `labels`, `annotations` |
| DaemonSet 部署 | **未适配** | 需要提供 Helm Chart/DaemonSet YAML |
| RBAC/PSP 感知 | **无** | 可以通过 K8s API 获取 Pod 的 SecurityContext |
| CRI 接口集成 | **无** | 可通过 CRI gRPC 接口获取容器详细信息 |

### 2.5 容器逃逸检测能力

**当前状态：无容器逃逸检测能力。**

需要监控的容器逃逸路径：

| 逃逸路径 | 需要的 Hook 点 | 当前覆盖 |
|---------|---------------|---------|
| 挂载宿主机文件系统 | `mount` syscall | **缺失** |
| nsenter / setns 切换 namespace | `setns` / `unshare` | **缺失** |
| 特权容器 + 内核模块加载 | `init_module` / `finit_module` | **缺失** |
| Docker Socket 暴露 | `connect` 到 `/var/run/docker.sock` | **部分**（有 connect hook，但未检测 UNIX 域） |
| CVE 利用（如 runc CVE-2019-5736） | `openat` 对 `/proc/self/exe` 的操作 | **缺失** |
| `CAP_SYS_PTRACE` 滥用 | `ptrace` | **缺失** |
| cgroup 逃逸 | `write` 到 `release_agent` | **缺失** |
| `CAP_SYS_ADMIN` + `mount` | `mount` | **缺失** |

---

## 3. 策略引擎分析

### 3.1 当前检测逻辑

**ehids-agent 当前没有策略引擎**，所有检测逻辑均为硬编码过滤：

#### 内核态过滤（硬编码）

| 模块 | 过滤逻辑 | 位置 |
|-----|---------|------|
| `udp_lookup_kern.c` | `dport == 13568`（ntohs(53)），仅捕获 DNS 端口 | 第 52 行 |
| `tcp_set_state_kern.c` | `family != AF_INET` 过滤非 IPv4 | 第 113 行 |
| `tcp_set_state_kern.c` | 过滤 localhost 回环地址 | 第 120 行 |
| `tcp_set_state_kern.c` | `dport != 0` 过滤无效连接 | 第 100 行 |
| `sec_socket_connect_kern.c` | 按地址族分发，过滤 `AF_UNIX` 和 `AF_UNSPEC` | 第 123 行 |

#### 用户态处理

```go
// Module.Write() 直接日志输出，无任何过滤/检测逻辑
func (this *Module) Write(result string) {
    s := fmt.Sprintf("probeName:%s, probeTpye:%s, %s", this.name, this.mType, result)
    this.logger.Println(s)
}
```

**结论**：
- **无规则引擎**：没有任何检测规则定义机制
- **无告警生成**：所有事件等同处理，全部日志输出
- **无白名单机制**：无法排除已知良性行为
- **无严重等级**：事件无分级
- **过滤逻辑硬编码**：修改过滤条件需要重新编译内核态代码

### 3.2 与 Falco 规则引擎对比

| 能力维度 | ehids-agent | Falco | 差距 |
|---------|-------------|-------|------|
| 规则定义语言 | 无 | YAML + 条件表达式 | **巨大** |
| 规则热加载 | 不支持 | 支持运行时更新 | **巨大** |
| 规则优先级 | 无 | EMERGENCY ~ DEBUG 8 级 | **巨大** |
| 条件表达式 | 无 | `evt.type = execve and proc.name = bash` 等 | **巨大** |
| 宏和列表 | 无 | 支持宏定义和列表复用 | **巨大** |
| 规则继承 | 无 | `append` / `override` 机制 | **巨大** |
| 社区规则库 | 无 | 300+ 内置规则 | **巨大** |
| 自定义输出格式 | 固定 `String()` | 支持模板化输出 | **较大** |

### 3.3 与 Tetragon TracingPolicy 对比

| 能力维度 | ehids-agent | Tetragon | 差距 |
|---------|-------------|----------|------|
| 策略定义 | 硬编码 C 代码 | YAML CRD (TracingPolicy) | **巨大** |
| 动态加载 | 需重编译 | `kubectl apply` 热加载 | **巨大** |
| 内核态过滤 | 简单常量比较 | Selector + matchArgs + matchActions | **巨大** |
| 参数匹配 | 无 | 支持对 syscall 参数做精确匹配 | **巨大** |
| 响应动作 | 仅日志 | Sigkill / Override / GetUrl / Post | **巨大** |
| K8s 集成 | 无 | 原生 CRD + Pod label selector | **巨大** |

### 3.4 策略引擎改进建议

```
建议分阶段实施：

Phase 1（短期）：在用户态 Write() 方法中加入基于配置文件的过滤规则
  - YAML 配置文件定义白名单/黑名单
  - 支持 PID、进程名、UID、IP 地址等基本过滤条件

Phase 2（中期）：引入 CEL（Common Expression Language）或类 Sigma 规则引擎
  - 支持复杂条件表达式
  - 支持规则热加载
  - 支持事件分级（INFO/WARN/CRITICAL）

Phase 3（长期）：参考 Tetragon TracingPolicy 设计
  - 内核态 BPF Map 驱动的过滤（减少用户态开销）
  - 支持通过 BPF Map 更新动态下发过滤规则
  - 支持 K8s CRD 定义策略
```

---

## 4. 执行阻断能力

### 4.1 当前状态

**ehids-agent 当前不具备任何执行阻断能力。**

所有 7 个探针模块均为**观测型**（observe-only），事件被捕获后仅做日志记录，不做任何阻断或干预。

### 4.2 当前 Hook 类型的阻断能力分析

| Hook 类型 | 使用的模块 | 是否支持阻断 | 原因 |
|----------|----------|------------|------|
| `tracepoint` | BPF Call | **不支持** | Tracepoint 程序不能修改返回值或终止执行 |
| `kprobe` | TCP/Socket/UDP | **不支持** | kprobe 是观测型，不能阻断执行流 |
| `kretprobe` | Proc (copy_process) / UDP | **不支持** | 返回探针只能观测返回值，不能修改 |
| `uprobe` | DNS / Java RASP | **不支持** | uprobe 是观测型，不能阻断 |

### 4.3 实现阻断能力的技术路线

#### 方案 A：LSM BPF（推荐 - Linux 5.7+）

```c
// LSM hook 可以返回错误码来阻断操作
SEC("lsm/bprm_check_security")
int BPF_PROG(block_exec, struct linux_binprm *bprm, int ret)
{
    // 检查是否在黑名单中
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 查询 BPF Map 中的策略
    struct policy_t *policy = bpf_map_lookup_elem(&exec_policy_map, &comm);
    if (policy && policy->action == ACTION_DENY) {
        return -EPERM;  // 阻断执行
    }
    return 0;  // 放行
}

SEC("lsm/file_open")
int BPF_PROG(block_file_open, struct file *file, int ret)
{
    // 可以阻断文件打开操作
    return -EPERM;
}

SEC("lsm/socket_connect")
int BPF_PROG(block_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // 可以阻断网络连接
    return -ECONNREFUSED;
}
```

**优点**：
- 是内核设计的安全决策点，语义最正确
- 可以返回错误码实现精确阻断
- 覆盖文件、网络、进程、模块等所有安全场景
- 不会影响非目标进程的性能

**缺点**：
- 需要 Linux 5.7+ 内核
- 需要内核编译时开启 `CONFIG_BPF_LSM`
- 部分发行版可能未默认启用

#### 方案 B：bpf_send_signal() 杀进程（Linux 5.3+）

```c
// 在现有 kprobe 中可以直接使用
SEC("kprobe/security_socket_connect")
int kprobe__security_socket_connect(struct pt_regs *ctx) {
    // ... 检测到恶意行为 ...
    if (is_malicious) {
        bpf_send_signal(SIGKILL);  // 杀掉当前进程
    }
    return 0;
}
```

**优点**：可在现有 kprobe 架构上直接使用
**缺点**：粒度粗，只能杀进程，不能精确阻断单次操作；操作已开始执行，存在 TOCTOU 窗口

#### 方案 C：bpf_override_return()（Linux 4.16+，需要 CONFIG_BPF_KPROBE_OVERRIDE）

```c
SEC("kprobe/__x64_sys_execve")
int block_execve(struct pt_regs *ctx) {
    // ... 策略检查 ...
    if (should_block) {
        bpf_override_return(ctx, -EPERM);  // 修改 syscall 返回值
    }
    return 0;
}
```

**优点**：可以让 syscall 返回错误，应用层可以感知并处理
**缺点**：
- 需要内核编译选项 `CONFIG_BPF_KPROBE_OVERRIDE`
- 仅支持标记了 `ALLOW_ERROR_INJECTION` 的函数
- 生产环境使用需谨慎

### 4.4 改造路径建议

```
推荐改造路径：LSM BPF 为主 + bpf_send_signal 作为 fallback

Step 1: 运行时检测内核是否支持 LSM BPF
  - 检查 /sys/kernel/security/lsm 是否包含 "bpf"
  - 检查内核版本 >= 5.7

Step 2: 如果支持 LSM BPF
  - 将 security_socket_connect kprobe 迁移为 LSM hook
  - 新增 bprm_check_security, file_open, sb_mount 等 LSM hook
  - 通过 BPF Map 下发阻断策略

Step 3: 如果不支持 LSM BPF（降级方案）
  - 保持 kprobe 观测
  - 对高危事件使用 bpf_send_signal(SIGKILL) 作为应急阻断

Step 4: 用户态策略联动
  - 用户态收到高危事件后，通过 cgroup freezer / kill 实现延迟阻断
  - 通过更新 BPF Map 动态调整阻断策略
```

---

## 5. 事件富化与关联能力

### 5.1 各事件的上下文字段对比

| 字段 | BPF Call | Proc Fork | TCP State | Socket Connect | UDP DNS | DNS Lookup | Java RASP |
|------|---------|-----------|-----------|---------------|---------|------------|-----------|
| PID/TGID | Y | Y | Y | Y | Y | Y | Y |
| Namespace PID | Y | - | - | - | - | - | - |
| PPID (父进程) | Y (3级) | Y (2级) | - | - | - | - | - |
| UID/GID | Y | Y | Y | Y | Y | Y | - |
| EUID/EGID | Y | - | - | - | - | - | - |
| Comm (进程名) | Y | Y | Y | Y | Y | - | - |
| Cmdline (命令行) | Y | Y | - | - | - | - | - |
| UTS Namespace ID | Y | Y | - | - | - | - | - |
| UTS Name (hostname) | Y | - | - | - | - | - | - |
| Start Time | Y | Y | - | - | - | - | - |
| 源/目的 IP | - | - | Y | Y | - | Y | - |
| 源/目的 Port | - | - | Y | Y | - | - | - |
| 网络流量 (Rx/Tx) | - | - | Y | - | - | - | - |
| DNS 域名 | - | - | - | - | Y | Y | - |
| DNS 解析结果 | - | - | - | - | Y | Y | - |
| 文件路径 | - | Y(部分) | - | - | - | - | Y |
| 容器 ID | - | - | - | - | - | - | - |
| cgroup ID | - | - | - | - | - | - | - |
| Mount namespace | - | - | - | - | - | - | - |
| 线程 ID | - | - | - | - | - | - | - |

### 5.2 事件富化能力评估

#### 5.2.1 信息丰富度不均衡

**BPF Call 事件**的上下文最丰富（通过 `get_common_proc()` 获取完整进程信息），包含三级进程树（当前 → 父 → 祖父），这是一个很好的设计模式。

**但其他模块严重缺乏上下文**：
- TCP/Socket 连接事件缺少完整进程信息（无 cmdline、无父进程、无 namespace 信息）
- UDP/DNS 事件仅有 PID 和 comm
- Java RASP 事件仅有 PID 和执行文件名

#### 5.2.2 建议统一富化方案

```c
// 建议：将 get_common_proc() 提取为公共头文件，所有探针统一调用
// 新增 ehids_common.h，包含：
struct event_context_t {
    // 进程上下文
    struct proc_common proc;
    // 容器上下文
    u64 cgroup_id;
    u32 mnt_ns_id;
    u32 pid_ns_id;
    u32 net_ns_id;
    // 事件元信息
    u64 timestamp;
    u32 event_type;
    u32 syscall_nr;
};
```

### 5.3 跨事件关联能力

**当前状态：无跨事件关联能力。**

| 关联能力 | 状态 | 说明 |
|---------|------|------|
| 进程树构建 | **无** | 虽然采集了 PPID，但用户态没有维护进程树 |
| 进程 → 网络关联 | **无** | TCP 事件和进程事件独立处理，无法关联 |
| DNS → 连接关联 | **无** | DNS 解析和 socket connect 事件无法关联 |
| 进程生命周期 | **不完整** | 仅有 fork，缺少 exec 和 exit |
| 会话追踪 | **无** | 无 session/TTY 信息 |
| 因果链追踪 | **无** | 无法构建「攻击者从 SSH 登录 → 下载恶意文件 → 执行 → 外连 C2」的完整链条 |

### 5.4 进程生命周期追踪完整度

```
完整进程生命周期：  fork → exec → [运行时行为] → exit

ehids-agent 覆盖：  fork（kretprobe copy_process）
                    exec ——  缺失
                    运行时行为 —— 仅 BPF syscall
                    exit ——  缺失

完整度评估：约 25%
```

### 5.5 与 Tracee 事件富化能力对比

| 能力 | ehids-agent | Tracee |
|-----|-------------|--------|
| 事件数量 | 7 个探针 | 300+ 事件类型 |
| 进程上下文 | 部分探针有 | 所有事件统一上下文 |
| 容器信息 | UTS namespace 仅部分探针 | 完整（container_id, image, K8s info） |
| 进程树 | 3 级 PPID（仅 BPF Call） | 用户态维护完整进程树 + /proc 扫描 |
| 参数捕获 | 简单字段 | 完整 syscall 参数解析 |
| 文件路径解析 | 有但不完整 | 完整路径解析（含 dentry 遍历） |
| 跨事件关联 | 无 | Derived Events（派生事件）/ 策略关联 |
| 网络流量分析 | DNS 包解析 | 完整 L7 协议解析（HTTP/DNS/...） |
| 内存取证 | 无 | 支持可执行内存区域扫描 |
| 用户态事件缓存 | 无 | Ring Buffer + 事件聚合 |

---

## 6. HIDS 部署架构评估

### 6.1 资源占用分析

#### 内核态资源

| 资源类型 | 当前使用 | 评估 |
|---------|---------|------|
| BPF Map 内存 | `bpf_context`: LRU_HASH 2048 条 | 较小，约几百 KB |
| | `conns`: HASH 10240 条 | 适中 |
| | `ringbuf_proc`: 16MB (1<<24) | **偏大**，建议可配置 |
| | `tbl_udp_msg_hdr`: HASH 10240 条 | 适中 |
| | `dns_data`: PERCPU_ARRAY 1 条 | 极小 |
| Perf Buffer | 多个 `PERF_EVENT_ARRAY` max_entries=4 | 较小 |
| BPF 程序数 | 8 个 BPF 程序 | 较少，开销可忽略 |

#### 用户态资源

| 维度 | 评估 | 风险 |
|-----|------|------|
| 内存占用 | 较低（无事件缓存，直接日志输出） | **低** |
| CPU 占用 | 取决于事件量，当前处理逻辑简单 | **低** |
| Goroutine 数 | 每个探针 1-3 个 goroutine | **低** |
| 文件描述符 | eBPF 相关 fd（Map + Program + Perf） | **低** |

#### 潜在资源风险

| 风险点 | 说明 | 影响 |
|-------|------|------|
| Perf Buffer 丢事件 | 高负载时 perf ring buffer 满溢 | 有 `LostSamples` 计数但无背压/降采样 |
| DNS 高频解析 | DNS 密集型应用可能产生大量事件 | 用户态解析 DNS 包有 CPU 开销 |
| 事件上报无限速 | `Write()` 直接日志打印无速率限制 | 日志爆炸风险 |
| Manager 退出竞态 | `context.Done()` 和 `reader.Read()` 存在竞态 | 可能导致 panic 或 goroutine 泄漏 |

### 6.2 稳定性评估

| 维度 | 状态 | 风险等级 |
|-----|------|---------|
| 错误处理 | `bpfManager.Start()` 失败直接 panic | **高** - 生产环境不可接受 |
| 优雅退出 | 有 signal handler + context cancel | **中** - 但未等待所有 goroutine 结束 |
| 热升级 | 不支持 | **高** - 升级需要重启，中断监控 |
| 自恢复 | 无 | **高** - 模块崩溃无重试机制 |
| 资源清理 | 依赖 `bpfManager.Stop(CleanAll)` | **中** - 异常退出可能残留 BPF 程序 |
| 健康检查 | 无 | **高** - 无法检测模块是否正常工作 |
| 指标暴露 | 无 Prometheus metrics | **高** - 无法监控 Agent 自身状态 |

### 6.3 DaemonSet 部署适配评估

| 要求 | 当前状态 | 改进建议 |
|-----|---------|---------|
| 容器化运行 | **未适配** | 需要特权容器或 `CAP_SYS_ADMIN` + `CAP_BPF` |
| BTF 支持 | 使用 CO-RE (bpf_core_read) | **较好** - 支持跨内核版本 |
| 节点资源限制 | 无 resource limit 配置 | 需要添加 `resources.requests/limits` |
| 配置管理 | 无配置文件 | 需要 ConfigMap 挂载 |
| 日志输出 | `log.Println` 标准输出 | 需要结构化日志（JSON） |
| Liveness/Readiness | 无 | 需要添加健康检查 HTTP 端点 |
| 节点亲和性 | 未考虑 | 需要 nodeSelector/tolerations |
| 安全上下文 | 未配置 | 需要 `securityContext.privileged` 或精细 capabilities |

#### 建议的 DaemonSet 配置框架

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ehids-agent
spec:
  selector:
    matchLabels:
      app: ehids-agent
  template:
    spec:
      hostPID: true          # 必须，需要访问宿主机 PID namespace
      hostNetwork: true       # 建议，便于网络监控
      containers:
      - name: ehids-agent
        securityContext:
          privileged: true     # 或使用精细 capabilities
          # capabilities:
          #   add: [SYS_ADMIN, BPF, PERFMON, NET_ADMIN, SYS_RESOURCE, SYS_PTRACE]
        volumeMounts:
        - name: sys-kernel-debug
          mountPath: /sys/kernel/debug
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /boot
          readOnly: true
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
      volumes:
      - name: sys-kernel-debug
        hostPath:
          path: /sys/kernel/debug
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
```

### 6.4 事件上报通道评估

#### 当前上报方式

```go
// 当前实现：直接 log 打印，无实际上报通道
func (this *Module) Write(result string) {
    s := fmt.Sprintf("probeName:%s, probeTpye:%s, %s", this.name, this.mType, result)
    this.logger.Println(s)
}
```

**问题**：
1. **无持久化**：事件仅输出到 stdout，进程重启或日志轮转后丢失
2. **无缓冲**：突发大量事件时无法削峰
3. **无重试**：上报失败后事件丢失
4. **无批量发送**：每个事件单独处理，网络开销大
5. **无结构化输出**：日志格式不统一，不便解析

#### 改进建议：多级上报架构

```
[内核态]                    [用户态 Agent]                [后端]

eBPF Program               ┌─────────────┐            ┌─────────────┐
  │                        │ Ring Buffer  │            │   Kafka      │
  ├─ Perf Event ──────────►│  (本地缓冲)  │───批量───►│   /          │
  │                        │             │            │  Elasticsearch│
  ├─ Ring Buffer ─────────►│ 事件富化     │            │   /          │
  │                        │  + 过滤     │            │  SIEM        │
  └─ BPF Map ─────────────►│  + 聚合     │            └─────────────┘
                           │             │                   │
                           │ 本地落盘     │            ┌─────────────┐
                           │ (故障容错)   │            │  SOC/SOAR   │
                           └─────────────┘            └─────────────┘
```

### 6.5 与 SIEM/SOC 集成建议

| 集成方式 | 推荐等级 | 说明 |
|---------|---------|------|
| **gRPC/Protobuf 上报** | 推荐 | 高效二进制序列化，支持流式传输，参考 Tetragon |
| **Kafka 异步投递** | 推荐 | 解耦 Agent 和后端，支持削峰填谷 |
| **Syslog (RFC 5424)** | 可选 | 兼容传统 SIEM |
| **OpenTelemetry** | 可选 | 标准化可观测性框架，支持 traces/metrics/logs |
| **Webhook/HTTP** | 紧急方案 | 简单但性能差，适合告警通知 |
| **本地文件 + Filebeat** | 可选 | 利用 ELK 栈现有基础设施 |

#### 推荐的事件输出格式

```json
{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "agent": {
    "id": "node-001",
    "version": "0.1.0"
  },
  "event": {
    "type": "security_socket_connect",
    "severity": "INFO",
    "module": "EBPFProbeKTCPSec"
  },
  "process": {
    "pid": 1234,
    "tgid": 1234,
    "ppid": 1,
    "name": "curl",
    "cmdline": "curl https://example.com",
    "uid": 1000,
    "start_time": 1704067200000
  },
  "container": {
    "id": "abc123def456",
    "name": "webapp",
    "image": "nginx:latest",
    "pod_name": "webapp-7d8f9b6c5-x2k4j",
    "namespace": "production"
  },
  "network": {
    "direction": "outbound",
    "transport": "tcp",
    "source": {"ip": "10.0.0.1", "port": 54321},
    "destination": {"ip": "93.184.216.34", "port": 443}
  }
}
```

---

## 总结与改进路线图

### 整体成熟度评估

| 维度 | 得分 (1-10) | 说明 |
|-----|------------|------|
| Syscall 覆盖 | **2** | 仅覆盖网络和 BPF，缺失执行/文件/提权 |
| 容器感知 | **3** | 有 UTS namespace 基础，缺少完整容器信息 |
| 策略引擎 | **1** | 无规则引擎，全部硬编码 |
| 执行阻断 | **0** | 完全不具备 |
| 事件富化 | **3** | BPF Call 模块较好，其他模块较差 |
| 部署架构 | **2** | 原型级，不适合生产部署 |
| **综合** | **~2/10** | 处于概念验证（PoC）阶段 |

### 改进路线图

```
Phase 1 - 基础能力补齐（1-2 个月）
├── 补充 execve/execveat hook（进程执行监控）
├── 补充 openat hook（文件访问监控）
├── 统一所有探针的进程上下文（复用 get_common_proc 模式）
├── 补充 sched_process_exit hook（进程退出）
├── 添加结构化日志输出（JSON）
└── 添加基本的 YAML 配置文件

Phase 2 - 容器与策略（2-3 个月）
├── 实现 cgroup ID 采集 + 容器 ID 关联
├── 集成 containerd/CRI API 获取容器元数据
├── 实现基础规则引擎（白名单/黑名单）
├── 补充 ptrace/mount/setns 等容器逃逸相关 hook
├── 添加 Prometheus metrics 暴露
└── 适配 DaemonSet 部署（Helm Chart）

Phase 3 - 生产级能力（3-6 个月）
├── 实现 LSM BPF 阻断能力
├── 用户态进程树维护 + 跨事件关联
├── 实现 Kafka/gRPC 事件上报通道
├── 添加事件聚合与降采样
├── K8s Informer 集成（Pod/Service 信息关联）
├── 健康检查 + 自恢复机制
└── 参考 Sigma 规则格式实现高级策略引擎

Phase 4 - 高级安全能力（6+ 个月）
├── 文件完整性监控（FIM）
├── 内核 rootkit 检测
├── 无文件攻击检测（memfd_create + mprotect）
├── 网络 L7 协议分析
├── 威胁情报集成（IOC 匹配）
└── MITRE ATT&CK 映射与告警
```

### 与业界产品的能力差距定位

```
                功能完整度
                    │
              10 ── ┤                              ◆ Datadog Security Agent
                    │                         ◆ Tracee
               8 ── ┤                    ◆ Tetragon
                    │               ◆ Falco
               6 ── ┤
                    │
               4 ── ┤
                    │
               2 ── ┤  ◆ ehids-agent (当前)
                    │
               0 ── ┼──────────────────────────────────
                    0    2    4    6    8    10
                              生产就绪度
```

ehids-agent 当前定位为**学习/研究型 eBPF HIDS 原型**，其核心价值在于展示了 eBPF 在 HIDS 场景中的基本架构模式（模块化探针注册、内核态采集+用户态解码、Perf/RingBuf 通道）。要成为生产级 HIDS Agent，需要在上述六个维度进行系统性补强。
