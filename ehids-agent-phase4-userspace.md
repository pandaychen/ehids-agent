# eHIDS-Agent 用户空间 Go 程序深度分析

> 基于源码实际逐行分析，覆盖 `main.go` 和 `user/` 目录下全部 22 个 `.go` 文件。

---

## 1. 程序入口与初始化流程

### 1.1 main 函数逐行执行流程

```
main.go 完整执行序列：
```

| 行号 | 代码 | 说明 |
|------|------|------|
| 18-20 | `rlimit.RemoveMemlock()` | 调用 cilium/ebpf 的 rlimit 包，移除 `RLIMIT_MEMLOCK` 限制，允许当前进程锁定足够的内存用于 eBPF map 和程序。底层调用 `setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)`。若失败直接 `log.Fatal` 退出 |
| 22-23 | `stopper` channel + `signal.Notify` | 创建缓冲为 1 的 signal channel，注册监听 `SIGINT`（Ctrl+C）和 `SIGTERM`（kill 默认信号） |
| 24 | `context.WithCancel(context.TODO())` | 创建可取消的 context，`cancelFun` 将在收到退出信号时调用，用于向所有模块广播停止信号 |
| 26-28 | logger 初始化 | 使用标准库默认 logger，打印项目 URL 和当前进程 PID |
| 30-49 | 模块遍历与启动循环 | **核心启动逻辑**，详见下节 |
| 51 | `<-stopper` | 主 goroutine 阻塞等待退出信号 |
| 52 | `cancelFun()` | 取消 context，触发所有模块的 `ctx.Done()` 通道 |
| 54-55 | 日志 + `time.Sleep(100ms)` | 打印退出日志，等待 100ms 让各 goroutine 有时间完成清理 |

### 1.2 模块遍历与启动循环详解

```go
for k, module := range user.GetModules() {
    if module.Name() != "EBPFProbeBPFCall" {
        //continue  // 模块启用临时开关（注释掉=全部启用）
    }
    logger.Printf("start to run %s module", k)
    err := module.Init(ctx, logger)   // 同步初始化
    if err != nil {
        panic(err)                     // 初始化失败直接 panic
    }
    go func(module user.IModule) {     // 异步启动
        err := module.Run()
        if err != nil {
            logger.Printf("%v\n", err)
        }
    }(module)
}
```

**执行语义：**
1. `GetModules()` 返回全局 `map[string]IModule`，遍历顺序不确定（Go map 随机序）
2. 每个模块先**同步调用** `Init()`，传入共享的 context 和 logger
3. 初始化成功后，**异步启动** `Run()` — 每个模块在独立 goroutine 中运行
4. 代码中保留了按模块名过滤的开关（`Name() != "EBPFProbeBPFCall"`），但 continue 被注释掉，实际全部模块都会启动

### 1.3 eBPF 程序的加载和附加顺序

每个模块的 `Run()` 方法内部调用链（以 `Module.Run()` 基类模板为准）：

```
Run()
 ├── child.Start()
 │    ├── assets.Asset("user/bytecode/xxx.o")    // 1. 从 go-bindata 嵌入的二进制中读取 ELF
 │    ├── setupManagers()                         // 2. 配置 ebpfmanager 的 Probe/Map 声明
 │    ├── bpfManager.InitWithOptions(reader, opts) // 3. 解析 ELF → 创建 eBPF map → 加载 eBPF 程序
 │    ├── bpfManager.Start()                       // 4. 附加 probe 到内核 hook 点
 │    └── initDecodeFun()                          // 5. 建立 map → decoder 的映射关系
 ├── readEvents()                                  // 6. 根据 map 类型创建 reader goroutine
 └── go run()                                      // 7. 启动 context 监听 goroutine
```

**各模块加载的 eBPF 程序及其 hook 点：**

| 模块名 | ELF 文件 | Probe 类型 | 内核 Hook 点 | eBPF Map |
|--------|----------|-----------|-------------|----------|
| `EBPFProbeProc` | `proc_kern.o` | kretprobe | `copy_process` | `ringbuf_proc` (RingBuf) |
| `EBPFProbeKTCP` | `tcp_set_state_kern.o` | kprobe | `tcp_set_state` | `events` (PerfEventArray), `conns` |
| `EBPFProbeKTCPSec` | `sec_socket_connect_kern.o` | kprobe | `security_socket_connect` | `ipv4_events`, `ipv6_events`, `other_socket_events` |
| `EBPFProbeKUDP` | `udp_lookup_kern.o` | kprobe+kretprobe | `udp_recvmsg` | `dns_events` |
| `EBPFProbeUDNS` | `dns_lookup_kern.o` | uprobe+uretprobe | `getaddrinfo` (libc) | `events` |
| `EBPFProbeBPFCall` | `bpf_call_kern.o` | tracepoint | `syscalls/sys_enter_bpf` | `events` (PerfEventArray) |
| `EBPFProbeUJavaRASP` | `java_exec_kern.o` | uprobe | `JDK_execvpe` (libjava.so) | `jdk_execvpe_events` |

> **注意：** `EBPFProbeKUDP` 模块的 `init()` 中 `Register(mod)` 被注释掉，实际不会被加载。

### 1.4 信号处理和优雅退出机制

```
退出流程时序图：

[SIGINT/SIGTERM] → stopper channel 可读
                 → cancelFun() 调用
                 → ctx.Done() 关闭
                 → 每个模块的 run() goroutine 感知到 ctx.Done()
                    → 调用 child.Stop()
                 → 每个 reader goroutine (perfEventReader/ringbufEventReader)
                    → 感知到 ctx.Done()，退出循环
                 → main 等待 100ms 后进程退出
```

**退出机制的关键问题：**

1. **无 WaitGroup 同步**：主 goroutine 仅 `time.Sleep(100ms)` 后退出，不等待子 goroutine 完成清理。如果 eBPF reader 的阻塞 `Read()` 调用未及时返回，可能导致资源泄漏
2. **Stop vs Close 不统一**：`Module.run()` 监听 `ctx.Done()` 后调用 `child.Stop()`（空实现），但每个子模块实现了 `Close()`（调用 `bpfManager.Stop(CleanAll)`）。`Close()` 方法实际上从未被主流程调用
3. **reader 不主动关闭**：`perf.Reader` 和 `ringbuf.Reader` 的 `Close()` 方法虽然在 `defer` 中注册，但 reader 正在阻塞的 `Read()` 不会被中断——需要外部调用 `reader.Close()` 才能让 `Read()` 返回 `ErrClosed`

---

## 2. 事件处理管线

### 2.1 整体数据流

```
┌──────────────┐    ┌──────────────────────┐    ┌───────────────┐    ┌──────────┐
│ Kernel eBPF  │───>│ RingBuf/PerfEventArray│───>│ Go Reader     │───>│ Decode() │
│   Program    │    │      (eBPF Map)       │    │ (goroutine)   │    │          │
└──────────────┘    └──────────────────────┘    └───────────────┘    └────┬─────┘
                                                                          │
                                                                    ┌─────▼─────┐
                                                                    │ String()  │
                                                                    │ 序列化     │
                                                                    └─────┬─────┘
                                                                          │
                                                                    ┌─────▼─────┐
                                                                    │  Write()  │
                                                                    │ 日志输出   │
                                                                    └───────────┘
```

### 2.2 从 Ring Buffer / Perf Buffer 读取事件的回调逻辑

`Module.readEvents()` 方法是事件分发的入口，根据 map 类型启动不同的 reader：

```go
func (this *Module) readEvents() error {
    var errChan = make(chan error, 8)
    for _, event := range this.child.Events() {   // 遍历子模块声明的所有 event map
        switch {
        case event.Type() == ebpf.RingBuf:
            go this.ringbufEventReader(errChan, event)    // RingBuf 类型
        case event.Type() == ebpf.PerfEventArray:
            go this.perfEventReader(errChan, event)       // PerfEventArray 类型
        default:
            errChan <- fmt.Errorf("Not support mapType:...")
        }
    }
    // 阻塞等待任意一个 reader 返回错误
    for {
        select {
        case err := <-errChan:
            return err
        }
    }
}
```

**关键设计细节：**

- 每个 eBPF map 对应一个独立的 reader goroutine
- `errChan` 缓冲 8 个错误，**任意一个 reader 出错即导致整个 `readEvents()` 返回**
- `readEvents()` 的错误会传播到 `Run()` → 传播到 main 中的 goroutine（仅打印日志，不影响其他模块）

#### 2.2.1 RingBuf Reader（`ringbufEventReader`）

```go
func (this *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
    rd, err := ringbuf.NewReader(em)  // 创建 ringbuf reader
    defer rd.Close()
    for {
        select {
        case _ = <-this.ctx.Done():   // 检查是否收到退出信号
            return
        default:
        }
        record, err := rd.Read()       // 阻塞读取（无超时）
        // ... 错误处理 ...
        result, err = this.child.Decode(em, record.RawSample)  // 解码
        this.Write(result)             // 输出
    }
}
```

**注意**：`select` 中的 `ctx.Done()` 检查是**非阻塞**的（`default` 分支），但紧接着的 `rd.Read()` 是**阻塞**的。这意味着如果 `rd.Read()` 正在等待数据，即使 ctx 被取消，reader 也不会立即退出——需要等到下一次事件到来或 reader 被 Close。

#### 2.2.2 PerfEventArray Reader（`perfEventReader`）

```go
func (this *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
    rd, err := perf.NewReader(em, os.Getpagesize())  // 缓冲区大小为 1 个页面
    defer rd.Close()
    for {
        select {
        case _ = <-this.ctx.Done():
            return
        default:
        }
        record, err := rd.Read()
        if record.LostSamples != 0 {  // 丢失样本处理
            log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
            continue
        }
        result, err = this.child.Decode(em, record.RawSample)
        this.Write(result)
    }
}
```

**与 RingBuf 的差异：**
- PerfEventArray reader 的缓冲区大小为 `os.Getpagesize()`（通常 4KB），较小
- 有 `LostSamples` 检测，ringbuf reader 没有（ringbuf 天然由内核保证不丢数据或覆盖旧数据）

#### 2.2.3 BPFCall 模块的特殊路径

`MBPFCallProbe` 使用了 ebpfmanager 内置的 `PerfMap` 回调机制，绕过了 `Module.readEvents()` 的通用路径：

```go
perfMap.PerfMapOptions = manager.PerfMapOptions{
    PerfRingBufferSize: 1 * os.Getpagesize(),
    DataHandler:        this.dataHandler,       // 自定义数据处理回调
    LostHandler:        this.lostEventsHandle,  // 自定义丢失处理回调
}
```

其 `dataHandler` 直接在回调中完成 Decode + Write，不经过基类的 `readEvents()` → `Decode()` 流程。而由于 `initDecodeFun()` 返回空（无 map 注册），`Events()` 返回空切片，`readEvents()` 不会启动任何 reader goroutine。

### 2.3 事件反序列化和解析

#### 2.3.1 通用解码流程

```
Module.Decode(em, rawBytes)
  │
  ├── child.DecodeFun(em)          // 通过 map 指针查找对应的 IEventStruct 原型
  │   └── eventFuncMaps[em]        // map[*ebpf.Map]IEventStruct 查表
  │
  └── EventsDecode(payload, es)
      ├── te := es.Clone()         // 克隆一个新的空事件对象（原型模式）
      ├── te.Decode(payload)       // 二进制反序列化
      └── s = te.String()          // 序列化为人类可读字符串
```

**为什么需要 Clone？** `eventFuncMaps` 中存储的是原型对象（prototype），每次解码时克隆一个新对象避免并发写入冲突和数据残留。

#### 2.3.2 各探针的 Decode 实现对比

| 事件结构体 | 解码方式 | 核心字段 | 富化处理 |
|-----------|---------|---------|---------|
| `ForkProcEvent` | `binary.Read` 逐字段读取 | ChildPid, ParentPid, GrandParentPid, Comm, Cmdline, Path | 三级进程树（子/父/祖父） |
| `TCPEvent` | `binary.Read` 逐字段读取 | StartNS, EndNS, PID, LAddr, LPort, RAddr, RPort, Rx, Tx | `inet_ntop` IP转换，Family 枚举，方向/结果标志位解析 |
| `EventIPV4` | `binary.Read` 逐字段读取 | TSUS, PID, UID, AF, LAddr, LPort, RAddr, RPort, TASK | `time.UnixMicro` 时间戳转换 |
| `EventIPV6` | `binary.Read` 逐字段读取 | TSUS, PID, UID, AF, TASK, RAddr[16], RPort | IPv6 地址 16 字节数组 |
| `EventOther` | `binary.Read` 逐字段读取 | TSUS, PID, UID, AF, TASK | 最简结构 |
| `UDPEvent` | 混合解码：`binary.Read` + 手动切片 + DNS 协议解析 | pid, comm, packet → DNS Questions/Answers | 使用 `rawdns` 库做 DNS 报文深度解析 |
| `DNSEVENT` | `binary.Read` 逐字段读取 | PID, UID, AF, AddrIpv4, AddrIpv6, HOST | AF 枚举，`inet_ntop` IP转换，NULL字节截断 |
| `BpfCallEvent` | **手动偏移切片**（非 binary.Read） | BPF cmd, 三级 PID 树(pid/ppid/pppid + namespace), UID/EUID, Comm, Cmdline, UtsName | `BPFCmd.String()` 枚举转换，hostname 提取 |
| `JavaJDKExecPeEvent` | `binary.Read` 逐字段读取 | Pid, Mode, File[128] | Mode 枚举（FORK/POSIX_SPAWN/VFORK/CLONE） |

#### 2.3.3 两种解码策略的技术对比

**策略一：`binary.Read` 逐字段**（大多数事件使用）

```go
buf := bytes.NewBuffer(payload)
binary.Read(buf, binary.LittleEndian, &e.Field1)
binary.Read(buf, binary.LittleEndian, &e.Field2)
// ...
```

- 优点：代码清晰，自动处理字段对齐
- 缺点：每个字段一次 `Read` 调用，性能开销较大；无法处理内核结构体中的 padding

**策略二：手动偏移切片**（`BpfCallEvent` 使用）

```go
this.Pid = uint32(ByteOrder.Uint32(data[8:12]))
this.Tgid = uint32(ByteOrder.Uint32(data[12:16]))
this.Comm = string(bytes.TrimRight(data[88:104], "\x00"))
```

- 优点：性能更好，可精确控制偏移（跳过 padding）
- 缺点：偏移量硬编码，需与内核结构体严格对齐，维护成本高

### 2.4 事件富化：上下文信息添加

事件富化主要发生在各事件结构体的 `String()` 方法中：

**IP 地址转换**（`common.go`）：
```go
func inet_ntop(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
```
将内核传来的 `uint32` 网络序 IP 转为点分十进制。

**时间戳转换**：
- `TCPEvent`：用内核单调时钟（nanoseconds）计算连接持续时间 → `time.Now().Add(-duration)`
- `EventIPV4/IPV6/Other`：微秒时间戳 → `time.UnixMicro()`
- `ForkProcEvent`：保留原始 `start_time` 数值

**协议族转换**：
```go
switch te.Family {
case AF_INET:  → "AF_INET"
case AF_INET6: → "AF_INET6"
case AF_FILE:  → "AF_FILE"
}
```

**进程信息**：内核通过 eBPF helper `bpf_get_current_comm()` 等函数直接在事件中填充，用户空间不做二次查询。

**DNS 深度解析**（`UDPEvent`）：
```go
dns.UnmarshalMessage(e.packet, &m)  // 解析 DNS 报文
// 提取 Questions: QNAME, QCLASS, QTYPE
// 提取 Answers: A 记录 → IP, CNAME 记录 → 域名
```

### 2.5 事件过滤和丢失处理

**事件过滤**：当前代码中**没有实现任何用户空间事件过滤**。所有从内核 buffer 读出的事件，经过 Decode 成功后全部输出。过滤逻辑（如果有）应在内核 eBPF 程序中完成。

**丢失处理**：

| 场景 | 处理方式 |
|------|---------|
| PerfEventArray 丢失样本 | `record.LostSamples != 0` → 打印日志，继续处理下一个事件 |
| RingBuf 丢失 | 无显式处理（RingBuf 机制下由内核自行管理覆盖策略） |
| BPFCall PerfMap 丢失 | `lostEventsHandle` 回调 → **空实现**，带有 TODO 注释引用 datadog-agent 方案 |
| Decode 错误 | 打印日志，`continue` 跳过当前事件 |

---

## 3. 模块框架设计

### 3.1 IModule 接口详解

```go
type IModule interface {
    Init(context.Context, *log.Logger) error  // 初始化模块
    Name() string                              // 返回模块名称
    Run() error                                // 启动事件监听（模板方法入口）
    Start() error                              // 加载并启动 eBPF 程序
    Stop() error                               // 停止模块
    Close() error                              // 关闭并清理资源
    SetChild(module IModule)                   // 设置子类引用（模板方法模式支持）
    Decode(*ebpf.Map, []byte) (string, error)  // 解码事件
    Events() []*ebpf.Map                       // 返回需要监听的 event map 列表
    DecodeFun(p *ebpf.Map) (IEventStruct, bool) // 根据 map 查找对应的解码器
}
```

**方法分类：**

| 分类 | 方法 | 由谁实现 |
|------|------|---------|
| 生命周期管理 | `Init`, `Start`, `Stop`, `Close` | 子类必须实现 `Init`/`Start`/`Close`；`Stop` 基类空实现 |
| 模板方法框架 | `Run`, `SetChild` | 基类 `Module` 实现 |
| 事件处理 | `Decode`, `Events`, `DecodeFun` | 子类必须实现 `Events`/`DecodeFun`；`Decode` 基类有默认实现（可覆盖） |
| 元数据 | `Name` | 基类 `Module` 实现（读取 `this.name`） |

### 3.2 Module 基类的模板方法模式

`Module` 是所有探针模块的基类，使用**手动模拟的模板方法模式**（Go 没有继承，通过 `child` 指针实现多态）：

```
┌─────────────────────────────────────────┐
│              Module (基类)               │
│                                         │
│  字段:                                   │
│    ctx    context.Context               │
│    logger *log.Logger                   │
│    child  IModule    ← 关键：子类引用    │
│    name   string                        │
│    mType  string     (kprobe/uprobe/...)│
│    reader []IClose                      │
│    opts   *ebpf.CollectionOptions       │
│                                         │
│  模板方法:                               │
│    Run() → child.Start()                │
│          → readEvents()                 │
│          → go run()                     │
│                                         │
│    Decode() → child.DecodeFun()         │
│             → EventsDecode()            │
│                                         │
│  通用方法:                               │
│    readEvents()                         │
│    perfEventReader()                    │
│    ringbufEventReader()                 │
│    Write()                              │
│    EventsDecode()                       │
└─────────────────────────────────────────┘
           ▲
           │ 组合（embedding）+ SetChild
           │
┌──────────┴──────────┐
│  MProcProbe          │
│  MTCPProbe           │
│  MTCPSecProbe        │
│  MUDPProbe           │
│  MUDNSProbe          │
│  MBPFCallProbe       │
│  MJavaRasp           │
└─────────────────────┘
```

**模板方法 `Run()` 的执行流程：**

```go
func (this *Module) Run() error {
    err := this.child.Start()   // ① 调用子类的 Start()：加载 eBPF 程序
    err = this.readEvents()     // ② 基类通用逻辑：为每个 map 启动 reader goroutine
    go func() { this.run() }()  // ③ 启动 context 监听 goroutine
    return nil
}
```

**`SetChild` 模式的工作原理：**

每个子类在 `Init()` 中调用 `this.Module.SetChild(this)`，将自身的指针存入基类的 `child` 字段。此后基类方法中通过 `this.child.XXX()` 调用子类重写的方法，实现多态调度。

```go
// 子类 Init 示例（所有子类结构一致）
func (this *MProcProbe) Init(ctx context.Context, logger *log.Logger) error {
    this.Module.Init(ctx, logger)   // 调用基类 Init
    this.Module.SetChild(this)      // 关键：注册子类引用
    this.eventMaps = make([]*ebpf.Map, 0, 2)
    this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
    return nil
}
```

### 3.3 IEventStruct 接口详解

```go
type IEventStruct interface {
    Decode(payload []byte) (err error)  // 从字节数组反序列化
    String() string                      // 序列化为人类可读字符串
    Clone() IEventStruct                 // 克隆新实例（原型模式）
}
```

**设计要点：**

1. **`Clone()` — 原型模式**：每个事件类型在 `eventFuncMaps` 中注册一个空原型实例。每次解码时，先 `Clone()` 创建新对象，避免：
   - 多个 reader goroutine 并发解码时的数据竞争
   - 前一个事件的残留数据污染下一个事件

2. **`Decode()` — 二进制协议**：所有实现都假设 `payload` 是小端序（`binary.LittleEndian`），与 Linux x86_64 内核传出的数据一致

3. **`String()` — 格式化输出**：负责事件富化（IP 转换、时间格式化、枚举映射），是事件处理管线的最后一个环节

**所有 IEventStruct 实现一览：**

| 结构体 | 所属模块 | 对应 Map | 关键字段数 |
|--------|---------|----------|-----------|
| `ForkProcEvent` | EBPFProbeProc | `ringbuf_proc` | 13 |
| `TCPEvent` | EBPFProbeKTCP | `events` | 12 |
| `EventIPV4` | EBPFProbeKTCPSec | `ipv4_events` | 9 |
| `EventIPV6` | EBPFProbeKTCPSec | `ipv6_events` | 7 |
| `EventOther` | EBPFProbeKTCPSec | `other_socket_events` | 5 |
| `UDPEvent` | EBPFProbeKUDP | `dns_events` | 5（含 DNS 解析） |
| `DNSEVENT` | EBPFProbeUDNS | `events` | 6 |
| `BpfCallEvent` | EBPFProbeBPFCall | `events` | 19（含嵌入 ProcEvent） |
| `JavaJDKExecPeEvent` | EBPFProbeUJavaRASP | `jdk_execvpe_events` | 3 |

### 3.4 模块注册机制

**全局注册表（`register.go`）：**

```go
var modules = make(map[string]IModule)  // 包级全局变量

func Register(p IModule) {
    if p == nil { panic("Register probe is nil") }
    name := p.Name()
    if _, dup := modules[name]; dup {
        panic(fmt.Sprintf("Register called twice for probe %s", name))
    }
    modules[name] = p
}

func GetModules() map[string]IModule {
    return modules
}
```

**注册时机 — `init()` 函数：**

每个 `probe_xxx.go` 文件都有 `init()` 函数，在程序启动时（`main()` 之前）自动执行：

```go
// probe_proc.go
func init() {
    mod := &MProcProbe{}
    mod.name = "EBPFProbeProc"
    mod.mType = PROBE_TYPE_KPROBE
    Register(mod)
}
```

**注册顺序**：Go 规范保证同一包内 `init()` 按文件名字母序执行，因此注册顺序为：

```
probe_bpf_call.go  → EBPFProbeBPFCall   (tracepoint)
probe_ktcp.go      → EBPFProbeKTCP      (kprobe)
probe_ktcp_sec.go  → EBPFProbeKTCPSec   (kprobe)
probe_kudp.go      → EBPFProbeKUDP      (kprobe) ← 注册被注释掉
probe_proc.go      → EBPFProbeProc      (kprobe)
probe_udns.go      → EBPFProbeUDNS      (uprobe)
probe_ujava_rasp.go→ EBPFProbeUJavaRASP (uprobe)
```

**实际注册的模块**（6 个）：`EBPFProbeBPFCall`, `EBPFProbeKTCP`, `EBPFProbeKTCPSec`, `EBPFProbeProc`, `EBPFProbeUDNS`, `EBPFProbeUJavaRASP`

**设计评价：** 这是标准的 Go `init()` + 全局注册表模式，类似 `database/sql` 的驱动注册。优点是新增模块只需创建新文件，无需修改 main.go；缺点是全局可变状态，测试不便。

---

## 4. 输出与告警

### 4.1 事件的输出格式和目标

**当前唯一输出目标**：标准日志（`log.Default()`），即 `stdout/stderr`。

**输出格式：**

```
[日期 时间] probeName:<模块名>, probeTpye:<探针类型>, <事件 String() 内容>
```

**实际输出示例：**

```
2024/01/15 10:30:45 probeName:EBPFProbeProc, probeTpye:kprobe,  fork event,childpid:12345, childtgid:12345, parentpid:1000, ...
2024/01/15 10:30:46 probeName:EBPFProbeKTCP, probeTpye:kprobe, start time:10:30:46, family:AF_INET, PID:5678, command:curl, ...
2024/01/15 10:30:47 probeName:EBPFProbeBPFCall, probeTpye:tracepoint, BPFCALL EVENT CPU:0, Cmd:BPF_MAP_CREATE, PID:9999, ...
```

### 4.2 Write() 方法分析

```go
func (this *Module) Write(result string) {
    s := fmt.Sprintf("probeName:%s, probeTpye:%s, %s", this.name, this.mType, result)
    this.logger.Println(s)
}
```

**特点：**
- 仅一行代码，纯日志打印
- `probeTpye` 是一个 typo（应为 `probeType`），但不影响功能
- 所有模块共享同一个 `log.Default()` 实例，logger 本身是线程安全的
- `BPFCallProbe` 的 `dataHandler` 直接调用 `this.Write()`，格式略有不同（多了 `CPU` 信息前缀）

### 4.3 可扩展性评估

**当前架构的扩展点和限制：**

| 维度 | 当前状态 | 扩展方案 |
|------|---------|---------|
| **输出目标** | 仅标准日志 | 可将 `Write()` 改为接口方法，注入不同的 Writer（文件/Kafka/gRPC/Elasticsearch） |
| **输出格式** | 纯文本拼接 | `BpfCallEvent` 有 JSON tag 但未使用；可改用 `json.Marshal` 输出结构化 JSON |
| **事件过滤** | 无 | 可在 `Write()` 或 `Decode()` 中添加规则引擎 |
| **告警** | 无 | 可在 `Write()` 中添加规则匹配 → 告警通知 |
| **聚合/去重** | 无 | 需要增加时间窗口聚合层 |
| **新增探针** | 创建 `probe_xxx.go` + `event_xxx.go` + `init()` 注册 | 模板化程度高，但代码重复多（每个 probe 文件几乎相同的 start/setupManagers/initDecodeFun 结构） |

**架构建议：**
1. 引入 `IWriter` 接口替代硬编码的 `logger.Println`
2. 事件输出改用结构化格式（JSON），而非在 `String()` 中做文本拼接
3. `BpfCallEvent.ProcEvent` 已有 JSON tag，是向结构化输出迁移的良好起点

---

## 5. Go 语言特定分析

### 5.1 cilium/ebpf 库的使用方式

项目使用 `cilium/ebpf v0.8.1`，但**不直接用它加载和管理 eBPF 程序**，而是通过 `ebpfmanager` 封装层间接使用。直接使用 cilium/ebpf 的场景仅限于：

**1. rlimit 管理**（`main.go`）：
```go
import "github.com/cilium/ebpf/rlimit"
rlimit.RemoveMemlock()  // 内核 5.11 之前需要，5.11+ 不再需要
```

**2. Map 类型判断**（`imodule.go`）：
```go
import "github.com/cilium/ebpf"
event.Type() == ebpf.RingBuf
event.Type() == ebpf.PerfEventArray
```

**3. Perf/RingBuf Reader**（`imodule.go`）：
```go
import "github.com/cilium/ebpf/perf"
import "github.com/cilium/ebpf/ringbuf"
perf.NewReader(em, os.Getpagesize())
ringbuf.NewReader(em)
```

**4. CollectionOptions 配置**（各 probe 文件）：
```go
ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        LogSize: 2097152,  // 2MB verifier log buffer
    },
}
```

**5. Map 指针作为事件路由 key**（`imodule.go`）：
```go
eventFuncMaps map[*ebpf.Map]IEventStruct  // 用 map 指针做查找
```

### 5.2 ebpfmanager 的封装方式

`github.com/ehids/ebpfmanager v0.2.2` 是项目核心依赖，封装了 cilium/ebpf 的加载和生命周期管理。

**使用模式（每个模块完全一致）：**

```go
// 1. 声明 Manager 结构（Probes + Maps）
this.bpfManager = &manager.Manager{
    Probes: []*manager.Probe{
        {
            Section:          "kprobe/tcp_set_state",      // ELF section 名
            EbpfFuncName:     "kprobe__tcp_set_state",     // eBPF 函数名
            AttachToFuncName: "tcp_set_state",             // 内核函数名
        },
    },
    Maps: []*manager.Map{
        { Name: "events" },
    },
}

// 2. 配置 Options
this.bpfManagerOptions = manager.Options{
    DefaultKProbeMaxActive: 512,          // kretprobe 最大并发数
    VerifierOptions: ebpf.CollectionOptions{...},
    RLimit: &unix.Rlimit{Cur: math.MaxUint64, Max: math.MaxUint64},
}

// 3. 初始化（解析 ELF + 创建 map + 加载程序）
this.bpfManager.InitWithOptions(bytes.NewReader(elfBytes), this.bpfManagerOptions)

// 4. 启动（附加 probe）
this.bpfManager.Start()

// 5. 获取 map 引用（用于事件读取）
mapObj, found, err := this.bpfManager.GetMap("events")

// 6. 停止（分离 probe + 清理 map）
this.bpfManager.Stop(manager.CleanAll)
```

**ebpfmanager 的 PerfMap 回调模式**（仅 `MBPFCallProbe` 使用）：

```go
// 声明 PerfMap
PerfMaps: []*manager.PerfMap{
    { Map: manager.Map{ Name: "events" } },
}

// 配置回调
perfMap, _ := this.bpfManager.GetPerfMap("events")
perfMap.PerfMapOptions = manager.PerfMapOptions{
    PerfRingBufferSize: 1 * os.Getpagesize(),
    DataHandler:        this.dataHandler,      // func(cpu int, data []byte, ...)
    LostHandler:        this.lostEventsHandle,  // func(CPU int, count uint64, ...)
}
```

这种回调模式让 ebpfmanager 内部管理 perf reader 的生命周期，与其他模块使用 cilium/ebpf 原生 reader 的方式不同。

**ELF 字节码加载**（`assets/ebpf_probe.go`）：

eBPF ELF 文件通过 `go-bindata` 工具在编译时嵌入到 Go 二进制中：
```go
assets.Asset("user/bytecode/proc_kern.o")  // 返回 []byte
```

### 5.3 并发模型（goroutine 编排）

**goroutine 全景图：**

```
main goroutine
  │
  ├── [阻塞] <-stopper (等待信号)
  │
  ├── goroutine: Module[0].Run()
  │     ├── [阻塞] readEvents() → 等待 errChan
  │     │     ├── goroutine: ringbufEventReader(map_a)  ← 事件读取循环
  │     │     └── goroutine: perfEventReader(map_b)     ← 事件读取循环
  │     └── goroutine: run()  ← context 监听
  │
  ├── goroutine: Module[1].Run()
  │     ├── [阻塞] readEvents()
  │     │     ├── goroutine: perfEventReader(map_c)
  │     │     ├── goroutine: perfEventReader(map_d)
  │     │     └── goroutine: perfEventReader(map_e)
  │     └── goroutine: run()
  │
  ├── goroutine: Module[2].Run()  (BPFCall - 使用 ebpfmanager 内部回调)
  │     ├── [阻塞] readEvents() → errChan 永远阻塞（无 reader 启动）
  │     └── goroutine: run()
  │     └── [ebpfmanager 内部 goroutine: PerfMap reader → dataHandler 回调]
  │
  └── ... (更多模块)
```

**goroutine 总数估算**（6 个活跃模块）：
- main: 1
- 每个模块 Run goroutine: 6
- 每个模块 run() goroutine: 6
- reader goroutine: Proc(1) + TCP(1) + TCPSec(3) + DNS(1) + JavaRASP(1) + BPFCall(0, ebpfmanager 内部管理) = 7
- ebpfmanager 内部 PerfMap reader: ≥1
- **总计约 21+ goroutine**

**并发安全分析：**

| 共享资源 | 访问方式 | 安全性 |
|----------|---------|--------|
| `log.Logger` | 多 goroutine 并发调用 `Println` | ✅ 安全（标准库 logger 内部有 mutex） |
| `eventFuncMaps` | 仅在 `initDecodeFun` 中写入（Start 阶段），reader 中只读 | ✅ 安全（写在读之前） |
| `context.Context` | 只读（`ctx.Done()` channel） | ✅ 安全 |
| `modules` 全局 map | `init()` 阶段写入，`main()` 阶段只读 | ✅ 安全（init 是单线程的） |

### 5.4 资源管理和生命周期

**资源创建与释放对照表：**

| 资源 | 创建位置 | 释放位置 | 是否确保释放 |
|------|---------|---------|------------|
| `ebpfmanager.Manager` | `Start()` 中 `InitWithOptions` + `Start` | `Close()` 中 `bpfManager.Stop(CleanAll)` | ❌ `Close()` 从未被调用 |
| `perf.Reader` | `perfEventReader` 中 `perf.NewReader` | `defer rd.Close()` | ⚠️ 依赖 goroutine 正常退出 |
| `ringbuf.Reader` | `ringbufEventReader` 中 `ringbuf.NewReader` | `defer rd.Close()` | ⚠️ 依赖 goroutine 正常退出 |
| `context.CancelFunc` | `main` 中 `context.WithCancel` | `main` 中 `cancelFun()` | ✅ 信号处理中调用 |
| eBPF 程序（内核资源） | `bpfManager.Start()` | `bpfManager.Stop(CleanAll)` | ❌ 同上，`Close()` 未被调用 |
| eBPF Map（内核资源） | `bpfManager.InitWithOptions()` | `bpfManager.Stop(CleanAll)` | ❌ 同上 |

**关键问题：eBPF 内核资源泄漏风险**

`Module.run()` 在收到 `ctx.Done()` 后调用 `child.Stop()`，但 `Stop()` 在所有子类中都是空实现（继承自基类的 `return nil`）。而实际清理逻辑在 `Close()` 方法中（调用 `bpfManager.Stop(CleanAll)`），但 **`Close()` 在整个程序中从未被任何代码路径调用**。

**实际影响：**
- 进程退出时，Linux 内核会自动清理该进程创建的 eBPF 程序和 map（因为文件描述符被关闭）
- 但 pinned map 和 pinned 程序不会被清理（如果有的话）
- 正常退出场景下影响不大，但不符合最佳实践

**建议修复方案：**

```go
// 方案 1：在 run() 中调用 Close 而非 Stop
func (this *Module) run() {
    <-this.ctx.Done()
    this.child.Close()  // 替代 this.child.Stop()
}

// 方案 2：在 main 中显式关闭
cancelFun()
for _, module := range user.GetModules() {
    module.Close()
}
```

**`IClose` 接口的孤立问题：**

```go
type IClose interface {
    Close() error
}
```

`Module` 结构体中有 `reader []IClose` 字段，但在整个代码库中**从未被使用**。这表明作者可能计划用它来管理 reader 的生命周期（将 `perf.Reader` 和 `ringbuf.Reader` 存入该切片以便统一关闭），但尚未实现。

### 5.5 `readEvents()` 阻塞问题分析

```go
func (this *Module) Run() error {
    err := this.child.Start()           // ① 同步
    err = this.readEvents()             // ② 阻塞！！
    go func() { this.run() }()          // ③ 永远不会执行到这里
    return nil
}
```

`readEvents()` 内部有一个无限循环等待 `errChan`，**永远不会正常返回**（除非某个 reader 出错）。这意味着：
- `go func() { this.run() }()` 这行代码**在正常情况下永远不会执行**
- `Run()` 方法永远不会返回 `nil`
- 但由于 `Run()` 在独立 goroutine 中调用，不会阻塞 main goroutine

**对 `BPFCallProbe` 的影响：** 该模块 `Events()` 返回空切片，`readEvents()` 直接阻塞在空的 `errChan` 上。`run()` goroutine 永远不会启动。但 ebpfmanager 内部的 PerfMap 回调机制独立工作，不受影响。上下文取消（ctx.Done）也不会被该模块感知。

---

## 附录：代码结构总览

```
main.go                    # 程序入口
assets/
  ebpf_probe.go            # go-bindata 生成的 ELF 嵌入代码（4.5MB+）
user/
  imodule.go               # IModule 接口 + Module 基类（核心框架，246行）
  ievent.go                # IEventStruct 接口（7行）
  iclose.go                # IClose 接口（5行）
  register.go              # 全局模块注册表（21行）
  common.go                # 常量定义 + inet_ntop 工具函数
  bpf_cmd.go               # BPF 系统调用命令枚举（stringer 生成）
  probe_proc.go            # 进程创建监控模块（kretprobe/copy_process）
  probe_ktcp.go            # TCP 状态变更监控模块（kprobe/tcp_set_state）
  probe_ktcp_sec.go        # 安全 socket 连接监控模块（kprobe/security_socket_connect）
  probe_kudp.go            # UDP 收包监控模块（kprobe/udp_recvmsg）← 未注册
  probe_udns.go            # DNS 查询监控模块（uprobe/getaddrinfo）
  probe_bpf_call.go        # BPF 系统调用监控模块（tracepoint/sys_enter_bpf）
  probe_ujava_rasp.go      # Java RASP 命令执行监控模块（uprobe/JDK_execvpe）
  event_proc.go            # ForkProcEvent 事件结构体
  event_tcp.go             # TCPEvent 事件结构体
  event_ktcp_sec.go        # EventIPV4/EventIPV6/EventOther 事件结构体
  event_kudp.go            # UDPEvent 事件结构体（DNS 报文解析）
  event_udns.go            # DNSEVENT 事件结构体
  event_bpf_call.go        # BpfCallEvent + ProcEvent 事件结构体
  event_java_rasp.go       # JavaJDKExecPeEvent 事件结构体
```

**代码量统计：** 用户空间 Go 代码约 1200 行（不含 go-bindata 生成的 `assets/ebpf_probe.go`），其中框架代码（imodule.go）约 246 行，7 个 probe 模块平均约 80 行/个，9 个事件结构体平均约 60 行/个。
