# PR #466 / #467 实测（Mac Studio）

这个目录只在测试分支 `codex/memtest-466-467` 上，用来实测，不要合并。

用真实数据比较 main 和 main + #466 + #467：结果是否一致、每类节点要多少内存、查询多快。

## 测什么

对每个构建（main、pr）依次：

1. 起一对 DPF 服务端（两个 `--role secondary --serve-queries`，端口 18091/18092），跑 4 轮：冷缓存 1 个客户端、热缓存 1 个、冷缓存 4 个并发、热缓存 4 个并发。
2. 起一台 OnionPIR 服务端（`--role primary --serve-queries`，端口 18093），跑冷缓存和热缓存各 1 轮。

每轮客户端查一次完整快照（db 0）和一次 delta（940611 到 948454，db 1），地址固定，结果逐条和 main 比。

内存记两样：
- footprint：进程自己必须占的内存（不含 mmap 文件的页缓存），用 `vmmap --summary` 在每轮之间读，加上 `/usr/bin/time -l` 的全程峰值。这个数决定机器最少要多大内存。
- RSS：每秒采样一次，含页缓存，只作参考。

冷缓存是每轮前 `sudo purge` 清掉页缓存，相当于小内存机器每次查询都要从磁盘读表。

## 为什么不用 Docker 限内存

macOS 没法给单个进程设内存上限。Docker Desktop 是在 Linux 虚拟机里跑，数据目录要走文件共享，mmap 读起来比本机 SSD 慢很多，测出来的主要是文件共享的速度，还得另外编一份 Linux 版。所以这里改成量 footprint（够不够 8 GB 或 16 GB 一看便知）加上冷缓存耗时（小内存机器每次查询的速度）。

## 准备

- 工具：Xcode 命令行工具、`brew install cmake`、rustup、python3（系统自带的即可）。
- 一个 Bitcoin-PIR 的 clone（只读，工作在 `WORK` 下的 worktree 里进行）。不设 `REPO` 时用本目录所在的仓库。
- 磁盘：数据 53 GB（已有 948454 这一代就不用再下），两份 release 构建约 15 GB。
- 时间（估算）：下载看带宽，1 Gbps 约 10 分钟，100 Mbps 约 1.2 小时；编译 10 到 20 分钟；测量约 1 到 1.5 小时（每次启动服务端要校验约 34 GB 文件）。
- 测试期间不要在这台机器上跑别的 BitcoinPIR 服务端或大任务。

### 打开 purge（可选，但冷缓存几轮需要）

脚本用 `sudo -n /usr/sbin/purge`，不能弹密码。不开的话冷缓存几轮会跳过。你在终端里自己跑一次：

```sh
echo "$(whoami) ALL=(root) NOPASSWD: /usr/sbin/purge" | sudo tee /etc/sudoers.d/bpir-purge >/dev/null && sudo chmod 440 /etc/sudoers.d/bpir-purge
```

测完可以删掉：`sudo rm /etc/sudoers.d/bpir-purge`。

## 运行

```sh
DATA=~/bpir-data/948454 WORK=~/bpir-memtest bash scripts/memtest/run.sh
```

- `DATA` 下没有 `databases.toml` 就会用 `scripts/data-bundle.sh` 下载（可断点续传，结束时校验 SHA256）。已有数据就指过去。
- `ONLY=dpf` 或 `ONLY=onion` 只测一种后端。

## 输出

`$WORK/report-<时间>/`：
- `report.md`：结果是否一致、内存表、速度表。
- `results.json`：每个客户端的分步耗时和全部内存采样。
- `logs/`：每台服务端的日志（末尾有 `/usr/bin/time -l` 的统计）。

## 文件

- `run.sh`：检查、下载、建 worktree（main，以及 main 合并两个 PR）、编译、调用 bench.py。两个 PR 在 `docs/OPERATOR_GUIDE.md` 的同一张表上有冲突，合并时用 `-X ours` 保留 #466 那行，代码不受影响。
- `bench.py`：起停服务端、清缓存、跑客户端、采样内存、写报告。只用 Python 标准库。
- `bench_client.rs`：测试客户端，会被复制到 main worktree 的 `crates/sdk/client/examples/` 里编译。

## 已知局限

- 两台 DPF 服务端在同一台机器上，共用页缓存，冷缓存时磁盘只读一遍，比两台分开的机器略乐观。
- `vmmap` 的输出格式如果和脚本里的正则对不上，footprint 一栏会是空的；看 `logs/` 末尾的 `peak memory footprint` 也行。
