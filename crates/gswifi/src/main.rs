//! `gswifi`: the Open GSWIFI command line client.

mod config;
mod protect;
mod registry;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::thread;

use clap::{Parser, Subcommand};
use gswifi_core::{Credentials, Secret, Stop};
use gswifi_link::json::{self, Object};
use gswifi_link::{status, RunOptions};
use log::{error, info};

use config::Network;

#[derive(Parser)]
#[command(name = "gswifi", version, about = "Open GSWIFI 校园网认证客户端")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 用命令行参数认证一个网卡
    Auth {
        /// 认证方式（gswifi drivers 查看）
        #[arg(short, long, default_value = "ruijie")]
        driver: String,
        /// 网卡名称；不填时寻找有 10.x.x.x 地址的网卡
        #[arg(short, long, default_value = "")]
        interface: String,
        #[arg(short, long)]
        username: String,
        /// 密码；不填时读取环境变量 GSWIFI_PASSWORD（不会出现在 ps 里）
        #[arg(short, long)]
        password: Option<String>,
        /// 认证方式的配置项 key=value，可重复，如 -o ext_format=classic
        #[arg(short = 'o', long = "option")]
        options: Vec<String>,
        /// 需要获取地址时执行的命令（sh -c）
        #[arg(long)]
        dhcp_script: Option<String>,
        /// 允许使用尚未在实验室/真实校园网验证的认证方式
        #[arg(long)]
        experimental: bool,
        /// 在日志里打印收发的每个报文
        #[arg(long)]
        trace: bool,
        /// 被拒绝或放弃时直接以退出码退出（默认等网卡地址变化后重新认证）
        #[arg(long)]
        exit_on_reject: bool,
        /// 把会话状态写成 JSON 文件放进这个目录（<目录>/<网卡名>.json，供界面读取）
        #[arg(long)]
        status_dir: Option<PathBuf>,
    },
    /// 按配置文件认证一个或多个网卡
    Run {
        #[arg(short, long, default_value = "/etc/gswifi/config.toml")]
        config: String,
        /// 把每个网络的会话状态写成 JSON 文件放进这个目录（<目录>/<name>.json，供界面读取）
        #[arg(long)]
        status_dir: Option<PathBuf>,
    },
    /// 列出支持的认证方式及其验证程度
    Drivers {
        /// 输出 JSON（供界面读取）
        #[arg(long)]
        json: bool,
    },
    /// 计算 NetKeeper/闪讯 的 PPPoE 拨号账号（随时间变化，拨号前即时计算）
    PppoeUsername {
        /// nk_version：1~13 经典 getPIN，14 海南
        #[arg(short = 'v', long)]
        nk_version: u8,
        #[arg(short, long)]
        username: String,
        /// 用这个 Unix 时间计算（默认当前时间）
        #[arg(long)]
        time: Option<u64>,
        /// 叠加到时间上的秒数（按服务器时间校正）
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
        time_offset: i64,
        /// 覆盖内置协议常量（仅经典 getPIN）
        #[arg(long)]
        material: Option<String>,
        /// 输出格式：escaped（C 字符串，可写进 pppd 的 user "..."）、raw、hex、json
        #[arg(long, default_value = "escaped")]
        format: String,
    },
    /// 输出示例配置文件
    ExampleConfig,
    /// 防共享检测：统一出口流量特征（nftables/sysctl/DNS）
    Protect {
        #[command(subcommand)]
        action: protect::Action,
    },
    /// 透明代理：统一 HTTP User-Agent（仅 Linux，配合 nftables 重定向）
    Proxy {
        /// 监听端口（IPv4 与 IPv6）
        #[arg(long, default_value_t = 1080)]
        port: u16,
        /// 把 HTTP 请求的 User-Agent 换成这个值；为空时不改写
        #[arg(long, default_value = "")]
        ua: String,
        /// 从 HTTP 请求中删除的请求头，可重复
        #[arg(long = "strip-header")]
        strip_header: Vec<String>,
        /// 同时转发的最大连接数，超出的连接被直接重置
        #[arg(long, default_value_t = 1024)]
        max_conns: usize,
        /// 连接空闲多久后关闭（秒）
        #[arg(long, default_value_t = 7440)]
        idle_timeout: u64,
        /// 每 5 秒把连接统计以 JSON 写入这个文件
        #[arg(long)]
        stats: Option<String>,
        /// 开始监听后执行的命令（sh -c，环境变量 GSWIFI_PROXY_PID 为本进程号）
        #[arg(long)]
        ready_cmd: Option<String>,
    },
}

fn init_logger() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            // The status file of this thread's network keeps the latest lines.
            status::log(record.level(), record.args());
            let ts = buf.timestamp_seconds();
            match thread::current().name() {
                Some(name) if name != "main" => writeln!(buf, "[{} {} {}] {}", ts, record.level(), name, record.args()),
                _ => writeln!(buf, "[{} {}] {}", ts, record.level(), record.args()),
            }
        })
        .init();
}

fn main() {
    init_logger();
    let cli = Cli::parse();
    match cli.command {
        Command::Auth { driver, interface, username, password, options, dhcp_script, experimental, trace, exit_on_reject, status_dir } => {
            let password = match password.or_else(|| std::env::var("GSWIFI_PASSWORD").ok()) {
                Some(p) => p,
                None => {
                    error!("请用 -p 或环境变量 GSWIFI_PASSWORD 提供密码");
                    exit(1);
                }
            };
            let mut table = toml::Table::new();
            for pair in &options {
                match config::cli_option(pair) {
                    Ok((k, v)) => {
                        table.insert(k, v);
                    }
                    Err(e) => {
                        error!("{}", e);
                        exit(1);
                    }
                }
            }
            let network = Network {
                name: interface.clone(),
                interface,
                driver,
                credentials: Credentials { username, password: Secret::new(password) },
                dhcp_script,
                experimental,
                trace,
                exit_on_reject,
                options: table,
            };
            gswifi_link::install_signal_handlers();
            exit(run_network(network, status_dir.as_deref()).exit_code());
        }
        Command::Run { config, status_dir } => {
            let text = match std::fs::read_to_string(&config) {
                Ok(t) => t,
                Err(e) => {
                    error!("无法读取配置文件 {}: {}", config, e);
                    exit(1);
                }
            };
            let networks = match config::parse(&text) {
                Ok(n) => n,
                Err(e) => {
                    error!("{}", e);
                    exit(1);
                }
            };
            gswifi_link::install_signal_handlers();
            exit(run_all(networks, status_dir.as_deref()));
        }
        Command::Drivers { json: true } => println!("{}", drivers_json()),
        Command::Drivers { json: false } => {
            println!("{:<12} {:<16} {:<8} 文档", "名称", "验证程度", "传输");
            for i in registry::all() {
                let docs: Vec<String> = i.docs.iter().map(|d| d.to_string()).collect();
                println!("{:<12} {:<16} {:<8} {}  {}", i.name, i.support.as_str(), format!("{:?}", i.transport), docs.join(","), i.title);
            }
        }
        Command::Protect { action } => exit(protect::run(action)),
        Command::ExampleConfig => print!("{}", config::EXAMPLE),
        Command::PppoeUsername { nk_version, username, time, time_offset, material, format } => {
            let now = time.unwrap_or_else(|| {
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
            });
            let opts = gswifi_netkeeper::Options { nk_version: Some(nk_version), material, time_offset, ..Default::default() };
            match gswifi_netkeeper::derive(&opts, &username, now) {
                Ok(d) => {
                    match format.as_str() {
                        "raw" => {
                            std::io::stdout().write_all(&d.username).ok();
                        }
                        "hex" => println!("{}", hex(&d.username)),
                        "json" => println!(
                            "{}",
                            Object::new()
                                .str("escaped", &gswifi_netkeeper::escape(&d.username))
                                .str("hex", &hex(&d.username))
                                .num("valid_until", d.valid_until)
                                .num("remaining", d.valid_until.saturating_sub(now.saturating_add_signed(time_offset)))
                                .finish()
                        ),
                        _ => println!("{}", gswifi_netkeeper::escape(&d.username)),
                    }
                    eprintln!("有效到 Unix 时间 {}（还剩 {} 秒）", d.valid_until, d.valid_until.saturating_sub(now.saturating_add_signed(time_offset)));
                }
                Err(e) => {
                    error!("{}", e);
                    exit(1);
                }
            }
        }
        Command::Proxy { port, ua, strip_header, max_conns, idle_timeout, stats, ready_cmd } => {
            let opts = gswifi_proxy::ProxyOptions {
                port,
                ua,
                strip_headers: strip_header,
                max_conns,
                idle_timeout,
                stats,
                ready_cmd,
            };
            run_proxy(opts);
        }
    }
}

#[cfg(target_os = "linux")]
fn run_proxy(opts: gswifi_proxy::ProxyOptions) {
    gswifi_proxy::run(opts);
}

#[cfg(not(target_os = "linux"))]
fn run_proxy(_opts: gswifi_proxy::ProxyOptions) {
    error!("透明代理只支持 Linux");
    exit(1);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `gswifi drivers --json`: what a front end needs to offer the drivers
/// honestly — the verification level, whether `experimental = true` is
/// required, and whether the driver can run a session at all.
fn drivers_json() -> String {
    json::array(registry::all().into_iter().map(|i| {
        let unavailable = registry::unavailable(i.name);
        Object::new()
            .str("name", i.name)
            .str("title", i.title)
            .str("transport", &format!("{:?}", i.transport).to_lowercase())
            .str("support", i.support.as_str())
            .bool("experimental", i.support.is_experimental())
            .raw("docs", &json::array(i.docs.iter().map(|d| d.to_string())))
            .bool("runnable", unavailable.is_none())
            .opt_str("unavailable", unavailable)
            .finish()
    }))
}

/// One thread per network; exits with the first non-zero code once all
/// sessions ended.
fn run_all(networks: Vec<Network>, status_dir: Option<&Path>) -> i32 {
    if networks.len() == 1 {
        return run_network(networks.into_iter().next().unwrap(), status_dir).exit_code();
    }
    let handles: Vec<_> = networks
        .into_iter()
        .map(|n| {
            let name = n.name.clone();
            let status_dir = status_dir.map(Path::to_path_buf);
            thread::Builder::new().name(name).spawn(move || run_network(n, status_dir.as_deref())).expect("spawn")
        })
        .collect();
    let mut code = 0;
    for h in handles {
        let c = h.join().map(|s| s.exit_code()).unwrap_or(1);
        if code == 0 {
            code = c;
        }
    }
    code
}

fn run_network(n: Network, status_dir: Option<&Path>) -> Stop {
    if let Some(dir) = status_dir {
        // A front end's convenience must not keep the session from running.
        if let Err(e) = status::begin(dir, &n.name) {
            log::warn!("{}", e);
        }
    }
    loop {
        let (stop, env) = run_once(&n);
        // Rejections and give-ups are terminal for this address only: a new
        // address or a rebuilt interface may well succeed (cleanroom
        // docs/gaps.md, "接口/IP 变更清除终态"; 安朗 "already online").
        let retryable = matches!(stop, Stop::Rejected { .. } | Stop::GaveUp { .. } | Stop::ServerNotFound);
        let env = env.filter(|_| retryable && !n.exit_on_reject);
        status::stopped(&stop, env.is_some());
        let Some(env) = env else { return stop };
        info!("等待网卡 {} 的地址变化后重新认证（exit_on_reject = true 可改为直接退出）", env.interface);
        if !gswifi_link::iface::wait_for_change(&env.interface, &env, &gswifi_link::STOP) {
            return Stop::Finished;
        }
        info!("网卡 {} 的地址已变化，重新认证", env.interface);
    }
}

/// One session; also returns the interface it ran on.
fn run_once(n: &Network) -> (Stop, Option<gswifi_core::Env>) {
    status::attempt();
    let Some(info) = registry::info(&n.driver) else {
        let names: Vec<_> = registry::all().iter().map(|i| i.name).collect();
        error!("不支持的认证方式 {:?}，可选: {}", n.driver, names.join(", "));
        return (Stop::Fatal("unknown driver".into()), None);
    };
    if info.support.is_experimental() && !n.experimental {
        error!(
            "{}（{}）的验证程度是 {}，尚未在实验室或真实校园网验证；确认要用请设置 experimental = true（命令行 --experimental）",
            info.title, info.name, info.support
        );
        return (Stop::Fatal("experimental driver".into()), None);
    }
    let env = match gswifi_link::iface::lookup(&n.interface) {
        Ok(env) => env,
        Err(e) => {
            error!("{}", e);
            return (Stop::Fatal(e), None);
        }
    };
    status::describe(info, &env);
    info!("网卡 {}: MAC {}，IPv4 {}", env.interface, gswifi_core::mac_str(&env.mac), env.net.ipv4());
    let run = RunOptions { interface: env.interface.clone(), mac: env.mac, dhcp_script: n.dhcp_script.clone(), trace: n.trace };
    let mut driver = match registry::build(&n.driver, env.clone(), n.credentials.clone(), n.options.clone()) {
        Ok(d) => d,
        Err(e) => {
            error!("{}", e);
            return (Stop::Fatal(e), None);
        }
    };
    let stop = match gswifi_link::run(driver.as_mut(), &run) {
        Ok(stop) => stop,
        Err(e) => {
            error!("{}", e);
            return (Stop::Fatal(e), None);
        }
    };
    match &stop {
        Stop::Finished => {}
        Stop::Rejected { message: Some(m), .. } => error!("认证被拒绝: {}", m),
        other => error!("认证结束: {:?}", other),
    }
    (stop, Some(env))
}
