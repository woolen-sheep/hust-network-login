# HUST-Network-Login

极简主义的华中科技大学校园网络认证工具，支持有线和无线网络。下载即用，大小约为 550k，静态链接无依赖。为路由器等嵌入式设备开发，支持所有主流硬件软件平台。No Python, No Dependencies, No Bullshit.

## 使用

从 Release 下载对应硬件和操作系统平台的可执行文件。

配置文件只有两行, 第一行为用户名，第二行为密码，例如

```text
M2020123123
mypasswordmypassword
```

保存为 my.conf

然后运行

```shell
./hust-network-login ./my.conf
```

my.conf 是刚才的配置文件，你可以换成其他名字。

连接成功后，程序将测试一次网络连通性。如果无法连接则进行重新登陆。

建议使用crontab运行程序：

```text
* * * * * /root/hust-network-login /root/account.conf >/root/login.log 2>&1
0 * * * * echo "$(tail -n 1000 /root/login.log)" > /root/login.log
```

### 使用两个账号

增加根据时间切换账号的功能

~~我也不知道为什么有这种需求~~

配置文件新增两行，为第二个账号。中国时间 `23:45` 至次日的 `7:00` 将切换为第二个账号。代价是编译产物体积增大。

## 编译

编译本地平台只需要使用 `cargo`。

```shell
cargo build --release
strip ./target/release/hust-network-login
```

strip 可以去除调试符号表，将体积减少到 600k 以下。

交叉编译推荐使用 `cross`，当然你也可以自己手动配置工具链。

```shell
cargo install cross
cross build --release --target mips-unknown-linux-musl
mips-linux-gnu-strip ./target/mips-unknown-linux-musl/release/hust-network-login
```

你应当根据自己的路由器平台选择硬件平台。支持的目标平台戳[这里](https://github.com/rust-embedded/cross)。
