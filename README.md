# net-speeder IPV6
修改版net-speeder：
1. 自动检测OpenVZ的venet网卡，编译时无需区分类型。
2. 支持IPV6

原版地址：
https://github.com/snooda/net-speeder


安装步骤：

1. 准备编译环境

    请参考原版说明。

2. 下载源码并解压

    wget https://github.com/Goodwu/net-speeder/archive/master.zip
    unzip master.zip

3. 编译：

    make

4. 使用方法(需要root权限启动）：

    #参数：./net_speeder 网卡名 加速规则（bpf规则）
    #ovz用法(加速所有ip和ipv6协议数据)： 
    ./net_speeder venet0 "ip or ip6"
