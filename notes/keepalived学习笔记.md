Keepalived 学习笔记  
  
# 资源  
> 官网：[keepalived](https://keepalived.org/)  
  
  
# Keepalived 介绍  
  
Keepalived is a routing software written in C.   
The main goal of this project is to provide simple and robust facilities for loadbalancing and high-availability to Linux system and Linux based infrastructures.  
  
Keepalived 的负载均衡时基于 IPVS 模块提供的四层负载均衡能力  
Keepalived 的高可用是通过 VRRP 协议实现  
  
keepalived 适合无状态服务的通用高可用实现，不适合有状态服务，如 mysql  
  
功能：  
- 基于 VRRP 协议完成地址流动  
- 为 VIP 地址所在的的节点生成 IPVS 规则（IPVS 规则用户在配置文件中定义好）  
- 为 IPVS 集群的各 RS 做健康检查  
- 基于脚本调用接口完成脚本中定义的功能，进而影响集群事务，支持 nginx, haproxy 等服务  
  
# Keepalived 架构  
> [Software Design](https://keepalived.org/doc/software_design.html)  
  
  
# Keepalived 安装  
  
## 包安装  
### ubuntu 22.04  
```bash  
apt update && apt install -y keepalived  
```  
  
安装完成后服务未启动， 查看service 文件，需要配置文件 `/etc/keepalived/keepalived.conf`  
```bash  
[Unit]  
Description=Keepalive Daemon (LVS and VRRP)  
After=network-online.target  
Wants=network-online.target  
# Only start if there is a configuration file  
ConditionFileNotEmpty=/etc/keepalived/keepalived.conf  
  
[Service]  
Type=notify  
# Read configuration variable file if it is present  
EnvironmentFile=-/etc/default/keepalived  
ExecStart=/usr/sbin/keepalived --dont-fork $DAEMON_ARGS  
ExecReload=/bin/kill -HUP $MAINPID  
  
[Install]  
WantedBy=multi-user.target  
```  
  
利用官方示例生成配置文件  
```bash  
cp /usr/share/doc/keepalived/samples/keepalived.conf.sample /etc/keepalived/keepalived.conf  
```  
然后重启服务  
  
  
### rocky8  
```bash  
yum install -y keepalived  
```  
  
## 编译安装  
  
高可用：  
- active/passive  
- active/active 双主  
心跳检查用专门网卡，和对外提供服务的网卡分开  
  
# Keepalived 配置文件  
环境：ubuntu22.04  
  
主配置文件：`/etc/keepalived/keepalived.conf`  
配置文件示例：`/usr/share/doc/keepalived/samples/` 目录  
环境配置文件：`/etc/default/keepalived`  
  
`man keepalived.conf` 查看帮助  
  
  
## 全局配置  
```bash  
global_defs {  
   router_id lvs-1  
   vrrp_skip_check_adv_addr  
   ! vrrp_mcast_group4 224.0.0.20  
}  
```  
  
- router_id  
String identifying the machine (doesn't have to be hostname).  
不同 keepalived 节点的该值不相同  
- vrrp_strict   
严格遵守 VRRP 协议  
- vrrp_skip_check_adv_addr   
默认会对所有通告报文都检查，会比较消耗性能，启用此配置后，如果收到的通告报文和上一个报文是同一个路由器，则跳过检查  
  
  
## 配置虚拟路由器  
```bash  
vrrp_instance VI_1 {  
    state BACKUP  
    interface eth1  
    nopreempt  
    virtual_router_id 100  
    priority 100  
    advert_int 1  
    authentication {  
        auth_type PASS  
        auth_pass Byxf885j  
    }  
    virtual_ipaddress {  
        10.0.0.100/24 dev eth0 label eth0:1  
    }  
    unicast_src_ip 192.168.0.206  
    unicast_peer {  
       192.168.0.207  
    }  
}  
```  
  
- VI_1   
vrrp 实例名，一般为业务名称  
- state  
MASTER|BACKUP，当前节点在此虚拟路由器上的初始状态  
If the priority is 255, then the instance will transition immediately to MASTER if state MASTER is specified; otherwise the instance will wait between 3 and 4 advert intervals before it can transition,depending on the priority.  
- interface  
vrrp 虚拟路由器使用的物理接口，可以和 vip 不用一个网络接口，实现心跳功能  
- virtual_router_id  
每个虚拟路由器的唯一标识，0-255，属于一个虚拟路由器的多个 keepalived 节点的该标识必须相同，一个网络中该值必须唯一  
- priority  
当前物理节点在此虚拟路由器的优先级，1-254，如果多个节点的优先级相同，则先启动的节点优先获取 VIP  
- advert_int  
vrrp 通告时间间隔，默认 1s  
- authentication  
认证机制，认证类型 PASS 表示简单密码，auth_pass 为预共享密码，仅前8 位有效，同一个虚拟路由器的多个 keepalived 节点必须相同  
- virtual_address  
虚拟 ip，可能有多个 VIP   
  
## 配置单独日志文件  
默认 keepalived 的日志记录在系统日志中，且类别为 `LOG_DAEMON`，查询帮助文档有说明，可以修改配置文件自定义日志文件的记录  
  
`keepalived -S`:  
```bash  
-S, --log-facility={0-7|local{0-7}|user|daemon}  
              Set syslog facility to LOG_LOCAL[0-7], LOG_USER or LOG_DAEMON.  
              The default syslog facility is LOG_DAEMON.  
```  
  
keepalived 有命令选项支持日志的设置，可以将该选项作为启动的选项，在 service 文件中指定：  
```bash  
[Unit]  
Description=Keepalive Daemon (LVS and VRRP)  
After=network-online.target  
Wants=network-online.target  
# Only start if there is a configuration file  
ConditionFileNotEmpty=/etc/keepalived/keepalived.conf  
  
[Service]  
Type=notify  
# Read configuration variable file if it is present  
EnvironmentFile=-/etc/default/keepalived  
ExecStart=/usr/sbin/keepalived --dont-fork $DAEMON_ARGS  
ExecReload=/bin/kill -HUP $MAINPID  
  
[Install]  
WantedBy=multi-user.target  
```  
service 文件中指定启动的选项为变量 `$DAEMON_ARGS`，该变量的值可以在环境配置文件 `/etc/default/keepalived` 中指定：  
```bash  
# Options to pass to keepalived  
  
# DAEMON_ARGS are appended to the keepalived command-line  
DAEMON_ARGS="-D -S 6"  
```  
  
`keepalived -D`:  
```bash  
-D, --log-detail  
    Detailed log messages.  
```  
  
经过上述配置，keepalived 的日志类别为 local6，然后在系统日志文件中设置日志的记录位置  
可以在 `/etc/rsyslog.d/` 目录中新建自定义的 `.conf` 配置文件配置：  
```bash  
local6.info           /var/log/keepalived.log  
```  
  
## 使用独立子配置文件  
主配置中仅配置全局的信息，将不同的集群配置在独立的子配置文件中，方便管理  
  
主配置文件加上 `include /etc/keepalived/conf.d/*.conf`，然后子配置文件在该目录下  
  
  
## VIP 配置单播模式  
默认 keepalived 主机之间通过多播相互通告消息，会造成网络拥塞，可以设置为单播，减少网络流量  
  
如果同时配置多播和单播，则使用单播  
  
不能启用 vrrp_strict  
  
如在 keepalived 节点实例 `vrrp_instance` 中配置单播：  
```bash  
vrrp_instance VI_1 {  
    state BACKUP  
    interface eth1  
    nopreempt  
    virtual_router_id 100  
    priority 100  
    advert_int 1  
    authentication {  
        auth_type PASS  
        auth_pass Byxf885j  
    }  
    virtual_ipaddress {  
        10.0.0.100/24 dev eth0 label eth0:1  
    }  
    unicast_src_ip 192.168.0.206 # 指定单播的源 IP  
    unicast_peer {  
       192.168.0.207 # 指定单播的目标主机，可以有多个，该集群中的其他节点主机地址  
    }  
}  
```  
  
## 配置通知脚本  
当 keepalived 状态变化时，可以自动触发脚本的执行，如发邮件通知等  
  
可以在全局配置 `global_defs` 中指定脚本执行的用户身份  
  
```bash  
# Specify the default username/groupname to run scripts under.  
# If this option is not specified, the user defaults to keepalived_script  
# if that user exists, otherwise root.  
# If groupname is not specified, it defaults to the user's group.  
script_user username [groupname]  
```  
  
### 通知脚本类型  
查看帮助文档 `man keepalived.conf`  
```bash  
# to MASTER transition  
notify_master /path/to_master.sh [username [groupname]]  
  
# to BACKUP transition  
notify_backup /path/to_backup.sh [username [groupname]]  
  
# FAULT transition  
notify_fault "/path/fault.sh VG_1" [username [groupname]]  
  
# executed when stopping vrrp  
notify_stop <STRING>|<QUOTED-STRING> [username [groupname]]  
  
# notify_deleted causes DELETED to be sent to notifies rather  
# than the default FAULT after a vrrp instance is deleted during a  
# reload. If a script is specified, that script will be executed  
# as well.  
notify_deleted [<STRING>|<QUOTED-STRING> [username [groupname]]]  
# for ANY state transition.  
# "notify" script is called AFTER the notify_* script(s) and  
# is executed with 4 additional arguments after the configured  
# arguments provided by Keepalived:  
#   $(n-3) = "GROUP"|"INSTANCE"  
#   $(n-2) = name of the group or instance  
#   $(n-1) = target state of transition (stop only applies to instances)  
#            ("MASTER"|"BACKUP"|"FAULT"|"STOP"|"DELETED")  
#   $(n)   = priority value  
#   $(n-3) and $(n-1) are ALWAYS sent in uppercase, and the possible  
# strings sent are the same ones listed above  
#   ("GROUP"/"INSTANCE", "MASTER"/"BACKUP"/"FAULT"/"STOP"/"DELETED")  
# (note: DELETED is only applicable to instances)  
notify <STRING>|<QUOTED-STRING> [username [groupname]]  
```  
  
### 调用通知脚本  
在 `vrrp_instance` 配置中调用  
格式为：`notify <STRING>|<QUOTED-STRING> [username [groupname]]`，如：  
```bash  
notify_master "/etc/keepalived/notify.sh"  
```  
  
# 抢占式和非抢占式  
抢占式 preempt，默认，如果主节点出故障，从节点获取 vip，主节点修复后，如果其优先级比当前 master 节点的优先级高，则抢回 vip  
  
切换节点可能造成一些延迟，如客户端原本记住了 vip 对于的 mac 地址（arp 缓存），切换节点后原来的 mac 地址和 vip 不对应，客户端会卡一会更新 arp 缓存信息  
  
建议设置为非抢占，防止网络抖动  
  
如果要关闭抢占模式，则各 keepalived 节点的配置 `vrrp_instance` 中的 state 均要配置为 `BACKUP`  
  
## 抢占延迟模式 preempt_delay  
优先级高的主机恢复后，延迟一段时间（默认300s）后再抢回 VIP  
  
需要各 keepalived 节点的配置 `vrrp_instance` 中的 state 均要配置为 `BACKUP`  
  
不能启用 vrrp_strict  
  
  
# Keepalived Master/Backup 模式  
## master/backup 单主架构  
  
  
### 脑裂  
主备节点同时拥有 VIP，主节点和备用节点都可能认为自己是“有效节点”，从而导致服务的重复运行或数据不一致的问题。  
  
原因：  
- 心跳线故障  
- 防火墙错误配置  
- Keepalived 配置错误  
  
arping 测试  
  
## master/master 双主模式  
主备模式一个 vip，当 MASTER 正常运行时，BACKUP 服务器未工作，如果访问量大，这种方式利用率低  
  
双主或多主模式有多个 vip  
  
双主模式：lvs1 上有两个 vip，vip1 和 vip2  
  
两个虚拟路由器，两个 vip，每个 keepalived 节点上配置两个 vrrp_instance 实例，一个实例的状态为 MASTER，另一个实例的状态为 BACKUP；另一个 keepalived 节点同样两个 vrrp_instance 实例，但 state 和第一个相反；即两个节点分别有一个 MASTER 状态和 BACKUP 状态的实例，注意调整优先级，不要让两个 VIP 都在一个节点上  
  
双主或多主模式设置为抢占模式，否则恢复后所有流量都访问到另一个节点  
  
# 同步组  
LVS NAT 模式 VIP 和 dip 同步漂移  
  
```bash  
vrrp_sync_group <STRING> {  
    group {  
        # name of the vrrp_instance (see below)  
        # Set of VRRP_Instance string  
        <STRING>  
        <STRING>  
        ...  
    }  
```  
  
# IPVS 配置  
一个虚拟服务器即一个 IPVS 集群  
  
## virtual_server 格式  
```bash  
virtual_server <IPADDR> [<PORT>]  # ip 和 端口  
virtual_server fwmark <INTEGER> # ipvs 防火墙打标记  
virtual_server group <STRING>  # 虚拟服务器组  
```  
  
例如：  
```bash  
virtual_server fwmark 100 {  
    delay_loop 6  
    lb_algo wrr  
    lb_kind NAT  
    persistence_timeout 50  
    protocol TCP  
  
    real_server 172.27.0.30 80 {  
        weight 1  
        HTTP_GET {  
            url {  
              path /index.html  
              status_code 200  
            }  
            connect_timeout 3  
            retry 3  
            delay_before_retry 3  
        }  
    }  
  
    real_server 172.27.0.31 80 {  
        weight 1  
        HTTP_GET {  
            url {  
              path /index.html  
              status_code 200  
            }  
            connect_timeout 3  
            retry 3  
            delay_before_retry 3  
        }  
    }  
}  
```  
