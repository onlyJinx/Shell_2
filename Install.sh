#!/bin/bash
##CDN 104.16.160.3|104.16.192.155|104.20.157.6
##ss -lnp|grep :$port|awk -F "pid=" '{print $2}'|sed s/,.*//xargs kill -9
function check(){
	###状态码赋值给s
	#return_code=$?
	###调用函数
	###函数名 参数1 参数2
	if [ "0" != "$?" ]; then
		echo "$1"
		exit 0
	fi
}

function check_port(){

	while [[ true ]]; do

		read -p "请输入监听端口(默认$1):" port
		port=${port:-$1}
		myport=$(ss -lnp|grep :$port)
		if [ -n "$myport" ];then
			echo "端口$port已被占用,输入 y 关闭占用进程,输入 n 退出程序直接回车更换其他端口"
			read sel
			if [ "$sel" == "y" ] || [ "$sel" == "Y" ]; then
				##关闭进程
				ss -lnp|grep :$port|awk -F "pid=" '{print $2}'|sed 's/,.*//'|xargs kill -9
				if ! [ -n "$(ss -lnp|grep :$port)" ]; then
					echo "已终止占用端口进程"
					break
				else
					echo "进程关闭失败,请手动关闭"
					exit 1
				fi
			elif [ "$sel" == "n" ] || [ "$sel" == "N" ]; then
				echo "已取消操作"
				exit 0
			else
				clear
			fi
		else
			break
		fi
	done

}

function check_version(){
	if [ -x "$(command -v $1)" ]; then
		echo "$2已安装，是否继续覆盖安装？(Y/N)"
		read -t 30 -p "" sel
		if [ "$sel" == "y" ] || [ "$sel" == "Y" ];then
			echo "继续执行安装"
		else
			echo "已取消安装"
			exit 0
		fi
	fi
}

function check_fin(){
	if [ -x "$(command -v $1)" ]; then
		echo "编译安装完成"
	else
		echo "编译失败，请手动检查！！"
		exit 1
	fi
}

function download_dir(){

	#函数 提示语 默认路劲
	read -p "$1" dir
	dir=${dir:-$2}
	 if [ ! -d $dir ]; then
	 	echo "文件夹不存在，已创建文件夹 $dir"
	 	mkdir $dir
	 fi
}

function check_directory_exist(){
	##a_dir=$1
	if [[ -d $1 ]]; then
		echo 文件夹 $1 存在，是否删除\(y/n\)?
		read sel
		if [ "$sel" == "y" ] || [ "$sel" == "Y" ]; then
			rm -fr $1
			if [[ "$?"=="0" ]]; then
				echo 文件夹 $1 已删除
			else
				echo 文件夹 $1 删除失败，请手动删除！
				exit 0
			fi
		else
			mv $1 $1_$(date +%T)
			echo 已将目录 $1 移动至 $1_$(date +%T)
		fi
	fi
}

function shadowsocks-libev(){

	check_directory_exist /root/shadowsocks-libev
	check_version ss-server shadowsocks
	read -t 60 -p "请输入密码，直接回车则设置为默认密码: nPB4bF5K8+apre." passwd
	passwd=${passwd:-nPB4bF5K8+apre.}

	check_port 443

	###echo "passwd=$passwd"
	###搬瓦工默认禁用epel
	#yum remove epel-release -y
	#yum install epel-release -y

	###yum install gcc gettext autoconf libtool automake make pcre-devel asciidoc xmlto c-ares-devel libev-devel libsodium-devel mbedtls-devel -y
	yum install gcc gettext autoconf libtool automake make pcre-devel wget git vim asciidoc xmlto libev-devel -y
	###手动编译libsodium-devel mbedtls-devel c-ares


	###Installation of MbedTLS
	wget --no-check-certificate https://tls.mbed.org/download/mbedtls-2.16.3-gpl.tgz
	###wget https://tls.mbed.org/download/mbedtls-2.16.2-apache.tgz
	tar xvf mbedtls*gpl.tgz
	cd mbedtls*
	make SHARED=1 CFLAGS=-fPIC
	sudo make DESTDIR=/usr install
	check "shadowsocks依赖MbedTLS编译失败！"
	cd ~
	sudo ldconfig

	###Installation of Libsodium
	## wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz
	## wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
	## tar xvf LATEST.tar.gz
	## cd libsodium-stable
	## ./configure --prefix=/usr && make
	## sudo make install
	## check "shadowsocks依赖Libsodium"
	## sudo ldconfig
	## cd ~

	wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
	cd LATEST
	./configure --prefix=/usr
	make && make install
	check "shadowsocks依赖Libsodium编译失败！"
	sudo ldconfig
	cd ~


	###Installation of c-ares
	git clone https://github.com/c-ares/c-ares.git
	cd c-ares
	./buildconf
	autoconf configure.ac
	./configure --prefix=/usr && make
	sudo make install
	check "shadowsocks依赖c-ares编译失败！"
	sudo ldconfig
	cd ~
	###安装方法引用http://blog.sina.com.cn/s/blog_6c4a60110101342m.html

	###报错 undefined reference to `ares_set_servers_ports_csv'，指定libsodium configure路径
	###Installation of shadowsocks-libev
	git clone https://github.com/shadowsocks/shadowsocks-libev.git
	cd shadowsocks-libev
	git submodule update --init --recursive
	./autogen.sh && ./configure --with-sodium-include=/usr/include --with-sodium-lib=/usr/lib
	##检查编译返回的状态码
	check "ShadowSocks-libev configure失败！"
	make && make install

	###尝试运行程序
	check_fin "ss-server"
	mkdir /etc/shadowsocks-libev
	###cp /root/shadowsocks-libev/debian/config.json /etc/shadowsocks-libev/config.json

	###crate config.json
	###"plugin_opts":"obfs=tls;failover=127.0.0.1:888"
	cat >/etc/shadowsocks-libev/config.json<<-EOF
	{
	    "server":"0.0.0.0",
	    "server_port":$port,
	    "local_port":1080,
	    "password":"$passwd",
	    "timeout":60,
	    "method":"xchacha20-ietf-poly1305",
	    "fast_open": true,
	    "nameserver": "8.8.8.8",
	    "plugin":"/etc/shadowsocks-libev/v2ray-plugin",
	    "plugin_opts":"server",
	    "mode": "tcp_and_udp"
	}
	EOF


	###下载V2ray插件
	wget https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.0/v2ray-plugin-linux-amd64-v1.3.0.tar.gz
	tar zxvf v2ray-plugin* && mv v2ray-plugin_linux_amd64 /etc/shadowsocks-libev/v2ray-plugin &&rm -f v2ray-plugin*


	###crate service
	cat >/etc/systemd/system/ssl.service<<-EOF
	[Unit]
	Description=Shadowsocks Server
	After=network.target
	[Service]
	ExecStart=/usr/local/bin/ss-server -c /etc/shadowsocks-libev/config.json
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF

	systemctl start ssl&&systemctl enable ssl
	### remove the file
	cd /root && rm -fr mbedtls* shadowsocks-libev libsodium LATEST.tar.gz c-ares

	clear
	###ss -lnp|grep 443
	echo -e port:"          ""\e[31m\e[1m$port\e[0m"
	echo -e password:"      ""\e[31m\e[1m$passwd\e[0m"
	echo -e method:"        ""\e[31m\e[1mxchacha20-ietf-poly1305\e[0m"
	echo -e plugin:"        ""\e[31m\e[1mv2ray-plugin\e[0m"
	echo -e plugin_opts:"   ""\e[31m\e[1mhttp\e[0m"
	echo -e config.json:"   ""\e[31m\e[1m/etc/shadowsocks-libev/config.json\n\n\e[0m"
	echo -e use \""\e[31m\e[1msystemctl status ssl\e[0m"\" run the shadowsocks-libev in background
	echo -e "\e[31m\e[1mhttps://github.com/shadowsocks\e[0m"
}

function transmission(){

	check_directory_exist transmission-3.00+
	check_version transmission-daemon transmission
	clear
	check_port 9091
	clear
	read -p "请输入用户名，直接回车则设置为默认用户 transmission:  " uname
	uname=${uname:-transmission}
	clear
	read -p "请输入密码，直接回车则设置为默认密码 transmission2020:  " passwd
	passwd=${passwd:-transmission2020}
	clear
	download_dir "输入下载文件保存路径(默认/usr/downloads): " "/usr/downloads"
	check "downloads文件夹创建失败！"
	config_path="/root/.config/transmission-daemon/settings.json"

	if [[ "$(type -P apt)" ]]; then
		echo "Debian"
		apt-get -y --no-install-recommends install ca-certificates libcurl4-openssl-dev libssl-dev pkg-config build-essential autoconf libtool zlib1g-dev intltool libevent-dev wget git
		check "transmission依赖安装失败"
	elif [[ "$(type -P yum)" ]]; then
		yum -y install gcc gcc-c++ make automake libtool gettext openssl-devel libevent-devel intltool libiconv curl-devel systemd-devel wget git
	else
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi
	
	wget https://github.com/transmission/transmission-releases/raw/master/transmission-3.00.tar.xz
	tar xf transmission-3.00.tar.xz && cd transmission-3.00

	./autogen.sh && make && make install
	rm -fr transmission-3.00 transmission-3.00.tar.xz
	###检查返回状态码
	check "transmission编译失败！"

	##crate service
	cat >/etc/systemd/system/transmission-daemon.service<<-EOF
	[Unit]
	Description=Transmission BitTorrent Daemon
	After=network.target

	[Service]
	User=root
	Type=simple
	ExecStart=/usr/local/bin/transmission-daemon -f --log-error
	ExecStop=/bin/kill -s STOP \$MAINPID
	ExecReload=/bin/kill -s HUP \$MAINPID

	[Install]
	WantedBy=multi-user.target
	EOF

	##调节UPD缓冲区
	echo "sysctl -w net.core.rmem_max=4195328" >> /etc/sysctl.conf
	echo "sysctl -w net.core.wmem_max=4195328" >> /etc/sysctl.conf
	/sbin/sysctl -p

	##首次启动，生成配置文件

	systemctl start transmission-daemon.service
	check "transmission启动失败！"
	systemctl stop transmission-daemon.service

	##systemctl status transmission-daemon.service

	## change config  sed引用 https://segmentfault.com/a/1190000020613397
	
	sed -i '/rpc-whitelist-enabled/ s/true/false/' $config_path
	sed -i '/rpc-host-whitelist-enabled/ s/true/false/' $config_path
	sed -i '/rpc-authentication-required/ s/false/true/' $config_path
	##取消未完成文件自动添加 .part后缀
	sed -i '/rename-partial-files/ s/true/false/' $config_path
	##单引号里特殊符号都不起作用$ or /\，使用双引号替代单引号
	##sed -i "/rpc-username/ s/\"\"/\"$uname\"/" $config_path
	sed -i "/rpc-username/ s/: \".*/: \"$uname\",/" $config_path
	sed -i "/rpc-port/ s/9091/$port/" $config_path
	##sed分隔符/和路径分隔符混淆，用:代替/
	sed -i ":download-dir: s:\/root\/Downloads:$dir:" $config_path
	sed -i "/rpc-password/ s/\"{.*/\"$passwd\",/" $config_path
	##开启限速
	sed -i "/speed-limit-up-enabled/ s/false/true/" $config_path
	##限速1M/s
	sed -i "/\"speed-limit-up\"/ s/:.*/: 1024,/" $config_path
	##limit rate
	sed -i "/ratio-limit-enabled/ s/false/true/" $config_path
	sed -i "/\"ratio-limit\"/ s/:.*/: 4,/" $config_path

	##替换webUI
	cd ~
	git clone https://github.com/ronggang/transmission-web-control.git
	mv /usr/local/share/transmission/web/index.html /usr/local/share/transmission/web/index.original.html
	cp -r /root/transmission-web-control/src/* /usr/local/share/transmission/web/

	systemctl start transmission-daemon.service
	systemctl enable transmission-daemon.service

	clear

	echo -e port:"          ""\e[31m\e[1m$port\e[0m"
	echo -e password:"      ""\e[31m\e[1m$passwd\e[0m"
	echo -e username:"      ""\e[31m\e[1m$uname\e[0m"
	echo -e download_dir:"      ""\e[31m\e[1m$dir\e[0m"
	echo -e config.json:"   ""\e[31m\e[1m/root/.config/transmission-daemon/settings.json\n\n\e[0m"
}


function aria2(){

	check_directory_exist aria2
	check_version aria2c aria2
	clear
	download_dir "输入下载文件保存路径(默认/usr/downloads): " "/usr/downloads"
	clear
	read -p "输入密码(默认密码crazy_0)： " key
	key=${key:-crazy_0}

	yum install -y gcc-c++ make libtool automake bison autoconf git intltool libssh2-devel expat-devel gmp-devel nettle-devel libssh2-devel zlib-devel c-ares-devel gnutls-devel libgcrypt-devel libxml2-devel sqlite-devel gettext xz-devel gperftools gperftools-devel gperftools-libs trousers-devel

	git clone https://github.com/aria2/aria2.git && cd aria2

	##静态编译
	##autoreconf -i && ./configure ARIA2_STATIC=yes
	
	autoreconf -i && ./configure
	make && make install

	###相关编译报错引用https://weair.xyz/build-aria2/
	check aria2
	###尝试运行程序
	clear
	check_fin "aria2c"
	cat >/etc/systemd/system/aria2.service<<-EOF
	[Unit]
	Description=aria2c
	After=network.target
	[Service]
	ExecStart=/usr/local/bin/aria2c --conf-path=/aria2.conf
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF


	##aria2 config file

	cat >/aria2.conf<<-EOF
	    rpc-secret=$key
	    enable-rpc=true
	    rpc-allow-origin-all=true
	    rpc-listen-all=true
	    max-concurrent-downloads=5
	    continue=true
	    max-connection-per-server=5
	    min-split-size=10M
	    split=16
	    max-overall-download-limit=0
	    max-download-limit=0
	    max-overall-upload-limit=0
	    max-upload-limit=0
	    dir=$dir
	    file-allocation=prealloc
	EOF

	systemctl enable aria2
	systemctl start aria2

	clear

	while [[ true ]]; do
		echo "是否安装webUI (y/n)?"
		read ins
		if [ "$ins" == "y" ] || [ "$ins" == "Y" ];then
			httpd
			clear
			echo -e port:"          ""\e[31m\e[1m$port\e[0m"
			break
		elif [ "$ins" == "n" ] || [ "$ins" == "N" ];then
			clear
			break
		fi
	done

	echo -e token:"      ""\e[31m\e[1m$key\e[0m"
	echo -e download_dir:"      ""\e[31m\e[1m$dir\e[0m"
	echo -e config.json:"   ""\e[31m\e[1m/aria2.conf\n\n\e[0m"

}


function Up_kernel(){
	if [[ "$(type -P apt)" ]]; then
		echo "deb https://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
		apt update
		apt install -y -t buster-backports linux-image-cloud-amd64 linux-headers-cloud-amd64 vim
		echo "set nocompatible" >> /etc/vim/vimrc.tiny
		echo "set backspace=2" >> /etc/vim/vimrc.tiny
		sed -i '/mouse=a/ s/mouse=a/mouse-=a/' /usr/share/vim/vim81/defaults.vim
	elif [[ "$(type -P yum)" ]]; then
		###导入elrepo密钥
		rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

		###安装elrepo仓库
		rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-2.el7.elrepo.noarch.rpm

		###安装内核
		yum --enablerepo=elrepo-kernel install kernel-ml -y

		###修改默认内核
		sed -i 's/saved/0/g' /etc/default/grub

		###重新创建内核配置
		grub2-mkconfig -o /boot/grub2/grub.cfg

		# Oracel内核
		# grub2-set-default 0
		# TCP-BBR
		#net.core.default_qdisc=fq
		#net.ipv4.tcp_congestion_control=bbr

		###查看tcp_bbr内核模块是否启动
		#lsmod | grep bbr

		#Please reboot your VPS after run command "yum update -y"

		#ping 127.0.0.1 -c 5 >>null
		#reboot

		###引用：http://www.jianshu.com/p/726bd9f37220
		###引用：https://legolasng.github.io/2017/05/08/upgrade-centos-kernel/#3安装新版本内核
	else
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi

	###使修改的内核配置生效
	echo net.core.default_qdisc=fq >> /etc/sysctl.conf
	echo net.ipv4.tcp_congestion_control=bbr >> /etc/sysctl.conf
	read -p "重启电脑生效，是否现在重启? (y/N): " sureReboot
	if [[ "y" == "$sureReboot" ]]; then
		reboot
	fi

}

function xray(){

	echo "XRAY 监听端口(默认 1000)?  "
	check_port 1000
	XRAY_XTLS_PORT=$port
	echo "回落端口(默认 5555)?  "
	check_port 5555
	XRAY_DESP_PORT=$port
	echo "GRPC 监听端口(默认 1234)?  "
	check_port 1234
	XRAY_GRPC_PORT=$port
	echo "WebSocks 监听端口(默认 1235)?  "
	check_port 1235
	XRAY_WS_PORT=$port
	read -p "Grpc Name(默认 GetNames)?  " XRAY_GRPC_NAME
	XRAY_GRPC_NAME=${XRAY_GRPC_NAME:-GetNames}
	read -p "WebSocks Path(默认 WscokilR39o)?  " XRAY_WS_PATH
	XRAY_WS_PATH=${XRAY_WS_PATH:-WscokilR39o}

	XRAY_CONFIG=/usr/local/etc/xray/config.json
	bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root --beta
	if [[ "$(type -P xray)" ]]; then
		XRAY_UUID=$(xray uuid)
		XRAY_GRPC_UUID=$(xray uuid)
		XRAY_WS_UUID=$(xray uuid)
	else 
		echo "XRAY安装失败！"
		exit 1
	fi
	wget -O $XRAY_CONFIG https://raw.githubusercontent.com/onlyJinx/Shell_2/main/xtls_tcp_grpc_ws.json

	sed -i 's/XTLS_PORT/$XRAY_XTLS_PORT/' $XRAY_CONFIG
	sed -i 's/DESP_PORT/$XRAY_DESP_PORT/' $XRAY_CONFIG
	sed -i 's/GRPC_PORT/$XRAY_GRPC_PORT/' $XRAY_CONFIG
	sed -i 's/GRPC_NAME/$XRAY_GRPC_NAME/' $XRAY_CONFIG
	sed -i 's/WS_PORT/$XRAY_WS_PORT/' $XRAY_CONFIG
	sed -i 's/WS_PATH/$XRAY_WS_PATH/' $XRAY_CONFIG

	sed -i 's/XtlsForUUID/$XRAY_UUID/' $XRAY_CONFIG
	sed -i 's/GRPC_UUID/$XRAY_GRPC_UUID/' $XRAY_CONFIG
	sed -i 's/WS_UUID/$XRAY_WS_UUID/' $XRAY_CONFIG

	systemctl start xray

	check "XRAY服务启动失败"

	echo "XRAY服务正在运行"

	echo vless://$XRAY_UUID@127.0.0.1:443?security=xtls\&sni=domain.com\&flow=xtls-rprx-direct#VLESS_xtls

	echo vless://$XRAY_GRPC_UUID@domain.com:443/?type=grpc\&encryption=none\&serviceName=$XRAY_GRPC_NAME\&security=tls\&sni=domain.com#GRPC

	echo vless://XRAY_WS_UUID@127.0.0.1:443?type=ws\&security=tls\&path=%2F$XRAY_WS_UUID%3Fed%3D2048\&host=domain.com\&sni=domain.com#WS

}

function trojan(){
	clear
	echo ""
	echo "Trojan HTTPS端口： "
	check_port 443
	trojan_https_port=$port

	echo "Trojan 回落端口： "
	check_port 80
	trojan_http_port=$port
	clear

	read -p "设置一个trojan密码(默认trojanWdai1)： " PW
	PW=${PW:-trojanWdai1}
	trojan_version=`curl -s https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name|cut -f4 -d "\""|cut -c 2-`
	#获取github仓库最新版release引用 https://bbs.zsxwz.com/thread-3958.htm

	wget https://github.com/trojan-gfw/trojan/releases/download/v${trojan_version}/trojan-${trojan_version}-linux-amd64.tar.xz && tar xvJf trojan-${trojan_version}-linux-amd64.tar.xz -C /etc
	ln -s /etc/trojan/trojan /usr/bin/trojan
	config_path=/etc/trojan/config.json
	sed -i '/password2/ d' $config_path
	sed -i "/certificate.crt/ s/.crt/.$cert/" $config_path
	sed -i "/local_port/ s/443/$trojan_https_port/" $config_path
	sed -i "/remote_port/ s/80/$trojan_http_port/" $config_path
	sed -i "/\"password1\",/ s/\"password1\",/\"$PW\"/" $config_path
	sed -i ":\"cert\": s:path\/to:etc\/trojan:" $config_path
	sed -i ":\"key\": s:path\/to:etc\/trojan:" $config_path

	###crate service
	cat >/etc/systemd/system/trojan.service<<-EOF
	[Unit]
	Description=trojan Server
	After=network.target
	[Service]
	ExecStart=/etc/trojan/trojan -c /etc/trojan/config.json
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF

	systemctl start trojan
	systemctl enable trojan

}

function nginx(){
	echo "检测443及80端口"
	check_port 443
	check_port 80

	read -p "输入NGINX版本(默认1.21.1)： " nginx_version
	nginx_version=${nginx_version:-1.21.1}
	nginx_url=http://nginx.org/download/nginx-${nginx_version}.tar.gz

	##安装依赖
	if [[ "$(type -P apt)" ]]; then
		apt-get install build-essential libpcre3 libpcre3-dev zlib1g-dev git openssl wget -y
	elif [[ "$(type -P yum)" ]]; then
		yum -y install gcc gcc-c++ pcre pcre-devel zlib zlib-devel openssl openssl-devel wget
	else
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi

	wget -P /tmp $nginx_url && tar zxf /tmp/nginx-${nginx_version}.tar.gz -C /tmp/ && cd /tmp/nginx-$nginx_version
	./configure \
	--prefix=/usr/local/nginx \
	--pid-path=/run/nginx.pid \
	--lock-path=/run/nginx.lock \
	--with-http_ssl_module \
	--with-http_stub_status_module \
	--with-http_realip_module \
	--with-threads \
	--with-stream_ssl_module \
	--with-http_v2_module \
	--with-stream_ssl_preread_module \
	--with-stream=dynamic

	make && make install
	check "编译nginx失败！"

	#清理残留
	rm -fr /tmp/nginx-$nginx_version

	ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx
	mv /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.conf_backup
	wget -O /usr/local/nginx/conf/nginx.conf https://raw.githubusercontent.com/onlyJinx/Shell_2/main/nginxForFsGrpc.conf
	echo "export ngp=/usr/local/nginx/conf/nginx.conf" >> /etc/profile
	source /etc/profile
	
	###crate service
	#单双引号不转义，反单引号 $ 要转

	if [[ "$(type -P apt)" ]]; then
		###crate service
		cat >/etc/systemd/system/nginx.service<<-EOF
			[Unit]
			Description=nginx - high performance web server
			Documentation=https://nginx.org/en/docs/
			After=network-online.target remote-fs.target nss-lookup.target
			Wants=network-online.target

			[Service]
			Type=forking
			PIDFile=/run/nginx.pid
			ExecStartPre=/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf
			ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
			ExecReload=/bin/kill -s HUP \$MAINPID
			ExecStop=/bin/kill -s TERM \$MAINPID

			[Install]
			WantedBy=multi-user.target
		EOF
	elif [[ "$(type -P yum)" ]]; then
		wget -P /etc/init.d https://raw.githubusercontent.com/onlyJinx/shell_CentOS7/master/nginx
		chmod a+x /etc/init.d/nginx
		chkconfig --add /etc/init.d/nginx
		chkconfig nginx on
	else
		ceho "can't create nginx service"
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi


	###nginx编译引用自博客
	###https://www.cnblogs.com/stulzq/p/9291223.html

	systemctl start nginx
	systemctl status nginx
	systemctl enable nginx

}
function caddy(){
	echo "先关闭监听443/80端口的程序(下面直接回车)"
	check_port 443
	check_port 80
	read -p "输入域名： " caddyDomain
	# if [[ "" -eq "$caddyDomain" ]]; then
	# 	echo "没有输入域名"
	# 	exit 1
	# fi
	read -p "输入邮箱(回车不设置)： " caddyEmain
	caddyEmain=${caddyEmain:-noemail@qq.com}
	read -p "设置用户名： " caddyUser
	caddyUser=${caddyUser:-Oieu!ji330}
	read -p "设置密码： " caddyPass
	caddyPass=${caddyPass:-5eele9P!il_}
	if ! [[ $(type -P go) ]]; then
		apt install -y wget
		yum install -y wget
		wget -P /tmp https://golang.google.cn/dl/go1.16.6.linux-amd64.tar.gz
		tar zxvf /tmp/go1.16.6.linux-amd64.tar.gz -C /tmp/
		export PATH=$PATH:/tmp/go/bin
	fi
	if [[ $(type -P go) ]]; then
		cd /tmp/
		go get -u github.com/caddyserver/xcaddy/cmd/xcaddy
		~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive
		if [[ -e /root/caddy ]]; then
			mkdir /etc/caddy
			mv /root/caddy /etc/caddy/
			chmod +x /etc/caddy/caddy
			cat >/etc/caddy/Caddyfile<<-EOF
				{
					http_port  80
					https_port 443
				}
				:443, $caddyDomain
				tls $caddyEmain
				route {
					forward_proxy {
						basic_auth $caddyUser $caddyPass
						hide_ip
						hide_via
						probe_resistance
					}
					file_server { root /etc/local/nginx/html }
				}
			EOF

			cat >/etc/systemd/system/caddy.service<<-EOF
				[Unit]
				Description=Caddy
				Documentation=https://caddyserver.com/docs/
				After=network.target network-online.target
				Requires=network-online.target

				[Service]
				User=root
				Group=root
				ExecStart=/etc/caddy/caddy run --environ --config /etc/caddy/Caddyfile
				ExecReload=/etc/caddy/caddy reload --config /etc/caddy/Caddyfile
				TimeoutStopSec=5s
				LimitNOFILE=1048576
				LimitNPROC=512
				PrivateTmp=true
				ProtectSystem=full
				AmbientCapabilities=CAP_NET_BIND_SERVICE

				[Install]
				WantedBy=multi-user.target
			EOF

		else
			echo "caddy编译失败"
		fi
		
	else
		echo "Go环境配置失败！"
	fi
	rm -fr /tmp/go1.16.6.linux-amd64.tar.gz /tmp/go

	clear
	echo -e username:"      ""\e[31m\e[1m$caddyUser\e[0m"
	echo -e password:"      ""\e[31m\e[1m$caddyPass\e[0m"
}

select option in "shadowsocks-libev" "transmission" "aria2" "Up_kernel" "trojan" "nginx" "caddy"
do
	case $option in
		"shadowsocks-libev")
			shadowsocks-libev
			break;;
		"transmission")
			transmission
			break;;
		"aria2")
			aria2
			break;;
		"Up_kernel")
			Up_kernel
			break;;
		"trojan")
			trojan
			break;;
		"nginx")
			nginx
			break;;
		"caddy")
			caddy
			break;;
		*)
			echo "nothink to do"
			break;;
	esac
done
