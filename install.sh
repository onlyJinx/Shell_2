#!/bin/bash
##CDN 104.16.160.3|104.16.192.155|104.20.157.6
##ss -lnp|grep :$port|awk -F "pid=" '{print $2}'|sed s/,.*//xargs kill -9
function check(){
	###函数名 参数1 参数2
	if [ "0" != "$?" ]; then
		echo "$1"
		exit 0
	else 
		echo "$2"
	fi
}
function RESTART_NGINX(){
	if [[ "$(command -v nginx)" ]]; then
	/usr/local/nginx/sbin/nginx -s stop
	/usr/local/nginx/sbin/nginx
	fi
}
function packageManager(){
	SYSTEMD_SERVICES="/etc/systemd/system"
	if [[ "$(type -P apt)" ]]; then
		PKGMANAGER_INSTALL="apt install -y --no-install-recommends"
		PKGMANAGER_UNINSTALL="apt remove -y"
		RUNNING_SYSTEM="debian"
	elif [[ "$(type -P yum)" ]]; then
		PKGMANAGER_INSTALL="yum install -y"
		PKGMANAGER_UNINSTALL="yum remove -y"
		RUNNING_SYSTEM="centOS"
	else
		echo "不支持的系统"
		exit 1
	fi
}
packageManager
function CHECK_PORT(){
	#提示语 默认端口
	#带NOINPUT参数时不跳过端口输入，直接调用默认端口
	while [[ true ]]; do
		if [[ "NOINPUT" == "$1" ]];then
			port=$2
		else
			read -p "$1" port
			port=${port:-$2}
		fi
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

function CHECK_VERSION(){
	#test run,software name,current version,latest version
	if [ -x "$(command -v $1)" ]; then
		echo "$2已安装 $3，是否继续覆盖安装服务器版本$4 ?(Y/n)"
		read -t 30 sel
		if [ "$sel" == "y" ] || [ "$sel" == "Y" ] || [ "$sel" == "" ];then
			echo "继续执行安装"
			NEED_UPDATE=1
		else
			echo "已取消安装"
			exit 0
		fi
	fi
}

function DOWNLOAD_PTAH(){

	#函数 提示语 默认路劲
	read -p "$1" dir
	dir=${dir:-$2}
	 if [ ! -d $dir ]; then
	 	echo "文件夹不存在，已创建文件夹 $dir"
	 	mkdir -p $dir
	 fi
}

function CKECK_FILE_EXIST(){
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
#脚本开始安装acme.sh
##acme.sh "域名(直接调用http)"
function acme.sh(){
	WEB_ROOT=""
	STANDALONE=""
	#当前CA
	CURRENT_ACME_CA=""
	#被调用传入域名
	CALL_FUNCTION="$1"
	#卸载Socat残留
	UNINSTALL_SOCAT=""
	#设置CA机构
	SET_ACME_SERVER=""
	#http退出函数
	ACME_HTTP_RETURN=""
	#手动DNS跳过安装证书
	NEED_INSTALL_CERT="1"
	CERT_INSTALL_PATH="/ssl"
	ACME_PATH_RUN="/root/.acme.sh/acme.sh"
	DEFAULT_WEB_ROOT="/usr/local/nginx/html/"
	#第一次手动DNS校验时保存的文件，用于第二次renew
	DOMAIN_AUTH_TEMP="/tmp/DOMAIN_AUTH_TEMP.TMP.5884748"
	function ACME_DNS_API(){
		echo "开始API认证模式"
		read -p "输入DNSPod ID" DNSPOD_ID
		export DP_Id=$DNSPOD_ID
		read -p "输入DNSPod KEY" DNSPOD_KEY
		export DP_Key=$DNSPOD_KEY
		ACME_APPLY_CER="$ACME_PATH_RUN --issue -d $APPLY_DOMAIN --dns dns_dp $SET_ACME_SERVER"
	}
	function ACME_HTTP(){
		echo "开始http校验"
		if [[ "$Wildcard" ]]; then
			echo "通配符域名不支持HTTP验证，请选择其他方式"
			exit 0
		fi
		if ! [[ "$(ss -lnp|grep ':80 ')" ]]; then
			echo -e "\e[32m\e[1m80端口空闲，使用临时ACME Web服务器\e[0m"
			if ! [[ "$(command -v socat)" ]]; then
				echo "socat未安装,安装socat完成HTTP认证(Y/n),否则直接退出"
				read INSTALL_SOCAT
				if [[ "" == "$INSTALL_SOCAT" ]] || [[ "y" == "$INSTALL_SOCAT" ]]; then
					$PKGMANAGER_INSTALL socat
					UNINSTALL_SOCAT="$PKGMANAGER_UNINSTALL socat"
					check "socat安装失败" "socat已安装"
				else 
					echo "已取消安装socat"
					ACME_HTTP_RETURN="1"
					return 0
				fi
			fi
			STANDALONE="--standalone"
		else
			echo -e "\e[32m\e[1m检测到80端口占用，尝试列出所有html目录。\e[0m"
			find / -name html
			read -p "输入网站根目录: " ENTER_NGINX_PTAH
			ENTER_NGINX_PTAH=${ENTER_NGINX_PTAH:-$DEFAULT_WEB_ROOT}
			WEB_ROOT="--webroot "$ENTER_NGINX_PTAH
			if ! [[ -d "$ENTER_NGINX_PTAH" ]]; then
				echo "输入的非目录，退出！"
				echo -e "\e[32m\e[1m如不确定，手动关闭80端口监听程序后\e[0m"
				echo "重新运行脚本让acme.sh临时监听80端口完成验证"
				exit 1
			fi
		fi
		ACME_APPLY_CER="$ACME_PATH_RUN --issue -d $APPLY_DOMAIN $WEB_ROOT $STANDALONE $SET_ACME_SERVER"
	}
	function ACME_DNS_MANUAL(){
		echo "开始DNS手动模式"
		if [[ "$ENTER_APPLY_DOMAIN" != "$APPLY_DOMAIN" ]]; then
			##相等即没有输入内容无空格(单个域名)
			echo -e "\e[32m\e[1m手动DNS记录只支持单个域名校验\e[0m"
			exit 0
		fi
		ACME_APPLY_CER="$ACME_PATH_RUN --issue -d $APPLY_DOMAIN --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please $SET_ACME_SERVER"
		echo "$APPLY_DOMAIN" > $DOMAIN_AUTH_TEMP
		NEED_INSTALL_CERT=""
	}
	function ACME_INSTALL_CERT(){
		#传入一个以空格为分隔符的域名字符串
		DOMAIN_LISTS=($1)
		for SINGLE_DOMAIN in ${DOMAIN_LISTS[@]}
		do
			echo -e "\e[32m\e[1m开始安装${SINGLE_DOMAIN}证书\e[0m"
			if [[ $Wildcard ]]; then
				KEY_DST_PATH="/ssl/Wildcard.key"
				CER_DST_PATH="/ssl/Wildcard.cer"
			else
				KEY_DST_PATH="/ssl/$SINGLE_DOMAIN.key"
				CER_DST_PATH="/ssl/$SINGLE_DOMAIN.cer"
			fi
			CERT_FILE="/root/.acme.sh/"$SINGLE_DOMAIN"/fullchain.cer"
			if [[ -e "$CERT_FILE" ]]; then
				$ACME_PATH_RUN --install-cert -d $SINGLE_DOMAIN \
				--key-file $KEY_DST_PATH \
				--fullchain-file $CER_DST_PATH
				if [[ "$CER_DST_PATH" ]]; then
					echo -e "\e[32m\e[1m${SINGLE_DOMAIN} 证书已安装！\e[0m"
				else
					echo "${SINGLE_DOMAIN} 证书安装失败！"
				fi
			else
				echo "安装未启动，找不到证书文件！"
			fi
		done
	}
	function SET_ACME_CA(){
		echo "选择CA机构"
		select option in "letsencrypt" "letsencrypt_test" "buypass" "buypass_test" "zerossl" "sslcom"
		do
			case $option in
				"letsencrypt")
					ACME_SERVER="letsencrypt"
					break;;
				"letsencrypt_test")
					ACME_SERVER="letsencrypt_test"
					break;;
				"buypass")
					ACME_SERVER="buypass"
					break;;
				"buypass_test")
					ACME_SERVER="buypass_test"
					break;;
				"zerossl")
					ACME_SERVER="zerossl"
					break;;
				"sslcom")
					ACME_SERVER="sslcom"
					break;;
				*)
					echo "Nothink to do"
					return 0
					break;;
			esac
		done
		SET_ACME_SERVER="--server $ACME_SERVER"
		CURRENT_ACME_CA="$ACME_SERVER"
		echo "已选择证书颁发机构${ACME_SERVER}"
	}


	#选择认证方式
	function SELECT_AUTH_MOTHOD(){
		##其他函数直接调用acme HTTP验证
		if [[ "$CALL_FUNCTION" ]]; then
			ENTER_APPLY_DOMAIN=$CALL_FUNCTION
			APPLY_DOMAIN=$CALL_FUNCTION
			Wildcard=""
			ACME_HTTP
		else
			echo -e "\e[32m\e[1m输入域名，多个域名使用空格分开(a.com b.com)\e[0m"
			read ENTER_APPLY_DOMAIN
			APPLY_DOMAIN=$(echo $ENTER_APPLY_DOMAIN | sed 's/ / -d /g')
			#通配符检测
			Wildcard="$(echo $APPLY_DOMAIN | grep \*)"
			select option in "HTTP" "DNS_MANUAL" "DNS_API" "SET_ACME_CA"
			do
				case $option in
					"HTTP")
						ACME_HTTP
						break;;
					"DNS_MANUAL")
						ACME_DNS_MANUAL
						break;;
					"DNS_API")
						ACME_DNS_API
						break;;
					"SET_ACME_CA")
						SET_ACME_CA
						SELECT_AUTH_MOTHOD
						break;;
					*)
						echo "nothink to do"
						exit;;
				esac
			done
		fi
	}

	if [[ -e $DOMAIN_AUTH_TEMP ]]; then
		echo -e "\e[32m\e[1m已检测到手动DNS第二次校验，尝试直接RENEW\e[0m"
		GET_APPLY_DOMAIN="$(cat $DOMAIN_AUTH_TEMP)"
		rm -f $DOMAIN_AUTH_TEMP
		#手动DNS在脚本环境运行有bug，dev分支已修复
		$ACME_PATH_RUN --upgrade -b dev
 		$ACME_PATH_RUN --renew -d $GET_APPLY_DOMAIN --yes-I-know-dns-manual-mode-enough-go-ahead-please
		ACME_INSTALL_CERT "$GET_APPLY_DOMAIN"
		exit 0
	fi

	SELECT_AUTH_MOTHOD

	if [[ "$ACME_HTTP_RETURN" ]]; then
		echo "已被拒绝安装socat,取消证书申请"
		return 0
	else 
		if ! [[ -e "$CERT_INSTALL_PATH" ]]; then
			mkdir $CERT_INSTALL_PATH
		fi
		if ! [[ -e $ACME_PATH_RUN ]]; then
			echo "未找到acme.sh脚本，尝试在线安装"
			cd /tmp
			read -p "输入email(回车跳过)? " ACME_EMAIL
			ACME_EMAIL=${ACME_EMAIL:-no_email@gmail.com}
			curl https://get.acme.sh | sh -s email=$ACME_EMAIL
		fi
		$ACME_PATH_RUN --upgrade --auto-upgrade
		echo "$ACME_APPLY_CER"
		echo "\e[32m\e[1m当前CA机构:${CURRENT_ACME_CA}\e[0m"
		$ACME_APPLY_CER
		if [[ "$NEED_INSTALL_CERT" ]]; then
			ACME_INSTALL_CERT "$ENTER_APPLY_DOMAIN"
		else 
			echo -e "\e[32m\e[1m将上面的txt解析到对应的域名上再重新运行脚本\e[0m"
			echo -e "\e[32m\e[1m第二次运行时自动校验解析\e[0m"
			echo "休眠30秒"
			sleep 30
		fi
	fi
	#卸载Socat残留
	$UNINSTALL_SOCAT

}

#脚本开始安装SS
function shadowsocks-libev(){

	CKECK_FILE_EXIST /root/shadowsocks-libev
	#CHECK_VERSION ss-server shadowsocks
	read -t 60 -p "请输入密码，直接回车则设置为默认密码: nPB4bF5K8+apre." passwd
	passwd=${passwd:-nPB4bF5K8+apre.}

	CHECK_PORT "请输入端口号(默认443)" 443

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
	check "SS编译安装失败"
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
	cat >$SYSTEMD_SERVICES/ssl.service<<-EOF
	[Unit]
	Description=Shadowsocks Server
	After=network.target
	[Service]
	ExecStart=/usr/local/bin/ss-server -c /etc/shadowsocks-libev/config.json
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF
	systemctl daemon-reload
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
#脚本开始安装transmission
function transmission(){
	function MODIFY_CONFIG(){
		sed -i '/rpc-whitelist-enabled/ s/true/false/' $1
		sed -i '/rpc-host-whitelist-enabled/ s/true/false/' $1
		sed -i '/rpc-authentication-required/ s/false/true/' $1
		##取消未完成文件自动添加 .part后缀
		sed -i '/rename-partial-files/ s/true/false/' $1
		##单引号里特殊符号都不起作用$ or /\，使用双引号替代单引号
		sed -i "/rpc-username/ s/: \".*/: \"$TRANSMISSION_USER_NAME\",/" $1
		sed -i "/rpc-port/ s/9091/$port/" $1
		##sed分隔符/和路径分隔符混淆，用:代替/
		sed -i ":download-dir: s:\/root\/Downloads:$dir:" $1
		sed -i "/rpc-password/ s/\"{.*/\"$TRANSMISSION_PASSWD\",/" $1
		##开启限速
		sed -i "/speed-limit-up-enabled/ s/false/true/" $1
		##限速1M/s
		sed -i "/\"speed-limit-up\"/ s/:.*/: 10240,/" $1
		##limit rate
		sed -i "/ratio-limit-enabled/ s/false/true/" $1
		sed -i "/\"ratio-limit\"/ s/:.*/: 10,/" $1
	}

	CKECK_FILE_EXIST transmission-3.00+
	CHECK_VERSION transmission-daemon transmission
	clear
	CHECK_PORT "请输入端口号(9091)" 9091
	clear
	read -p "请输入用户名(transmission):  " TRANSMISSION_USER_NAME
	TRANSMISSION_USER_NAME=${TRANSMISSION_USER_NAME:-transmission}
	clear
	read -p "请输入密码(transmission2020):  " TRANSMISSION_PASSWD
	TRANSMISSION_PASSWD=${TRANSMISSION_PASSWD:-transmission2020}
	clear
	DOWNLOAD_PTAH "文件保存路径(默认/usr/downloads): " "/usr/downloads"
	check "downloads文件夹创建失败！"

	if [[ "$(type -P apt)" ]]; then
		echo "Debian"
		$PKGMANAGER_INSTALL ca-certificates libcurl4-openssl-dev libssl-dev pkg-config build-essential autoconf libtool zlib1g-dev intltool libevent-dev wget git
		check "transmission依赖安装失败"
	elif [[ "$(type -P yum)" ]]; then
		$PKGMANAGER_INSTALL gcc gcc-c++ make automake libtool gettext openssl-devel libevent-devel intltool libiconv curl-devel systemd-devel wget git
	else
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi
	
	wget https://github.com/transmission/transmission-releases/raw/master/transmission-3.00.tar.xz
	tar xf transmission-3.00.tar.xz && cd transmission-3.00

	./autogen.sh && make && make install
	rm -fr ../transmission-3.00 ../transmission-3.00.tar.xz
	###检查返回状态码
	check "transmission编译失败！"

	##crate service
	cat >$SYSTEMD_SERVICES/transmission.service<<-EOF
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
	systemctl daemon-reload
	##调节UPD缓冲区
	if ! [[ "$(cat /etc/sysctl.conf|grep 4195328)" ]]; then
		echo "net.core.rmem_max=4195328" >> /etc/sysctl.conf
		echo "net.core.wmem_max=4195328" >> /etc/sysctl.conf
		/sbin/sysctl -p
		/usr/sbin/sysctl -p
	fi
	##首次启动，生成配置文件
	systemctl start transmission.service
	check "transmission启动失败！"
	sleep 2
	systemctl stop transmission.service
	sleep 2
	TRANSMISSION_CONFIG="/root/.config/transmission-daemon/settings.json"
	## change config  sed引用 https://segmentfault.com/a/1190000020613397
	count=0
	for((i=1;i<3;i++))
	do
		if [[ -e $TRANSMISSION_CONFIG ]]; then
			MODIFY_CONFIG $TRANSMISSION_CONFIG
			break
		else
			systemctl daemon-reload	
			systemctl start transmission.service
			sleep 2
			systemctl stop transmission.service
			sleep 2
			let count++
		fi
	done
	##替换webUI
	cd ~
	git clone https://github.com/ronggang/transmission-web-control.git
	mv /usr/local/share/transmission/web/index.html /usr/local/share/transmission/web/index.original.html
	mv /root/transmission-web-control/src/* /usr/local/share/transmission/web/
	rm -fr transmission-web-control
	systemctl start transmission.service
	clear
	check "transmission-daemon 运行失败" "transmission-daemon 运行正常"
	systemctl enable transmission.service > /dev/nul 2>&1&

	echo -e port:"          ""\e[31m\e[1m$port\e[0m"
	echo -e password:"      ""\e[31m\e[1m$TRANSMISSION_PASSWD\e[0m"
	echo -e username:"      ""\e[31m\e[1m$TRANSMISSION_USER_NAME\e[0m"
	echo -e DOWNLOAD_PTAH:"      ""\e[31m\e[1m$dir\e[0m"
	echo -e config.json:"   ""\e[31m\e[1m/root/.config/transmission-daemon/settings.json\n\n\e[0m"

	NGINX_CONFIG=/usr/local/nginx/conf/nginx.conf
	if [[ -e $NGINX_CONFIG ]];then
		echo "检测到NGINX配置文件，是否开启https WEBUI反代?(Y/n) "
		read ENABLE_HTTPS_TS
		if [[ "" == "$ENABLE_HTTPS_TS" ]] || [[ "y" == "$ENABLE_HTTPS_TS" ]]; then
			while [[ true ]]; do
				read -p "输入域名(ctrl+c强制终止) " TRANSMISSION_DOMAIN
				if [[ "$TRANSMISSION_DOMAIN" ]]; then
					while [[ true ]]; do
						echo "输入文件下载服务器路径(不能为空,不带斜杠)"
						read TRRNA_FILE_SERVER_PATH
						if [[ $"TRRNA_FILE_SERVER_PATH" ]]; then
							break
						fi
					done
					cat >/usr/local/nginx/conf/sites-enabled/${TRANSMISSION_DOMAIN}<<-EOF
					server {
					    listen       4433 http2 ssl;
					    server_name  ${TRANSMISSION_DOMAIN};
					    ssl_certificate      /ssl/${TRANSMISSION_DOMAIN}.cer;
					    ssl_certificate_key  /ssl/${TRANSMISSION_DOMAIN}.key;
					    ssl_session_cache    shared:SSL:1m;
					    ssl_session_timeout  5m;
					    ssl_protocols TLSv1.2 TLSv1.3;
					    ssl_prefer_server_ciphers  on;
					    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
					    location / {
					        proxy_redirect off;
					        proxy_pass http://127.0.0.1:${port};
					        proxy_http_version 1.1;
					        proxy_set_header Upgrade \$http_upgrade;
					        proxy_set_header Connection "upgrade";
					        proxy_set_header Host \$http_host;
					    }
					    location /${TRRNA_FILE_SERVER_PATH}/ {
					        alias ${dir}/;
					        autoindex on;
					    }
					}
					EOF
					acme.sh $TRANSMISSION_DOMAIN
					RESTART_NGINX
					echo -e "\e[32m\e[1m打开网址https://${TRANSMISSION_DOMAIN}测试登录\e[0m"
					echo -e "\e[32m\e[1m文件下载服务器地址https://${TRANSMISSION_DOMAIN}/${TRRNA_FILE_SERVER_PATH}/ \e[0m"
					break
				fi
			done

		fi
	fi
}

#脚本开始安装aria2
function aria2(){

	CKECK_FILE_EXIST aria2
	CHECK_VERSION aria2c aria2
	clear
	DOWNLOAD_PTAH "文件保存路径(/usr/downloads): " "/usr/downloads"
	clear
	read -p "输入密码(默认密码crazy_0): " key
	key=${key:-crazy_0}

	if [[ "debian" == "$RUNNING_SYSTEM" ]]; then
		$PKGMANAGER_INSTALL git libxml2-dev libcppunit-dev \
		autoconf automake autotools-dev autopoint libtool \
		build-essential libtool pkg-config
		ARIA2_AUTOCONF="autoreconf -i -I /usr/share/aclocal/"
	else
		$PKGMANAGER_INSTALL gcc-c++ make libtool automake bison \
		autoconf git intltool libssh2-devel expat-devel \
		gmp-devel nettle-devel libssh2-devel zlib-devel \
		c-ares-devel gnutls-devel libgcrypt-devel libxml2-devel \
		sqlite-devel gettext xz-devel gperftools gperftools-devel \
		gperftools-libs trousers-devel
		ARIA2_AUTOCONF="autoreconf -i"
	fi

	git clone https://github.com/aria2/aria2.git && cd aria2

	##静态编译
	##autoreconf -i && ./configure ARIA2_STATIC=yes
	
	$ARIA2_AUTOCONF && ./configure
	make && make install
	rm -fr aria2

	###相关编译报错引用https://weair.xyz/build-aria2/
	check "aria2c编译安装失败"
	ARIA2_CONFIG_DIR="/etc/aria2"
	if ! [[ -d "$ARIA2_CONFIG_DIR" ]]; then
		mkdir $ARIA2_CONFIG_DIR
	fi
	cat >$SYSTEMD_SERVICES/aria2.service<<-EOF
	[Unit]
	Description=aria2c
	After=network.target
	[Service]
	ExecStart=/usr/local/bin/aria2c --conf-path=$ARIA2_CONFIG_DIR/aria2.conf
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF
	##aria2 config file

	cat >$ARIA2_CONFIG_DIR/aria2.conf<<-EOF
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
	systemctl daemon-reload
	systemctl enable aria2
	systemctl start aria2

	clear
	if [[ "$(command -v nginx)" ]]; then
		echo "already installed nginx, download WEBUI?(Y/n) "
		read ARIA2_WEBUI
		if [[ "$ARIA2_WEBUI" == "y" ]] || [[ "$ARIA2_WEBUI" == "" ]]; then
			find / -name html
			read -p "full your web root  " ARIA2_WEBUI_ROOT
			if ! [[ -d "$ARIA2_WEBUI_ROOT" ]]; then
				echo "your full path no exist"
				exit 0
			else
				if [[ "$(ls $ARIA2_WEBUI_ROOT)" ]]; then
					echo "注意！输入的文件夹里发现文件，输入yes确定强制覆盖"
					read overwrite
					if ! [[ "yes" == "$overwrite" ]]; then
						echo "已取消覆盖，退出！"
						exit 0
					fi
				fi
			fi
			cd /tmp
			git clone https://github.com/ziahamza/webui-aria2.git
			mv /tmp/webui-aria2/docs/* $ARIA2_WEBUI_ROOT
			rm -fr /tmp/webui-aria2
			RESTART_NGINX
		fi
	fi
	# while [[ true ]]; do

	# done

	echo -e "\e[32m\e[1mTONKE:        ${key}\e[0m"
	echo -e "\e[32m\e[1mDOWNLOAD_PTAH:${dir}\e[0m"
	echo -e "\e[32m\e[1mCONFIG_JSON:  /etc/aria2/aria2.conf\e[0m"

}

#脚本开始安装内核更新
function Up_kernel(){
	if [[ "$(type -P apt)" ]]; then
		if ! [[ "$(cat /etc/apt/sources.list | grep buster-backports)" ]]; then
			echo "deb https://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
		fi
		apt update
		apt upgrade -y
		$PKGMANAGER_INSTALL -t buster-backports linux-image-cloud-amd64 linux-headers-cloud-amd64 vim
		check "内核安装失败"
		echo "set nocompatible" >> /etc/vim/vimrc.tiny
		echo "set backspace=2" >> /etc/vim/vimrc.tiny
		sed -i '/mouse=a/ s/mouse=a/mouse-=a/' /usr/share/vim/vim81/defaults.vim
	elif [[ "$(type -P yum)" ]]; then
		yum update
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
	echo -e "\e[32m\e[1m重启电脑生效，是否现在重启? (y/N): \e[0m"
	read sureReboot
	if [[ "y" == "$sureReboot" ]]; then
		reboot
	fi

}
#脚本开始安装xray
function Project_X(){
	function INSTALL_BINARY(){
		#获取github仓库最新版release引用 https://bbs.zsxwz.com/thread-3958.htm
		wget -P /tmp https://github.com/XTLS/Xray-core/releases/download/v$XRAY_RELEASE_LATEST/Xray-linux-64.zip
		if ! [[ "$(type -P unzip)" ]];then
			$PKGMANAGER_INSTALL unzip
		fi
		unzip -o /tmp/Xray-linux-64.zip -d /tmp
		if ! [[ -d /usr/local/share/xray ]];then
			mkdir /usr/local/share/xray
		fi
		alias mv='mv -i'
		mv /tmp/geoip.dat /usr/local/share/xray/geoip.dat
		mv /tmp/geosite.dat /usr/local/share/xray/geosite.dat
		mv /tmp/xray /usr/local/bin/xray
		rm -f /tmp/README.md /tmp/LICENSE Xray-linux-64.zip
	}

	if [[ "$(type -P xray)" ]]; then
		XTLS_INSTALLED_VERSION=$(xray version|sed -n 1p|cut -d ' ' -f 2)
	fi
	XRAY_RELEASE_LATEST=`wget -q -O - https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name|cut -f4 -d "\""|cut -c 2-`
	CHECK_VERSION xray Xray $XTLS_INSTALLED_VERSION $XRAY_RELEASE_LATEST

	if [[ "$NEED_UPDATE" == "1" ]]; then
		INSTALL_BINARY
		##格式化版本号，去掉小数点
		TMP_VERSION=$(xray version|sed -n 1p|cut -d ' ' -f 2|sed 's/\.//g')
		XRAY_RELEASE_LATEST_FORMAT=$(echo $XRAY_RELEASE_LATEST | sed 's/\.//g')
		if [[ "$TMP_VERSION" == "$XRAY_RELEASE_LATEST_FORMAT" ]]; then
			echo "Xray已更新(v$XRAY_RELEASE_LATEST)"
			systemctl restart xray
			xray version
		else
			echo "更新失败"
			exit 1
		fi
	else
		CHECK_PORT "XRAY_XTLS 监听端口(1000)?  " 1000
		XRAY_XTLS_PORT=$port
		read -p "回落端口(5555)?  " XRAY_DESP_PORT
		XRAY_DESP_PORT=${XRAY_DESP_PORT:-5555}
		CHECK_PORT "GRPC 监听端口(2002)?  " 2002
		XRAY_GRPC_PORT=$port
		CHECK_PORT "WebSocks 监听端口(1234)?  " 1234
		XRAY_WS_PORT=$port
		read -p "Grpc Name(grpcforward)?  " XRAY_GRPC_NAME
		XRAY_GRPC_NAME=${XRAY_GRPC_NAME:-grpcforward}
		read -p "WebSocks Path(默认 wsforward)?  " XRAY_WS_PATH
		XRAY_WS_PATH=${XRAY_WS_PATH:-wsforward}
		echo "请输入域名(project_x.com)"
		echo "稍后配合acme.sh申请SSL证书"
		read  XRAY_DOMAIN
		XRAY_DOMAIN=${XRAY_DOMAIN:-project_x.com}
		INSTALL_BINARY
		if [[ "$(type -P /usr/local/bin/xray)" ]]; then
			XRAY_UUID=$(/usr/local/bin/xray uuid)
			XRAY_GRPC_UUID=$(/usr/local/bin/xray uuid)
			XRAY_WS_UUID=$(/usr/local/bin/xray uuid)
		else 
			echo "XRAY安装失败！"
			exit 1
		fi
		if ! [[ -d /usr/local/etc/xray ]];then
			mkdir /usr/local/etc/xray
		fi
		XRAY_CONFIG=/usr/local/etc/xray/config.json
		wget -O $XRAY_CONFIG https://raw.githubusercontent.com/onlyJinx/Shell_2/main/xtls_tcp_grpc_ws.json
		sed -i "s/XTLS_PORT/$XRAY_XTLS_PORT/" $XRAY_CONFIG
		sed -i "s/DESP_PORT/$XRAY_DESP_PORT/" $XRAY_CONFIG
		sed -i "s/GRPC_PORT/$XRAY_GRPC_PORT/" $XRAY_CONFIG
		sed -i "s/GRPC_NAME/$XRAY_GRPC_NAME/" $XRAY_CONFIG
		sed -i "s/WS_PORT/$XRAY_WS_PORT/" $XRAY_CONFIG
		sed -i "s/WS_PATH/$XRAY_WS_PATH/" $XRAY_CONFIG
		sed -i "s/SSL_XRAY_CER/$XRAY_DOMAIN/" $XRAY_CONFIG
		sed -i "s/SSL_XRAY_KEY/$XRAY_DOMAIN/" $XRAY_CONFIG

		sed -i "s/XtlsForUUID/$XRAY_UUID/" $XRAY_CONFIG
		sed -i "s/GRPC_UUID/$XRAY_GRPC_UUID/" $XRAY_CONFIG
		sed -i "s/WS_UUID/$XRAY_WS_UUID/" $XRAY_CONFIG

		cat > $SYSTEMD_SERVICES/xray.service <<-EOF
		[Unit]
		Description=Xray Service
		Documentation=https://github.com/xtls
		After=network.target nss-lookup.target
		[Service]
		User=root
		#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		#NoNewPrivileges=true
		ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
		Restart=on-failure
		RestartPreventExitStatus=23
		LimitNPROC=10000
		LimitNOFILE=1000000
		[Install]
		WantedBy=multi-user.target
		EOF

		NGINX_CONFIG=/usr/local/nginx/conf/nginx.conf
		if [[ -e $NGINX_CONFIG ]];then
			cat >/usr/local/nginx/conf/sites-enabled/${XRAY_DOMAIN}<<-EOF
			server {
				listen       4433 http2 ssl;
				server_name  ${XRAY_DOMAIN};
				ssl_certificate      /ssl/${XRAY_DOMAIN}.cer;
				ssl_certificate_key  /ssl/${XRAY_DOMAIN}.key;
				ssl_session_cache    shared:SSL:1m;
				ssl_session_timeout  5m;
				ssl_protocols TLSv1.2 TLSv1.3;
				ssl_prefer_server_ciphers  on;
				ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

				location /${XRAY_GRPC_NAME} {
					if (\$content_type !~ "application/grpc") {
						return 404;
					}
					client_max_body_size 0;
					client_body_timeout 1071906480m;
					grpc_read_timeout 1071906480m;
					grpc_pass grpc://127.0.0.1:${XRAY_GRPC_PORT};
				}
				location /${XRAY_WS_PATH} {
					proxy_redirect off;
					proxy_pass http://127.0.0.1:${XRAY_WS_PORT};
					proxy_http_version 1.1;
					proxy_set_header Upgrade \$http_upgrade;
					proxy_set_header Connection "upgrade";
					proxy_set_header Host \$http_host;
				}
			}
			EOF
		fi

		acme.sh "$XRAY_DOMAIN"
		RESTART_NGINX

		echo -e "\e[32m\e[1mvless://$XRAY_UUID@$XRAY_DOMAIN:443?security=xtls&sni=$XRAY_DOMAIN&flow=xtls-rprx-direct#VLESS_xtls(需要配置好SNI转发才能用)\e[0m"

		echo -e "\e[32m\e[1mvless://$XRAY_GRPC_UUID@$XRAY_DOMAIN:443?type=grpc&encryption=none&serviceName=$XRAY_GRPC_NAME&security=tls&sni=$XRAY_DOMAIN#GRPC\e[0m"

		echo -e "\e[32m\e[1mvless://$XRAY_WS_UUID@$XRAY_DOMAIN:443?type=ws&security=tls&path=/$XRAY_WS_PATH?ed=2048&host=$XRAY_DOMAIN&sni=$XRAY_DOMAIN#WS\e[0m"
	fi
}
#脚本开始安装trojan
function trojan(){
	clear
	CHECK_PORT "请输入Trojan HTTPS端口: " 443
	TROJAN_HTTPS_PORT=$port
	echo "Trojan 回落端口: "
	read TROJAN_CALLBACK_PORT
	TROJAN_HTTP_PORT=${TROJAN_CALLBACK_PORT:-5555}
	while [[ true ]]; do
		echo "输入Trojan域名"
		read ENTER_TROJAN_DOMAIN
		if [[ "$ENTER_TROJAN_DOMAIN" ]]; then
			TROJAN_DOMAIN="$ENTER_TROJAN_DOMAIN"
			break
		fi
	done
	echo "设置trojan密码(默认trojanWdai1)"
	echo "不可以包含#@?"
	read TROJAN_PASSWD
	TROJAN_PASSWD=${TROJAN_PASSWD:-trojanWdai1}
	trojan_version=`curl -s https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name|cut -f4 -d "\""|cut -c 2-`
	#获取github仓库最新版release引用 https://bbs.zsxwz.com/thread-3958.htm

	wget https://github.com/trojan-gfw/trojan/releases/download/v${trojan_version}/trojan-${trojan_version}-linux-amd64.tar.xz && tar xvJf trojan-${trojan_version}-linux-amd64.tar.xz -C /etc
	ln -s /etc/trojan/trojan /usr/bin/trojan
	rm -f trojan-${trojan_version}-linux-amd64.tar.xz
	TROJAN_CONFIG=/etc/trojan/config.json
	sed -i '/password2/ d' $TROJAN_CONFIG
	sed -i "/local_port/ s/443/$TROJAN_HTTPS_PORT/" $TROJAN_CONFIG
	sed -i "/remote_port/ s/80/$TROJAN_HTTP_PORT/" $TROJAN_CONFIG
	sed -i "/\"password1\",/ s/\"password1\",/\"$TROJAN_PASSWD\"/" $TROJAN_CONFIG
	sed -i ":certificate: s:/path/to/certificate.crt:/ssl/${TROJAN_DOMAIN}.cer:" $TROJAN_CONFIG
	sed -i ":private: s:/path/to/private.key:/ssl/${TROJAN_DOMAIN}.key:" $TROJAN_CONFIG

	###crate service
	cat >$SYSTEMD_SERVICES/trojan.service<<-EOF
	[Unit]
	Description=trojan Server
	After=network.target
	[Service]
	ExecStart=/etc/trojan/trojan -c /etc/trojan/config.json
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF
	##申请SSL证书
	acme.sh $TROJAN_DOMAIN

	systemctl daemon-reload
	systemctl start trojan
	systemctl enable trojan
	echo "."
	echo -e "\e[32m\e[1mtrojan://${TROJAN_PASSWD}@${TROJAN_DOMAIN}:${TROJAN_HTTPS_PORT}?sni=${TROJAN_DOMAIN}#Trojan\e[0m"

}
#脚本开始安装nginx
function INSTALL_NGINX(){
	CHECK_PORT "NOINPUT" 443
	CHECK_PORT "NOINPUT" 80
	read -p "输入NGINX版本(默认1.21.1)： " NGINX_VERSION
	NGINX_VERSION=${NGINX_VERSION:-1.21.1}
	nginx_url=http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
	NGINX_CONFIG=/usr/local/nginx/conf/nginx.conf

	##安装依赖
	if [[ "$(type -P apt)" ]]; then
		$PKGMANAGER_INSTALL build-essential libpcre3 libpcre3-dev zlib1g-dev git openssl wget libssl-dev
	elif [[ "$(type -P yum)" ]]; then
		$PKGMANAGER_INSTALL gcc gcc-c++ pcre pcre-devel zlib zlib-devel openssl openssl-devel wget
	else
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi

	wget -P /tmp $nginx_url && tar zxf /tmp/nginx-${NGINX_VERSION}.tar.gz -C /tmp/ && cd /tmp/nginx-$NGINX_VERSION
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
	rm -fr /tmp/nginx-$NGINX_VERSION

	ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx
	mv $NGINX_CONFIG ${NGINX_CONFIG}_backup
	wget -O /usr/local/nginx/conf/nginx.conf https://raw.githubusercontent.com/onlyJinx/Shell_2/main/nginxForFsGrpc.conf
	echo "export ngp=$NGINX_CONFIG" >> /etc/profile
	source /etc/profile
	
	###crate service
	#单双引号不转义，反单引号 $ 要转

	if [[ "$RUNNING_SYSTEM"="debian" ]]; then
		###crate service
		cat >$SYSTEMD_SERVICES/nginx.service<<-EOF
			[Unit]
			Description=nginx - high performance web server
			Documentation=https://nginx.org/en/docs/
			After=network-online.target remote-fs.target nss-lookup.target
			Wants=network-online.target

			[Service]
			Type=forking
			PIDFile=/run/nginx.pid
			ExecStartPre=/usr/local/nginx/sbin/nginx -t -c $NGINX_CONFIG
			ExecStart=/usr/local/nginx/sbin/nginx -c $NGINX_CONFIG
			ExecReload=/bin/kill -s HUP \$MAINPID
			ExecStop=/bin/kill -s TERM \$MAINPID

			[Install]
			WantedBy=multi-user.target
		EOF
	elif [[ "$RUNNING_SYSTEM"="centOS" ]]; then
		wget -P /etc/init.d https://raw.githubusercontent.com/onlyJinx/shell_CentOS7/master/nginx
		chmod a+x /etc/init.d/nginx
		chkconfig --add /etc/init.d/nginx
		chkconfig nginx on
	else
		ceho "can't create nginx service"
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi
	#创建配置文件夹
	NGINX_SITE_ENABLED="/usr/local/nginx/conf/sites-enabled"
	mkdir $NGINX_SITE_ENABLED
	###nginx编译引用自博客
	###https://www.cnblogs.com/stulzq/p/9291223.html
	systemctl daemon-reload
	systemctl enable nginx
	###systemctl status nginx
	clear
	echo "编译nginx成功"
	echo "是否开启SSL配置?(Y/n) "
	read ENAGLE_NGINX_SSL
	if [[ "" == "$ENAGLE_NGINX_SSL" ]] || [[ "y" == "$ENAGLE_NGINX_SSL" ]]; then
		read -p "输入域名: " NGINX_DOMAIN
		if [[ "" == "$NGINX_DOMAIN" ]]; then
			echo "空域名！退出。"
			systemctl start nginx
		else 
			cat >${NGINX_SITE_ENABLED}/${NGINX_DOMAIN}<<-EOF
			server {
				listen       4433 http2 ssl;
				server_name  ${NGINX_DOMAIN};

				ssl_certificate      /ssl/${NGINX_DOMAIN}.cer;
				ssl_certificate_key  /ssl/${NGINX_DOMAIN}.key;

				ssl_session_cache    shared:SSL:1m;
				ssl_session_timeout  5m;
				ssl_protocols TLSv1.2 TLSv1.3;
				ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
				ssl_prefer_server_ciphers  on;
				location / {
					root   html;
					index  index.html index.htm;
				}
			}
			EOF
			#开启80端口强制重定向443
			sed -i 's/#ENABLE_REDIRECT//' $NGINX_CONFIG
			#开始申请SSL证书
			acme.sh "$NGINX_DOMAIN"
			systemctl start nginx
		fi
	else 
		systemctl start nginx
	fi
}
#脚本开始安装caddy
function caddy(){
	CHECK_PORT "NOINPUT" 443
	CHECK_PORT "NOINPUT" 80
	while [[ true ]]; do
		read -p "输入域名(不能为空)： " CADDY_DOMAIN
		if ! [[ "$CADDY_DOMAIN" ]]; then
			echo "域名不能为空，重新输入！"
		else 
			break
		fi		
	done
	read -p "输入邮箱(回车不设置)： " CADDY_EMAIL
	CADDY_EMAIL=${CADDY_EMAIL:-noemail@qq.com}
	read -p "设置用户名(禁止@:): " CADDY_USER
	CADDY_USER=${CADDY_USER:-Oieu!ji330}
	read -p "设置密码(禁止@:): " CADDY_PASSWD
	CADDY_PASSWD=${CADDY_PASSWD:-5eele9P!il_}
	if ! [[ $(type -P go) ]]; then
		$PKGMANAGER_INSTALL wget
		wget -P /tmp https://golang.google.cn/dl/go1.16.6.linux-amd64.tar.gz
		tar zxvf /tmp/go1.16.6.linux-amd64.tar.gz -C /tmp/
		export PATH=$PATH:/tmp/go/bin
	fi
	if [[ $(type -P go) ]]; then
		cd /tmp/
		go get -u github.com/caddyserver/xcaddy/cmd/xcaddy
		~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive
		if [[ -e /tmp/caddy ]]; then
			mkdir /etc/caddy
			mv /tmp/caddy /etc/caddy/
			chmod +x /etc/caddy/caddy
			cat >/etc/caddy/Caddyfile<<-EOF
				{
					http_port  80
					https_port 443
				}
				:443, $CADDY_DOMAIN
				tls $CADDY_EMAIL
				route {
					forward_proxy {
						basic_auth $CADDY_USER $CADDY_PASSWD
						hide_ip
						hide_via
						probe_resistance
					}
					file_server { root /usr/local/nginx/html }
				}
			EOF

			cat >$SYSTEMD_SERVICES/caddy.service<<-EOF
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
			systemctl daemon-reload
			systemctl start caddy
			systemctl enable caddy 
			check "caddy启动失败"

		else
			echo "caddy编译失败"
			exit 1
		fi
		
	else
		echo "Go环境配置失败！"
		exit 1
	fi
	rm -fr /tmp/go1.16.6.linux-amd64.tar.gz /tmp/go
	clear
	systemctl status caddy
	echo -e "\e[32m\e[1mnaive+https://${CADDY_USER}:${CADDY_PASSWD}@${CADDY_DOMAIN}/#Naive\e[0m"
}

echo "输入对应的数字选项:"
select option in "acme.sh" "shadowsocks-libev" "transmission" "aria2" "Up_kernel" "trojan" "nginx" "Project_X" "caddy"
do
	case $option in
		"acme.sh")
			acme.sh
			break;;
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
			INSTALL_NGINX
			break;;
		"Project_X")
			Project_X
			break;;
		"caddy")
			caddy
			break;;
		*)
			echo "nothink to do"
			break;;
	esac
done
