#!/bin/bash
ICON_ARRARY=( "🐬" "🥀" "🍁" "🍂" "👗" "🚀" "🎀" "🎯" "🦋")
function check(){
	###函数名 参数1 参数2
	if [ "0" != "$?" ]; then
		echo "$1"
		exit 0
	else 
		echo "$2"
	fi
}
function NGINX_SNI(){
	#域名 端口
	NGINX_BIN="$(command -v nginx)"
	if [[ "$NGINX_BIN" ]]; then
		NGINX_SNI_CONFIG="$NGINX_CONFIG"
		sed -i "/$1/d" $NGINX_SNI_CONFIG
		if [[ `cat $NGINX_SNI_CONFIG | grep ssl_preread_server_name` ]];then
			echo "检测到NGINX_SNI配置"
			sed -i "/ssl_preread_server_name/a\ \ \ \ \ \ \ \ $1 127.0.0.1:$2;" $NGINX_SNI_CONFIG
			echo "SNI已配置"
			return 0
		else 
			echo "找不到SNI配置"
			return -1
		fi
	else 
		echo "找不到NGINX配置文件"
		return -1
	fi
}
function GET_RANDOM_STRING(){
	GET_RANDOM_STR=`openssl rand -base64 25`
	GET_RANDOM_STR=${GET_RANDOM_STR//\//_}
	GET_RANDOM_STR=${GET_RANDOM_STR// /_}
	GET_RANDOM_STR=${GET_RANDOM_STR//=/}
	GET_RANDOM_STR=${GET_RANDOM_STR//+/!}
	echo $GET_RANDOM_STR
}
function FORAM_DOMAIN(){
	###传入默认域名, 配合ONE_KEY
	if [[ "$1" ]]; then
		FORAM_DOMAIN_ENTER=$1
	else
		read FORAM_DOMAIN_ENTER
	fi
	if [[ "" == "$FORAM_DOMAIN_ENTER" ]]; then
		echo -e "\e[31m\e[1m域名不可为空,重新输入！\e[0m"
		FORAM_DOMAIN
		return 0
	elif ! [[ `echo $FORAM_DOMAIN_ENTER|grep '\.'` ]]; then
		echo -e "\e[31m\e[1m输入的域名不规范,重新输入！\e[0m"
		FORAM_DOMAIN
		return 0		
	elif [[ `echo $FORAM_DOMAIN_ENTER | grep http` ]]; then
		FORAM_DOMAIN_ENTER=`echo $FORAM_DOMAIN_ENTER | cut -d '/' -f3`
	fi
	RETURN_DOMAIN=$FORAM_DOMAIN_ENTER
	echo -e "\e[31m\e[1m已格式化域名${RETURN_DOMAIN}\e[0m"
}
function packageManager(){
	SYSTEMD_SERVICES="/etc/systemd/system"
	NGINX_CONFIG="/etc/nginx/conf/nginx.conf"
	NGINX_SITE_ENABLED="/etc/nginx/conf/sites"
	NGINX_WEBROOT="/etc/nginx/html"
	LINUX_PLATFORM=`uname -m`
	if [[ "x86_64" == "$LINUX_PLATFORM" ]]; then
		LINUX_PLATFORM="amd64"
	elif [[ "aarch64" == "$LINUX_PLATFORM" ]]; then
		LINUX_PLATFORM="arm64"
	else
		echo -e "\e[32m\e[1m不支持的系统框架,退出\e[0m"
		echo $LINUX_PLATFORM
		exit -1
	fi
	echo -e "\e[32m\e[1m当前系统框架: ${LINUX_PLATFORM}\e[0m"
	if [[ "$(type -P apt)" ]]; then
		PKGMANAGER_INSTALL="apt install -y --no-install-recommends"
		PKGMANAGER_UNINSTALL="apt remove -y"
		RUNNING_SYSTEM="debian"
	elif [[ "$(type -P yum)" ]]; then
		PKGMANAGER_INSTALL="yum install -y"
		PKGMANAGER_UNINSTALL="yum remove -y"
		RUNNING_SYSTEM="centOS"
	else
		echo "未知包管理器命令"
		exit 1
	fi
}
packageManager
function GetRandomNumber(){
    min=$1
    max=$(($2-$min+1))
    num=$(date +%s%N)
    echo $(($num%$max+$min))
}
function GetRandomIcon(){
	RANDOM_ICON_INDEX=$(GetRandomNumber 0 8)
	RANDOM_ICON=${ICON_ARRARY[${RANDOM_ICON_INDEX}]}
	if [[ "$RANDOM_ICON" == "NON" ]]; then
		echo "图标重复,将重新生成"
		GetRandomIcon
		return
	else
		ICON_ARRARY[${RANDOM_ICON_INDEX}]="NON"
	fi
}
function CHECK_PORT(){
	#提示语 默认端口
	#带NOINPUT参数时不跳过端口输入，直接调用默认端口
	while [[ true ]]; do
		if [[ "NOINPUT" == "$1" ]];then
			port=$2
		else
			read -p "$1" port
			port=${port:-$2}
			if [[ ! "$port" -gt "0" ]]; then
				echo  -e "\e[31m\e[1m输入端口必须大于0\e[0m"
				CHECK_PORT "重新输入端口号"
				return 0
			fi
		fi

		myport=$(ss -lnp|grep :$port)
		if [ -n "$myport" ];then
			echo "端口${port}已被占用,回车关闭占用进程,输入n退出程序"
			echo "直接输入端口号更换其他端口"
			read sel
			if [[ "$sel" == "" ]]; then
				##关闭进程
				if [[ $(echo $myport | grep nginx) ]]; then
					systemctl stop nginx
				else 
					ss -lnp|grep :$port|awk -F "pid=" '{print $2}'|sed 's/,.*//'|xargs kill -9
				fi
				#exclude udp port
				if [ -z "$(ss -lnp|grep :$port|grep tcp)" ]; then
					echo -e "\e[32m\e[1m已终止占用端口进程\e[0m"
					break
				else
					echo -e "\e[31m\e[1m进程关闭失败,请手动关闭\e[0m"
					exit 1
				fi
			elif [[ "$sel" == "n" ]]; then
				echo "已取消操作"
				exit 0
			elif [[ $sel -gt 0 ]]; then
				CHECK_PORT "NOINPUT" $sel
				return 0
			else 
				echo "非法操作！"
				exit -1
			fi
		else
			break
		fi
	done
	echo "当前端口已设置为: "$port
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
	if [[ "$1" != "NOINPUT" ]]; then
		read -p "$1" dir
	fi
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
##acme.sh "域名(直接调用http)" "NGINX网站目录"
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
	DEFAULT_WEB_ROOT="$NGINX_WEBROOT"
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
			#检测是否传入WEB_ROOT参数,如有,跳过网站根目录输入
			if [[ "$HTTP_CALL_FUNCTION_WEB_ROOT" ]]; then
				ENTER_NGINX_PTAH=$HTTP_CALL_FUNCTION_WEB_ROOT
			else 
				echo -e "\e[32m\e[1m检测到80端口占用，尝试列出所有html目录。\e[0m"
				find / -name html
				read -p "输入网站根目录(${NGINX_WEBROOT}): " ENTER_NGINX_PTAH
				ENTER_NGINX_PTAH=${ENTER_NGINX_PTAH:-$DEFAULT_WEB_ROOT}
			fi
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
		read -p "是否将设置为默认CA?(Y/n)" CONFIRM_SET_DEFAULT_CA
		if [[ "y" == "$CONFIRM_SET_DEFAULT_CA" || "" == "$CONFIRM_SET_DEFAULT_CA" ]]; then
			$ACME_PATH_RUN --set-default-ca --server $ACME_SERVER
			echo -e "\e[32m\e[1m已将默认证书机构更改为${ACME_SERVER}\e[0m"
		else
			SET_ACME_SERVER="--server $ACME_SERVER"
			CURRENT_ACME_CA="$ACME_SERVER"
			echo "已临时更改证书颁发机构为${ACME_SERVER}"
		fi
	}

	#选择认证方式
	function SELECT_AUTH_MOTHOD(){
		##其他函数直接调用acme HTTP验证
		if [[ "$CALL_FUNCTION" ]]; then
			ENTER_APPLY_DOMAIN=$CALL_FUNCTION
			APPLY_DOMAIN=$CALL_FUNCTION
			HTTP_CALL_FUNCTION_WEB_ROOT="/etc/nginx/html"
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
			echo -e "\e[31m\e[1m未找到acme.sh脚本，尝试在线安装\e[0m"
			cd /tmp
			read -p "输入email(回车跳过)? " ACME_EMAIL
			ACME_EMAIL=${ACME_EMAIL:-no_email@gmail.com}
			curl https://get.acme.sh | sh -s email=$ACME_EMAIL
		fi
		$ACME_PATH_RUN --upgrade --auto-upgrade
		echo "$ACME_APPLY_CER"
		echo -e "\e[32m\e[1m当前CA机构:${CURRENT_ACME_CA:-Default}\e[0m"
		$ACME_APPLY_CER
		if [[ "$NEED_INSTALL_CERT" ]]; then
			ACME_INSTALL_CERT "$ENTER_APPLY_DOMAIN"
		else 
			echo -e "\e[32m\e[1m将上面的txt解析到对应的域名上再重新运行脚本\e[0m"
			echo -e "\e[32m\e[1m第二次运行时自动校验解析\e[0m"
			echo "休眠30秒"
			count=30
			while [[ $count -gt 0 ]];do
			echo -ne "\e[31m\e[1m$count\e[0m"
			let count--
			sleep 1
			echo -ne "\r   \r"
			done
		fi
	fi
	#卸载Socat残留
	$UNINSTALL_SOCAT
}

#shadowsocks
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

	if [[ "debian" == "$RUNNING_SYSTEM" ]]; then
		##Debian
		$PKGMANAGER_INSTALL gettext build-essential autoconf \
		libtool libpcre3-dev asciidoc xmlto libmbedtls-dev \
		libev-dev libudns-dev libc-ares-dev automake pkg-config git

		git clone https://github.com/jedisct1/libsodium --branch stable
		cd libsodium
		./configure
		make && make check
		make install
		ldconfig
		cd ~
		rm -fr libsodium
		SHADOWSOCKS_CONFIGURE=' '
	else
		##CentOS
		$PKGMANAGER_INSTALL gcc gettext autoconf \
		libtool automake make pcre-devel \
		wget git vim asciidoc xmlto libev-devel

		###Installation of c-ares
		git clone https://github.com/c-ares/c-ares.git
		cd c-ares
		./buildconf
		autoconf configure.ac
		./configure --prefix=/usr && make
		make install
		check "shadowsocks依赖c-ares编译失败！"
		ldconfig
		cd ~
		###安装方法引用http://blog.sina.com.cn/s/blog_6c4a60110101342m.html

		###Installation of MbedTLS
		wget --no-check-certificate https://tls.mbed.org/download/mbedtls-2.16.3-gpl.tgz
		tar xvf mbedtls-2.16.3-gpl.tgz
		cd mbedtls-2.16.3
		make SHARED=1 CFLAGS=-fPIC
		make DESTDIR=/usr install
		check "shadowsocks依赖MbedTLS编译失败！"
		cd ~
		ldconfig

		wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
		if [[ -a "/root/LATEST.tar.gz" ]]; then
			tar zxf LATEST.tar.gz
			if [[ libsodium-stable ]]; then
				cd libsodium-stable
				./configure --prefix=/usr
				make && make install
				check "shadowsocks依赖Libsodium编译失败！"
				ldconfig
				cd ~
			else 
				echo "未找到libsodium"
				exit -1
			fi
		else
			echo "libsodium下载失败"
			exit -1
		fi

		SHADOWSOCKS_CONFIGURE='--with-sodium-include=/usr/include --with-sodium-lib=/usr/lib'
	fi

	###报错 undefined reference to `ares_set_servers_ports_csv'，指定libsodium configure路径
	###Installation of shadowsocks-libev
	git clone https://github.com/shadowsocks/shadowsocks-libev.git
	cd shadowsocks-libev
	git submodule update --init --recursive
	./autogen.sh
	./configure $SHADOWSOCKS_CONFIGURE
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
	    "server_port":${port},
	    "local_port":1080,
	    "password":"${passwd}",
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
	SHADOWSOCKS_V2RAY_PLUGIN="1.3.0"
	wget https://github.com/shadowsocks/v2ray-plugin/releases/download/v${SHADOWSOCKS_V2RAY_PLUGIN}/v2ray-plugin-linux-${LINUX_PLATFORM}-v${SHADOWSOCKS_V2RAY_PLUGIN}.tar.gz
	tar zxf v2ray-plugin-linux-${LINUX_PLATFORM}-v${SHADOWSOCKS_V2RAY_PLUGIN}.tar.gz
	mv v2ray-plugin_linux_${LINUX_PLATFORM} /etc/shadowsocks-libev/v2ray-plugin
	rm -f v2ray-plugin-linux-${LINUX_PLATFORM}-v${SHADOWSOCKS_V2RAY_PLUGIN}.tar.gz

	###crate service
	cat >$SYSTEMD_SERVICES/shadowsocks.service<<-EOF
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
	systemctl start shadowsocks && systemctl enable shadowsocks
	### remove the file
	cd /root && rm -fr mbedtls* shadowsocks-libev libsodium LATEST.tar.gz c-ares

	###ss -lnp|grep 443
	echo -e port:"          ""\e[31m\e[1m$port\e[0m"
	echo -e password:"      ""\e[31m\e[1m$passwd\e[0m"
	echo -e method:"        ""\e[31m\e[1mxchacha20-ietf-poly1305\e[0m"
	echo -e plugin:"        ""\e[31m\e[1mv2ray-plugin\e[0m"
	echo -e plugin_opts:"   ""\e[31m\e[1mhttp\e[0m"
	echo -e config.json:"   ""\e[31m\e[1m/etc/shadowsocks-libev/config.json\n\n\e[0m"
	echo -e use \""\e[31m\e[1msystemctl status shadowsocks\e[0m"\" run the shadowsocks-libev in background
	echo -e "\e[31m\e[1mhttps://github.com/shadowsocks\e[0m"
}
#transmission
function transmission(){
	TRANSMISSION_NGINX_CONFIG=$NGINX_CONFIG
	TRANSMISSION_CONFIG="/root/.config/transmission-daemon/settings.json"
	TRANSMISSION_DOWNLOAD_LINK="https://github.com/transmission/transmission-releases/raw/master/transmission-3.00.tar.xz"
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

	function TRANSMISSION_CREATE_NGINX_SITE(){
		cat >$NGINX_SITE_ENABLED/${TRANSMISSION_DOMAIN}<<-EOF
		server {
		    listen       4433 http2 ssl proxy_protocol;
		    server_name  ${TRANSMISSION_DOMAIN};
		    ssl_certificate      /ssl/${TRANSMISSION_DOMAIN}.cer;
		    ssl_certificate_key  /ssl/${TRANSMISSION_DOMAIN}.key;
		    ssl_session_cache    shared:SSL:1m;
		    ssl_session_timeout  5m;
		    ssl_protocols TLSv1.2 TLSv1.3;
		    ssl_prefer_server_ciphers  on;
		    error_page 404 https://${TRANSMISSION_DOMAIN}/${TRRNA_FILE_SERVER_PATH}/;
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
	}
	CKECK_FILE_EXIST transmission-3.00+
	CHECK_VERSION transmission-daemon transmission
	CHECK_PORT "NOINPUT" 9091
	#read -p "请输入用户名(transmission):  " TRANSMISSION_USER_NAME
	TRANSMISSION_USER_NAME=${TRANSMISSION_USER_NAME:-transmission}
	#read -p "请输入密码(transmission2020):  " TRANSMISSION_PASSWD
	TRANSMISSION_PASSWD=${TRANSMISSION_PASSWD:-transmission2020}
	if [[ "$ONE_KEY_TRANSMISSION_DOWN_PATH" ]]; then
		DOWNLOAD_PTAH "NOINPUT" "$ONE_KEY_TRANSMISSION_DOWN_PATH"
	else
		DOWNLOAD_PTAH "文件保存路径(默认/usr/downloads): " "/usr/downloads"
	fi
	if [[ -e $TRANSMISSION_NGINX_CONFIG ]];then
		OUTPUT_HTTPS_LOGIN_ADDR=""
		if [[ "$ONE_KEY_TRANSMISSION_ENABLE_HTTPS_TS" ]]; then
			ENABLE_HTTPS_TS="y"
		else
			echo "检测到NGINX配置文件，是否开启https WEBUI反代?(Y/n) "
			read ENABLE_HTTPS_TS
		fi
		
		if [[ "" == "$ENABLE_HTTPS_TS" || "y" == "$ENABLE_HTTPS_TS" ]]; then
			echo "输入transmission域名"
			FORAM_DOMAIN "$ONE_KEY_TRANSMISSION_DOMAIN"
			TRANSMISSION_DOMAIN=$RETURN_DOMAIN
			#echo "输入文件下载服务器路径(downloads)"
			#read TRRNA_FILE_SERVER_PATH
			TRRNA_FILE_SERVER_PATH=${TRRNA_FILE_SERVER_PATH:-downloads}
			acme.sh $TRANSMISSION_DOMAIN "/etc/nginx/html"
			if [[ -e "/ssl/${TRANSMISSION_DOMAIN}.key" ]]; then
				echo -e "\e[32m\e[1m已检测到证书\e[0m"
				TRANSMISSION_CREATE_NGINX_SITE
				OUTPUT_HTTPS_LOGIN_ADDR="true"
			else 
				echo -e "\e[31m\e[1m找不到证书，取消配置WEBUI HTTPS\e[0m"
			fi
		else 
			echo -e "\e[31m\e[1m已确认取消HTTPS WEBUI配置\e[0m"
		fi
	fi

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
	
	wget -P /tmp/ $TRANSMISSION_DOWNLOAD_LINK
	
	if [[ ! -a "/tmp/transmission-3.00.tar.xz" ]]; then
		echo "检测不到transmission-3.00.tar.xz"
		echo "确认下载连接是否有效"
		echo $TRANSMISSION_DOWNLOAD_LINK
		echo "停止安装(S)还是输入有效下载链接继续安装(R)?"
		read TRANSMISSION_RE_DOWNLOAD
		if [[ "$TRANSMISSION_RE_DOWNLOAD" == "S" || "$TRANSMISSION_RE_DOWNLOAD" == "s" ]]; then
			echo "STOP"
			exit 0
		elif [[ "$TRANSMISSION_RE_DOWNLOAD" == "R" || "$TRANSMISSION_RE_DOWNLOAD" == "r" ]]; then
			echo "请输入下载地址"
			read TRANSMISSION_DOWNLOAD_LINK
			wget -P /tmp/ $TRANSMISSION_DOWNLOAD_LINK
			if [[ ! -a "/tmp/transmission-3.00.tar.xz" ]]; then
				echo "再次下载失败,退出"
				exit -1
			fi
		else
			echo "非法输入,退出"
			exit -1
		fi
	fi
	tar xvf /tmp/transmission-3.00.tar.xz -C /tmp && cd /tmp/transmission-3.00
	/tmp/transmission-3.00/configure --prefix=/etc/transmission  && make && make install
	rm -fr /tmp/transmission-3.00.tar.xz /tmp/transmission-3.00
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
	ExecStart=/etc/transmission/bin/transmission-daemon -f --log-error
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
		/sbin/sysctl -p > /dev/nul 2>&1
		/usr/sbin/sysctl -p > /dev/nul 2>&1
	fi
	##首次启动，生成配置文件
	systemctl start transmission.service
	TRANSMISSION_SERVICE_LIFE=`systemctl is-active transmission.service`
	if [[ "active" == "$TRANSMISSION_SERVICE_LIFE" ]]; then
		echo -e "\e[32m\e[1mtransmission服务已启动\e[0m"
		# echo -e "\e[31m\e[1m休眠5s\e[0m"
		# sleep 5
		TRANSMISSION_COUNT=1
		while [[ true ]]; do
			systemctl stop transmission.service
			TRANSMISSION_SERVICE_LIFE=`systemctl is-active transmission.service`
			echo -e "\e[31m\e[1m[debug]===============TRANSMISSION_SERVICE_LIFE=====================\e[0m"
			echo "TRANSMISSION_SERVICE_LIFE：" $TRANSMISSION_SERVICE_LIFE
			echo -e "\e[31m\e[1m[debug]=================Service Status===================\e[0m"
			systemctl status transmission|grep Active
			if [[ "active" != "$TRANSMISSION_SERVICE_LIFE" && -e "$TRANSMISSION_CONFIG" ]]; then
				echo -e "\e[32m\e[1m检测到transmission配置文件\e[0m"
				MODIFY_CONFIG "$TRANSMISSION_CONFIG"
				break
			else 
				if [[ $TRANSMISSION_COUNT -gt 11 ]]; then
					echo "循环次数过多,停止修改配置文件"
					echo "退出安装(e)还是继续(Y)?"
					read TRANSMISSION_EXIT_CONFIRM
					if [[ "$TRANSMISSION_EXIT_CONFIRM" == "e" || "$TRANSMISSION_EXIT_CONFIRM" == "E" ]]; then
						exit -1
					else 
						break
					fi	
				else
					echo "transmission服务未停止或找不到配置文件, 1秒后重试"
					echo "当前重试次数: " $TRANSMISSION_COUNT
					let TRANSMISSION_COUNT++
					systemctl status transmission|grep Active
					echo -e "\e[31m\e[1m[debug]================按任意键继续====================\e[0m"
					read TRANSMISSION_TEMP_READ
					cat $TRANSMISSION_CONFIG
					sleep 1
					systemctl start transmission.service
				fi
			fi
		done
		## change config  sed引用 https://segmentfault.com/a/1190000020613397
		##替换webUI
		cd ~
		git clone https://github.com/ronggang/transmission-web-control.git
		mv /etc/transmission/share/transmission/web/index.html /etc/transmission/share/transmission/web/index.original.html
		mv /root/transmission-web-control/src/* /etc/transmission/share/transmission/web/
		rm -fr transmission-web-control
		systemctl start transmission.service
		systemctl enable transmission.service
		if [[ "$OUTPUT_HTTPS_LOGIN_ADDR" ]]; then
			systemctl restart nginx
			echo -e "\e[32m\e[1m打开网址  https://${TRANSMISSION_DOMAIN}  测试登录  \e[0m"
			echo -e "\e[32m\e[1m文件下载服务器地址  https://${TRANSMISSION_DOMAIN}/${TRRNA_FILE_SERVER_PATH}/\e[0m"
		else 
			echo -e "\e[32m\e[1m打开 http://your_IP:${port}  测试登录  \e[0m"
		fi
		echo -e password:"      ""\e[32m\e[1m$TRANSMISSION_PASSWD\e[0m"
		echo -e username:"      ""\e[32m\e[1m$TRANSMISSION_USER_NAME\e[0m"
		echo -e DOWNLOAD_PTAH:"      ""\e[32m\e[1m$dir\e[0m"
		#echo -e config.json:"   ""\e[32m\e[1m/root/.config/transmission-daemon/settings.json\n\n\e[0m"
	else 
		echo -e "\e[31m\e[1mtransmission首次启动失败。\e[0m"
		exit -1
	fi
}

#aria2
function aria2(){
	function DOWNLOAD_ARIA2_WEBUI(){
		cd /tmp
		git clone https://github.com/ziahamza/webui-aria2.git
		mv /tmp/webui-aria2/docs/* $ARIA2_WEBUI_ROOT
		rm -fr /tmp/webui-aria2
		systemctl restart nginx
	}
	CKECK_FILE_EXIST aria2
	CHECK_VERSION aria2c aria2
	DOWNLOAD_PTAH "文件保存路径(/usr/downloads): " "/usr/downloads"
	read -p "输入密码(默认密码crazy_0): " ARIA2_PASSWD
	ARIA2_PASSWD=${ARIA2_PASSWD:-crazy_0}
	CHECK_PORT "输入RPC监听端口(6800): " 6800
	ARIA2_PORT=$port
	if [[ "$(command -v nginx)" ]]; then
		DOWNLOAD_ARIA2_WEBUI_=""
		echo "检测到NGINX，是否下载WEBUI?(Y/n) "
		read ENABLE_ARIA2_WEBUI
		if [[ "$ENABLE_ARIA2_WEBUI" == "y" ]] || [[ "$ENABLE_ARIA2_WEBUI" == "" ]]; then
			find / -name html
			read -p "输入网站根目录(${NGINX_WEBROOT})  " ARIA2_WEBUI_ROOT
			ARIA2_WEBUI_ROOT=${ARIA2_WEBUI_ROOT:-/etc/nginx/html}
			if ! [[ -d "$ARIA2_WEBUI_ROOT" ]]; then
				echo "your full path no exist"
				exit 0
			else
				if [[ "$(ls $ARIA2_WEBUI_ROOT)" ]]; then
					echo "注意！输入的文件夹里发现文件，是否强制覆盖(Y/n)?"
					read overwrite
					if ! [[ "" == "$overwrite" ]]; then
						echo "已将文件夹备份为后缀_BACKUP文件夹"
						mv $ARIA2_WEBUI_ROOT ${ARIA2_WEBUI_ROOT}_BACKUP
					fi
					DOWNLOAD_ARIA2_WEBUI_="true"
				fi
			fi
		fi
	fi

	if [[ "debian" == "$RUNNING_SYSTEM" ]]; then
		##Debian
		$PKGMANAGER_INSTALL git libxml2-dev libcppunit-dev \
		autoconf automake autotools-dev autopoint libtool \
		build-essential libtool pkg-config
		#ARIA2_AUTOCONF="autoreconf -i -I /usr/share/aclocal/"
	elif [[ "$RUNNING_SYSTEM"="CentOS" && "$LINUX_PLATFORM"="amd64" ]]; then
		##Centos
		$PKGMANAGER_INSTALL gcc-c++ make libtool automake bison \
		autoconf git intltool libssh2-devel expat-devel \
		gmp-devel nettle-devel zlib-devel \
		c-ares-devel gnutls-devel libgcrypt-devel libxml2-devel \
		sqlite-devel gettext xz-devel gperftools gperftools-devel \
		gperftools-libs trousers-devel
	else
		##arm64
		$PKGMANAGER_INSTALL gcc-c++ make libtool automake bison \
		autoconf git intltool libssh2 expat-devel  \
		gmp-devel nettle-devel zlib-devel  \
		c-ares-devel gnutls-devel libgcrypt-devel libxml2-devel  \
		sqlite-devel gettext xz-devel trousers
	fi
	ARIA2_AUTOCONF="autoreconf -i"
	libtoolize --automake --copy --debug  --force
	git clone https://github.com/aria2/aria2.git && cd aria2

	##静态编译
	##autoreconf -i && ./configure ARIA2_STATIC=yes
	
	$ARIA2_AUTOCONF && ./configure --prefix=/etc/aria2
	check "aria2c configure失败"
	make && make install
	check "aria2c编译安装失败"
	#rm -fr aria2
	ln -s /etc/aria2/bin/aria2c /usr/bin/aria2c
	###相关编译报错引用https://weair.xyz/build-aria2/
	check "aria2c编译安装失败"
	ARIA2_CONFIG_DIR="/etc/aria2"
	cat >$SYSTEMD_SERVICES/aria2.service<<-EOF
	[Unit]
	Description=aria2c
	After=network.target
	[Service]
	ExecStart=/etc/aria2/bin/aria2c --conf-path=$ARIA2_CONFIG_DIR/aria2.conf
	User=root
	[Install]
	WantedBy=multi-user.target
	EOF
	##aria2 config file

	cat >$ARIA2_CONFIG_DIR/aria2.conf<<-EOF
	rpc-secret=$ARIA2_PASSWD
	enable-rpc=true
	rpc-listen-port=$ARIA2_PORT
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
	systemctl start aria2
	ARIA2_SERVICE_LIFE=`systemctl is-active aria2.service`
	if [[ "active" == "$ARIA2_SERVICE_LIFE" ]]; then
		systemctl enable aria2
		echo -e "\e[32m\e[1maria2服务启动成功\e[0m"
		if [[ "$DOWNLOAD_ARIA2_WEBUI_" ]]; then
			echo -e "\e[32m\e[1m开始下载WEBUI\e[0m"
			DOWNLOAD_ARIA2_WEBUI
		fi
		echo -e "\e[32m\e[1mPORT:        ${ARIA2_PORT}\e[0m"
		echo -e "\e[32m\e[1mTONKE:        ${ARIA2_PASSWD}\e[0m"
		echo -e "\e[32m\e[1mDOWNLOAD_PTAH:${dir}\e[0m"
		echo -e "\e[32m\e[1mCONFIG_JSON:  /etc/aria2/aria2.conf\e[0m"
	else 
		echo -e "\e[31m\e[1maria2服务启动失败，请检查error log\e[0m"
	fi
}

#脚本开始安装内核更新
function Up_kernel(){
	echo -e "\e[32m\e[1m更新后是否重启电脑?(Y/n): \e[0m"
	read REBOOT_FOR_UPDATE
	if [[ "$(type -P apt)" ]]; then
		if ! [[ "$(cat /etc/apt/sources.list | grep buster-backports)" ]]; then
			echo "deb https://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
		fi
		apt update
		apt upgrade -y
		$PKGMANAGER_INSTALL -t buster-backports linux-image-cloud-${LINUX_PLATFORM} linux-headers-cloud-${LINUX_PLATFORM} vim
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
	if [[ "" == "$REBOOT_FOR_UPDATE" || "y" == "$REBOOT_FOR_UPDATE" ]]; then
		reboot
	fi

}
#xray
function Project_X(){
	#检测安装v2ray/xray
	PROJECT_BIN_VERSION=$1
	if [[ "$ONE_KEY_NODE_SUFFIX" ]]; then
		NODE_SUFFIX="$ONE_KEY_NODE_SUFFIX"
	else
		read -p "输入节点名后缀,回车则不设置: " NODE_SUFFIX
	fi
	if [[ "arm64" == "$LINUX_PLATFORM" ]]; then
		XRAY_PLATFORM='arm64-v8a'
	else
		XRAY_PLATFORM='64'
	fi
	function INSTALL_XRAY_BINARY(){
		if ! [[ "$(type -P unzip)" ]];then
			$PKGMANAGER_INSTALL unzip
		fi
		if [[ "xray" == "$PROJECT_BIN_VERSION" ]]; then
			XRAY_BIN_PACKGE="Xray-linux-${XRAY_PLATFORM}.zip"
			rm -f /tmp/$XRAY_BIN_PACKGE
			XRAY_BIN_DOWNLOAD_LINK="https://github.com/XTLS/Xray-core/releases/download/v$XRAY_RELEASE_LATEST/Xray-linux-${XRAY_PLATFORM}.zip"
		elif [[ "v2ray" == "$PROJECT_BIN_VERSION" ]]; then
			XRAY_BIN_PACKGE="v2ray-linux-${XRAY_PLATFORM}.zip"
			rm -f /tmp/$XRAY_BIN_PACKGE
			XRAY_BIN_DOWNLOAD_LINK="https://github.com/v2fly/v2ray-core/releases/download/v${V2RAY_BIN_VERSION}/v2ray-linux-${XRAY_PLATFORM}.zip"
		else 
			echo "未知参数,退出！"
			exit -1
		fi
		mkdir /tmp/v2fly 2>/dev/nul
		wget -P /tmp/v2fly $XRAY_BIN_DOWNLOAD_LINK
		if [[ -a "/tmp/v2fly/$XRAY_BIN_PACKGE" ]]; then
			mkdir /etc/${PROJECT_BIN_VERSION}
			unzip -o /tmp/v2fly/$XRAY_BIN_PACKGE -d /tmp/v2fly
			mv /tmp/v2fly/geoip.dat /etc/${PROJECT_BIN_VERSION}/geoip.dat
			mv /tmp/v2fly/geosite.dat /etc/${PROJECT_BIN_VERSION}/geosite.dat
			mv /tmp/v2fly/${PROJECT_BIN_VERSION} /etc/${PROJECT_BIN_VERSION}/
			rm -fr /tmp/v2fly
			#获取github仓库最新版release引用 https://bbs.zsxwz.com/thread-3958.htm
		elif [[ "v2ray" == "$PROJECT_BIN_VERSION" ]]; then
				echo -e "\e[31m\e[1mv2fly版本号异常,请重新输入版本号(格式:4.41.1)\e[0m"
				read V2RAY_BIN_VERSION
				INSTALL_XRAY_BINARY
				return 0
		else
			echo "下载异常,请检查一下下载链接"
			echo "$XRAY_BIN_DOWNLOAD_LINK"
			exit 0
		fi

	}

	if [[ "v2ray" == "$PROJECT_BIN_VERSION" ]]; then
		if [[ "$NOE_KEY_V2RAY_BIN_VERSION" ]]; then
			V2RAY_BIN_VERSION=$NOE_KEY_V2RAY_BIN_VERSION
		else
			#不放在INSTALL_XRAY_BINARY,防止申请完证书后还需要继续输入版本号
			echo "输入v2ray版本号(4.41.1)"
			read V2RAY_BIN_VERSION
			V2RAY_BIN_VERSION=${V2RAY_BIN_VERSION:-4.41.1}
		fi
		if [[ "$(type -P v2ray)" ]]; then
			V2ray_INSTALLED_VERSION=$(v2ray -version|grep V2Ray|cut -d ' ' -f2)
			CHECK_VERSION v2ray v2fly "$V2ray_INSTALLED_VERSION" "$V2RAY_BIN_VERSION"
		fi
	elif [[ "xray" == "$PROJECT_BIN_VERSION" ]]; then
		if [[ "$(type -P xray)" ]]; then
			XTLS_INSTALLED_VERSION=$(xray version|sed -n 1p|cut -d ' ' -f 2)
			XRAY_RELEASE_LATEST=`wget -q -O - https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name|cut -f4 -d "\""|cut -c 2-`
			CHECK_VERSION xray Xray $XTLS_INSTALLED_VERSION $XRAY_RELEASE_LATEST
		fi
	else 
		echo "错误！"
		exit -1
	fi


	if [[ "$NEED_UPDATE" == "1" ]]; then
		INSTALL_XRAY_BINARY
		if [[ "v2ray" == "$PROJECT_BIN_VERSION" ]]; then
			echo "已更新V2fly,版本信息如下"
			v2ray -version
		elif [[ "xray" == "$PROJECT_BIN_VERSION" ]]; then
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
			echo "错误！"
			exit -1
		fi

	else
		#不再支持自定义端口,Path,Service Name
		#CHECK_PORT "XRAY_XTLS 监听端口(1000)?  " 1000
		CHECK_PORT "NOINPUT" 15423
		RAY_TCP_PORT=$port
		#read -p "回落端口(5555)?  " XRAY_DESP_PORT
		XRAY_DESP_PORT=${XRAY_DESP_PORT:-19954}
		#CHECK_PORT "GRPC 监听端口(2002)?  " 2002
		CHECK_PORT "NOINPUT" 8845
		XRAY_GRPC_PORT=$port
		#CHECK_PORT "WebSocks 监听端口(1234)?  " 1234
		CHECK_PORT "NOINPUT" 35446
		XRAY_WS_PORT=$port
		CHECK_PORT "NOINPUT" 45877
		XRAY_TROJAN_PORT=$port
		#read -p "Grpc Name(grpcforward)?  " XRAY_GRPC_NAME
		#XRAY_GRPC_NAME=${XRAY_GRPC_NAME:-grpcforward}
		XRAY_GRPC_NAME=`GET_RANDOM_STRING`
		XRAY_TROJAN_GRPC_NAME=`GET_RANDOM_STRING`
		XRAY_TROJAN_TCP_PASSWD=`GET_RANDOM_STRING`
		#感叹号替换成小数点,兼容clash
		XRAY_TROJAN_GRPC_NAME=${XRAY_TROJAN_GRPC_NAME//!/.}
		#read -p "WebSocks Path(默认 wsforward)?  " XRAY_WS_PATH
		#XRAY_WS_PATH=${XRAY_WS_PATH:-wsforward}
		XRAY_WS_PATH=`GET_RANDOM_STRING`

		XRAY_UUID=$(cat /proc/sys/kernel/random/uuid)
		XRAY_GRPC_UUID=$(cat /proc/sys/kernel/random/uuid)
		XRAY_WS_UUID=$(cat /proc/sys/kernel/random/uuid)
		XRAY_TROJAN_PASSWD=$(cat /proc/sys/kernel/random/uuid)

		echo "请输入xray/v2fly域名"
		FORAM_DOMAIN "$ONE_KEY_V2RAY_DOMAIN"
		XRAY_DOMAIN=$RETURN_DOMAIN
		acme.sh "$XRAY_DOMAIN" "/etc/nginx/html"
		if [[ -a "/ssl/${XRAY_DOMAIN}.key" ]]; then
			echo -e "\e[32m\e[1m已检测到证书文件\e[0m"
			# read  XRAY_DOMAIN
			# XRAY_DOMAIN=${XRAY_DOMAIN:-project_x.com}
			INSTALL_XRAY_BINARY
			XRAY_CONFIG=/etc/${PROJECT_BIN_VERSION}/config.json
			wget -O $XRAY_CONFIG https://raw.githubusercontent.com/onlyJinx/Shell_2/test/xtls_tcp_grpc_ws.json
			sed -i "s/XTLS_PORT/$RAY_TCP_PORT/" $XRAY_CONFIG
			sed -i "s/XTLS_UUID/$XRAY_UUID/" $XRAY_CONFIG
			sed -i "s/DESP_PORT/$XRAY_DESP_PORT/" $XRAY_CONFIG

			sed -i "s/VLESS_GRPC_PORT/$XRAY_GRPC_PORT/" $XRAY_CONFIG
			sed -i "s/VLESS_GRPC_NAME/$XRAY_GRPC_NAME/" $XRAY_CONFIG
			sed -i "s/VLESS_GRPC_UUID/$XRAY_GRPC_UUID/" $XRAY_CONFIG

			sed -i "s/WS_PORT/$XRAY_WS_PORT/" $XRAY_CONFIG
			sed -i "s/WS_PATH/$XRAY_WS_PATH/" $XRAY_CONFIG
			sed -i "s/WS_UUID/$XRAY_WS_UUID/" $XRAY_CONFIG

			sed -i "s/TROJAN_GRPC_PORT/$XRAY_TROJAN_PORT/" $XRAY_CONFIG
			sed -i "s/TROJAN_GRPC_PASSWD/$XRAY_TROJAN_PASSWD/" $XRAY_CONFIG
			sed -i "s/TROJAN_GRPC_SERVICE_NAME/$XRAY_TROJAN_GRPC_NAME/" $XRAY_CONFIG

			sed -i "s/SSL_XRAY_CER/$XRAY_DOMAIN/" $XRAY_CONFIG
			sed -i "s/SSL_XRAY_KEY/$XRAY_DOMAIN/" $XRAY_CONFIG

			sed -i "s/V2RAY_TROJAN_PASSWORD/$XRAY_TROJAN_TCP_PASSWD/" $XRAY_CONFIG

			#流控,用于订阅生成
			RAY_FLOW='flow=xtls-rprx-direct&'
			V2RAY_TRANSPORT='security=xtls'
			V2RAY_TCP_NODENAME="xTLS"
			if [[ "v2ray" == "$PROJECT_BIN_VERSION" ]]; then
				sed -i '/xtls-rprx-direct/d' $XRAY_CONFIG
				sed -i 's/"xtls"/"tls"/' $XRAY_CONFIG
				sed -i 's/"grpc"/"gun"/g' $XRAY_CONFIG
				sed -i 's/"xtlsSettings"/"tlsSettings"/' $XRAY_CONFIG
				RAY_FLOW=""
				V2RAY_TRANSPORT='security=tls'
				V2RAY_TCP_NODENAME="v2fly"
			fi
			cat > $SYSTEMD_SERVICES/${PROJECT_BIN_VERSION}.service <<-EOF
			[Unit]
			Description=${PROJECT_BIN_VERSION} Service
			Documentation=https://github.com/xtls
			After=network.target nss-lookup.target
			[Service]
			User=root
			#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
			#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
			#NoNewPrivileges=true
			ExecStart=/etc/${PROJECT_BIN_VERSION}/${PROJECT_BIN_VERSION} run -config $XRAY_CONFIG
			Restart=on-failure
			RestartPreventExitStatus=23
			LimitNPROC=10000
			LimitNOFILE=1000000
			[Install]
			WantedBy=multi-user.target
			EOF
			NGINX_HTTPS_DEFAULT=${NGINX_SITE_ENABLED}/Default
			if [[ -e "$NGINX_HTTPS_DEFAULT" ]]; then
				sed -i '/^}/d' $NGINX_HTTPS_DEFAULT
				cat >>$NGINX_HTTPS_DEFAULT<<-EOF
				    #vless_grpc
				    location /${XRAY_GRPC_NAME}/Tun {
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
				    location /${XRAY_TROJAN_GRPC_NAME}/Tun {
				        if (\$content_type !~ "application/grpc") {
				            return 404;
				        }
				        client_max_body_size 0;
				        client_body_timeout 1071906480m;
				        grpc_read_timeout 1071906480m;
				        grpc_pass grpc://127.0.0.1:${XRAY_TROJAN_PORT};
				    }
				}
				EOF
			fi
			NGINX_HTPTS_DOMAIN=`cat $NGINX_HTTPS_DEFAULT | grep server_name | awk '{print $2}'`
			NGINX_SNI "${XRAY_DOMAIN}" "$RAY_TCP_PORT"
			systemctl daemon-reload
			systemctl start ${PROJECT_BIN_VERSION}
			systemctl enable ${PROJECT_BIN_VERSION}
			systemctl restart nginx

			GetRandomIcon
			XRAY_TCP_ICON=$RANDOM_ICON
			GetRandomIcon
			XRAY_GRPC_ICON=$RANDOM_ICON
			GetRandomIcon
			XRAY_WS_ICON=$RANDOM_ICON
			GetRandomIcon
			XRAY_TROJAN_ICON=$RANDOM_ICON

			base64 -d -i /etc/sub/trojan.sys > /etc/sub/subscription_tmp
			echo trojan://$XRAY_TROJAN_TCP_PASSWD@${XRAY_DOMAIN}:443?sni=${XRAY_DOMAIN}#${XRAY_TROJAN_ICON} Trojan ${NODE_SUFFIX} >> /etc/sub/subscription_tmp
			echo vless://${XRAY_GRPC_UUID}@${NGINX_HTPTS_DOMAIN}:443?type=grpc\&encryption=none\&serviceName=${XRAY_GRPC_NAME}\&security=tls\&sni=${NGINX_HTPTS_DOMAIN}#${XRAY_GRPC_ICON} gRPC ${NODE_SUFFIX} >> /etc/sub/subscription_tmp
			echo vless://${XRAY_UUID}@${XRAY_DOMAIN}:443?${V2RAY_TRANSPORT}\&${RAY_FLOW}sni=${XRAY_DOMAIN}#${XRAY_TCP_ICON} ${V2RAY_TCP_NODENAME} ${NODE_SUFFIX} >> /etc/sub/subscription_tmp
			echo \#vless://${XRAY_WS_UUID}@${NGINX_HTPTS_DOMAIN}:443?type=ws\&security=tls\&path=/${XRAY_WS_PATH}?ed=2048\&host=${NGINX_HTPTS_DOMAIN}\&sni=${NGINX_HTPTS_DOMAIN}#${XRAY_WS_ICON} WebSocks ${NODE_SUFFIX} >> /etc/sub/subscription_tmp
			base64 /etc/sub/subscription_tmp > /etc/sub/trojan.sys
			#添加clash订阅
			ADD_CLASH_SUB -n "${XRAY_WS_ICON} Trojan ${NODE_SUFFIX}" -t trojan -s ${XRAY_DOMAIN} -p 443 -a $XRAY_TROJAN_TCP_PASSWD -d -i ${XRAY_DOMAIN}
			ADD_CLASH_SUB -n "${XRAY_TROJAN_ICON} trojan-grpc ${NODE_SUFFIX}" -s ${NGINX_HTPTS_DOMAIN} -t trojan -a ${XRAY_TROJAN_PASSWD} -r ${XRAY_TROJAN_GRPC_NAME} -p 443 -d -e grpc -i ${NGINX_HTPTS_DOMAIN}
			if [[ "v2ray" == "$PROJECT_BIN_VERSION" ]]; then
				ADD_CLASH_SUB -n "${XRAY_TCP_ICON} v2fly ${NODE_SUFFIX}" -s ${XRAY_DOMAIN} -t vless -p 443 -u ${XRAY_UUID} -c none -d -l
			fi
		else 
			echo -e "\e[31m\e[1m找不到证书文件,退出安装！\e[0m"
		fi
	fi	
}
#trojan
function trojan(){
	read -p "输入节点名后缀,回车则不设置: " NODE_SUFFIX
	TROJAN_LAEST_VERSION=`curl -s https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name|cut -f4 -d "\""|cut -c 2-`
	TROJAN_CONFIG=/etc/trojan/config.json
	function TROJAN_BINARY(){
		cd /tmp
		wget https://github.com/trojan-gfw/trojan/releases/download/v${TROJAN_LAEST_VERSION}/trojan-${TROJAN_LAEST_VERSION}-linux-amd64.tar.xz 
		tar xvJf trojan-${TROJAN_LAEST_VERSION}-linux-amd64.tar.xz
		mv /tmp/trojan/trojan /etc/trojan/trojan
		if ! [[ -e "/etc/trojan/config.json" ]]; then
			mv /tmp/trojan/config.json /etc/trojan/config.json
		fi
		ln -s /etc/trojan/trojan /usr/bin/trojan
		rm -fr trojan-${TROJAN_LAEST_VERSION}-linux-amd64.tar.xz trojan
	}
	if [[ "$(type -P trojan)" ]]; then
		TROJAN_CURRENT_CERSION=$(/etc/trojan/trojan -v 2>&1 | grep Welcome | cut -d ' ' -f4)
		echo -e "检测到已安装trojan v\e[32m\e[1m${TROJAN_CURRENT_CERSION}\e[0m"
		echo -e "当前服务端最新版v\e[32m\e[1m${TROJAN_LAEST_VERSION}\e[0m"
		echo "回车只更新binary(不丢配置),输入new全新安装,输入其他任意键退出"
		read TROJAN_CONFIRM
		if [[ "" == "$TROJAN_CONFIRM" ]]; then
			TROJAN_BINARY
			echo -e "\e[32m\e[1m已更新成功,版本信息显示\e[0m"
			systemctl restart trojan
			/etc/trojan/trojan -v 2>&1 | grep Welcome
			exit 0
		elif [[ "new" == "$TROJAN_CONFIRM" ]]; then
			rm -f $TROJAN_CONFIG
			echo "开始安装Trojan"
		else 
			echo "已取消安装"
			exit 0
		fi
	fi
	#获取github仓库最新版release引用 https://bbs.zsxwz.com/thread-3958.htm
	echo "输入trojan域名"
	FORAM_DOMAIN
	TROJAN_DOMAIN=$RETURN_DOMAIN
	CHECK_NGINX_443=`ss -lnp|grep ":443 "|grep nginx`
	#不再支持端口，密码自定义
	if [[ "$CHECK_NGINX_443" ]]; then
		echo -e "\e[32m\e[1mNGINX正在监听443端口，检查SNI配置\e[0m"
		CHECK_PORT "NOINPUT" 5978
		TROJAN_HTTPS_PORT=$port
	else 
		CHECK_PORT "NOINPUT" 443
		TROJAN_HTTPS_PORT="443"
	fi
	#echo "Trojan 回落端口(5555): "
	#read TROJAN_CALLBACK_PORT
	TROJAN_HTTP_PORT=${TROJAN_CALLBACK_PORT:-5555}
	#echo "设置trojan密码(默认trojanWdai1)"
	#echo "不可以包含#@?"
	#read TROJAN_PASSWD
	#TROJAN_PASSWD=${TROJAN_PASSWD:-trojanWdai1}
	TROJAN_PASSWD=`GET_RANDOM_STRING`

	##申请SSL证书
	acme.sh $TROJAN_DOMAIN "/etc/nginx/html"
	if [[ -e "/ssl/${TROJAN_DOMAIN}.key" ]]; then
		echo -e "\e[32m\e[1m已检测到证书\e[0m"
		mkdir /etc/trojan
		TROJAN_BINARY
		sed -i '/password2/ d' $TROJAN_CONFIG
		sed -i "/remote_port/ s/80/$TROJAN_HTTP_PORT/" $TROJAN_CONFIG
		sed -i "/local_port/ s/443/$TROJAN_HTTPS_PORT/" $TROJAN_CONFIG
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
		systemctl daemon-reload
		systemctl start trojan
		NGINX_SERVICE_LIFE=`systemctl is-active trojan.service`
		if [[ "active" == "$NGINX_SERVICE_LIFE" ]]; then
			echo -e "\e[32m\e[1mtrojan服务启动成功\e[0m"
			NGINX_SNI $TROJAN_DOMAIN $TROJAN_HTTPS_PORT
			systemctl restart nginx
			systemctl enable trojan

			GetRandomIcon
			TROJAN_GFW_ICON=$RANDOM_ICON

			base64 -d -i /etc/sub/trojan.sys > /etc/sub/subscription_tmp
			#echo -e "\e[32m\e[1mtrojan://${TROJAN_PASSWD}@${TROJAN_DOMAIN}:443?sni=${TROJAN_DOMAIN}#Trojan\e[0m"
			echo trojan://${TROJAN_PASSWD}@${TROJAN_DOMAIN}:443?sni=${TROJAN_DOMAIN}#${TROJAN_GFW_ICON} Trojan-gfw${NODE_SUFFIX} >> /etc/sub/subscription_tmp
			base64 /etc/sub/subscription_tmp > /etc/sub/trojan.sys
			ADD_CLASH_SUB -n "${TROJAN_GFW_ICON} trojan-gfw${NODE_SUFFIX}" -t trojan -s ${TROJAN_DOMAIN} -p 443 -a ${TROJAN_PASSWD} -d -i ${TROJAN_DOMAIN}
		fi
	else 
		"检测不到证书，退出"
		return -1
	fi

}
#nginx
function INSTALL_NGINX(){
	CHECK_PORT "NOINPUT" 443
	CHECK_PORT "NOINPUT" 80
	NGINX_CONFIG=/etc/nginx/conf/nginx.conf
	NGINX_BIN=/etc/nginx/sbin/nginx
	NGINX_SITE_ENABLED="/etc/nginx/conf/sites"
	SUBSCRIPTION_PATH=`GET_RANDOM_STRING`
	SUBSCRIPTION_FILE="/etc/sub/trojan.sys"
	if ! [[ -d /etc/sub ]]; then
		mkdir /etc/sub
	fi
	touch $SUBSCRIPTION_FILE
	function NGINX_BINARY(){
		wget -P /tmp $nginx_url && tar zxf /tmp/nginx-${NGINX_VERSION}.tar.gz -C /tmp/ && cd /tmp/nginx-$NGINX_VERSION
		if [[ -e "/tmp/nginx-${NGINX_VERSION}.tar.gz" ]]; then
			./configure \
			--prefix=/etc/nginx \
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
			rm -fr /tmp/nginx-$NGINX_VERSION /tmp/nginx-${NGINX_VERSION}.tar.gz
		else 
			echo -e "\e[32m\e[1m找不到nginx压缩包,检查是否下载成功。\e[0m"
			exit 0
		fi

	}
	if [[ -e $NGINX_BIN ]]; then
		NGINX_CURRENT_VERSION=`$NGINX_BIN -v 2>&1 | cut -d '/' -f2`
		echo -e "已检测到nginx v\e[32m\e[1m${NGINX_CURRENT_VERSION}\e[0m,是否继续编译更新版本?(Y/n)"
		read NGINX_UPDATE_COMFIRM
		if [[ "" == "$NGINX_UPDATE_COMFIRM" ]]; then

			###接收一键函数传递的变量
			if [[ "$ONE_KEY_NGINX_VERSION" ]]; then
				NGINX_VERSION=$ONE_KEY_NGINX_VERSION
			else
				read -p "输入NGINX版本(默认1.21.1)： " NGINX_VERSION			
				NGINX_VERSION=${NGINX_VERSION:-1.21.1}
			fi
			nginx_url=http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
			systemctl stop nginx
			NGINX_BINARY
			systemctl start nginx
			NGINX_CURRENT_VERSION=`$NGINX_BIN -v 2>&1 | cut -d '/' -f2`
			echo -e "\e[32m\e[1m编译完成,当前版本号: ${NGINX_CURRENT_VERSION}\e[0m"
			return 0
		else 
			echo -e "\e[32m\e[1m已取消操作！\e[0m"
			systemctl start nginx
			exit 0
		fi
	fi
	###接收一键函数传递的变量
	if [[ "$ONE_KEY_NGINX_VERSION" ]]; then
		NGINX_VERSION=$ONE_KEY_NGINX_VERSION
	else
		read -p "输入NGINX版本(默认1.21.1)： " NGINX_VERSION
		NGINX_VERSION=${NGINX_VERSION:-1.21.1}
	fi	
	nginx_url=http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
	if [[ "$ONE_KEY_ENABLE_NGINX_SSL" ]]; then
		ENAGLE_NGINX_SSL=$ONE_KEY_ENABLE_NGINX_SSL
	else 
		read -p "是否开启SSL配置?(Y/n) " ENAGLE_NGINX_SSL
	fi
	
	if [[ "" == "$ENAGLE_NGINX_SSL" ]] || [[ "y" == "$ENAGLE_NGINX_SSL" ]]; then
		echo "输入NGING 域名"
		FORAM_DOMAIN "$ONE_KEY_NGINX_DOMAIN"
		NGINX_DOMAIN=$RETURN_DOMAIN
		ENAGLE_NGINX_SSL_=true
	fi
	#检测openssl版本
	CURRENT_OPENSSL_VERSION=`openssl version|cut -d ' ' -f2`
	if [[ "$CURRENT_OPENSSL_VERSION" != "1.1.1k" ]]; then
		echo -e "\e[32m\e[1m当前openssl版本为${CURRENT_OPENSSL_VERSION},是否更新至1.1.1k(Y/n)?\e[0m"
		if [[ "$ONE_KEY_CONFIRM_OPENSSL" ]]; then
			CONFIRM_OPENSSL="$ONE_KEY_CONFIRM_OPENSSL"
		else 
			read CONFIRM_OPENSSL
		fi
	fi
	##安装依赖
	if [[ "$(type -P apt)" ]]; then
		$PKGMANAGER_INSTALL build-essential libpcre3 libpcre3-dev zlib1g-dev git openssl wget libssl-dev
	elif [[ "$(type -P yum)" ]]; then
		$PKGMANAGER_INSTALL gcc gcc-c++ pcre pcre-devel zlib zlib-devel openssl openssl-devel wget
	else
		echo "error: The script does not support the package manager in this operating system."
		exit 1
	fi
	#开始编译
	if [[ "$CONFIRM_OPENSSL" == "" || "$CONFIRM_OPENSSL" == "y" ]]; then
		echo [debug] ==============================
		echo "CONFIRM_OPENSSL = " $CONFIRM_OPENSSL
		read
		wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
		tar xf openssl-1.1.1k.tar.gz
		cd openssl-1.1.1k
		./config
		make test && make install
		rm -fr openssl-1.1.1k.tar.gz openssl-1.1.1k
		check "OPENSSL更新失败"
		mv /usr/bin/openssl /usr/bin/openssl.bak
		mv /usr/include/openssl /usr/include/openssl.bak
		ln -s /usr/local/bin/openssl /usr/bin/openssl
		ln -s /usr/local/include/openssl /usr/include/openssl
		echo "/usr/local/ssl/lib" >> /etc/ld.so.conf
		rm -fr openssl-1.1.1k.tar.gz openssl-1.1.1k
		ldconfig -v
		echo -e "\e[32m\e[1m当前openssl版本号: \e[0m"`openssl version`
		sleep 2
	fi

	NGINX_BINARY

	ln -s /etc/nginx/sbin/nginx /usr/bin/nginx
	mv $NGINX_CONFIG ${NGINX_CONFIG}_backup
	wget -O $NGINX_CONFIG https://raw.githubusercontent.com/onlyJinx/Shell_2/test/nginxForFsGrpc.conf
	
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
			ExecStartPre=$NGINX_BIN -t -c $NGINX_CONFIG
			ExecStart=$NGINX_BIN -c $NGINX_CONFIG
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
	mkdir $NGINX_SITE_ENABLED
	###nginx编译引用自博客
	###https://www.cnblogs.com/stulzq/p/9291223.html
	systemctl daemon-reload
	systemctl enable nginx
	###systemctl status nginx
	echo -e "\e[32m\e[1m编译nginx成功\e[0m"

	##启用https
	if [[ "$ENAGLE_NGINX_SSL_" ]]; then
		systemctl start nginx
		#开始申请SSL证书
		acme.sh "$NGINX_DOMAIN" "/etc/nginx/html"
		if [[ -e "/ssl/${NGINX_DOMAIN}".key ]]; then
			echo -e "\e[32m\e[1m证书申请成功，开始写入ssl配置\e[0m"
			cat >${NGINX_SITE_ENABLED}/Default<<-EOF
			server {
			    listen       4433 http2 ssl proxy_protocol;
			    server_name  ${NGINX_DOMAIN} default;
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
			    location /${SUBSCRIPTION_PATH}/ {
			        alias /etc/sub/;
			        index trojan.sys;
			    }
			}
			EOF
			echo "export ngp=$NGINX_SITE_ENABLED/Default" >> /etc/profile
			#开启80端口强制重定向443
			sed -i 's/#ENABLE_REDIRECT//' $NGINX_CONFIG
			systemctl restart nginx
			echo "v2ray订阅地址: https://${NGINX_DOMAIN}/${SUBSCRIPTION_PATH}/trojan.sys"
			echo "clash订阅地址: https://${NGINX_DOMAIN}/${SUBSCRIPTION_PATH}/clash.yaml"			
		else
			echo "证书申请失败，ssl配置未写入"
		fi
	else 
		systemctl start nginx
		echo "export ngp=$NGINX_CONFIG" >> /etc/profile
	fi
}
#caddy
function caddy(){
	echo "输入Caddy域名"
	FORAM_DOMAIN "$ONE_KEY_CADDY_DOMAIN"
	CADDY_DOMAIN=$RETURN_DOMAIN
	if [[ "$ONE_KEY_NODE_SUFFIX" ]]; then
		NODE_SUFFIX=$ONE_KEY_NODE_SUFFIX
	else 
		read -p "输入节点名后缀,回车则不设置: " NODE_SUFFIX
	fi
	#read -p "设置用户名(禁止@:): " CADDY_USER
	#CADDY_USER=${CADDY_USER:-Oieu!ji330}
	CADDY_USER=`GET_RANDOM_STRING`
	CADDY_USER=${CADDY_USER//\//_}
	#read -p "设置密码(禁止@:): " CADDY_PASSWD
	#CADDY_PASSWD=${CADDY_PASSWD:-5eele9P!il_}
	CADDY_PASSWD=`GET_RANDOM_STRING`
	CADDY_PASSWD=${CADDY_PASSWD//\//_}
	CHECK_NGINX_443=`ss -lnp|grep ":443 "|grep nginx`
	if [[ "$CHECK_NGINX_443" ]]; then
		echo "NGINX正在监听443端口，检查SNI配置"
		#echo "输入Caddy分流端口(非443)"
		#read CADDY_HTTPS_PORT
		CHECK_PORT "NOINPUT" 15486
		CADDY_HTTPS_PORT=$port
		CHECK_PORT "NOINPUT" 16254
		CADDY_HTTP_PORT=$port
		#证书申请完之后再重启NGINX使SNI分流生效
		#否则会因分流回落端口无响应导致申请证书失败
		acme.sh "$CADDY_DOMAIN" "/etc/nginx/html"
		CADDY_TLS="tls /ssl/${CADDY_DOMAIN}.cer /ssl/${CADDY_DOMAIN}.key"
		if [[ -e "/ssl/${CADDY_DOMAIN}.key" ]]; then
			echo "已检测到SSL证书，安装继续"
		else 
			echo "证书申请失败，退出安装！"
			return -1
		fi
	else 
		CHECK_PORT "NOINPUT" 443
		CADDY_HTTPS_PORT=$port
		CHECK_PORT "NOINPUT" 80
		CADDY_HTTP_PORT=$port
		CADDY_TLS="tls noemail@qq.com"
	fi

	if ! [[ $(type -P go) ]]; then
		echo -e "\e[31m\e[1m未配置GO环境，开始配置环境\e[0m"
		$PKGMANAGER_INSTALL wget
		wget -P /tmp https://golang.google.cn/dl/go1.16.6.linux-${LINUX_PLATFORM}.tar.gz
		echo "正在解压golang压缩包..."
		tar zxf /tmp/go1.16.6.linux-${LINUX_PLATFORM}.tar.gz -C /tmp/
		export PATH=$PATH:/tmp/go/bin
	fi
	if [[ $(type -P go) ]]; then
		cd /tmp/
		go get -u github.com/caddyserver/xcaddy/cmd/xcaddy
		~/go/bin/xcaddy build \
		--with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive \
		--with github.com/mastercactapus/caddy2-proxyprotocol
		if [[ -e /tmp/caddy ]]; then
			mkdir /etc/caddy
			mv /tmp/caddy /etc/caddy/
			chmod +x /etc/caddy/caddy
			cat >/etc/caddy/Caddyfile<<-EOF
				{
				    http_port  $CADDY_HTTP_PORT
				    https_port $CADDY_HTTPS_PORT
				    servers {
				        listener_wrappers {
				        proxy_protocol {
				                timeout 2s
				                allow 0.0.0.0/0
				            }
				            tls
				        }
				    }
				}
				:${CADDY_HTTPS_PORT}, $CADDY_DOMAIN {
				    $CADDY_TLS
				    route {
				        forward_proxy {
				            basic_auth $CADDY_USER $CADDY_PASSWD
				            hide_ip
				            hide_via
				            probe_resistance
				        }
				        file_server { 
				            root $NGINX_WEBROOT
				        }
				    }
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
			CHECK_CADDY_LIFE=`systemctl is-active caddy`
			#active返回状态码0，其余返回非0
			if [[ "active" == "$CHECK_CADDY_LIFE" ]]; then
				echo -e "\e[32m\e[1mCaddy运行正常\e[0m"
				systemctl enable caddy
				NGINX_SNI $CADDY_DOMAIN $CADDY_HTTPS_PORT
				systemctl restart nginx
				rm -fr /tmp/go1.16.6.linux-${LINUX_PLATFORM}.tar.gz /tmp/go /root/go
				base64 -d -i /etc/sub/trojan.sys > /etc/sub/subscription_tmp
				#echo -e "\e[32m\e[1mnaive+https://${CADDY_USER}:${CADDY_PASSWD}@${CADDY_DOMAIN}/#Naive\e[0m"

				GetRandomIcon
				CADDY_ICON=$RANDOM_ICON
				echo naive+https://${CADDY_USER}:${CADDY_PASSWD}@${CADDY_DOMAIN}/#${CADDY_ICON} Naive ${NODE_SUFFIX} >> /etc/sub/subscription_tmp
				base64 /etc/sub/subscription_tmp > /etc/sub/trojan.sys
			else
				echo -e "\e[31m\e[1mCaddy启动失败，安装退出\e[0m"
				rm -fr /tmp/go1.16.6.linux-${LINUX_PLATFORM}.tar.gz /tmp/go
			fi
		else
			echo -e "\e[31m\e[1mcaddy编译失败\e[0m"
			exit 1
		fi
		
	else
		echo -e "\e[31m\e[1mGo环境配置失败！\e[0m"
		exit 1
	fi
}
#hysteria
function hysteria(){
	DESTINATION_PATH="/etc/hysteria"
	HYSTERIA_BIN="/etc/hysteria/hysteria"
	hysteria_LATEST=`curl -s https://api.github.com/repos/HyNetwork/hysteria/releases/latest | grep tag_name|cut -f4 -d "\""`
	hysteria_DOWNLOAD_LINK=https://github.com/HyNetwork/hysteria/releases/download/${hysteria_LATEST}/hysteria-linux-${LINUX_PLATFORM}
	if [[ -a "$HYSTERIA_BIN" ]]; then
		CHRRENT_HYSTERIA_VERSION=`$HYSTERIA_BIN -v|cut -d ' ' -f3`
		if [[ "$CHRRENT_HYSTERIA_VERSION" != "$hysteria_LATEST" ]]; then
			echo "当前版本为${CHRRENT_HYSTERIA_VERSION},服务端已有新版${hysteria_LATEST},是否更新?(Y/n)"
			read UPDATE_HYSTERIA_VERSION
			if [[ "$UPDATE_HYSTERIA_VERSION" == "" || "$UPDATE_HYSTERIA_VERSION" == "y" ]]; then
				systemctl stop hysteria.service
				wget -O ${DESTINATION_PATH}/hysteria $hysteria_DOWNLOAD_LINK
				chmod +x ${DESTINATION_PATH}/hysteria
				systemctl start hysteria.service
				echo -e "\e[32m\e[1m已更新，当前版本为：`$HYSTERIA_BIN -v|cut -d ' ' -f3`\e[0m"
				return 0
			fi
		else 
			read -p "当前版本已与服务端保持最新($CHRRENT_HYSTERIA_VERSION),是否全新编译?(y/N)" HYSTERIA_REBUILD_CONFIRM
			if [[ "y" != "$HYSTERIA_REBUILD_CONFIRM" ]]; then
				echo  -e "\e[32m\e[1m已取消操作\e[0m"
				return 0
			fi
		fi
	fi
	echo "输入Hysteria域名"
	FORAM_DOMAIN
	hysteria_DOMAIN=$RETURN_DOMAIN
	read -p "输入obfs混淆(io!jioOhu8eH)" hysteria_OBFS
	hysteria_OBFS=${hysteria_OBFS:-io!jioOhu8eH}
	read -p "输入认证密码(ieLj3fhG!o34)" hysteria_AUTH
	hysteria_AUTH=${hysteria_AUTH:-ieLj3fhG!o34}
	acme.sh "$hysteria_DOMAIN" "/etc/nginx/html"
	if [[ -e "/ssl/${hysteria_DOMAIN}.key" ]]; then
		echo "已检测到证书"
		mkdir $DESTINATION_PATH
		wget -O ${DESTINATION_PATH}/hysteria $hysteria_DOWNLOAD_LINK
		chmod +x ${DESTINATION_PATH}/hysteria
		cat >${DESTINATION_PATH}/config.json<<-EOF
		{
		    "listen": ":443",
		    "cert": "/ssl/${hysteria_DOMAIN}.cer",
		    "key": "/ssl/${hysteria_DOMAIN}.key",
		    "obfs": "${hysteria_OBFS}",
		    "auth": {
		        "mode": "password",
		        "config": {
		            "password": "$hysteria_AUTH"
		        }
		    },
		    "up_mbps": 1000,
		    "down_mbps": 1000
		}
		EOF
		###crate service
		cat >$SYSTEMD_SERVICES/hysteria.service<<-EOF
		[Unit]
		Description=hysteria Server
		After=network.target
		[Service]
		ExecStart=/etc/hysteria/hysteria -config /etc/hysteria/config.json server
		User=root
		[Install]
		WantedBy=multi-user.target
		EOF
		systemctl daemon-reload
		systemctl start hysteria.service
		systemctl is-active hysteria.service
		if [[ "active" == "`systemctl is-active hysteria.service`" ]]; then
			systemctl enable hysteria.service
			echo -e "\e[32m\e[1mhysteria已成功启动\e[0m"
			echo $hysteria_DOMAIN
			echo "obfs: "$hysteria_OBFS
			echo "auth: "$hysteria_AUTH
		else
			echo -e "\e[31m\e[1m服务启动失败，检查报错信息\e[0m"
		fi
	else
		echo -e "\e[31m\e[1m检测不到证书，安装退出\e[0m"
	fi
}
function ADD_CLASH_SUB(){

  # - name: "vless"
  #   type: vless
  #   server: server
  #   port: 443
  #   uuid: uuid
  #   cipher: none
  #   udp: true
  #   tls: true
  	#重置OPTIND,防止第一次调用函数导致的IND偏移
  	OPTIND=1
	CLASH_SUB_FILE=/etc/sub/clash.yaml
	#初始化变量
	auto_sub_name=""
	auto_sub_server=""
	auto_sub_port=""
	auto_sub_type=""
	auto_sub_password=""
	auto_sub_uuid=""
	auto_sub_network=""
	auto_sub_sni=""
	auto_sub_grpc_service=""
	auto_sub_grpc_opt=""
	auto_sub_udp=""
	auto_sub_cipher=""
	auto_sub_tls=""
	
	if [[ ! -a "$CLASH_SUB_FILE" ]]; then
		echo 'proxies:' > $CLASH_SUB_FILE
	fi
	while getopts ":n:s:p:t:a:u:e:i:r:dlc:" sub_gen; do
		case $sub_gen in
			n)	auto_sub_name="name: ${OPTARG}";;
			s)	auto_sub_server="server: ${OPTARG}";;
			p)	auto_sub_port="port: ${OPTARG}";;
			t)	auto_sub_type="type: ${OPTARG}";;
			a)	auto_sub_password="password: ${OPTARG}";;
			u)	auto_sub_uuid="uuid: ${OPTARG}";;
			e)	auto_sub_network="network: ${OPTARG}";;
			i)	auto_sub_sni="sni: ${OPTARG}";;
			r)	auto_sub_grpc_service="grpc-service-name: ${OPTARG}"
				auto_sub_grpc_opt='grpc-opts:';;
			d)	auto_sub_udp="udp: true";;
			c)	auto_sub_cipher="cipher: ${OPTARG}";;
			l)	auto_sub_tls="tls: true";;
			?)	echo '参数错误'
				echo 'n:name'
				echo 's:server'
				echo 'p:port'
				echo 't:type'
				echo 'c:cipher'
				echo 'a:password'
				echo 'u:uuid'
				echo 'e:network'
				echo 'i:sni'
				echo 'r:grpc-service-name'
				echo 'd:udp(无参数)'
				echo 'l:tls(无参数)'
				exit 0;;
		esac
	done
	cat >> $CLASH_SUB_FILE<<-EOF
	  - $auto_sub_name
	    $auto_sub_server
	    $auto_sub_type
	    $auto_sub_port
	    $auto_sub_password
	    $auto_sub_uuid
	    $auto_sub_cipher
	    $auto_sub_network
	    $auto_sub_sni
	    $auto_sub_grpc_opt
	      $auto_sub_grpc_service
	    $auto_sub_udp
	    $auto_sub_tls
	EOF
	sed -i '/^\s*$/d' $CLASH_SUB_FILE
}
function REMOVE_SOFTWARE(){
	function REMOVE_SOFTWARE_BIN(){
		REMOVE_SOFTWARE_NAME=$1
		systemctl disable $REMOVE_SOFTWARE_NAME
		systemctl stop $REMOVE_SOFTWARE_NAME
		rm -fr /etc/$REMOVE_SOFTWARE_NAME /etc/systemd/system/${REMOVE_SOFTWARE_NAME}.service
		if [[ -a "/usr/bin/$REMOVE_SOFTWARE_NAME" ]]; then
			rm -f /usr/bin/$REMOVE_SOFTWARE_NAME
		fi
		echo -e "\e[31m\e[1m列出一些可能的残留文件,按照需要手动清理\e[0m"
		find / -name ${REMOVE_SOFTWARE_NAME}*
	}
	select option in "nginx" "Project_V" "transmission" "trojan" "Project_X" "caddy" "hysteria" "aria2"
	do
		case $option in
			"transmission")
				rm -fr /root/.config/transmission-daemon
				REMOVE_SOFTWARE_BIN "transmission"
				break;;
			"aria2")
				REMOVE_SOFTWARE_BIN "aria2"
				break;;
			"trojan")
				REMOVE_SOFTWARE_BIN "trojan"
				break;;
			"nginx")
				rm -fr /etc/sub
				REMOVE_SOFTWARE_BIN "nginx"
				break;;
			"Project_X")
				REMOVE_SOFTWARE_BIN "xray"
				break;;
			"Project_V")
				REMOVE_SOFTWARE_BIN "v2ray"
				break;;
			"caddy")
				rm -fr /root/.local/share/caddy /root/.config/caddy
				REMOVE_SOFTWARE_BIN "caddy"
				break;;
			"hysteria")
				REMOVE_SOFTWARE_BIN "hysteria"
				break;;
			*)
				echo "nothink to do"
				break;;
		esac
	done
}

function Onekey_install(){

	echo "输入节点后缀(通用)" 
	read ONE_KEY_NODE_SUFFIX
	echo "输入NGINX域名"
	read ONE_KEY_NGINX_DOMAIN
	echo "输入V2ray域名"
	read ONE_KEY_V2RAY_DOMAIN
	echo "输入Caddy域名"
	read ONE_KEY_CADDY_DOMAIN
	echo "输入Transmission域名"
	read ONE_KEY_TRANSMISSION_DOMAIN
	echo "输入acme.sh邮箱(回车跳过)"
	read ONE_KEY_ACME_EMAIL

	ONE_KEY_NGINX_VERSION="1.21.1"
	ONE_KEY_ENABLE_NGINX_SSL="y"
	##默认不编译OPENSSL
	ONE_KEY_CONFIRM_OPENSSL="no"
	NOE_KEY_V2RAY_BIN_VERSION="4.41.1"
	ONE_KEY_TRANSMISSION_ENABLE_HTTPS_TS="yes"
	ONE_KEY_TRANSMISSION_DOWN_PATH="/usr/downloads"
	ONE_KEY_ACME_EMAIL=${ONE_KEY_ACME_EMAIL:-no_email@gmail.com}

	curl https://get.acme.sh | sh -s email=$ONE_KEY_ACME_EMAIL
	INSTALL_NGINX
	Project_X "v2ray"
	transmission
	caddy

	echo "v2ray订阅地址: https://${NGINX_DOMAIN}/${SUBSCRIPTION_PATH}/trojan.sys"
	echo "clash订阅地址: https://${NGINX_DOMAIN}/${SUBSCRIPTION_PATH}/clash.yaml"
}
echo -e "\e[31m\e[1m输入对应的数字选项:\e[0m"
select option in "Onekey_install" "Up_kernel" "nginx" "Project_V" "transmission" "trojan" "Project_X" "caddy" "hysteria" "acme.sh" "shadowsocks-libev" "aria2" "uninstall_software" "Timezone"
do
	case $option in
		"acme.sh")
			acme.sh
			break;;
		"shadowsocks-libev")
			shadowsocks-libev
			break;;
		"Onekey_install")
			Onekey_install
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
			Project_X "xray"
			break;;
		"Project_V")
			Project_X "v2ray"
			break;;
		"caddy")
			caddy
			break;;
		"hysteria")
			hysteria
			break;;
		"Timezone")
			timedatectl set-timezone Asia/Shanghai
			break;;
		"uninstall_software")
			REMOVE_SOFTWARE
			break;;
		*)
			echo "nothink to do"
			break;;
	esac
done

#!/bin/bash
# NGINX_life="$(systemctl is-active nginx.service)"
# getTime=`date '+%m-%d %H:%M'`
# outupt_log=/etc/run.log
# if [[ "$NGINX_life" != "active" ]]; then
#             echo "RT" | /usr/bin/mailx -s "NGINX服务状态异常 $getTime" 925198583@qq.com
# fi
# echo "nginx status: $NGINX_life  $getTime">> $outupt_log
