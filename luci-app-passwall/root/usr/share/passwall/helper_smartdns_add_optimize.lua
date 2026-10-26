local api = require "luci.passwall.api"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local SMARTDNS_CONF = var["-SMARTDNS_CONF"]
local LOCAL_GROUP = var["-LOCAL_GROUP"]
local LOCAL_DNS = var["-LOCAL_DNS"]
local VPS_GROUP = var["-VPS_GROUP"]
local VPS_DNS = var["-VPS_DNS"]
if not VPS_GROUP or VPS_GROUP == "" or VPS_GROUP == "nil" then
	VPS_GROUP = LOCAL_GROUP
end
local REMOTE_GROUP = var["-REMOTE_GROUP"]
local REMOTE_PROXY_SERVER = var["-REMOTE_PROXY_SERVER"]
local USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"]
local REMOTE_DNS = var["-REMOTE_DNS"]
local TUN_DNS = var["-TUN_DNS"]
local DNS_MODE = var["-DNS_MODE"]
local NODE = var["-NODE"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
local USE_GFW_LIST = var["-USE_GFW_LIST"]
local CHN_LIST = var["-CHN_LIST"]
local DEFAULT_PROXY_MODE = var["-DEFAULT_PROXY_MODE"]
local NO_PROXY_IPV6 = var["-NO_PROXY_IPV6"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
local NFTFLAG = var["-NFTFLAG"]
local SUBNET = var["-SUBNET"]
local LISTEN_PORT = var["-LISTEN_PORT"]
local LOCAL_PORT = var["-LOCAL_PORT"]
local DNS_REDIRECT = var["-DNS_REDIRECT"] == "1"
local NO_IP_ALIAS = var["-NO_IP_ALIAS"] or "1"
local CACHE_MODE = var["-CACHE_MODE"] or "default"
local NO_RULE_ADDR = var["-NO_RULE_ADDR"] or "0"
local SPLIT_SHUNT = var["-SPLIT_SHUNT"] or "0"
local SERVE_EXPIRED = var["-SERVE_EXPIRED"] or "1"
local IS_SHUNT_NODE = api.uci_get_c(NODE, "protocol") == "_shunt"

local function get_remote_rule_extra()
	local extra = ""
	if IS_SHUNT_NODE or SERVE_EXPIRED == "0" then
		extra = extra .. " -no-serve-expired"
	end
	if NO_IP_ALIAS == "1" then
		extra = extra .. " -no-ip-alias"
	end
	if IS_SHUNT_NODE or CACHE_MODE == "nocache" then
		extra = extra .. " -no-cache"
	elseif CACHE_MODE == "300" then
		extra = extra .. " -rr-ttl-max 300"
	elseif CACHE_MODE == "60" then
		extra = extra .. " -rr-ttl-max 60"
	elseif CACHE_MODE == "30" then
		extra = extra .. " -rr-ttl-max 30"
	end
	return extra
end

local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes

local TMP_PATH = api.TMP_PATH
local RULES_PATH = "/usr/share/passwall/rules"
local USER_RULES_PATH = "/etc/passwall/rules"
local CACHE_RULES_PATH = api.CACHE_PATH .. "/user_rules"
local FLAG_PATH = TMP_PATH .. "/acl/" .. FLAG
local TMP_CONF_FILE = FLAG_PATH .. "/smartdns.conf"
local config_lines = {}
local split_rules_list = {}
local split_rules_map = {}
local USE_GEOVIEW = api.uci_get_c("@global_rules[0]", "enable_geoview")

if not api.is_finded("geoview") then
	USE_GEOVIEW = "0"
end

local function log(...)
	if NO_LOGIC_LOG == "1" then
		return
	end
	api.log(...)
end

local function is_file_nonzero(path)
	if path and #path > 1 then
		local size = fs.stat(path, "size")
		if size and size > 0 then
			return true
		end
	end
	return nil
end

local function insert_unique(dest_table, value, lookup_table)
	if not lookup_table[value] then
		table.insert(dest_table, value)
		lookup_table[value] = true
	end
end

local geosite_path = api.uci_get_c("@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
geosite_path = geosite_path:match("^(.*)/") .. "/geosite.dat"

local function get_geosite(list_arg, out_path)
	if not is_file_nonzero(geosite_path) then return 1, "File geosite.dat not found" end
	if not list_arg or list_arg == "" then return 1, "Site list cannot be empty" end
	if not out_path or out_path == "" then return 1, "Output path cannot be empty" end
	local bin = api.finded_com("geoview")
	local cmd = string.format("%q -type geosite -append=true -input %q -list %q -output %q -lowmem=true",
		bin, geosite_path, list_arg, out_path)
	return api.exec_call(cmd)
end

local function is_rule_cache_valid(cache_base, src_rule_file)
	local ok_file = cache_base .. "_ok"
	local ok_stat = fs.stat(ok_file)
	if not ok_stat or not ok_stat.mtime then return false end
	if not fs.access(cache_base) then return false end
	if src_rule_file and fs.access(src_rule_file) then
		local src_stat = fs.stat(src_rule_file)
		if src_stat and src_stat.mtime and src_stat.mtime > ok_stat.mtime then return false end
	end
	if fs.access(cache_base .. "_geo") and fs.access(geosite_path) then
		local geo_stat = fs.stat(geosite_path)
		if geo_stat and geo_stat.mtime and geo_stat.mtime > ok_stat.mtime then return false end
	end
	return true
end

sys.call("mkdir -p %s" % FLAG_PATH)
sys.call("mkdir -p %s" % CACHE_RULES_PATH)

local LOCAL_EXTEND_ARG = ""
if LOCAL_GROUP == "null" or LOCAL_GROUP == "" then
	LOCAL_GROUP = nil
else
	local options = {
		{ key = "dualstack_ip_selection", config_key = "dualstack-ip-selection", yes_no = true, arg_yes = "-d yes", arg_no = "-d no", default = "yes" },
		{ key = "speed_check_mode", config_key = "speed-check-mode", prefix = "-speed-check-mode ", default = "ping,tcp:80,tcp:443" },
		{ key = "serve_expired", config_key = "serve-expired", yes_no = true, arg_yes = "", arg_no = "-no-serve-expired", default = "yes" },
		{ key = "response_mode", config_key = "response-mode", prefix = "-response-mode ", default = "first-ping" },
		{ key = "rr_ttl", config_key = "rr-ttl", prefix = "-rr-ttl " },
		{ key = "rr_ttl_min", config_key = "rr-ttl-min", prefix = "-rr-ttl-min " },
		{ key = "rr_ttl_max", config_key = "rr-ttl-max", prefix = "-rr-ttl-max " },
		{ key = "rr_ttl_reply_max", config_key = "rr-ttl-reply-max", prefix = "-rr-ttl-reply-max " },
		{
			key = "force_aaaa_soa",
			config_key = "force-qtype-SOA",
			prefix = "-address ",
			get_value = function(custom_config)
				local soa = custom_config["force-qtype-SOA"]
				local has_28 = soa and ((" " .. soa .. " "):find("%s28%s") ~= nil)
				return (has_28
					or custom_config["force-AAAA-SOA"] == "yes"
					or api.uci_get("smartdns", "@smartdns[0]", "force_aaaa_soa") == "1")
					and "#6" or nil
			end
		}
	}
	local custom_config = {}
	local f_in = io.open("/etc/smartdns/custom.conf", "r")
	if f_in then
		for line in f_in:lines() do
			line = api.trim(line)
			if line ~= "" and not line:match("^#") then
				local k, v = line:match("^(%S+)%s+(.+)$")
				if k and v then
					custom_config[k] = v
				end
			end
		end
		f_in:close()
	end
	for _, opt in ipairs(options) do
		local val
		if opt.get_value then
			val = opt.get_value(custom_config)
		else
			val = custom_config[opt.config_key] or api.uci_get("smartdns", "@smartdns[0]", opt.key) or opt.default
		end
		if val == "yes" then val = "1" elseif val == "no" then val = "0" end
		if opt.yes_no then
			local arg_val = (val == "1" and opt.arg_yes or opt.arg_no)
			if arg_val and arg_val ~= "" then
				LOCAL_EXTEND_ARG = LOCAL_EXTEND_ARG .. (LOCAL_EXTEND_ARG ~= "" and " " or "") .. arg_val
			end
		else
			if val and (not opt.value or (opt.invert and val ~= opt.value) or (not opt.invert and val == opt.value)) then
				LOCAL_EXTEND_ARG = LOCAL_EXTEND_ARG .. (LOCAL_EXTEND_ARG ~= "" and " " or "") .. (opt.prefix or "") .. (opt.arg or val)
			end
		end
	end
end

if not REMOTE_GROUP or REMOTE_GROUP == "nil" then
	REMOTE_GROUP = "passwall_proxy"
end
if REMOTE_DNS then
	REMOTE_DNS = REMOTE_DNS:gsub("#", ":")
end

local SANDBOX_GROUP = "passwall_" .. FLAG
local force_https_soa = api.uci_get_c("@global[0]", "force_https_soa") or 0
local proxy_server_name = "psw-proxy-server"

local local_domain = api.uci_get_c("dhcp.@dnsmasq[0].domain")
if not local_domain or local_domain == "" then
	local local_str = api.uci_get_c("dhcp.@dnsmasq[0].local") or "/lan/"
	local_domain = string.match(local_str, "^/?([^/]+)/?$") or "lan"
end
if local_domain then
	local_domain = local_domain:gsub("^[/.%s]+", ""):gsub("[/.%s]+$", "")
end

local dnsmasq_lease = api.uci_get_c("dhcp.@dnsmasq[0].leasefile") or "/tmp/dhcp.leases"
local odhcpd_lease = api.uci_get_c("dhcp.odhcpd.leasefile")
if not odhcpd_lease or odhcpd_lease == "" then
	odhcpd_lease = fs.access("/tmp/odhcpd.leases") and "/tmp/odhcpd.leases" or "/tmp/hosts/odhcpd"
end

-- 基础绑定与服务配置（使用端口绑定规则组沙盒，零污染 SmartDNS 默认组与 15354 直连回查端口）
local listen_address = "[::]:" .. LISTEN_PORT .. (DNS_REDIRECT and "" or "@lo")
local vps_bind_group = VPS_GROUP or LOCAL_GROUP
config_lines = {
	"# ── PassWall SmartDNS Group Rules Configuration ──",
	tonumber(LISTEN_PORT) ~= 0 and ("bind " .. listen_address .. " -group " .. SANDBOX_GROUP .. (NO_RULE_ADDR == "1" and " -no-rule-addr" or "")) or "",
	tonumber(LISTEN_PORT) ~= 0 and ("bind-tcp " .. listen_address .. " -group " .. SANDBOX_GROUP .. (NO_RULE_ADDR == "1" and " -no-rule-addr" or "")) or "",
	(tonumber(LOCAL_PORT) ~= 0 and vps_bind_group) and ("bind [::]:" .. LOCAL_PORT .. "@lo -group " .. vps_bind_group .. (NO_RULE_ADDR == "1" and " -no-rule-addr" or "")) or "",
	(tonumber(LOCAL_PORT) ~= 0 and vps_bind_group) and ("bind-tcp [::]:" .. LOCAL_PORT .. "@lo -group " .. vps_bind_group .. (NO_RULE_ADDR == "1" and " -no-rule-addr" or "")) or "",
	tonumber(force_https_soa) == 1 and "force-qtype-SOA 65" or "force-qtype-SOA -,65",
	"server 223.5.5.5 -bootstrap-dns",
	(local_domain and local_domain ~= "") and ("local-domain " .. local_domain) or "",
	"dnsmasq-lease-file " .. dnsmasq_lease,
	(odhcpd_lease and odhcpd_lease ~= "") and ("odhcpd-lease-file " .. odhcpd_lease) or "",
	"hosts-file /tmp/hosts/*",
	is_file_nonzero("/etc/hosts") and "hosts-file /etc/hosts" or "",
	DNS_MODE == "socks" and string.format("proxy-server socks5://%s -name %s", REMOTE_PROXY_SERVER, proxy_server_name) or ""
}

if DNS_REDIRECT then
	local hosts = {}
	api.uci:foreach("dhcp", "host", function(s)
		if datatypes.hostname(s.name or "") and datatypes.ip4addr(s.ip or "") then
			hosts[#hosts + 1] = s.ip .. " " .. s.name
		end
	end)

	local hosts_file = FLAG_PATH .. "/dhcp-static-hosts"
	if fs.writefile(hosts_file, table.concat(hosts, "\n") .. "\n") and #hosts > 0 then
		table.insert(config_lines, string.format("hosts-file %q", hosts_file))
	end
end

-- 注册代理上游服务器组 (REMOTE_GROUP)
if DNS_MODE == "socks" then
	for w in string.gmatch(REMOTE_DNS, '[^|]+') do
		-- 协议和默认端口由 SmartDNS 根据原始 URL 识别。
		local dns = api.split(api.trim(w), ",")
		local server_param = "server " .. api.trim(dns[1])
		if dns[2] and dns[2] ~= "" then
			-- 保留 URL 中的域名，固定连接 IP 交给 SmartDNS 处理，避免手动替换影响 SNI 和 HTTP Host。
			server_param = server_param .. " -host-ip " .. api.trim(dns[2]):gsub("^%[(.*)%]$", "%1")
		end

		if not api.is_local_ip(w) then
			server_param = server_param .. " -proxy " .. proxy_server_name
		end

		server_param = server_param .. " -group " .. REMOTE_GROUP .. " -exclude-default-group"
		if SUBNET and SUBNET ~= "" and SUBNET ~= "0" then
			server_param = server_param .. " -subnet " .. SUBNET
		end
		table.insert(config_lines, server_param)
	end
else
	table.insert(config_lines, string.format("server %s -group %s -exclude-default-group", TUN_DNS:gsub("#", ":"), REMOTE_GROUP))
	log("  - " .. DNS_MODE:gsub("^%l", string.upper) .. " " .. TUN_DNS .. " -> " .. REMOTE_GROUP)
end

local setflag = (NFTFLAG == "1") and "inet#passwall#" or ""
local set_type = (NFTFLAG == "1") and "-nftset" or "-ipset"

-- 注册节点列表专属直连组 (passwall_vps)
if VPS_GROUP == "passwall_vps" then
	table.insert(config_lines, "")
	table.insert(config_lines, "# ── 节点列表专属直连组 (passwall_vps) ──")
	local vps_servers = {}
	if VPS_DNS and VPS_DNS ~= "" then
		for w in string.gmatch(VPS_DNS, "[^|]+") do
			local s_entry = api.trim(w)
			if s_entry ~= "" then
				local dns = api.split(s_entry, ",")
				local s_url = api.trim(dns[1])
				local server_param = "server " .. s_url
				if s_url:find("://", 1, true) then
					if s_url:find("223.5.5.5", 1, true) then
						server_param = "server-https " .. s_url .. " -host-name dns.alidns.com"
					elseif s_url:find("180.184.1.1", 1, true) or s_url:find("180.184.2.2", 1, true) then
						server_param = "server-https " .. s_url .. " -host-name doh.volcengine.com"
					elseif s_url:find("1.12.12.12", 1, true) or s_url:find("120.53.53.53", 1, true) then
						server_param = "server-https " .. s_url .. " -host-name doh.pub"
					elseif s_url:lower():find("^https://") then
						server_param = "server-https " .. s_url
					elseif s_url:lower():find("^tls://") then
						server_param = "server-tls " .. s_url
					elseif s_url:lower():find("^tcp://") then
						server_param = "server-tcp " .. s_url
					end
				end
				if dns[2] and dns[2] ~= "" then
					server_param = server_param .. " -host-ip " .. api.trim(dns[2]):gsub("^%[(.*)%]$", "%1")
				end
				table.insert(vps_servers, server_param .. " -set-mark 255 -group passwall_vps -exclude-default-group")
			end
		end
	end
	if #vps_servers == 0 then
		table.insert(vps_servers, "server-https https://223.5.5.5/dns-query -host-name dns.alidns.com -set-mark 255 -group passwall_vps -exclude-default-group")
		table.insert(vps_servers, "server-https https://180.184.1.1/dns-query -host-name doh.volcengine.com -set-mark 255 -group passwall_vps -exclude-default-group")
	end
	for _, s_line in ipairs(vps_servers) do
		table.insert(config_lines, s_line)
	end

	table.insert(config_lines, "")
	table.insert(config_lines, "# ── 节点列表专属直连组规则作用域 (passwall_vps) ──")
	table.insert(config_lines, "group-begin passwall_vps -inherit none")
	table.insert(config_lines, "force-qtype-SOA 65")
	local vps_sets = { "#4:" .. setflag .. "psw_vps", "#6:" .. setflag .. "psw_vps6" }
	table.insert(config_lines, string.format("domain-rules /./ -nameserver passwall_vps -speed-check-mode none -d no %s %s", set_type, table.concat(vps_sets, ",")))
	table.insert(config_lines, "group-end")
end

-- 注册自研卓越级智能双轨决策组 (passwall_auto)
local AUTO_GROUP = "passwall_auto"
if USE_DEFAULT_DNS == "auto" and only_global ~= 1 then
	table.insert(config_lines, "")
	table.insert(config_lines, "# ── 智能双轨自适应决策组 (" .. AUTO_GROUP .. ") ──")

	-- 1. 复制/添加国内直连主用服务器，打上 -whitelist-ip 标记
	local local_servers = {}
	if LOCAL_DNS and LOCAL_DNS ~= "" then
		for endpoint in string.gmatch(LOCAL_DNS, "[^, ]+") do
			local s_endpoint = api.trim(endpoint)
			if s_endpoint ~= "" then
				local proto, addr = s_endpoint:match("^(%w+)://(.+)$")
				proto = proto and proto:lower() or "udp"
				addr = addr or s_endpoint
				local host, port = addr:match("^(.-)#(%d+)$")
				if host then
					if host:find(":", 1, true) and not host:find("[", 1, true) then host = "[" .. host .. "]" end
					addr = host .. ":" .. port
				elseif addr:find(":", 1, true) and not addr:find("[", 1, true) and not addr:find(":", addr:find(":") + 1, true) then
					-- ipv4:port or host:port
				elseif addr:find(":", 1, true) and not addr:find("[", 1, true) then
					addr = "[" .. addr .. "]"
				end
				table.insert(local_servers, "server " .. (proto == "tcp" and "tcp://" or "") .. addr)
			end
		end
	end
	if #local_servers == 0 then
		api.uci:foreach("smartdns", "server", function(s)
			if s.enabled ~= "0" and (not LOCAL_GROUP or s.server_group == LOCAL_GROUP) and s.ip and s.ip ~= "" then
				local addr = s.ip
				if not addr:find("://", 1, true) then
					if addr:find(":", 1, true) and not addr:find("[", 1, true) then
						addr = "[" .. addr .. "]"
					end
					if s.port and s.port ~= "" then addr = addr .. ":" .. s.port end
				end
				table.insert(local_servers, "server " .. addr)
			end
		end)
	end
	if #local_servers == 0 then
		table.insert(local_servers, "server 223.5.5.5")
		table.insert(local_servers, "server 119.29.29.29")
	end
	for _, s_param in ipairs(local_servers) do
		table.insert(config_lines, s_param .. " -group " .. AUTO_GROUP .. " -exclude-default-group -whitelist-ip")
	end

	-- 2. 复制远程代理后备服务器，打上 -fallback 标记并强制设置 -speed-check-mode none -d no
	if DNS_MODE == "socks" then
		for w in string.gmatch(REMOTE_DNS, '[^|]+') do
			local dns = api.split(api.trim(w), ",")
			local server_param = "server " .. api.trim(dns[1])
			if dns[2] and dns[2] ~= "" then
				server_param = server_param .. " -host-ip " .. api.trim(dns[2]):gsub("^%[(.*)%]$", "%1")
			end
			if not api.is_local_ip(w) then
				server_param = server_param .. " -proxy " .. proxy_server_name
			end
			if SUBNET and SUBNET ~= "" and SUBNET ~= "0" then
				server_param = server_param .. " -subnet " .. SUBNET
			end
			local auto_param = server_param .. " -group " .. AUTO_GROUP .. " -exclude-default-group -fallback -speed-check-mode none -d no"
			if NO_PROXY_IPV6 == "1" then
				auto_param = auto_param .. " -blacklist-ip"
			end
			table.insert(config_lines, auto_param)
		end
	else
		local auto_param = string.format("server %s -group %s -exclude-default-group -fallback -speed-check-mode none -d no", TUN_DNS:gsub("#", ":"), AUTO_GROUP)
		if NO_PROXY_IPV6 == "1" then
			auto_param = auto_param .. " -blacklist-ip"
		end
		table.insert(config_lines, auto_param)
	end

	-- 3. 进入 passwall_auto 规则组作用域
	table.insert(config_lines, "group-begin " .. AUTO_GROUP .. " -inherit none")
	table.insert(config_lines, tonumber(force_https_soa) == 1 and "force-qtype-SOA 65" or "force-qtype-SOA -,65")

	-- (3.1) GFW Bogus IP 与私网保留网段拦截（直接丢弃伪造结果并秒级触发 fallback）
	local bogus_ips = {
		"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "::/128", "::1/128", "fc00::/7", "fe80::/10",
		-- GFW 常见投毒伪造 IP 签名库
		"24.114.241.77", "37.61.54.158", "46.82.174.68", "59.24.3.173", "64.33.88.161",
		"64.33.99.11", "64.62.105.171", "64.62.107.163", "64.62.110.147", "64.94.110.11",
		"65.104.202.252", "65.160.219.160", "66.33.105.11", "69.63.187.12", "78.16.49.15",
		"93.46.8.89", "128.242.245.116", "159.106.121.75", "188.125.72.69", "188.125.72.70",
		"189.163.17.60", "199.59.148.10", "200.21.225.82", "202.106.1.2", "202.181.7.85",
		"203.98.7.65", "208.56.247.166", "209.145.54.50", "209.220.30.174", "209.36.73.33",
		"211.137.96.205", "211.98.71.195", "213.169.251.35", "216.221.188.182", "216.234.179.13",
		"243.185.187.39"
	}
	for _, bip in ipairs(bogus_ips) do
		table.insert(config_lines, string.format("ip-rules %s -bogus-nxdomain", bip))
	end

	-- (3.2) 大陆 IP 路由白名单判定
	if is_file_nonzero(RULES_PATH .. "/chnroute") then
		table.insert(config_lines, string.format("ip-set -name %s -file %s", AUTO_GROUP .. "-chnroute", RULES_PATH .. "/chnroute"))
		table.insert(config_lines, string.format("ip-rules ip-set:%s -whitelist-ip", AUTO_GROUP .. "-chnroute"))
	end
	if is_file_nonzero(RULES_PATH .. "/chnroute6") then
		table.insert(config_lines, string.format("ip-set -name %s -file %s", AUTO_GROUP .. "-chnroute6", RULES_PATH .. "/chnroute6"))
		local ip6_rule = string.format("ip-rules ip-set:%s -whitelist-ip", AUTO_GROUP .. "-chnroute6")
		if NO_PROXY_IPV6 == "1" then
			ip6_rule = ip6_rule .. " -blacklist-ip"
		end
		table.insert(config_lines, ip6_rule)
	end
	if NO_PROXY_IPV6 == "1" then
		table.insert(config_lines, "ip-rules ::/0 -blacklist-ip")
	end

	table.insert(config_lines, "group-end")
end

local function clean_domain_line(line)
	if not line or line == "" or line:find("#") then return nil end
	if line:find("regexp:") or line:find("ext:") or line:find("rule-set:") or line:find("rs:") then return nil end
	if line:find("domain:") or line:find("full:") then
		line = string.match(line, ":([^:]+)$") or ""
	end
	line = api.get_std_domain(line)
	if line ~= "" and not line:find("#") and not line:find(":") then
		return line
	end
	return nil
end

-- 1. 屏蔽列表文件准备
local file_block_host = CACHE_RULES_PATH .. "/block_host"
if not is_rule_cache_valid(file_block_host, USER_RULES_PATH .. "/block_host") then
	api.remove(file_block_host .. "*")
end
local block_geosite_flag = fs.access(file_block_host) and fs.access(file_block_host .. "_ok") and fs.access(file_block_host .. "_geo")
if USE_BLOCK_LIST == "1" and not fs.access(file_block_host) then
	local block_domain, lookup_block_domain = {}, {}
	local geosite_arg = ""
	local f = io.open(USER_RULES_PATH .. "/block_host")
	if f then
		for line in f:lines() do
			if not line:find("#") and line:find("geosite:") then
				line = string.match(line, ":([^:]+)$")
				if line then geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line end
			else
				local d = clean_domain_line(line)
				if d then insert_unique(block_domain, d, lookup_block_domain) end
			end
		end
		f:close()
	end
	if #block_domain > 0 then
		local f_out = io.open(file_block_host, "w")
		for i = 1, #block_domain do
			f_out:write(block_domain[i] .. "\n")
		end
		f_out:close()
	end
	local success = true
	if USE_GEOVIEW == "1" and geosite_arg ~= "" then
		local code, out = get_geosite(geosite_arg, file_block_host)
		if code == 0 then
			log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)完成")
			sys.call("touch " .. file_block_host .. "_geo")
		else
			log("  - 解析[屏蔽列表] Geosite 到屏蔽域名表(blocklist)失败！[" .. out .. "]")
			success = false
		end
	end
	if success and fs.access(file_block_host) then
		sys.call("touch " .. file_block_host .. "_ok")
	end
end

-- 2. 节点域名列表文件准备 (vpslist)
local file_vpslist = TMP_PATH .. "/vpslist"
if not is_file_nonzero(file_vpslist) then
	local f_out = io.open(file_vpslist, "w")
	local written_domains = {}
	local function process_address(address)
		address = (address or ""):lower()
		if api.vps_domain_exclude(address) then return end
		if datatypes.hostname(address) and not written_domains[address] then
			f_out:write(address .. "\n")
			written_domains[address] = true
		end
	end
	api.uci_foreach_c("nodes", function(t)
		process_address(t.address)
		process_address(t.download_address)
		local dns, _ = api.get_domain_port_from_url(t.domain_resolver_dns or t.domain_resolver_dns_https or "")
		if dns and dns ~= "" then
			process_address(dns)
		end
	end)
	api.uci_foreach_c("subscribe_list", function(t)
		local url, _ = api.get_domain_port_from_url(t.url or "")
		if url and url ~= "" then
			process_address(url)
		end
	end)
	f_out:close()
end

-- 3. 直连（白名单）列表文件准备
local file_direct_host = CACHE_RULES_PATH .. "/direct_host"
if not is_rule_cache_valid(file_direct_host, USER_RULES_PATH .. "/direct_host") then
	api.remove(file_direct_host .. "*")
end
local direct_geosite_flag = fs.access(file_direct_host) and fs.access(file_direct_host .. "_ok") and fs.access(file_direct_host .. "_geo")
if USE_DIRECT_LIST == "1" and not fs.access(file_direct_host) then
	local direct_domain, lookup_direct_domain = {}, {}
	local geosite_arg = ""
	local f = io.open(USER_RULES_PATH .. "/direct_host")
	if f then
		for line in f:lines() do
			if not line:find("#") and line:find("geosite:") then
				line = string.match(line, ":([^:]+)$")
				if line then geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line end
			else
				local d = clean_domain_line(line)
				if d then insert_unique(direct_domain, d, lookup_direct_domain) end
			end
		end
		f:close()
	end
	if #direct_domain > 0 then
		local f_out = io.open(file_direct_host, "w")
		for i = 1, #direct_domain do
			f_out:write(direct_domain[i] .. "\n")
		end
		f_out:close()
	end
	local success = true
	if USE_GEOVIEW == "1" and geosite_arg ~= "" then
		local code, out = get_geosite(geosite_arg, file_direct_host)
		if code == 0 then
			log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)完成")
			sys.call("touch " .. file_direct_host .. "_geo")
		else
			log("  - 解析[直连列表] Geosite 到域名白名单(whitelist)失败！[" .. out .. "]")
			success = false
		end
	end
	if success and fs.access(file_direct_host) then
		sys.call("touch " .. file_direct_host .. "_ok")
	end
end

-- 4. 代理（黑名单）列表文件准备
local file_proxy_host = CACHE_RULES_PATH .. "/proxy_host"
if not is_rule_cache_valid(file_proxy_host, USER_RULES_PATH .. "/proxy_host") then
	api.remove(file_proxy_host .. "*")
end
local proxy_geosite_flag = fs.access(file_proxy_host) and fs.access(file_proxy_host .. "_ok") and fs.access(file_proxy_host .. "_geo")
if USE_PROXY_LIST == "1" and not fs.access(file_proxy_host) then
	local proxy_domain, lookup_proxy_domain = {}, {}
	local geosite_arg = ""
	local f = io.open(USER_RULES_PATH .. "/proxy_host")
	if f then
		for line in f:lines() do
			if not line:find("#") and line:find("geosite:") then
				line = string.match(line, ":([^:]+)$")
				if line then geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line end
			else
				local d = clean_domain_line(line)
				if d then insert_unique(proxy_domain, d, lookup_proxy_domain) end
			end
		end
		f:close()
	end
	if #proxy_domain > 0 then
		local f_out = io.open(file_proxy_host, "w")
		for i = 1, #proxy_domain do
			f_out:write(proxy_domain[i] .. "\n")
		end
		f_out:close()
	end
	local success = true
	if USE_GEOVIEW == "1" and geosite_arg ~= "" then
		local code, out = get_geosite(geosite_arg, file_proxy_host)
		if code == 0 then
			log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)完成")
			sys.call("touch " .. file_proxy_host .. "_geo")
		else
			log("  - 解析[代理列表] Geosite 到代理域名表(blacklist)失败！[" .. out .. "]")
			success = false
		end
	end
	if success and fs.access(file_proxy_host) then
		sys.call("touch " .. file_proxy_host .. "_ok")
	end
end

-- 5. 分流规则列表文件准备
local only_global = (DEFAULT_PROXY_MODE == "proxy" and CHN_LIST == "0" and USE_GFW_LIST == "0") and 1
local shunt_direct_host, shunt_proxy_host, shunt_black_host
if IS_SHUNT_NODE and not only_global then
	local direct_domain, lookup_direct_domain = {}, {}
	local proxy_domain, lookup_proxy_domain = {}, {}
	local black_domain, lookup_black_domain = {}, {}
	local seen_shunt_domain = {}
	local CACHE_FLAG_PATH = CACHE_RULES_PATH .. "/" .. FLAG
	shunt_direct_host = CACHE_FLAG_PATH .. "/shunt_direct_host"
	shunt_proxy_host = CACHE_FLAG_PATH .. "/shunt_proxy_host"
	shunt_black_host = CACHE_FLAG_PATH .. "/shunt_black_host"
	local geosite_direct_arg, geosite_proxy_arg, geosite_black_arg = "", "", ""
	local SHUNT_LIST = "SPLIT=" .. tostring(SPLIT_SHUNT) .. "\n"

	local t = api.uci_get_c(NODE)
	local default_node_id = t["default_node"] or "_direct"
	api.uci_foreach_c("shunt_rules", function(s)
		local _node_id = t[s[".name"]]
		if _node_id and t["shunt_group"] == s.group then
			if _node_id == "_default" then
				_node_id = default_node_id
			end
			local domain_list = s.domain_list or ""
			local r_doms, r_lookup = {}, {}
			local r_geosite = ""
			for line in string.gmatch(domain_list, "[^\r\n]+") do
				if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("ext:") and not line:find("rule-set:") and not line:find("rs:") then
					if line:find("geosite:") then
						local gl = string.match(line, ":([^:]+)$")
						if gl and gl ~= "" then
							r_geosite = r_geosite .. (r_geosite ~= "" and "," or "") .. gl
							if _node_id == "_direct" then
								geosite_direct_arg = geosite_direct_arg .. (geosite_direct_arg ~= "" and "," or "") .. gl
							elseif _node_id == "_blackhole" then
								geosite_black_arg = geosite_black_arg .. (geosite_black_arg ~= "" and "," or "") .. gl
							else
								geosite_proxy_arg = geosite_proxy_arg .. (geosite_proxy_arg ~= "" and "," or "") .. gl
							end
						end
					else
						local d = clean_domain_line(line)
						if d and not seen_shunt_domain[d] then
							seen_shunt_domain[d] = true
							insert_unique(r_doms, d, r_lookup)
							if _node_id == "_direct" then
								insert_unique(direct_domain, d, lookup_direct_domain)
							elseif _node_id == "_blackhole" then
								insert_unique(black_domain, d, lookup_black_domain)
							else
								insert_unique(proxy_domain, d, lookup_proxy_domain)
							end
						end
					end
				end
			end

			SHUNT_LIST = SHUNT_LIST .. s[".name"] .. ":" .. _node_id .. ":" .. domain_list .. "\n"

			local cfg_group = s.smartdns_group or ""
			local resolved_group = REMOTE_GROUP
			if _node_id == "_blackhole" then
				resolved_group = "blackhole"
			elseif cfg_group == "cn" then
				resolved_group = LOCAL_GROUP or "cn"
			elseif cfg_group == "passwall_proxy" then
				resolved_group = REMOTE_GROUP
			elseif _node_id == "_direct" then
				resolved_group = LOCAL_GROUP or "cn"
			end

			local rdata = {
				name = s[".name"],
				remarks = s.remarks or s[".name"],
				node_id = _node_id,
				host_file = CACHE_FLAG_PATH .. "/shunt_" .. s[".name"] .. "_host",
				group = cfg_group,
				resolved_group = resolved_group,
				serve_expired = s.smartdns_serve_expired or "",
				force_ipv4 = s.smartdns_force_ipv4 or "",
				doms = r_doms,
				geosite = r_geosite
			}
			table.insert(split_rules_list, rdata)
			split_rules_map[s[".name"]] = rdata
			if SPLIT_SHUNT == "1" then
				log(string.format("  - Sing-Box/Xray分流规则(%s)使用分组：%s", rdata.remarks, resolved_group))
			else
				log(string.format("  - Sing-Box/Xray分流规则(%s)使用分组：%s", s.remarks or s[".name"], (_node_id == "_direct" and (LOCAL_GROUP or "默认")) or (_node_id == "_blackhole" and "屏蔽") or (REMOTE_GROUP or "默认")))
			end
		end
	end)

	local MD5_FILE = CACHE_FLAG_PATH .. "/md5.txt"
	local cache_md5 = ""
	local USE_CACHE = true
	if fs.access(MD5_FILE) then
		cache_md5 = fs.readfile(MD5_FILE)
	end
	local new_md5 = api.md5_string(SHUNT_LIST)
	if cache_md5 == "" or new_md5 == "" or cache_md5 ~= new_md5 then
		USE_CACHE = false
	else
		local md5_stat = fs.stat(MD5_FILE)
		local geo_stat = fs.stat(geosite_path)
		if geo_stat and geo_stat.mtime and md5_stat and md5_stat.mtime and geo_stat.mtime > md5_stat.mtime then
			USE_CACHE = false
		elseif SPLIT_SHUNT == "1" then
			for _, rdata in ipairs(split_rules_list) do
				if (#rdata.doms > 0 or (USE_GEOVIEW == "1" and rdata.geosite ~= "")) and not is_file_nonzero(rdata.host_file) then
					USE_CACHE = false
					break
				end
			end
		else
			if ((#direct_domain > 0 or (USE_GEOVIEW == "1" and geosite_direct_arg ~= "")) and not is_file_nonzero(shunt_direct_host))
				or ((#proxy_domain > 0 or (USE_GEOVIEW == "1" and geosite_proxy_arg ~= "")) and not is_file_nonzero(shunt_proxy_host))
				or ((#black_domain > 0 or (USE_GEOVIEW == "1" and geosite_black_arg ~= "")) and not is_file_nonzero(shunt_black_host)) then
				USE_CACHE = false
			end
		end
	end

	if not USE_CACHE then
		api.remove(CACHE_FLAG_PATH)
		sys.call("mkdir -p %s" % CACHE_FLAG_PATH)
		fs.writefile(MD5_FILE, new_md5)
	end

	if SPLIT_SHUNT == "1" then
		for _, rdata in ipairs(split_rules_list) do
			if not is_file_nonzero(rdata.host_file) and #rdata.doms > 0 then
				local fo = io.open(rdata.host_file, "w")
				for i = 1, #rdata.doms do fo:write(rdata.doms[i] .. "\n") end
				fo:close()
			end
		end
	else
		if not is_file_nonzero(shunt_direct_host) and #direct_domain > 0 then
			local f_out = io.open(shunt_direct_host, "w")
			for i = 1, #direct_domain do f_out:write(direct_domain[i] .. "\n") end
			f_out:close()
		end
		if not is_file_nonzero(shunt_proxy_host) and #proxy_domain > 0 then
			local f_out = io.open(shunt_proxy_host, "w")
			for i = 1, #proxy_domain do f_out:write(proxy_domain[i] .. "\n") end
			f_out:close()
		end
		if not is_file_nonzero(shunt_black_host) and #black_domain > 0 then
			local f_out = io.open(shunt_black_host, "w")
			for i = 1, #black_domain do f_out:write(black_domain[i] .. "\n") end
			f_out:close()
		end
	end

	if not USE_CACHE and USE_GEOVIEW == "1" then
		local ok = true
		local function resolve(arg, dest)
			if arg == "" then return end
			local code, out = get_geosite(arg, dest)
			if code ~= 0 then
				ok = false
				log("  - 解析[分流节点] Geosite 失败！[" .. out .. "]")
			end
		end
		for _, rdata in ipairs(split_rules_list) do
			if rdata.geosite ~= "" then
				resolve(rdata.geosite, rdata.host_file)
			end
		end
		if ok then
			local claimed = {}
			for k, v in pairs(seen_shunt_domain) do claimed[k] = v end
			if SPLIT_SHUNT == "1" then
				for _, rdata in ipairs(split_rules_list) do
					if is_file_nonzero(rdata.host_file) then
						local kept = {}
						for line in io.lines(rdata.host_file) do
							local d = clean_domain_line(line)
							if d and not claimed[d] then
								claimed[d] = true
								kept[#kept + 1] = d
							end
						end
						local fo = io.open(rdata.host_file, "w")
						if fo then
							for i = 1, #kept do fo:write(kept[i] .. "\n") end
							fo:close()
						end
					end
				end
			else
				local kept_direct, kept_proxy, kept_black = {}, {}, {}
				for _, rdata in ipairs(split_rules_list) do
					local target_kept = (rdata.node_id == "_direct" and kept_direct)
						or (rdata.node_id == "_blackhole" and kept_black)
						or kept_proxy
					if is_file_nonzero(rdata.host_file) then
						for line in io.lines(rdata.host_file) do
							local d = clean_domain_line(line)
							if d and not claimed[d] then
								claimed[d] = true
								target_kept[#target_kept + 1] = d
							end
						end
					end
				end
				local function append_kept(dest, items)
					if #items > 0 then
						local fo = io.open(dest, "a")
						if fo then
							for i = 1, #items do fo:write(items[i] .. "\n") end
							fo:close()
						end
					end
				end
				append_kept(shunt_direct_host, kept_direct)
				append_kept(shunt_proxy_host,  kept_proxy)
				append_kept(shunt_black_host,  kept_black)
			end
		end
		if ok then
			log("  - 解析[分流节点] Geosite 完成")
		else
			api.remove(MD5_FILE)
		end
	end

	if USE_CACHE and USE_GEOVIEW == "1" and (geosite_direct_arg ~= "" or geosite_proxy_arg ~= "" or geosite_black_arg ~= "") then
		log("  - [分流节点] Geosite 使用缓存结果，跳过重复解析")
	end
end

-- ════════════════════════════════════════════════════════════
-- 6. 统一预先注册域名集 (domain-set)
-- 保证所有 rules 查找 domain-set 时均已在内存哈希表中就绪
-- ════════════════════════════════════════════════════════════
table.insert(config_lines, "")
table.insert(config_lines, "# ── 域名集注册 (domain-set) ──")
if USE_BLOCK_LIST == "1" and is_file_nonzero(file_block_host) then
	if block_geosite_flag then
		log("  - [屏蔽列表] Geosite 使用缓存结果，跳过重复解析")
	end
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-block", file_block_host))
end
if is_file_nonzero("/etc/smartdns/domain-block.list") then
	table.insert(config_lines, "domain-set -name psw-smartdns-block -file /etc/smartdns/domain-block.list")
end
if is_file_nonzero(file_vpslist) then
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-vpslist", file_vpslist))
end
if USE_DIRECT_LIST == "1" and is_file_nonzero(file_direct_host) then
	if direct_geosite_flag then
		log("  - [直连列表] Geosite 使用缓存结果，跳过重复解析")
	end
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-directlist", file_direct_host))
end
if CHN_LIST ~= "0" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-chnlist", RULES_PATH .. "/chnlist"))
end
if USE_PROXY_LIST == "1" and is_file_nonzero(file_proxy_host) then
	if proxy_geosite_flag then
		log("  - [代理列表] Geosite 使用缓存结果，跳过重复解析")
	end
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-proxylist", file_proxy_host))
end
if USE_GFW_LIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-gfwlist", RULES_PATH .. "/gfwlist"))
end
if IS_SHUNT_NODE and not only_global then
	if SPLIT_SHUNT == "1" then
		for _, rdata in ipairs(split_rules_list) do
			if is_file_nonzero(rdata.host_file) then
				table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-shunt-" .. rdata.name, rdata.host_file))
			end
		end
	else
		if is_file_nonzero(shunt_direct_host) then
			table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-shunt-direct", shunt_direct_host))
		end
		if is_file_nonzero(shunt_proxy_host) then
			table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-shunt-proxy", shunt_proxy_host))
		end
		if is_file_nonzero(shunt_black_host) then
			table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-shunt-black", shunt_black_host))
		end
	end
end

-- ════════════════════════════════════════════════════════════
-- 7. PassWall 专属端口沙盒规则组 (group-begin passwall ... group-end)
-- 仅对 LISTEN_PORT (15355) 生效，完全隔离主 SmartDNS (6053) 默认组与 15354 (cn) 端口
-- ════════════════════════════════════════════════════════════
table.insert(config_lines, "")
table.insert(config_lines, "# ── PassWall 端口级独立规则组沙盒: " .. SANDBOX_GROUP .. " ──")
table.insert(config_lines, "group-begin " .. SANDBOX_GROUP .. " -inherit none")

-- 动态将智能双轨/fallback解析出的境外 IP 注入PassWall代理路由集
if USE_DEFAULT_DNS == "auto" and only_global ~= 1 then
	if NFTFLAG == "1" then
		local auto_sets = { "#4:" .. setflag .. "psw_gfw" }
		if NO_PROXY_IPV6 ~= "1" then
			table.insert(auto_sets, "#6:" .. setflag .. "psw_gfw6")
		end
		table.insert(config_lines, "nftset-no-speed " .. table.concat(auto_sets, ","))
	else
		local auto_sets = { "#4:psw_gfw" }
		if NO_PROXY_IPV6 ~= "1" then
			table.insert(auto_sets, "#6:psw_gfw6")
		end
		table.insert(config_lines, "ipset-no-speed " .. table.concat(auto_sets, ","))
	end
end

-- (7.1) 默认托底 DNS (最先声明，优先级最低)
local DEFAULT_DNS_GROUP = (USE_DEFAULT_DNS == "remote" and REMOTE_GROUP) or (USE_DEFAULT_DNS == "auto" and AUTO_GROUP) or LOCAL_GROUP
if only_global == 1 then
	DEFAULT_DNS_GROUP = REMOTE_GROUP
end
if DEFAULT_DNS_GROUP then
	local domain_rules_str = "domain-rules /./ -nameserver " .. DEFAULT_DNS_GROUP
	if DEFAULT_DNS_GROUP == REMOTE_GROUP then
		domain_rules_str = domain_rules_str .. " -speed-check-mode none -d no" .. get_remote_rule_extra()
		domain_rules_str = domain_rules_str .. ((not (only_global and IS_SHUNT_NODE) and NO_PROXY_IPV6 == "1") and " -address #6" or "")
	elseif DEFAULT_DNS_GROUP == AUTO_GROUP then
		domain_rules_str = domain_rules_str .. " -speed-check-mode none -d no" .. get_remote_rule_extra()
		if NO_PROXY_IPV6 == "1" then
			domain_rules_str = domain_rules_str .. " -address #6"
		end
	elseif DEFAULT_DNS_GROUP == LOCAL_GROUP then
		domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	end
	table.insert(config_lines, domain_rules_str)
	log(string.format("  - 默认 DNS 分组：%s", DEFAULT_DNS_GROUP == AUTO_GROUP and "智能双轨决策(passwall_auto)" or DEFAULT_DNS_GROUP))
end

-- (7.2) 中国域名表 (chnlist)
if CHN_LIST ~= "0" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	local domain_set_name = "psw-chnlist"
	if CHN_LIST == "direct" then
		local sets = { "#4:" .. setflag .. "psw_chn", "#6:" .. setflag .. "psw_chn6" }
		local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s", domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "", set_type, table.concat(sets, ","))
		domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
		table.insert(config_lines, domain_rules_str)
		log(string.format("  - 中国域名表(chnlist)使用分组：%s", LOCAL_GROUP or "默认"))
	elseif CHN_LIST == "proxy" then
		local sets = { "#4:" .. setflag .. "psw_chn" }
		if NO_PROXY_IPV6 == "1" then
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s -address #6 %s %s", domain_set_name, REMOTE_GROUP, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
		else
			table.insert(sets, "#6:" .. setflag .. "psw_chn6")
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s -d no %s %s", domain_set_name, REMOTE_GROUP, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
		end
		log(string.format("  - 中国域名表(chnlist)使用分组：%s", REMOTE_GROUP or "默认"))
	end
end

-- (7.3) 分流节点规则 (按 UCI 优先级从低到高逆序输出，确保排在前面的分流规则拥有更高覆盖优先级)
if IS_SHUNT_NODE and not only_global then
	local direct_target_sets = (CHN_LIST == "direct")
		and { "#4:" .. setflag .. "psw_chn", "#6:" .. setflag .. "psw_chn6" }
		or  { "#4:" .. setflag .. "psw_white", "#6:" .. setflag .. "psw_white6" }
	local shunt_target_sets = { "#4:" .. setflag .. "psw_shunt", "#6:" .. setflag .. "psw_shunt6" }

	if SPLIT_SHUNT == "1" then
		for i = #split_rules_list, 1, -1 do
			local rdata = split_rules_list[i]
			if is_file_nonzero(rdata.host_file) then
				local domain_set_name = "psw-shunt-" .. rdata.name
				if rdata.resolved_group == "blackhole" then
					table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -a #", domain_set_name))
				elseif rdata.resolved_group == (LOCAL_GROUP or "cn") then
					local sets = (rdata.node_id == "_direct") and direct_target_sets or shunt_target_sets
					local extend = LOCAL_EXTEND_ARG
					if rdata.serve_expired == "1" or rdata.serve_expired == "yes" then
						extend = extend:gsub("%s*%-no%-serve%-expired", "")
					elseif rdata.serve_expired == "0" or rdata.serve_expired == "no" then
						if not extend:find("%-no%-serve%-expired") then
							extend = extend .. " -no-serve-expired"
						end
					end
					if rdata.force_ipv4 == "1" then
						extend = extend:gsub("%s*%-address%s+%S+", "") .. " -address #6"
					elseif rdata.force_ipv4 == "0" then
						extend = extend:gsub("%s*%-address%s+#6", "")
					end
					local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s%s",
						domain_set_name,
						LOCAL_GROUP and ("-nameserver " .. LOCAL_GROUP) or "",
						set_type,
						table.concat(sets, ","),
						extend ~= "" and (" " .. extend) or "")
					table.insert(config_lines, domain_rules_str)
				else
					local expired_rule = ""
					local extra = get_remote_rule_extra()
					if rdata.serve_expired == "1" or rdata.serve_expired == "yes" then
						expired_rule = ""
						extra = extra:gsub("%s*%-no%-serve%-expired", "")
					elseif rdata.serve_expired == "0" or rdata.serve_expired == "no" then
						extra = extra:gsub("%s*%-no%-serve%-expired", "")
						expired_rule = " -no-serve-expired"
					end
					local rule_ipv6
					if rdata.force_ipv4 == "1" then
						rule_ipv6 = " -address #6"
					elseif rdata.force_ipv4 == "0" then
						rule_ipv6 = " -d no"
					else
						rule_ipv6 = (NO_PROXY_IPV6 == "1") and " -address #6" or " -d no"
					end
					table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s%s%s %s %s",
						domain_set_name, REMOTE_GROUP, expired_rule, extra, rule_ipv6, set_type, table.concat(shunt_target_sets, ",")))
				end
			end
		end
	else
		if is_file_nonzero(shunt_proxy_host) then
			local rule_ipv6 = (NO_PROXY_IPV6 == "1") and " -address #6" or " -d no"
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s%s %s %s",
				"psw-shunt-proxy", REMOTE_GROUP, get_remote_rule_extra(), rule_ipv6, set_type, table.concat(shunt_target_sets, ",")))
		end
		if is_file_nonzero(shunt_direct_host) then
			local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s%s",
				"psw-shunt-direct",
				LOCAL_GROUP and ("-nameserver " .. LOCAL_GROUP) or "",
				set_type,
				table.concat(direct_target_sets, ","),
				LOCAL_EXTEND_ARG ~= "" and (" " .. LOCAL_EXTEND_ARG) or "")
			table.insert(config_lines, domain_rules_str)
		end
		if is_file_nonzero(shunt_black_host) then
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -a #", "psw-shunt-black"))
		end
	end
end

-- (7.4) 防火墙域名表 (gfwlist)
if USE_GFW_LIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	local domain_set_name = "psw-gfwlist"
	local sets = { "#4:" .. setflag .. "psw_gfw" }
	if NO_PROXY_IPV6 == "1" then
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s -address #6 %s %s", domain_set_name, REMOTE_GROUP, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	else
		table.insert(sets, "#6:" .. setflag .. "psw_gfw6")
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s -d no %s %s", domain_set_name, REMOTE_GROUP, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	end
	log(string.format("  - 防火墙域名表(gfwlist)使用分组：%s", REMOTE_GROUP or "默认"))
end

-- (7.5) 代理域名表 (blacklist)
if USE_PROXY_LIST == "1" and is_file_nonzero(file_proxy_host) then
	local domain_set_name = "psw-proxylist"
	local sets = { "#4:" .. setflag .. "psw_black" }
	if NO_PROXY_IPV6 == "1" then
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s -address #6 %s %s", domain_set_name, REMOTE_GROUP, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	else
		table.insert(sets, "#6:" .. setflag .. "psw_black6")
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -nameserver %s -speed-check-mode none%s -d no %s %s", domain_set_name, REMOTE_GROUP, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	end
	log(string.format("  - 代理域名表(blacklist)使用分组：%s", REMOTE_GROUP or "默认"))
end

-- (7.6) 域名白名单 (whitelist)
if USE_DIRECT_LIST == "1" and is_file_nonzero(file_direct_host) then
	local sets = { "#4:" .. setflag .. "psw_white", "#6:" .. setflag .. "psw_white6" }
	local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s", "psw-directlist", LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "", set_type, table.concat(sets, ","))
	domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	table.insert(config_lines, domain_rules_str)
	log(string.format("  - 域名白名单(whitelist)使用分组：%s", LOCAL_GROUP or "默认"))
end

-- (7.7) 屏蔽列表 (blocklist)
if USE_BLOCK_LIST == "1" and is_file_nonzero(file_block_host) then
	table.insert(config_lines, "domain-rules /domain-set:psw-block/ -a #")
end
if is_file_nonzero("/etc/smartdns/domain-block.list") then
	table.insert(config_lines, "domain-rules /domain-set:psw-smartdns-block/ -a #")
end

-- (7.8) 节点域名列表 (vpslist - 最高优先级免代理保护)
if is_file_nonzero(file_vpslist) then
	local target_group = VPS_GROUP or LOCAL_GROUP
	local sets = { "#4:" .. setflag .. "psw_vps", "#6:" .. setflag .. "psw_vps6" }
	local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s", "psw-vpslist", target_group and "-nameserver " .. target_group or "", set_type, table.concat(sets, ","))
	if target_group == "passwall_vps" then
		domain_rules_str = domain_rules_str .. " -speed-check-mode none -d no"
	elseif LOCAL_EXTEND_ARG ~= "" then
		domain_rules_str = domain_rules_str .. " " .. LOCAL_EXTEND_ARG
	end
	table.insert(config_lines, domain_rules_str)
	log(string.format("  - 节点列表中的域名(vpslist)使用分组：%s", target_group or "默认"))
end

-- 用户自定义扩展配置插槽
if is_file_nonzero("/etc/passwall/smartdns-user.conf") then
	table.insert(config_lines, "conf-file /etc/passwall/smartdns-user.conf")
end

table.insert(config_lines, "group-end")

if #config_lines > 0 then
	local f_out = io.open(TMP_CONF_FILE, "w")
	for i = 1, #config_lines do
		local line = config_lines[i]
		if line ~= "" then
			f_out:write(line .. "\n")
		end
	end
	f_out:close()
end

	if SMARTDNS_CONF and SMARTDNS_CONF ~= "" and SMARTDNS_CONF ~= TMP_CONF_FILE then
		api.remove(SMARTDNS_CONF)
		fs.symlink(TMP_CONF_FILE, SMARTDNS_CONF)
	end
	if DNS_REDIRECT then
		log("  - SmartDNS 已作为系统 DNS 重定向直接承载！")
	else
		log("  - SmartDNS 已作为上游启动！")
	end
