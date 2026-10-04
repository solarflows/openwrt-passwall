local api = require "luci.passwall.api"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local SMARTDNS_CONF = var["-SMARTDNS_CONF"]
local LOCAL_GROUP = var["-LOCAL_GROUP"]
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
local NO_IP_ALIAS = var["-NO_IP_ALIAS"] or "1"
local CACHE_MODE = var["-CACHE_MODE"] or "default"
local NO_RULE_ADDR = var["-NO_RULE_ADDR"] or "0"
local SPLIT_SHUNT = var["-SPLIT_SHUNT"] or "0"
local SERVE_EXPIRED = var["-SERVE_EXPIRED"] or "1"

local function get_remote_rule_extra()
	local extra = ""
	if SERVE_EXPIRED == "0" then
		extra = extra .. " -no-serve-expired"
	end
	if NO_IP_ALIAS == "1" then
		extra = extra .. " -no-ip-alias"
	end
	if CACHE_MODE == "nocache" then
		extra = extra .. " -no-cache"
	elseif CACHE_MODE == "300" then
		extra = extra .. " -rr-ttl-max 300"
	elseif CACHE_MODE == "60" then
		extra = extra .. " -rr-ttl-max 60"
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
local tmp_lines = {}
local split_rules_map = {}
local USE_GEOVIEW = api.uci_get_c("@global_rules[0]", "enable_geoview")
local IS_SHUNT_NODE = api.uci_get_c(NODE, "protocol") == "_shunt"

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
		if sys.exec('[ -s "%s" ] && echo -n 1' % path) == "1" then
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

local function get_geosite(list_arg, out_path)
	local geosite_path = api.uci_get_c("@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
	geosite_path = geosite_path:match("^(.*)/") .. "/geosite.dat"
	if not is_file_nonzero(geosite_path) then return 1, "File geosite.dat not found" end
	if not list_arg or list_arg == "" then return 1, "Site list cannot be empty" end
	if not out_path or out_path == "" then return 1, "Output path cannot be empty" end
	local bin = api.finded_com("geoview")
	local cmd = string.format("%q -type geosite -append=true -input %q -list %q -output %q -lowmem=true",
		bin, geosite_path, list_arg, out_path)
	return api.exec_call(cmd)
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
		{ key = "response_mode", config_key = "response-mode", prefix = "-response-mode ", default = "first-ping" },
		{ key = "rr_ttl", config_key = "rr-ttl", prefix = "-rr-ttl " },
		{ key = "rr_ttl_min", config_key = "rr-ttl-min", prefix = "-rr-ttl-min " },
		{ key = "rr_ttl_max", config_key = "rr-ttl-max", prefix = "-rr-ttl-max " },
		{
			key = "force_aaaa_soa",
			config_key = "force-qtype-SOA",
			prefix = "-address ",
			get_value = function(custom_config)
				local soa = custom_config["force-qtype-SOA"]
				return ((soa and soa:match("(^|%s)28(%s|$)"))
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
			line = line:gsub("^%s+", ""):gsub("%s+$", "")
			if not line:match("^#") and line ~= "" then
				local k, v = line:match("^(%S+)%s+(.*)$")
				if k and v then
					custom_config[k] = v
				end
			end
		end
		f_in:close()
	end
	for _, opt in ipairs(options) do
		local val = custom_config[opt.config_key] or api.uci_get("smartdns", "@smartdns[0]", opt.key) or opt.default
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
	if REMOTE_DNS then
		REMOTE_DNS = REMOTE_DNS:gsub("#", ":")
	end
	sys.call('sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1')
end

local force_https_soa = api.uci_get_c("@global[0]", "force_https_soa") or 0
local proxy_server_name = "psw-proxy-server"

-- 基础绑定与服务配置
config_lines = {
	"# ── PassWall SmartDNS Group Rules Configuration ──",
	tonumber(LISTEN_PORT) ~= 0 and ("bind [::]:" .. LISTEN_PORT .. "@lo" .. (NO_RULE_ADDR == "1" and " -no-rule-addr" or "")) or "",
	(tonumber(LOCAL_PORT) ~= 0 and LOCAL_GROUP) and "bind [::]:" .. LOCAL_PORT .. "@lo -group " ..  LOCAL_GROUP or "",
	tonumber(force_https_soa) == 1 and "force-qtype-SOA 65" or "force-qtype-SOA -,65",
	"server 223.5.5.5 -bootstrap-dns",
	is_file_nonzero("/etc/hosts") and "hosts-file /etc/hosts" or "",
	DNS_MODE == "socks" and string.format("proxy-server socks5://%s -name %s", REMOTE_PROXY_SERVER, proxy_server_name) or ""
}

local setflag = (NFTFLAG == "1") and "inet#passwall#" or ""
local set_type = (NFTFLAG == "1") and "-nftset" or "-ipset"

-- 1. 屏蔽列表文件准备
local file_block_host = CACHE_RULES_PATH .. "/block_host"
if not fs.access(file_block_host .. "_ok") then
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
				geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
			else
				line = api.get_std_domain(line)
				if line ~= "" and not line:find("#") then
					insert_unique(block_domain, line, lookup_block_domain)
				end
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
	api.uci_foreach_c("nodes", function(node)
		local address = node.address
		if address and not datatypes.ipaddr(address) and not written_domains[address] then
			f_out:write(address .. "\n")
			written_domains[address] = true
		end
	end)
	f_out:close()
end

-- 3. 直连（白名单）列表文件准备
local file_direct_host = CACHE_RULES_PATH .. "/direct_host"
if not fs.access(file_direct_host .. "_ok") then
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
				geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
			else
				line = api.get_std_domain(line)
				if line ~= "" and not line:find("#") then
					insert_unique(direct_domain, line, lookup_direct_domain)
				end
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
if not fs.access(file_proxy_host .. "_ok") then
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
				geosite_arg = geosite_arg .. (geosite_arg ~= "" and "," or "") .. line
			else
				line = api.get_std_domain(line)
				if line ~= "" and not line:find("#") then
					insert_unique(proxy_domain, line, lookup_proxy_domain)
				end
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
	local CACHE_FLAG_PATH = CACHE_RULES_PATH .. "/" .. FLAG
	shunt_direct_host = CACHE_FLAG_PATH .. "/shunt_direct_host"
	shunt_proxy_host = CACHE_FLAG_PATH .. "/shunt_proxy_host"
	shunt_black_host = CACHE_FLAG_PATH .. "/shunt_black_host"
	local geosite_direct_arg, geosite_proxy_arg, geosite_black_arg = "", "", ""
	local SHUNT_LIST = ""

	local t = api.uci_get_c(NODE)
	local default_node_id = t["default_node"] or "_direct"
	api.uci_foreach_c("shunt_rules", function(s)
		local _node_id = t[s[".name"]]
		if _node_id and t["shunt_group"] == s.group then
			if _node_id == "_default" then
				_node_id = default_node_id
			end
			local domain_list = s.domain_list or ""
			for line in string.gmatch(domain_list, "[^\r\n]+") do
				if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("ext:") and not line:find("rule-set:") and not line:find("rs:") then
					if line:find("geosite:") then
						line = string.match(line, ":([^:]+)$")
						if _node_id == "_direct" then
							geosite_direct_arg = geosite_direct_arg .. (geosite_direct_arg ~= "" and "," or "") .. line
						elseif _node_id == "_blackhole" then
							geosite_black_arg = geosite_black_arg .. (geosite_black_arg ~= "" and "," or "") .. line
						else
							geosite_proxy_arg = geosite_proxy_arg .. (geosite_proxy_arg ~= "" and "," or "") .. line
						end
					else
						if line:find("domain:") or line:find("full:") then
							line = string.match(line, ":([^:]+)$")
						end
						line = api.get_std_domain(line)
						if line ~= "" and not line:find("#") then
							if _node_id == "_direct" then
								insert_unique(direct_domain, line, lookup_direct_domain)
							elseif _node_id == "_blackhole" then
								insert_unique(black_domain, line, lookup_black_domain)
							else
								insert_unique(proxy_domain, line, lookup_proxy_domain)
							end
						end
					end
				end
			end
			SHUNT_LIST = SHUNT_LIST .. domain_list .. (_node_id:sub(1, 1) == "_" and "not-node" or "node")
				if SPLIT_SHUNT == "1" then
					split_rules_map[s[".name"]] = {
						name = s[".name"],
						remarks = s.remarks or s[".name"],
						node_id = _node_id,
						host_file = CACHE_FLAG_PATH .. "/shunt_" .. s[".name"] .. "_host",
						group = s.smartdns_group or "",
						serve_expired = s.smartdns_serve_expired or "",
						force_ipv4 = s.smartdns_force_ipv4 or "0"
					}
				end
			log(string.format("  - Sing-Box/Xray分流规则(%s)使用分组：%s", s.remarks, REMOTE_GROUP or "默认"))
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
		api.remove(CACHE_FLAG_PATH)
		sys.call("mkdir -p %s" % CACHE_FLAG_PATH)
		fs.writefile(MD5_FILE, new_md5)
		USE_CACHE = false
	end

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
		resolve(geosite_direct_arg, shunt_direct_host)
		resolve(geosite_proxy_arg,  shunt_proxy_host)
		resolve(geosite_black_arg,  shunt_black_host)
		if SPLIT_SHUNT == "1" and USE_GEOVIEW == "1" and not USE_CACHE then
			api.uci_foreach_c("shunt_rules", function(s)
				local r_geosite = ""
				local dlist = s.domain_list or ""
				for line in string.gmatch(dlist, '[^\\r\\n]+') do
					if line:find("geosite:") then
						local gl = string.match(line, ":([^:]+)$")
						if gl then r_geosite = r_geosite .. (r_geosite ~= "" and "," or "") .. gl end
					end
				end
				local r_file = CACHE_FLAG_PATH .. "/shunt_" .. s[".name"] .. "_host"
				local r_doms, r_lookup = {}, {}
				for line in string.gmatch(dlist, '[^\\r\\n]+') do
					if line ~= "" and not line:find("#") and not line:find("geosite:") and not line:find("regexp:") and not line:find("ext:") and not line:find("rule-set:") and not line:find("rs:") then
						if line:find("domain:") or line:find("full:") then line = string.match(line, ":([^:]+)$") end
						line = api.get_std_domain(line)
						if line ~= "" and not line:find("#") then insert_unique(r_doms, line, r_lookup) end
					end
				end
				if #r_doms > 0 then
					local fo = io.open(r_file, "w")
					for i = 1, #r_doms do fo:write(r_doms[i] .. '\n') end
					fo:close()
				end
				if r_geosite ~= "" then
					resolve(r_geosite, r_file)
				end
			end)
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
-- 保证所有 rules/matches 查找 domain-set 时均已在内存哈希表中就绪
-- ════════════════════════════════════════════════════════════
table.insert(config_lines, "")
table.insert(config_lines, "# ── 域名集注册 (domain-set) ──")
if USE_BLOCK_LIST == "1" and is_file_nonzero(file_block_host) then
	if block_geosite_flag then
		log("  - [屏蔽列表] Geosite 使用缓存结果，跳过重复解析")
	end
	table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-block", file_block_host))
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
		for rname, rdata in pairs(split_rules_map) do
			if is_file_nonzero(rdata.host_file) then
				table.insert(config_lines, string.format("domain-set -name %s -file %s", "psw-shunt-" .. rname, rdata.host_file))
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
-- 7. 国内与直连规则 (默认组)
-- ════════════════════════════════════════════════════════════
table.insert(config_lines, "")
table.insert(config_lines, "# ── 国内与直连规则 (默认组) ──")
if USE_BLOCK_LIST == "1" and is_file_nonzero(file_block_host) then
	table.insert(config_lines, "domain-rules /domain-set:psw-block/ -a #")
end
if is_file_nonzero(file_vpslist) then
	local sets = { "#4:" .. setflag .. "psw_vps" }
	local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s", "psw-vpslist", LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "", set_type, table.concat(sets, ","))
	domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	table.insert(config_lines, domain_rules_str)
	log(string.format("  - 节点列表中的域名(vpslist)使用分组：%s", LOCAL_GROUP or "默认"))
end
if USE_DIRECT_LIST == "1" and is_file_nonzero(file_direct_host) then
	local sets = { "#4:" .. setflag .. "psw_white", "#6:" .. setflag .. "psw_white6" }
	local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s", "psw-directlist", LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "", set_type, table.concat(sets, ","))
	domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	table.insert(config_lines, domain_rules_str)
	log(string.format("  - 域名白名单(whitelist)使用分组：%s", LOCAL_GROUP or "默认"))
end
if CHN_LIST == "direct" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	local sets = { "#4:" .. setflag .. "psw_chn", "#6:" .. setflag .. "psw_chn6" }
	local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s", "psw-chnlist", LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "", set_type, table.concat(sets, ","))
	domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	table.insert(config_lines, domain_rules_str)
	log(string.format("  - 中国域名表(chnlist)使用分组：%s", LOCAL_GROUP or "默认"))
end

if IS_SHUNT_NODE and not only_global and SPLIT_SHUNT == "1" then
	for rname, rdata in pairs(split_rules_map) do
		if rdata.group == "cn" and is_file_nonzero(rdata.host_file) then
			local sets = { "#4:" .. setflag .. "psw_shunt", "#6:" .. setflag .. "psw_shunt6" }
			local domain_rules_str = string.format("domain-rules /domain-set:%s/ %s %s %s -speed-check-mode tcp-syn:443,tcp-syn:80,ping", "psw-shunt-" .. rname, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "-nameserver cn", set_type, table.concat(sets, ","))
			table.insert(config_lines, domain_rules_str)
			log(string.format("  - 分流规则(%s)使用国内高速分组：%s", rdata.remarks, LOCAL_GROUP or "cn"))
		end
	end
end

-- ════════════════════════════════════════════════════════════
-- 8. SmartDNS 现代规则组沙盒 (group-begin ... group-end)
-- ════════════════════════════════════════════════════════════
table.insert(config_lines, "")
table.insert(config_lines, "# ── 代理规则组沙盒: " .. REMOTE_GROUP .. " ──")
table.insert(config_lines, "group-begin " .. REMOTE_GROUP)

-- 组内上游 DNS 服务器注册
if DNS_MODE == "socks" then
	for w in string.gmatch(REMOTE_DNS, '[^|]+') do
		local server_dns = api.trim(w)
		local server_param
		local dnsType = string.match(server_dns, "^(.-)://")
		dnsType = dnsType and string.lower(dnsType) or nil
		local dnsServer = string.match(server_dns, "://(.+)") or server_dns

		if dnsType and dnsType ~= "" and dnsType ~= "udp" then
			if dnsType == "tcp" then
				server_param = "server-tcp " .. dnsServer
			elseif dnsType == "tls" then
				server_param = "server-tls " .. dnsServer
			elseif dnsType == "quic" then
				server_param = "server-quic " .. dnsServer
			elseif dnsType == "https" or dnsType == "h3" then
				local http_host = nil
				local url = w
				local s = api.split(w, ",")
				if s and #s > 1 then
					url = s[1]
					local dns_ip = s[2]
					local host_port = api.get_domain_from_url(s[1])
					if host_port and #host_port > 0 then
						http_host = host_port
						local s2 = api.split(host_port, ":")
						if s2 and #s2 > 1 then http_host = s2[1] end
						url = url:gsub(http_host, dns_ip)
					end
				end
				server_dns = url
				if http_host then server_dns = server_dns .. " -http-host " .. http_host end
				server_param = (dnsType == "https" and "server-https " or "server-h3 ") .. server_dns
			end
		else
			server_param = "server " .. dnsServer
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

-- 组内通用策略配置
table.insert(config_lines, "speed-check-mode none")

-- 规则组路由匹配 (必须位于 group-begin 内部，domain-set 无斜杠)
table.insert(config_lines, "")
table.insert(config_lines, "# 组路由匹配 (group-match)")
if USE_PROXY_LIST == "1" and is_file_nonzero(file_proxy_host) then
	table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-proxylist"))
end
if USE_GFW_LIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-gfwlist"))
end
if CHN_LIST == "proxy" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-chnlist"))
end
if IS_SHUNT_NODE and not only_global then
	if SPLIT_SHUNT == "1" then
		for rname, rdata in pairs(split_rules_map) do
			if rdata.group ~= "cn" and is_file_nonzero(rdata.host_file) then
				table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-shunt-" .. rname))
			end
		end
	else
		if is_file_nonzero(shunt_direct_host) then
			table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-shunt-direct"))
		end
		if is_file_nonzero(shunt_proxy_host) then
			table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-shunt-proxy"))
		end
		if is_file_nonzero(shunt_black_host) then
			table.insert(config_lines, string.format("group-match -domain domain-set:%s", "psw-shunt-black"))
		end
	end
end

-- 组内域名规则与防火墙打标 (在组沙盒内生效)
table.insert(config_lines, "")
table.insert(config_lines, "# 组内域名规则 (domain-rules)")
if USE_PROXY_LIST == "1" and is_file_nonzero(file_proxy_host) then
	local domain_set_name = "psw-proxylist"
	local sets = { "#4:" .. setflag .. "psw_black" }
	if NO_PROXY_IPV6 == "1" then
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none -no-serve-expired%s -address #6 %s %s", domain_set_name, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	else
		table.insert(sets, "#6:" .. setflag .. "psw_black6")
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none -no-serve-expired%s -address -6 -d no %s %s", domain_set_name, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	end
	log(string.format("  - 代理域名表(blacklist)使用分组：%s", REMOTE_GROUP or "默认"))
end

if USE_GFW_LIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	local domain_set_name = "psw-gfwlist"
	local sets = { "#4:" .. setflag .. "psw_gfw" }
	if NO_PROXY_IPV6 == "1" then
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none -no-serve-expired%s -address #6 %s %s", domain_set_name, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	else
		table.insert(sets, "#6:" .. setflag .. "psw_gfw6")
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none -no-serve-expired%s -address -6 -d no %s %s", domain_set_name, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	end
	log(string.format("  - 防火墙域名表(gfwlist)使用分组：%s", REMOTE_GROUP or "默认"))
end

if CHN_LIST == "proxy" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	local domain_set_name = "psw-chnlist"
	local sets = { "#4:" .. setflag .. "psw_chn" }
	if NO_PROXY_IPV6 == "1" then
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none -no-serve-expired%s -address #6 %s %s", domain_set_name, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	else
		table.insert(sets, "#6:" .. setflag .. "psw_chn6")
		table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none -no-serve-expired%s -address -6 -d no %s %s", domain_set_name, get_remote_rule_extra(), set_type, table.concat(sets, ",")))
	end
	log(string.format("  - 中国域名表(chnlist)使用分组：%s", REMOTE_GROUP or "默认"))
end

if IS_SHUNT_NODE and not only_global then
	local sets = { "#4:" .. setflag .. "psw_shunt", "#6:" .. setflag .. "psw_shunt6" }
	local default_ipv6_rule = (NO_PROXY_IPV6 == "1" and " -address #6" or "")
	if SPLIT_SHUNT == "1" then
		for rname, rdata in pairs(split_rules_map) do
			if rdata.group ~= "cn" and is_file_nonzero(rdata.host_file) then
				local domain_set_name = "psw-shunt-" .. rname
				local expired_rule = ""
				local extra = get_remote_rule_extra()
				if rdata.serve_expired == "1" or rdata.serve_expired == "yes" then
					expired_rule = ""
					extra = extra:gsub("%%s*-no-serve-expired", "")
				elseif rdata.serve_expired == "0" or rdata.serve_expired == "no" then
					expired_rule = " -no-serve-expired"
				end
				local rule_ipv6 = (rdata.force_ipv4 == "1" or NO_PROXY_IPV6 == "1") and " -address #6" or ""
				table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none%s%s%s %s %s", domain_set_name, expired_rule, extra, rule_ipv6, set_type, table.concat(sets, ",")))
			end
		end
	else
		if is_file_nonzero(shunt_direct_host) then
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none%s%s %s %s", "psw-shunt-direct", get_remote_rule_extra(), default_ipv6_rule, set_type, table.concat(sets, ",")))
		end
		if is_file_nonzero(shunt_proxy_host) then
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none%s%s %s %s", "psw-shunt-proxy", get_remote_rule_extra(), default_ipv6_rule, set_type, table.concat(sets, ",")))
		end
		if is_file_nonzero(shunt_black_host) then
			table.insert(config_lines, string.format("domain-rules /domain-set:%s/ -speed-check-mode none%s%s %s %s", "psw-shunt-black", get_remote_rule_extra(), default_ipv6_rule, set_type, table.concat(sets, ",")))
		end
	end
end

-- 用户自定义扩展配置插槽
if is_file_nonzero("/etc/passwall/smartdns-user.conf") then
	table.insert(config_lines, "conf-file /etc/passwall/smartdns-user.conf")
end

table.insert(config_lines, "group-end")

-- ════════════════════════════════════════════════════════════
-- 9. 默认托底 DNS
-- ════════════════════════════════════════════════════════════
table.insert(config_lines, "")
table.insert(config_lines, "# ── 默认托底 DNS ──")
local DEFAULT_DNS_GROUP = (USE_DEFAULT_DNS == "direct" and LOCAL_GROUP) or (USE_DEFAULT_DNS == "remote" and REMOTE_GROUP)
if only_global == 1 then
	DEFAULT_DNS_GROUP = REMOTE_GROUP
end
if DEFAULT_DNS_GROUP then
	local domain_rules_str = "domain-rules /./ -nameserver " .. DEFAULT_DNS_GROUP
	if DEFAULT_DNS_GROUP == REMOTE_GROUP then
		domain_rules_str = domain_rules_str .. " -speed-check-mode none -d no -no-serve-expired" .. get_remote_rule_extra()
		domain_rules_str = domain_rules_str .. " -address " .. ((only_global and IS_SHUNT_NODE) and "-6" or (NO_PROXY_IPV6 == "1" and "#6" or "-6"))
	elseif DEFAULT_DNS_GROUP == LOCAL_GROUP then
		domain_rules_str = domain_rules_str .. (LOCAL_EXTEND_ARG ~= "" and " " .. LOCAL_EXTEND_ARG or "")
	end
	table.insert(config_lines, domain_rules_str)
end

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

fs.symlink(TMP_CONF_FILE, SMARTDNS_CONF)
sys.call(string.format('echo "conf-file %s" >> /etc/smartdns/custom.conf', string.gsub(SMARTDNS_CONF, "passwall", "passwall*")))
log("  - SmartDNS (规则组模式) 已作为上游启动！")
