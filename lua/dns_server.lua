local bit = require "bit"
local byte = string.byte
local char = string.char
local lshift = bit.lshift
local rshift = bit.rshift
local concat = table.concat
local insert = table.insert
local char = string.char
local band = bit.band
local sub = string.sub
local gsub = string.gsub
local clear_tb = require "table.clear"
local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string
local re_find = ngx.re.find
local str_lower = string.lower

ffi.cdef[[
int ngx_stream_lua_mmdb_lookup(void *s, char **country_code,
    size_t *country_code_size);

int ngx_stream_lua_get_binary_remote_addr(void *s, char **country_code,
    size_t *country_code_size);
]]

local _M = {}

local TYPE_A      = 1
local TYPE_NS     = 2
local TYPE_CNAME  = 5
local TYPE_SOA    = 6
local TYPE_PTR    = 12
local TYPE_MX     = 15
local TYPE_TXT    = 16
local TYPE_AAAA   = 28
local TYPE_SRV    = 33
local TYPE_SPF    = 99

local labels = {}
local cname_resp_tb = {}
local mx_resp_tb = {}
local txt_resp_tb = {}

local ccbuf = ffi.new("char *[1]")
local sizep = ffi.new("size_t[1]")

local limiter
do
    local limit_req_module = require "resty.limit.req"

    -- local rate = 2000000
    local rate = 20

    -- local burst = 1000
    local burst = 20
    local err
    limiter, err = limit_req_module.new("limit_req_zone", rate, burst)
    if not limiter then
        return error("failed to instantiate a resty.limit.req object: "
                     .. (err or ""))
    end
end

local function get_binary_remote_addr()
    local s = getfenv(0).__ngx_sess
    if not s then
        return error("no session found")
    end

    local rc = C.ngx_stream_lua_get_binary_remote_addr(s, ccbuf, sizep)
    if rc ~= 0 then
        -- ngx.log(ngx.ERR, "error: ", rc)
        return nil
    end

    return ffi_str(ccbuf[0], sizep[0])
end

local function get_country_code()
    local s = getfenv(0).__ngx_sess
    if not s then
        return error("no session found")
    end

    local rc = C.ngx_stream_lua_mmdb_lookup(s, ccbuf, sizep)
    if rc ~= 0 then
        -- ngx.log(ngx.ERR, "error: ", rc)
        return nil
    end

    return ffi_str(ccbuf[0], sizep[0])
end

local function _decode_name(buf, pos)
    clear_tb(labels)

    local nptrs = 0
    local p = pos
    while nptrs < 128 do
        local fst = byte(buf, p)

        if not fst then
            return nil, 'truncated';
        end

        -- print("fst at ", p, ": ", fst)

        if fst == 0 then
            if nptrs == 0 then
                pos = pos + 1
            end
            break
        end

        if band(fst, 0xc0) ~= 0 then
            -- being a pointer
            if nptrs == 0 then
                pos = pos + 2
            end

            nptrs = nptrs + 1

            local snd = byte(buf, p + 1)
            if not snd then
                return nil, 'truncated'
            end

            p = lshift(band(fst, 0x3f), 8) + snd + 1

            -- print("resolving ptr ", p, ": ", byte(buf, p))

        else
            -- being a label
            local label = sub(buf, p + 1, p + fst)
            insert(labels, label)

            -- print("resolved label ", label)

            p = p + fst + 1

            if nptrs == 0 then
                pos = p
            end
        end
    end

    return concat(labels, "."), pos
end

local function send_bad_req(id, sock)
    if not id then
        return
    end

    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    local ok, err = sock:send{
        ident_hi, ident_lo, "\x80\1\0\0\0\0\0\0\0\0",
    }
    if not ok then
        ngx.log(ngx.ERR, "failed to send: ", err)
        return
    end
end

local function _encode_label(label)
    return char(#label) .. label
end

local function _encode_name(name)
    return gsub(name, "([^.]+)%.?", _encode_label) .. '\0'
end

local aws_cname =
    -- _encode_name("openresty-portal-525905983.ap-southeast-1.elb.amazonaws.com")
    _encode_name("openresty-org-635249771.ap-southeast-1.elb.amazonaws.com")

local yf_cnames = {
    ['openresty.org'] = _encode_name("km4x14.openresty.org.yfcdn.net"),
    ['qa.openresty.org'] = _encode_name("amtg9l.openresty.org.yfcdn.net"),
    ['www.openresty.org'] = _encode_name("zjrngg.openresty.org.yfcdn.net"),
    ['opm.openresty.org'] = _encode_name("fydgdu.openresty.org.yfcdn.net"),
    ['con.openresty.org'] = _encode_name("btwyzsojtms.openresty.yfcdn.net"),
}

local openresty_org = _encode_name("openresty.org")

local ns_records
do
    local bits = {}
    local idx = 0
    local ns_servers = {"a.restydns.com", "c.restydns.com"}
    for _, srv in ipairs(ns_servers) do
        local auth_ns = _encode_name(srv)

        local len = #auth_ns
        local len_hi = char(rshift(len, 8))
        local len_lo = char(band(len, 0xff))

        idx = idx + 1
        bits[idx] = openresty_org

        idx = idx + 1
        bits[idx] = "\0\2\0\x01\0\0\2\x58"

        idx = idx + 1
        bits[idx] = len_hi

        idx = idx + 1
        bits[idx] = len_lo

        idx = idx + 1
        bits[idx] = auth_ns
    end

    ns_records = concat(bits)
end

local regdoms = {
	['openresty.org'] = openresty_org,
	['qa.openresty.org'] = openresty_org,
	['www.openresty.org'] = openresty_org,
	['opm.openresty.org'] = openresty_org,
	['con.openresty.org'] = openresty_org,
}

local refused_tb = {}

local function send_refused_ans(id, sock, raw_quest_rr)
    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    refused_tb[1] = ident_hi
    refused_tb[2] = ident_lo
    refused_tb[3] = "\x84\x05\0\1\0\0\0\0\0\0"
    refused_tb[4] = raw_quest_rr

    local bytes, err = sock:send(refused_tb)
    if not bytes then
        ngx.log(ngx.ERR, "failed to send REFUSED packet: ", err)
    end
end

local nxdomain_tb = {}

local function send_nxdomain_ans(id, sock, raw_quest_rr)
    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    nxdomain_tb[1] = ident_hi
    nxdomain_tb[2] = ident_lo
    nxdomain_tb[3] = "\x84\3\0\1\0\0\0\0\0\0"
    nxdomain_tb[4] = raw_quest_rr

    local bytes, err = sock:send(nxdomain_tb)
    if not bytes then
        ngx.log(ngx.ERR, "failed to send NXDOMAIN packet: ", err)
    end
end

local mx_records
do
    local mx_data = {
        {10, "alt4.aspmx.l.google.com"},
        {5, "alt1.aspmx.l.google.com"},
        {5, "alt2.aspmx.l.google.com"},
    }
    local bits = {}
    local idx = 0
    for _, r in ipairs(mx_data) do
        local exchange = _encode_name(r[2])
        local len = #exchange + 2
        local len_hi = char(rshift(len, 8))
        local len_lo = char(band(len, 0xff))

        idx = idx + 1
        bits[idx] = openresty_org

        idx = idx + 1
        bits[idx] = "\0\x0f\0\x01\0\0\x0e\x10"

        idx = idx + 1
        bits[idx] = len_hi

        idx = idx + 1
        bits[idx] = len_lo

        idx = idx + 1
        bits[idx] = "\0"

        idx = idx + 1
        bits[idx] = char(r[1])

        idx = idx + 1
        bits[idx] = exchange
    end
    mx_records = concat(bits)
end

local txt_records
do
    local bits = {}
    local idx = 0

    idx = idx + 1
    bits[idx] = openresty_org

    idx = idx + 1
    bits[idx] = "\0\x10\0\x01\0\0\x0e\x10"

    local data = "v=spf1 a mx ~all"
    local len = #data + 1
    local len_hi = char(rshift(len, 8))
    local len_lo = char(band(len, 0xff))

    idx = idx + 1
    bits[idx] = len_hi

    idx = idx + 1
    bits[idx] = len_lo

    idx = idx + 1
    bits[idx] = char(len - 1)

    idx = idx + 1
    bits[idx] = data

    txt_records = concat(bits)
end

local opm_txt_records
do
    local bits = {}
    local idx = 0

    idx = idx + 1
    bits[idx] = _encode_name("opm.openresty.org")

    idx = idx + 1
    bits[idx] = "\0\x10\0\x01\0\0\x0e\x10"

    local data = "v=spf1 include:mailgun.org ~all"
    local len = #data + 1
    local len_hi = char(rshift(len, 8))
    local len_lo = char(band(len, 0xff))

    idx = idx + 1
    bits[idx] = len_hi

    idx = idx + 1
    bits[idx] = len_lo

    idx = idx + 1
    bits[idx] = char(len - 1)

    idx = idx + 1
    bits[idx] = data

    opm_txt_records = concat(bits)
end

local opm_txt_records2
do
    local bits = {}
    local idx = 0

    idx = idx + 1
    bits[idx] = _encode_name("pic._domainkey.opm.openresty.org")

    idx = idx + 1
    bits[idx] = "\0\x10\0\x01\0\0\x0e\x10"

    local data = "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQe3HDdjNLTyHuQ4WigASF10QjMvEX3/iLz8ogTLRZ9wXlg3gTlUdBeS3bwFxEdOBDhRV1iZVJFXFpGh7F7xceAy8sU/0FJ0jEb9PnkxSPtCiRWIJ+PSBFrzUceYs+1LXhxVVnhxQURc6CMgBFgthFAOwHlK52dAnRPguwYXzuQQIDAQAB"
    local len = #data + 1
    local len_hi = char(rshift(len, 8))
    local len_lo = char(band(len, 0xff))

    idx = idx + 1
    bits[idx] = len_hi

    idx = idx + 1
    bits[idx] = len_lo

    idx = idx + 1
    bits[idx] = char(len - 1)

    idx = idx + 1
    bits[idx] = data

    opm_txt_records2 = concat(bits)
end

local soa_records = {}
do
    local bits = {}
    local idx = 0

    for i, mname in ipairs{"a.restydns.com", "c.restydns.com"} do
        mname = _encode_name(mname)
        local rname = _encode_name("agentzh.gmail.com")

        idx = idx + 1
        bits[idx] = openresty_org

        idx = idx + 1
        bits[idx] = "\0\x06\0\x01\0\0\0\x3c"

        local len = #mname + #rname + 5 * 4
        local len_hi = char(rshift(len, 8))
        local len_lo = char(band(len, 0xff))

        idx = idx + 1
        bits[idx] = len_hi

        idx = idx + 1
        bits[idx] = len_lo

        idx = idx + 1
        bits[idx] = mname

        idx = idx + 1
        bits[idx] = rname

        idx = idx + 1
        bits[idx] = "\x06\x33\xa1\x34"

        idx = idx + 1
        bits[idx] = "\0\0\x03\x84"

        idx = idx + 1
        bits[idx] = "\0\0\x03\x84"

        idx = idx + 1
        bits[idx] = "\0\0\x07\x08"

        idx = idx + 1
        bits[idx] = "\0\0\0\x3c"
    end

    soa_records = concat(bits)
end

local additional_records
do
    local bits = {}
    local idx = 0

    local rows = {
        {"a.restydns.com", "46.51.220.188"},
        {"c.restydns.com", "52.199.132.92"},
    }

    for _, row in ipairs(rows) do
        local name = _encode_name(row[1])

        idx = idx + 1
        bits[idx] = name

        idx = idx + 1
        bits[idx] = "\0\x01\0\x01\0\0\x0e\x10"

        idx = idx + 1
        bits[idx] = "\0\x04"

        local addr = row[2]

        for num in string.gmatch(addr, "%d+") do
            local c = char(tonumber(num))
            idx = idx + 1
            bits[idx] = c
        end
    end

    additional_records = concat(bits)
end

local soa_resp_tb = {}

local function send_soa_ans(id, sock, qname, raw_quest_rr, raw_quest_name)
    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    local regdom = regdoms[qname]
    if not regdom then
        return send_nxdomain_ans(id, sock, raw_quest_rr)
    end

    soa_resp_tb[1] = ident_hi
    soa_resp_tb[2] = ident_lo
    soa_resp_tb[3] = "\x84\0\0\1\0\2\0\2\0\2"
    soa_resp_tb[4] = raw_quest_rr
    soa_resp_tb[5] = soa_records
    soa_resp_tb[6] = ns_records
    soa_resp_tb[7] = additional_records

    local ok, err = sock:send(soa_resp_tb)
    if not ok then
        ngx.log(ngx.ERR, "failed to send: ", err)
        return
    end
end

local function send_txt_ans(id, sock, qname, raw_quest_rr, raw_quest_name)
    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    if qname == "opm.openresty.org" then
        local tb = {
            ident_hi, ident_lo,
            "\x84\0\0\1\0\1\0\2\0\2",
            raw_quest_rr,
            opm_txt_records,
            ns_records,
            additional_records,
        }

        local ok, err = sock:send(tb)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return
        end

        return
    end

    if qname == "pic._domainkey.opm.openresty.org" then
        local tb = {
            ident_hi, ident_lo,
            "\x84\0\0\1\0\1\0\2\0\2",
            raw_quest_rr,
            opm_txt_records2,
            ns_records,
            additional_records,
        }

        local ok, err = sock:send(tb)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return
        end

        return
    end

    if qname ~= "openresty.org" then
        return send_nxdomain_ans(id, sock, raw_quest_rr)
    end

    txt_resp_tb[1] = ident_hi
    txt_resp_tb[2] = ident_lo
    txt_resp_tb[3] = "\x84\0\0\1\0\1\0\2\0\2"
    txt_resp_tb[4] = raw_quest_rr
    txt_resp_tb[5] = txt_records
    txt_resp_tb[6] = ns_records
    txt_resp_tb[7] = additional_records

    local ok, err = sock:send(txt_resp_tb)
    if not ok then
        ngx.log(ngx.ERR, "failed to send: ", err)
        return
    end
end

local function send_mx_ans(id, sock, qname, raw_quest_rr, raw_quest_name,
    country_code)

    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    -- country_code = "CN"

    local regdom = regdoms[qname]
    if not regdom then
        return send_nxdomain_ans(id, sock, raw_quest_rr)
    end

    if qname ~= "openresty.org" then
        return send_nxdomain_ans(id, sock, raw_quest_rr)
    end

    mx_resp_tb[1] = ident_hi
    mx_resp_tb[2] = ident_lo
    mx_resp_tb[3] = "\x84\0\0\1\0\3\0\2\0\2"
    mx_resp_tb[4] = raw_quest_rr
    mx_resp_tb[5] = mx_records
    mx_resp_tb[6] = ns_records
    mx_resp_tb[7] = additional_records

    local ok, err = sock:send(mx_resp_tb)
    if not ok then
        ngx.log(ngx.ERR, "failed to send: ", err)
        return
    end
end

local function send_cname_ans(id, sock, qname, raw_quest_rr, raw_quest_name,
    country_code)

    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    if qname == "email.opm.openresty.org" then
        local cname = _encode_name("mailgun.org")
        local len = #cname

        local len_hi = char(rshift(len, 8))
        local len_lo = char(band(len, 0xff))

        cname_resp_tb[1] = ident_hi
        cname_resp_tb[2] = ident_lo
        cname_resp_tb[3] = "\x84\0\0\1\0\1\0\2\0\2"
        cname_resp_tb[4] = raw_quest_rr
        cname_resp_tb[5] = raw_quest_name
        cname_resp_tb[6] = "\0\x05\0\x01\0\0\x0e\x10"
        cname_resp_tb[7] = len_hi
        cname_resp_tb[8] = len_lo
        cname_resp_tb[9] = cname
        cname_resp_tb[10] = ns_records
        cname_resp_tb[11] = additional_records

        local ok, err = sock:send(cname_resp_tb)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return
        end

        return
    end

    -- country_code = "CN"

    local regdom = regdoms[qname]
    if not regdom then
        return send_nxdomain_ans(id, sock, raw_quest_rr)
    end

    local cname
    if country_code == "CN" then
        cname = yf_cnames[qname]
        if not cname then
            ngx.log(ngx.ERR, "domain name ", qname,
                    " does not have an entry in yf_names")
            return send_nxdomain_ans(id, sock, raw_quest_rr)
        end
    else
        cname = aws_cname
    end

    local len = #cname
    local len_hi = char(rshift(len, 8))
    local len_lo = char(band(len, 0xff))

    cname_resp_tb[1] = ident_hi
    cname_resp_tb[2] = ident_lo
    cname_resp_tb[3] = "\x84\0\0\1\0\1\0\2\0\2"
    cname_resp_tb[4] = raw_quest_rr
    cname_resp_tb[5] = raw_quest_name
    cname_resp_tb[6] = "\0\x05\0\x01\0\0\x0e\x10"
    cname_resp_tb[7] = len_hi
    cname_resp_tb[8] = len_lo
    cname_resp_tb[9] = cname
    cname_resp_tb[10] = ns_records
    cname_resp_tb[11] = additional_records

    local ok, err = sock:send(cname_resp_tb)
    if not ok then
        ngx.log(ngx.ERR, "failed to send: ", err)
        return
    end
end

function _M.go()
    local client_addr = get_binary_remote_addr()
    local delay, err = limiter:incoming(client_addr, true)
    if not delay then
        if err == "rejected" then
            ngx.log(ngx.ERR, "request rejected")
            return
        end
        ngx.log(ngx.ERR, "failed to limit req: ", err)
        return
    end

    if delay >= 0.001 then
        -- local excess = err
        ngx.log(ngx.WARN, "request delayed by ", delay, " sec")
        ngx.sleep(delay)
    end

    local sock, err = ngx.req.udp_socket()
    if not sock then
        ngx.log(ngx.ERR, "failed to get the request socket: ", err)
        return ngx.exit(ngx.ERROR)
    end

    local req, err = sock:receive()
    if not req then
        ngx.log(ngx.ERR, "failed to receive: ", err)
        return ngx.exit(ngx.ERROR)
    end

    local id

    local n = #req
    if n < 12 then
        ngx.log(ngx.ERR, "request truncated")
        return send_bad_req(id, sock)
    end

    local ident_hi = byte(req, 1)
    local ident_lo = byte(req, 2)
    id = lshift(ident_hi, 8) + ident_lo

    -- print("req id: ", id)

    local flags_hi = byte(req, 3)
    local flags_lo = byte(req, 4)
    local flags = lshift(flags_hi, 8) + flags_lo

    if band(flags, 0x8000) == 1 then
        ngx.log(ngx.ERR, "bad QR flag in the DNS request")
        return send_bad_req(id, sock)
    end

    local code = band(flags, 0xf)

    local nqs_hi = byte(req, 5)
    local nqs_lo = byte(req, 6)
    local nqs = lshift(nqs_hi, 8) + nqs_lo

    if nqs ~= 1 then
        ngx.log(ngx.ERR, "bad number of questions: ", nqs)
        return send_bad_req(id, sock)
    end

    local nan_hi = byte(req, 7)
    local nan_lo = byte(req, 8)
    local nan = lshift(nan_hi, 8) + nan_lo

    if nan ~= 0 then
        ngx.log(ngx.ERR, "bad number of answers in the request: ", nan)
        return send_bad_req(id, sock)
    end

    local quest_qname, pos = _decode_name(req, 13)
    if not quest_qname then
        ngx.log(ngx.ERR, "bad question")
        return send_bad_req(id, sock)
    end

    local raw_quest_rr = sub(req, 13, pos + 3)
    local raw_quest_name = sub(req, 13, pos - 1)

    if re_find(quest_qname, "[A-Z]", "jo") then
        quest_qname = str_lower(quest_qname)
    end

    if not re_find(quest_qname, [[openresty\.org$]], "jo") then
        ngx.log(ngx.ERR, "out of zone domain in query: ", quest_qname)
        return send_refused_ans(id, sock, raw_quest_rr)
    end

    -- print("question qname: ", quest_qname)

    local typ_hi = byte(req, pos)
    local typ_lo = byte(req, pos + 1)
    local typ = lshift(typ_hi, 8) + typ_lo

    -- print("type: ", typ)

    if typ == TYPE_MX then
        print("MX req from ", get_country_code(), ", qname ", quest_qname)
        return send_mx_ans(id, sock, quest_qname, raw_quest_rr, raw_quest_name)
    end

    if typ == TYPE_TXT then
        print("TXT req from ", get_country_code(), ", qname ", quest_qname)
        return send_txt_ans(id, sock, quest_qname, raw_quest_rr, raw_quest_name)
    end

    if typ == TYPE_SOA then
        print("SOA req from ", get_country_code(), ", qname ", quest_qname)
        return send_soa_ans(id, sock, quest_qname, raw_quest_rr, raw_quest_name)
    end

    local cc = get_country_code()

    print("type ", typ, " req, country ", cc, ", qname ", quest_qname)

    return send_cname_ans(id, sock, quest_qname, raw_quest_rr, raw_quest_name,
                          cc)
end

return _M
