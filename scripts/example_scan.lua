local vs = require('vulnscanner')
local host = arg[1] or '127.0.0.1'
print('Scanning TCP ports 22-25 on', host)
local res = vs.scan_tcp(host, 22, 25, 20, 300)
for i=1,#res do
    local r = res[i]
    print(string.format('TCP Port %d: open=%s note=%s', r.port, tostring(r.open), r.note))
end

print('\nSending UDP probes to ports 53-55')
local u = vs.udp_probe(host, 53, 55)
for i=1,#u do
    local r = u[i]
    print(string.format('UDP Port %d: note=%s', r.port, r.note))
end

-- Example CVE fetch (no API key): will likely return empty unless configured
local cve = 'CVE-2023-4567'
local info = vs.fetch_cve(cve, '')
print('\nCVE info for', cve, 'CVSS=', info.cvss)
if info.description then print('Description:', info.description) end
local cached = vs.get_cvss_cached(cve)
print('Cached CVSS for', cve, '=', cached)
