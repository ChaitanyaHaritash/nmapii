---
-- Nmap NSE file-checker.nse - Version 1.3
-- Copy script to: /usr/share/nmap/scripts/file-checker.nse
-- Update db: sudo nmap --script-updatedb
-- executing: nmap --script-help file-checker.nse
-- executing: nmap -sS -Pn -p 80 --script file-checker.nse <target or domain>
-- executing: nmap -sS -Pn -p 80 --script file-checker.nse --script-args index=/etc/passwd <target or domain>
-- executing: nmap -sS -Pn -p 80 --script file-checker.nse --script-args "index=/robots.txt,read=true" <target or domain>
---


-- Script Banner Description --
description = [[

Author: r00t-3xp10it
NSE script to check/read contents of the selected file/path in target webserver.
This module will search if 'index' file exists, and if used --script-args read=true
then file-checker.nse script will read/display the contents of the 'index' file.
'default behavior its to search for robots.txt file in webserver'

Some Syntax examples:
nmap -sS -Pn -p 80 --script file-checker.nse <target or domain>
nmap -sS -Pn -p 80 --script file-checker.nse --script-args read=true <target or domain>
nmap -sS -Pn -p 80 --script file-checker.nse --script-args index=/etc/passwd <target or domain>
nmap -sS -Pn -p 80 --script file-checker.nse --script-args "index=/robots.txt,read=true" <target or domain>
nmap -sV -Pn -T4 -iR 400 -p 80,443 --open --reason --script file-checker.nse --script-args read=true -oN robots.log
nmap -sI -Pn -p 80,443 --scan-delay 5 --script file-checker.nse --script-args "index=/etc/passwd,read=true" <zombie>,<target or domain>

]]

---
-- @usage
-- nmap --script-help file-checker.nse
-- nmap -sS -Pn -p 80 --script file-checker.nse <target or domain>
-- nmap -sS -Pn -p 80 --script file-checker.nse --script-args read=true <target or domain>
-- nmap -sS -Pn -p 80 --script file-checker.nse --script-args index=/etc/passwd <target or domain>
-- nmap -sS -Pn -p 80 --script file-checker.nse --script-args "index=/robots.txt,read=true" <target or domain>
-- nmap -sV -Pn -iR 400 -p 80 --open --script file-checker.nse --script-args "index=/etc/passwd,read=true" -oN credentials.log
-- nmap -sI -Pn -p 80,443 --scan-delay 5 --script file-checker.nse --script-args "index=/robots.txt,read=true" <zombie>,<target or domain>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | file-checker:
-- |   index: /robots.txt
-- |   STATUS: 200 OK FOUND
-- |     module author: r00t-3xp10it
-- |
-- | CONTENTS:
-- | User-agent: *
-- | Disallow: /porn/
-- | Disallow: /login/
-- | Disallow: /search/
-- | Disallow: /privacy/
-- | Disallow: /credentials/
-- |_
-- @args file-checker.index the file/path name to search - Default: /robots.txt
-- @args file-checker.read read contents of the 'index' file selected - Default: false
---

author = "r00t-3xp10it"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- DEPENDENCIES (lua nse libraries) --
local shortport = require "shortport"
local stdnse = require ('stdnse')
local http = require "http"


  -- THE RULE SECTION --
  -- Port rule will only execute if port 80/443 tcp http/https its on open state
  portrule = shortport.port_or_service({80, 443}, "http, https", "tcp", "open")
  -- Seach for string stored in variable @args or use the default ones...
  local index = stdnse.get_script_args(SCRIPT_NAME..".index") or "/robots.txt"
  local read = stdnse.get_script_args(SCRIPT_NAME..".read") or "false"


-- THE ACTION SECTION --
action = function(host, port)
-- fake user-agent to send in 'header' :D
-- If you dont want to use this feature then delete < options >
-- from local response (http.get) and 'comment' the next 2 lines... 
local options = {header={}}
options['header']['User-Agent'] = "Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25"
-- read response from target (http.get) 
local response = http.get(host, port, index, options)



-- Check if 'index' exist on target webserver
if (response.status == 200 ) then

  if (read == "true") then
    -- Display return code and index body ...
    return "\n  index: "..index.."\n  STATUS: "..response.status.." OK FOUND\n    module author: r00t-3xp10it\n\nCONTENTS:\n"..response.body.."\n"
  else
    -- Display only return code (default behavior)...
    return "\n  index: "..index.."\n  STATUS: "..response.status.." OK FOUND\n    module author: r00t-3xp10it\n\n"
  end

  -- More Error codes displays (NOT FOUND)...
  elseif (response.status == 400 ) then
    return "\n  index: "..index.."\n  STATUS: "..response.status.." BAD REQUEST\n    module author: r00t-3xp10it\n\n"
  elseif (response.status == 302 ) then
    return "\n  index: "..index.."\n  STATUS: "..response.status.." REDIRECTED\n    module author: r00t-3xp10it\n\n"
  elseif (response.status == 401 ) then
    return "\n  index: "..index.."\n  STATUS: "..response.status.." UNAUTHORIZED\n    module author: r00t-3xp10it\n\n"
  elseif (response.status == 404 ) then
    return "\n  index: "..index.."\n  STATUS: "..response.status.." NOT FOUND\n    module author: r00t-3xp10it\n\n"
  elseif (response.status == 403 ) then
    return "\n  index: "..index.."\n  STATUS: "..response.status.." FORBIDDEN\n    module author: r00t-3xp10it\n\n"
  elseif (response.status == 503 ) then
    return "\n  index: "..index.."\n  STATUS: "..response.status.." UNAVAILABLE\n    module author: r00t-3xp10it\n\n"
  else
    -- undefined error code (NOT FOUND)...
    return "\n  index: "..index.."\n  STATUS: "..response.status.." UNDEFINED ERROR\n    module author: r00t-3xp10it\n\n"
 end
end
