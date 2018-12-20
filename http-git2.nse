local http = require("http")
local shortport = require("shortport")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Checks for a Git repository found in a website's document root
/.git/<something>) and retrieves as much repo information as
possible, including language/framework, remotes, last commit
message, and repository description.
]]

---
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-git:
-- |   127.0.0.1:80/.git/
-- |     Git repository found!
-- |     .git/config matched patterns 'passw'
-- |     Repository description: Unnamed repository; edit this file 'description' to name the...
-- |     Remotes:
-- |       http://github.com/someuser/somerepo
-- |     Project type: Ruby on Rails web application (guessed from .git/info/exclude)
-- |   127.0.0.1:80/damagedrepository/.git/
-- |_    Potential Git repository found (found 2/6 expected files)
--
-- @args http-git.root URL path to search for a .git directory. Default: /
--
-- @xmloutput
-- <table key="127.0.0.1:80/.git/">
--   <table key="remotes">
--     <elem>http://github.com/anotherperson/anotherepo</elem>
--   </table>
--   <table key="project-type">
--     <table key=".git/info/exclude">
--       <elem>JBoss Java web application</elem>
--       <elem>Java application</elem>
--     </table>
--   </table>
--   <elem key="repository-description">A nice repository</elem>
--   <table key="files-found">
--     <elem key=".git/COMMIT_EDITMSG">false</elem>
--     <elem key=".git/info/exclude">true</elem>
--     <elem key=".git/config">true</elem>
--     <elem key=".git/description">true</elem>
--     <elem key=".gitignore">false</elem>
--   </table>
--   <table key="interesting-matches">
--     <table key=".git/config">
--       <elem>passw</elem>
--     </table>
--   </table>
-- </table>

categories = { "default", "safe", "vuln" }
author = "Alex Weber"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
portrule = shortport.http

-- We consider 200 to mean "okay, file exists and we received its contents".
local STATUS_OK = 200
-- Long strings (like a repository's description) will be truncated to this
-- number of characters in normal output.
local TRUNC_LENGTH = 60

function action(host, port)
  local out

  -- We can accept a single root, or a table of roots to try
  local root_arg = stdnse.get_script_args("http-git.root")
  local roots
  if type(root_arg) == "table" then
    roots = root_arg
  elseif type(root_arg) == "string" or type(root_arg) == "number" then
    roots = { tostring(root_arg) }
  elseif root_arg == nil then -- if we didn't get an argument
    roots = { "/" }
  end

  -- Try each root in succession
  for _, root in ipairs(roots) do
    root = tostring(root)
    root = root or '/'

    -- Put a forward slash on the beginning and end of the root, if none was
    -- provided. We will print this, so the user will know that we've mangled it
    if not string.find(root, "/$") then -- if there is no slash at the end
      root = root .. "/"
    end
    if not string.find(root, "^/") then -- if there is no slash at the beginning
      root = "/" .. root
    end

    -- If we can't get a valid /.git/HEAD, don't even bother continuing
    -- We could try for /.git/, but we will not get a 200 if directory
    -- listings are disallowed.
    local resp = http.get(host, port, root .. ".git/HEAD")
    local sha1_pattern = "^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
    if resp.status == STATUS_OK and ( resp.body:match("^ref: ") or resp.body:match(sha1_pattern) ) then
      out = out or {}
      local replies = {}
      -- This function returns true if we got a 200 OK when
      -- fetching 'filename' from the server
      local function ok(filename)
        return (replies[filename].status == STATUS_OK)
      end
      -- These are files that are small, very common, and don't
      -- require zlib to read
      -- These files are created by creating and using the repository,
      -- or by popular development frameworks.
      local repo = {
        ".gitignore",
        ".git/config",
        ".git/index",
      }

      local pl_requests = {} -- pl_requests = pipelined requests (temp)
      -- Go through all of the filenames and do an HTTP GET
      for _, name in ipairs(repo) do -- for every filename
        http.pipeline_add(root .. name, nil, pl_requests)
      end
      -- Do the requests.
      replies = http.pipeline_go(host, port, pl_requests)
      if replies == nil then
        stdnse.debug1("pipeline_go() error. Aborting.")
        return nil
      end

      for i, reply in ipairs(replies) do
        -- We want this to be indexed by filename, not an integer, so we convert it
        -- We added to the pipeline in the same order as the filenames, so this is safe.
        replies[repo[i]] = reply -- create index by filename
        replies[i] = nil -- delete integer-indexed entry
      end

      -- Mark each file that we tried to get as 'found' (true) or 'not found' (false).
      local location = host.ip .. ":" .. port.number .. root .. ".git/"
      out[location] = {}
      -- A nice shortcut
      local loc = out[location]
      loc["files-found"] = {}
      for name, _ in pairs(replies) do
        loc["files-found"][name] = ok(name)
      end

      -- Look through all the repo files we grabbed and see if we can find anything interesting.

      -- .git/config contains a list of remotes, so we try to extract them.
      if ok(".git/config") then
        local config = replies[".git/config"].body
        local remotes = {}

        -- Try to extract URLs of all remotes.
        for url in string.gmatch(config, "\n%s*url%s*=%s*(%S*/%S*)") do
          table.insert(remotes, url)
        end

        for _, url in ipairs(remotes) do
          loc["remotes"] = loc["remotes"] or {}
          table.insert(loc["remotes"], url)
        end
      end

      loc["index-file"] = ""
      if ok(".git/index") then
        local git_index_filename = tostring(host.targetname) .. "_" .. tostring(host.ip) .. "__git_index"
        file = io.open(git_index_filename, "w")
        file:write(replies[".git/index"].body)
        file:close()

        loc["index-file"] = ".git/index + + + saved into " .. git_index_filename
      else
        loc["index-file"] = ".git/index NOT FOUND. FUCK."
      end
    end
  end

  -- If we didn't get anything, we return early. No point doing the
  -- normal formatting!
  if out == nil then
    return nil
  end

  -- Truncate to TRUNC_LENGTH characters and replace control characters (newlines, etc) with spaces.
  local function summarize(str)
    str = stdnse.string_or_blank(str, "<unknown>")
    local original_length = #str
    str = string.sub(str, 1, TRUNC_LENGTH)
    str = string.gsub(str, "%c", " ")
    if original_length > TRUNC_LENGTH then
      str = str .. "..."
    end
    return str
  end

  -- We convert the full output to pretty output for -oN
  local normalout
  for location, info in pairs(out) do
    normalout = normalout or {}
    -- This table gets converted to a string format_output, and then inserted into the 'normalout' table
    local new = {}
    -- Headings for each place we found a repo
    new["name"] = location

    -- How sure are we that this is a Git repository?
    local count = { tried = 0, ok = 0 }
    for _, found in pairs(info["files-found"]) do
      count.tried = count.tried + 1
      if found then count.ok = count.ok + 1 end
    end

    -- If 3 or more of the files we were looking for are not on the server,
    -- we are less confident that we got a real Git repository
    if count.tried - count.ok <= 2 then
      table.insert(new, "Git repository found!")
    else                                                          -- We already got .git/HEAD, so we add 1 to 'tried' and 'ok'
      table.insert(new, "Potential Git repository found (found " .. (count.ok + 1) .. "/" .. (count.tried + 1) .. " expected files)")
    end

    -- Show what patterns matched what files
    for name, matches in pairs(info["interesting-matches"] or {}) do
      table.insert(new, ("%s matched patterns '%s'"):format(name, table.concat(matches, "' '")))
    end

    if info["repository-description"] then
      table.insert(new, "Repository description: " .. summarize(info["repository-description"]))
    end

    if info["last-commit-message"] then
      table.insert(new, "Last commit message: " .. summarize(info["last-commit-message"]))
    end

    -- If we found any remotes in .git/config, process them now
    if info["remotes"] then
      local old_name = info["remotes"]["name"]  -- in case 'name' is a remote
      info["remotes"]["name"] = "Remotes:"
      -- Remove the newline from format_output's output - it looks funny with it
      local temp = string.gsub(stdnse.format_output(true, info["remotes"]), "^\n", "")
      -- using 'temp' here because gsub() has multiple return values that insert() will try
      -- to use, and I don't know of a better way to prevent that ;)
      table.insert(new, temp)
      info["remotes"]["name"] = old_name
    end

    -- Take the first guessed project type from each ignorefile
    if info["project-type"] then
      for name, types in pairs(info["project-type"]) do
        table.insert(new, "Project type: " .. types[1] .. " (guessed from " .. name .. ")")
      end
    end
    table.insert(new, "")
    table.insert(new, info["index-file"])
    -- Insert this location's information.
    table.insert(normalout, new)
  end

  return out, stdnse.format_output(true, normalout)
end
