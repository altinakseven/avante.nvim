local fn = vim.fn
local Utils = require("avante.utils")
local Path = require("plenary.path")
local Scan = require("plenary.scandir")
local Config = require("avante.config")

---@class avante.Path
---@field history_path Path
---@field cache_path Path
local P = {}

---@param bufnr integer | nil
---@return string dirname
local function generate_project_dirname_in_storage(bufnr)
  local project_root = Utils.root.get({
    buf = bufnr,
  })
  -- Replace path separators with double underscores
  local path_with_separators = string.gsub(project_root, "/", "__")
  -- Replace other non-alphanumeric characters with single underscores
  local dirname = string.gsub(path_with_separators, "[^A-Za-z0-9._]", "_")
  return tostring(Path:new("projects"):joinpath(dirname))
end

local function filepath_to_filename(filepath) return tostring(filepath):sub(tostring(filepath:parent()):len() + 2) end

-- History path
local History = {}

function History.get_history_dir(bufnr)
  local dirname = generate_project_dirname_in_storage(bufnr)
  local history_dir = Path:new(Config.history.storage_path):joinpath(dirname):joinpath("history")
  if not history_dir:exists() then history_dir:mkdir({ parents = true }) end
  return history_dir
end

---@return avante.ChatHistory[]
function History.list(bufnr)
  local history_dir = History.get_history_dir(bufnr)
  local files = vim.fn.glob(tostring(history_dir:joinpath("*.json")), true, true)
  local latest_filename = History.get_latest_filename(bufnr, false)
  local res = {}
  for _, filename in ipairs(files) do
    if not filename:match("metadata.json") then
      local filepath = Path:new(filename)
      local content = filepath:read()
      local history = vim.json.decode(content)
      history.filename = filepath_to_filename(filepath)
      table.insert(res, history)
    end
  end
  --- sort by timestamp
  --- sort by latest_filename
  table.sort(res, function(a, b)
    if a.filename == latest_filename then return true end
    if b.filename == latest_filename then return false end
    local a_messages = Utils.get_history_messages(a)
    local b_messages = Utils.get_history_messages(b)
    local timestamp_a = #a_messages > 0 and a_messages[#a_messages].timestamp or a.timestamp
    local timestamp_b = #b_messages > 0 and b_messages[#b_messages].timestamp or b.timestamp
    return timestamp_a > timestamp_b
  end)
  return res
end

-- Get a chat history file name given a buffer
---@param bufnr integer
---@param new boolean
---@return Path
function History.get_latest_filepath(bufnr, new)
  local history_dir = History.get_history_dir(bufnr)
  local filename = History.get_latest_filename(bufnr, new)
  return history_dir:joinpath(filename)
end

function History.get_filepath(bufnr, filename)
  local history_dir = History.get_history_dir(bufnr)
  return history_dir:joinpath(filename)
end

function History.get_metadata_filepath(bufnr)
  local history_dir = History.get_history_dir(bufnr)
  return history_dir:joinpath("metadata.json")
end

function History.get_latest_filename(bufnr, new)
  local history_dir = History.get_history_dir(bufnr)
  local filename
  
  -- First try to get the filename from metadata
  local metadata_filepath = History.get_metadata_filepath(bufnr)
  if metadata_filepath:exists() and not new then
    local ok, metadata_content = pcall(function() return metadata_filepath:read() end)
    if ok and metadata_content then
      local ok2, metadata = pcall(vim.json.decode, metadata_content)
      if ok2 and metadata and metadata.latest_filename then
        filename = metadata.latest_filename
        Utils.debug("Found latest filename in metadata: " .. filename)
      end
    end
  end
  
  -- If we couldn't get the filename from metadata, try to find the latest file
  if not filename or filename == "" then
    local pattern = tostring(history_dir:joinpath("*.json"))
    local files = vim.fn.glob(pattern, true, true)
    
    -- Filter out metadata.json
    files = vim.tbl_filter(function(file)
      return not file:match("metadata%.json$")
    end, files)
    
    if #files > 0 and not new then
      -- Sort files by modification time to find the most recent one
      table.sort(files, function(a, b)
        return vim.fn.getftime(a) > vim.fn.getftime(b)
      end)
      
      -- Get the filename without the path
      filename = vim.fn.fnamemodify(files[1], ":t")
      Utils.debug("Found latest filename by modification time: " .. filename)
    else
      -- If no files exist or we're creating a new one
      filename = #files .. ".json"
      Utils.debug("Creating new filename: " .. filename)
    end
  end
  
  return filename
end

function History.save_latest_filename(bufnr, filename)
  local metadata_filepath = History.get_metadata_filepath(bufnr)
  local metadata
  if not metadata_filepath:exists() then
    metadata = {}
  else
    local metadata_content = metadata_filepath:read()
    metadata = vim.json.decode(metadata_content)
  end
  metadata.latest_filename = filename
  metadata_filepath:write(vim.json.encode(metadata), "w")
end

---@param bufnr integer
function History.new(bufnr)
  local filepath = History.get_latest_filepath(bufnr, true)
  ---@type avante.ChatHistory
  local history = {
    title = "untitled",
    timestamp = Utils.get_timestamp(),
    messages = {},
    filename = filepath_to_filename(filepath),
  }
  return history
end

-- Loads the chat history for the given buffer.
---@param bufnr integer
---@param filename string?
---@return avante.ChatHistory
function History.load(bufnr, filename)
  local history_filepath = filename and History.get_filepath(bufnr, filename)
    or History.get_latest_filepath(bufnr, false)
  
  -- Debug output to help diagnose issues
  Utils.debug("Loading history from: " .. tostring(history_filepath))
  
  if history_filepath:exists() then
    local ok, content = pcall(function() return history_filepath:read() end)
    
    if ok and content ~= nil then
      -- Try to decode the JSON content
      local ok2, history = pcall(vim.json.decode, content)
      
      if ok2 and history then
        history.filename = filepath_to_filename(history_filepath)
        Utils.debug("Successfully loaded history: " .. history.filename)
        return history
      else
        Utils.warn("Failed to decode history file: " .. tostring(history_filepath))
      end
    else
      Utils.warn("Failed to read history file: " .. tostring(history_filepath))
    end
  else
    Utils.debug("History file does not exist: " .. tostring(history_filepath))
  end
  
  -- If we couldn't load the history, create a new one
  Utils.debug("Creating new history")
  return History.new(bufnr)
end

-- Saves the chat history for the given buffer.
---@param bufnr integer
---@param history avante.ChatHistory
History.save = function(bufnr, history)
  local history_filepath = History.get_filepath(bufnr, history.filename)
  history_filepath:write(vim.json.encode(history), "w")
  History.save_latest_filename(bufnr, history.filename)
end

P.history = History

-- Prompt path
local Prompt = {}

-- Given a mode, return the file name for the custom prompt.
---@param mode AvanteLlmMode
---@return string
function Prompt.get_custom_prompts_filepath(mode) return string.format("custom.%s.avanterules", mode) end

function Prompt.get_builtin_prompts_filepath(mode) return string.format("%s.avanterules", mode) end

---@class AvanteTemplates
---@field initialize fun(directory: string): nil
---@field render fun(template: string, context: AvanteTemplateOptions): string
local _templates_lib = nil

Prompt.custom_modes = {
  agentic = true,
  legacy = true,
  editing = true,
  suggesting = true,
}

Prompt.custom_prompts_contents = {}

---@param project_root string
---@return string templates_dir
function Prompt.get_templates_dir(project_root)
  if not P.available() then error("Make sure to build avante (missing avante_templates)", 2) end

  -- get root directory of given bufnr
  local directory = Path:new(project_root)
  if Utils.get_os_name() == "windows" then directory = Path:new(directory:absolute():gsub("^%a:", "")[1]) end
  ---@cast directory Path
  ---@type Path
  local cache_prompt_dir = P.cache_path:joinpath(directory)
  if not cache_prompt_dir:exists() then cache_prompt_dir:mkdir({ parents = true }) end

  -- Add safety checks for scanner
  local scanner = {}
  local ok, result = pcall(function()
    return Scan.scan_dir(directory:absolute(), { depth = 1, add_dirs = true })
  end)
  
  if ok and result then
    scanner = result
  else
    Utils.warn("Failed to scan directory: " .. tostring(directory:absolute()))
  end

  for _, entry in ipairs(scanner) do
    -- Add safety check for entry
    if type(entry) ~= "string" then
      Utils.warn("Invalid entry in scanner: " .. tostring(entry))
      goto continue
    end
    
    local ok, file = pcall(function() return Path:new(entry) end)
    if not ok or not file then
      Utils.warn("Failed to create Path from entry: " .. entry)
      goto continue
    end
    
    local is_file = false
    ok, is_file = pcall(function() return file:is_file() end)
    if not ok then
      Utils.warn("Failed to check if entry is file: " .. entry)
      goto continue
    end
    
    if is_file then
      -- Use a safer split method
      local pieces = {}
      for piece in string.gmatch(entry, "[^/]+") do
        table.insert(pieces, piece)
      end
      
      if #pieces == 0 then
        Utils.warn("No pieces found in entry: " .. entry)
        goto continue
      end
      
      local piece = pieces[#pieces]
      local mode = piece:match("([^.]+)%.avanterules$")
      if not mode or not Prompt.custom_modes[mode] then goto continue end
      if Prompt.custom_prompts_contents[mode] == nil then
        Utils.info(string.format("Using %s as %s system prompt", entry, mode))
        local ok, content = pcall(function() return file:read() end)
        if ok and content then
          Prompt.custom_prompts_contents[mode] = content
        else
          Utils.warn("Failed to read file: " .. entry)
        end
      end
    end
    ::continue::
  end

  -- Get the plugin directory path safely
  local plugin_dir = ""
  local ok, source_info = pcall(function() return debug.getinfo(1).source:match("@?(.*/)")end)
  if ok and source_info then
    plugin_dir = source_info:gsub("/lua/avante/path.lua$", "") .. "/templates"
  else
    Utils.warn("Failed to get plugin directory path")
    plugin_dir = "./templates" -- Fallback
  end
  
  -- Copy templates safely
  ok, _ = pcall(function()
    Path:new(plugin_dir):copy({ destination = cache_prompt_dir, recursive = true })
  end)
  if not ok then
    Utils.warn("Failed to copy templates from " .. plugin_dir .. " to " .. tostring(cache_prompt_dir))
  end

  -- Process custom prompts safely
  vim.iter(Prompt.custom_prompts_contents):filter(function(_, v) return v ~= nil end):each(function(k, v)
    local ok, orig_file = pcall(function() return cache_prompt_dir:joinpath(Prompt.get_builtin_prompts_filepath(k)) end)
    if not ok or not orig_file then
      Utils.warn("Failed to get original file path for mode: " .. k)
      return
    end
    
    local ok2, orig_content = pcall(function() return orig_file:read() end)
    if not ok2 or not orig_content then
      Utils.warn("Failed to read original file for mode: " .. k)
      return
    end
    
    local ok3, f = pcall(function() return cache_prompt_dir:joinpath(Prompt.get_custom_prompts_filepath(k)) end)
    if not ok3 or not f then
      Utils.warn("Failed to get custom file path for mode: " .. k)
      return
    end
    
    pcall(function()
      f:write(orig_content, "w")
      f:write("{% block custom_prompt -%}\n", "a")
      f:write(v, "a")
      f:write("\n{%- endblock %}", "a")
    end)
  end)

  local dir = cache_prompt_dir:absolute()
  return dir
end

---@param mode AvanteLlmMode
---@return string
function Prompt.get_filepath(mode)
  if Prompt.custom_prompts_contents[mode] ~= nil then return Prompt.get_custom_prompts_filepath(mode) end
  return Prompt.get_builtin_prompts_filepath(mode)
end

---@param path string
---@param opts AvanteTemplateOptions
function Prompt.render_file(path, opts) return _templates_lib.render(path, opts) end

---@param mode AvanteLlmMode
---@param opts AvanteTemplateOptions
function Prompt.render_mode(mode, opts)
  local filepath = Prompt.get_filepath(mode)
  return _templates_lib.render(filepath, opts)
end

function Prompt.initialize(directory) 
  if not directory or type(directory) ~= "string" then
    Utils.error("Invalid directory provided to initialize: " .. tostring(directory))
    error("Invalid directory provided to initialize", 2)
  end
  _templates_lib.initialize(directory) 
end

P.prompts = Prompt

local RepoMap = {}

-- Get a chat history file name given a buffer
---@param project_root string
---@param ext string
---@return string
function RepoMap.filename(project_root, ext)
  -- Replace path separators with double underscores
  local path_with_separators = fn.substitute(project_root, "/", "__", "g")
  -- Replace other non-alphanumeric characters with single underscores
  return fn.substitute(path_with_separators, "[^A-Za-z0-9._]", "_", "g") .. "." .. ext .. ".repo_map.json"
end

function RepoMap.get(project_root, ext) return Path:new(P.data_path):joinpath(RepoMap.filename(project_root, ext)) end

function RepoMap.save(project_root, ext, data)
  local file = RepoMap.get(project_root, ext)
  file:write(vim.json.encode(data), "w")
end

function RepoMap.load(project_root, ext)
  local file = RepoMap.get(project_root, ext)
  if file:exists() then
    local content = file:read()
    return content ~= nil and vim.json.decode(content) or {}
  end
  return nil
end

P.repo_map = RepoMap

---@return AvanteTemplates|nil
function P._init_templates_lib()
  if _templates_lib ~= nil then return _templates_lib end
  local ok, module = pcall(require, "avante_templates")
  ---@cast module AvanteTemplates
  ---@cast ok boolean
  if not ok then return nil end
  _templates_lib = module

  return _templates_lib
end

function P.setup()
  local history_path = Path:new(Config.history.storage_path)
  if not history_path:exists() then history_path:mkdir({ parents = true }) end
  P.history_path = history_path

  local cache_path = Path:new(vim.fn.stdpath("cache") .. "/avante")
  if not cache_path:exists() then cache_path:mkdir({ parents = true }) end
  P.cache_path = cache_path

  local data_path = Path:new(vim.fn.stdpath("data") .. "/avante")
  if not data_path:exists() then data_path:mkdir({ parents = true }) end
  P.data_path = data_path

  vim.defer_fn(P._init_templates_lib, 1000)
end

function P.available() return P._init_templates_lib() ~= nil end

function P.clear()
  P.cache_path:rm({ recursive = true })
  P.history_path:rm({ recursive = true })

  if not P.cache_path:exists() then P.cache_path:mkdir({ parents = true }) end
  if not P.history_path:exists() then P.history_path:mkdir({ parents = true }) end
end

return P
