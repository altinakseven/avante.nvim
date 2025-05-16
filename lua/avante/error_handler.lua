local api = vim.api
local Utils = require("avante.utils")
local HistoryMessage = require("avante.history_message")

---@class avante.ErrorHandler
local M = {}

-- Store the original error handler
M.original_error_handler = nil

-- Track if we're currently handling an error to prevent recursion
M.handling_error = false

-- Store errors that have been handled
M.handled_errors = {}

-- Initialize the error handler
function M.setup()
  -- Store the original error handler
  M.original_error_handler = vim.lsp.handlers["window/showMessage"]

  -- Override the LSP error handler
  vim.lsp.handlers["window/showMessage"] = function(_, result, ctx, config)
    -- Call the original handler first
    if M.original_error_handler then
      M.original_error_handler(_, result, ctx, config)
    end

    -- Only handle errors
    if result.type ~= vim.lsp.protocol.MessageType.Error then
      return
    end

    -- Add to context for AI agent
    M.add_error_to_context(result.message, "lsp")
  end

  -- Set up a global error handler
  vim.schedule(function()
    local old_error = vim.notify_once
    vim.notify_once = function(msg, level, opts)
      if level == vim.log.levels.ERROR then
        M.add_error_to_context(msg, "vim")
      end
      return old_error(msg, level, opts)
    end
  end)
end

-- Add an error to the AI agent's context
---@param error_message string The error message
---@param error_type string The type of error (e.g., "lua", "lsp", "vim")
function M.add_error_to_context(error_message, error_type)
  -- Prevent recursion
  if M.handling_error then
    return
  end
  M.handling_error = true

  -- Log the error
  Utils.debug("Error captured: " .. error_type .. " - " .. error_message)

  -- Add to handled errors
  table.insert(M.handled_errors, {
    message = error_message,
    type = error_type,
    timestamp = os.time()
  })

  -- Get the current sidebar
  local avante = require("avante")
  local sidebar = avante.get()
  
  if sidebar then
    -- Create a history message for the error
    local message = HistoryMessage:new({
      role = "system",
      content = "**Error encountered:** " .. error_type .. " error\n```\n" .. error_message .. "\n```\n\nPlease handle this error and continue with the task.",
    }, {
      just_for_display = false,
    })

    -- Add the error message to the history
    pcall(function()
      if sidebar.on_messages_add then
        sidebar.on_messages_add({ message })
      end
    end)
    
    -- Update the UI to show the error
    pcall(function()
      if sidebar.on_chunk then
        sidebar.on_chunk("\n**Error encountered:** " .. error_type .. " error\n```\n" .. error_message .. "\n```\n\nPlease handle this error and continue with the task.")
      end
    end)
  end

  M.handling_error = false
end

-- Wrap a function with error handling
---@param func function The function to wrap
---@return function The wrapped function
function M.wrap(func)
  return function(...)
    local status, result = xpcall(func, function(err)
      -- Get the stack trace
      local traceback = debug.traceback(err, 2)
      
      -- Add to context
      M.add_error_to_context(traceback, "lua")
      
      -- Return the error for the caller
      return traceback
    end, ...)
    
    if not status then
      -- Error already handled by xpcall
      return nil, result
    end
    
    return result
  end
end

-- Get all handled errors
---@return table[] List of handled errors
function M.get_handled_errors()
  return M.handled_errors
end

-- Clear handled errors
function M.clear_handled_errors()
  M.handled_errors = {}
end

return M