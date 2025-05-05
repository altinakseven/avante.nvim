local Utils = require("avante.utils")
local P = require("avante.providers")

---@class AvanteBedrockProviderFunctor
local M = {}

M.api_key_name = "BEDROCK_KEYS"

M = setmetatable(M, {
  __index = function(_, k)
    local model_handler = M.load_model_handler()
    return model_handler[k]
  end,
})

function M.load_model_handler()
  local provider_conf, _ = P.parse_config(P["bedrock"])
  local bedrock_model = provider_conf.model
  if provider_conf.model:match("anthropic") then bedrock_model = "claude" end

  local ok, model_module = pcall(require, "avante.providers.bedrock." .. bedrock_model)
  if ok then return model_module end
  local error_msg = "Bedrock model handler not found: " .. bedrock_model
  error(error_msg)
end

function M:parse_messages(prompt_opts)
  local model_handler = M.load_model_handler()
  return model_handler.parse_messages(self, prompt_opts)
end

function M:parse_response(ctx, data_stream, event_state, opts)
  local model_handler = M.load_model_handler()
  return model_handler.parse_response(self, ctx, data_stream, event_state, opts)
end

function M:transform_tool(tool)
  local model_handler = M.load_model_handler()
  return model_handler.transform_tool(self, tool)
end

function M:build_bedrock_payload(prompt_opts, request_body)
  local model_handler = M.load_model_handler()
  return model_handler.build_bedrock_payload(self, prompt_opts, request_body)
end

function M:parse_stream_data(ctx, data, opts)
  -- @NOTE: Decode and process Bedrock response
  -- Each response contains a Base64-encoded `bytes` field, which is decoded into JSON.
  -- The `type` field in the decoded JSON determines how the response is handled.
  local bedrock_match = data:gmatch("event(%b{})")
  for bedrock_data_match in bedrock_match do
    local jsn = vim.json.decode(bedrock_data_match)
    local data_stream = vim.base64.decode(jsn.bytes)
    local json = vim.json.decode(data_stream)
    self:parse_response(ctx, data_stream, json.type, opts)
  end
end

function M:parse_response_without_stream(data, event_state, opts)
  if opts.on_chunk == nil then return end
  local bedrock_match = data:gmatch("exception(%b{})")
  opts.on_chunk("\n**Exception caught**\n\n")
  for bedrock_data_match in bedrock_match do
    local jsn = vim.json.decode(bedrock_data_match)
    opts.on_chunk("- " .. jsn.message .. "\n")
  end
  vim.schedule(function() opts.on_stop({ reason = "complete" }) end)
end

-- Function to execute shell commands and return the output
local function execute_command(command)
  local handle = io.popen(command)
  local result = handle:read("*a")
  handle:close()
  return result:gsub("[\n\r]+$", "") -- Trim trailing newlines
end

-- Function to calculate SHA256 hash using openssl
local function sha256_hash(input)
  -- Create a temporary file for the input
  local temp_file = vim.fn.tempname()
  local file = io.open(temp_file, "w")
  file:write(input)
  file:close()
  
  -- Calculate hash using openssl
  local hash = execute_command("openssl dgst -sha256 -hex < " .. temp_file .. " | sed 's/^.* //'")
  
  -- Remove temporary file
  os.remove(temp_file)
  
  return hash
end

-- Function to calculate HMAC-SHA256 using openssl with string key
local function hmac_sha256_string(key, message)
  -- Escape special characters
  local escaped_key = key:gsub("'", "'\\''")
  local escaped_message = message:gsub("'", "'\\''")
  
  -- Calculate HMAC using openssl
  local command = "echo -n '" .. escaped_message .. "' | openssl dgst -sha256 -mac HMAC -macopt \"key:" .. escaped_key .. "\" | sed 's/^.* //'"
  local hmac = execute_command(command)
  
  return hmac
end

-- Function to calculate HMAC-SHA256 using openssl with hex key
local function hmac_sha256_hex(key, message)
  -- Escape special characters
  local escaped_message = message:gsub("'", "'\\''")
  
  -- Calculate HMAC using openssl
  local command = "echo -n '" .. escaped_message .. "' | openssl dgst -sha256 -mac HMAC -macopt \"hexkey:" .. key .. "\" | sed 's/^.* //'"
  local hmac = execute_command(command)
  
  return hmac
end

-- Function to URL encode a string
local function url_encode(str)
  -- Only encode the colon character as required by AWS
  return str:gsub(":", "%%3A")
end

-- Function to sign AWS API requests using Signature Version 4
-- Following AWS documentation exactly
local function sign_request(method, service, region, host, endpoint, request_body, aws_access_key_id, aws_secret_access_key, additional_headers)
  -- URL encode the endpoint path (just the colon)
  local encoded_endpoint = url_encode(endpoint)
  
  -- Request details
  local algorithm = "AWS4-HMAC-SHA256"
  local amz_date = os.date("!%Y%m%dT%H%M%SZ")
  local date_stamp = os.date("!%Y%m%d")
  
  -- Create canonical request
  local content_type = "application/json"
  local payload_hash = sha256_hash(request_body)
  
  -- Prepare canonical headers - all headers must be sorted alphabetically
  local all_headers = {
    ["content-type"] = content_type,
    ["host"] = host,
    ["x-amz-date"] = amz_date
  }
  
  -- Add additional headers if provided
  if additional_headers then
    for name, value in pairs(additional_headers) do
      all_headers[string.lower(name)] = value
    end
  end
  
  -- Sort headers alphabetically
  local header_names = {}
  for name, _ in pairs(all_headers) do
    table.insert(header_names, name)
  end
  table.sort(header_names)
  
  -- Build canonical headers string and signed headers list
  local canonical_headers = ""
  local signed_headers = ""
  
  for i, name in ipairs(header_names) do
    canonical_headers = canonical_headers .. name .. ":" .. all_headers[name] .. "\n"
    signed_headers = signed_headers .. name
    if i < #header_names then
      signed_headers = signed_headers .. ";"
    end
  end
  
  -- Create canonical request EXACTLY as AWS expects it
  local canonical_request = method .. "\n" ..
                           encoded_endpoint .. "\n" ..
                           "\n" ..
                           canonical_headers .. "\n" ..
                           signed_headers .. "\n" ..
                           payload_hash
  
  -- Create string to sign EXACTLY as AWS expects it
  local credential_scope = date_stamp .. "/" .. region .. "/" .. service .. "/aws4_request"
  local canonical_request_hash = sha256_hash(canonical_request)
  local string_to_sign = algorithm .. "\n" ..
                         amz_date .. "\n" ..
                         credential_scope .. "\n" ..
                         canonical_request_hash
  
  -- Calculate signature following AWS documentation exactly
  -- Step 1: Create a signing key
  -- kSecret = your secret access key
  local kSecret = "AWS4" .. aws_secret_access_key
  
  -- kDate = HMAC-SHA256(kSecret, Date)
  local kDate = hmac_sha256_string(kSecret, date_stamp)
  
  -- kRegion = HMAC-SHA256(kDate, Region)
  local kRegion = hmac_sha256_hex(kDate, region)
  
  -- kService = HMAC-SHA256(kRegion, Service)
  local kService = hmac_sha256_hex(kRegion, service)
  
  -- kSigning = HMAC-SHA256(kService, "aws4_request")
  local kSigning = hmac_sha256_hex(kService, "aws4_request")
  
  -- Step 2: Calculate signature
  -- signature = HMAC-SHA256(kSigning, stringToSign)
  local signature = hmac_sha256_hex(kSigning, string_to_sign)
  
  -- Create authorization header
  local authorization_header = algorithm .. " " ..
                             "Credential=" .. aws_access_key_id .. "/" .. credential_scope .. ", " ..
                             "SignedHeaders=" .. signed_headers .. ", " ..
                             "Signature=" .. signature
  
  -- Debug output
  Utils.debug("Canonical Request:")
  Utils.debug(canonical_request)
  Utils.debug("")
  Utils.debug("String to Sign:")
  Utils.debug(string_to_sign)
  Utils.debug("")
  Utils.debug("Signature: " .. signature)
  Utils.debug("")
  Utils.debug("Authorization Header:")
  Utils.debug(authorization_header)
  
  -- Return headers for curl
  local headers = {
    ["Content-Type"] = content_type,
    ["X-Amz-Date"] = amz_date,
    ["Authorization"] = authorization_header
  }
  
  -- Add additional headers to the result
  if additional_headers then
    for name, value in pairs(additional_headers) do
      headers[name] = value
    end
  end
  
  return headers, amz_date
end

---@param prompt_opts AvantePromptOptions
---@return table
function M:parse_curl_args(prompt_opts)
  local provider_conf, request_body = P.parse_config(self)
  
  local api_key = self.parse_api_key()
  if api_key == nil then error("Cannot get the bedrock api key!") end
  local parts = vim.split(api_key, ",")
  local aws_access_key_id = parts[1]
  local aws_secret_access_key = parts[2]
  local aws_region = parts[3]
  local aws_session_token = parts[4]
  
  local endpoint = string.format(
    "/model/%s/invoke-with-response-stream",
    provider_conf.model
  )
  
  local host = string.format("bedrock-runtime.%s.amazonaws.com", aws_region)
  local url = "https://" .. host .. endpoint
  
  local body_payload = self:build_bedrock_payload(prompt_opts, request_body)
  local json_body = vim.json.encode(body_payload)
  
  -- Generate SigV4 headers using our implementation
  local headers = {
    ["Content-Type"] = "application/json",
  }
  
  -- Add AWS session token if provided
  if aws_session_token and aws_session_token ~= "" then 
    headers["x-amz-security-token"] = aws_session_token 
  end
  
  -- Add our SigV4 authentication headers
  local auth_headers = sign_request(
    "POST", 
    "bedrock", 
    aws_region, 
    host, 
    endpoint, 
    json_body, 
    aws_access_key_id, 
    aws_secret_access_key,
    {
      ["Accept"] = "application/vnd.amazon.eventstream",
      ["X-Amzn-Bedrock-Accept"] = "*/*"
    }
  )
  
  -- Merge the authentication headers
  for name, value in pairs(auth_headers) do
    headers[name] = value
  end
  
  return {
    url = url,
    proxy = provider_conf.proxy,
    insecure = provider_conf.allow_insecure,
    headers = headers,
    body = body_payload,
    -- No rawArgs for AWS authentication since we're using headers
  }
end

function M.on_error(result)
  if not result.body then
    return Utils.error("API request failed with status " .. result.status, { once = true, title = "Avante" })
  end

  local ok, body = pcall(vim.json.decode, result.body)
  if not (ok and body and body.error) then
    return Utils.error("Failed to parse error response", { once = true, title = "Avante" })
  end

  local error_msg = body.error.message

  Utils.error(error_msg, { once = true, title = "Avante" })
end

return M