ua/avante/llm.lua</path>
<content lines="145-152">
  -- Check if the instructions contains an image path
  local image_paths = {}
  if opts.prompt_opts and opts.prompt_opts.image_paths then
    image_paths = vim.list_extend(image_paths, opts.prompt_opts.image_paths)
  end

  local project_root = Utils.root.get()
  Utils.debug("Project root: " .. tostring(project_root))
  
  local templates_dir
  local ok, result = pcall(function()
    return Path.prompts.get_templates_dir(project_root)
  end)
  
  if not ok then
    Utils.error("Failed to get templates directory: " .. tostring(result))
    error("Failed to get templates directory: " .. tostring(result))
  end
  
  templates_dir = result
  Utils.debug("Templates directory: " .. tostring(templates_dir))
  
  if not templates_dir or type(templates_dir) ~= "string" then
    Utils.error("Invalid templates directory: " .. tostring(templates_dir))
    error("Invalid templates directory: " .. tostring(templates_dir))
  end
  
  ok, result = pcall(function()
    Path.prompts.initialize(templates_dir)
  end)
  
  if not ok then
    Utils.error("Failed to initialize templates: " .. tostring(result))
    error("Failed to initialize templates: " .. tostring(result))
  end
