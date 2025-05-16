local ErrorHandler = require("avante.error_handler")

describe("ErrorHandler", function()
  before_each(function()
    -- Reset the error handler state before each test
    ErrorHandler.handling_error = false
    ErrorHandler.handled_errors = {}
  end)

  it("should wrap functions with error handling", function()
    -- Create a function that will throw an error
    local function throws_error()
      error("Test error")
    end

    -- Wrap the function with our error handler
    local wrapped = ErrorHandler.wrap(throws_error)

    -- The wrapped function should return nil and the error
    local result, err = wrapped()
    assert.is_nil(result)
    assert.is_not_nil(err)
    assert.matches("Test error", err)
  end)

  it("should add errors to the handled_errors table", function()
    -- Add an error to the context
    ErrorHandler.add_error_to_context("Test error", "test")

    -- Check that the error was added to the handled_errors table
    assert.equals(1, #ErrorHandler.handled_errors)
    assert.equals("Test error", ErrorHandler.handled_errors[1].message)
    assert.equals("test", ErrorHandler.handled_errors[1].type)
  end)

  it("should clear handled errors", function()
    -- Add an error to the context
    ErrorHandler.add_error_to_context("Test error", "test")
    
    -- Clear the errors
    ErrorHandler.clear_handled_errors()
    
    -- Check that the errors were cleared
    assert.equals(0, #ErrorHandler.handled_errors)
  end)

  it("should prevent recursion when handling errors", function()
    -- Set handling_error to true to simulate an error being handled
    ErrorHandler.handling_error = true
    
    -- Add an error to the context
    ErrorHandler.add_error_to_context("Test error", "test")
    
    -- Check that no error was added due to recursion prevention
    assert.equals(0, #ErrorHandler.handled_errors)
  end)
end)