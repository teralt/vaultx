defmodule Vaultx.TypesTest do
  use ExUnit.Case, async: true

  alias Vaultx.Types

  describe "type definitions" do
    test "defines core types" do
      # This test ensures the Types module compiles and defines expected types
      # We can't directly test types at runtime, but we can ensure the module loads
      assert Code.ensure_loaded?(Types)
    end
  end
end
