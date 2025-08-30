defmodule Vaultx.Base.JSONTest do
  use ExUnit.Case, async: false

  alias Vaultx.Base.JSON

  setup do
    # Store original environment variables
    original_env = System.get_env("VAULTX_JSON_LIBRARY")

    on_exit(fn ->
      if original_env do
        System.put_env("VAULTX_JSON_LIBRARY", original_env)
      else
        System.delete_env("VAULTX_JSON_LIBRARY")
      end
    end)

    :ok
  end

  describe "encode/1" do
    test "encodes valid data successfully" do
      data = %{"name" => "test", "value" => 123}

      assert {:ok, json_string} = JSON.encode(data)
      assert is_binary(json_string)
      assert String.contains?(json_string, "test")
    end

    test "handles encoding errors gracefully" do
      invalid_data = %{func: fn -> :ok end}

      result = JSON.encode(invalid_data)
      assert {:error, %Vaultx.Base.Error{}} = result
    end
  end

  describe "encode!/1" do
    test "encodes valid data and returns string" do
      data = %{"name" => "test", "value" => 123}

      json_string = JSON.encode!(data)
      assert is_binary(json_string)
      assert String.contains?(json_string, "test")
    end

    test "raises error for invalid data" do
      assert_raise Vaultx.Base.Error, fn ->
        JSON.encode!(%{func: fn -> :ok end})
      end
    end
  end

  describe "decode/1" do
    test "decodes valid JSON successfully" do
      json_string = ~s({"name": "test", "value": 123})

      assert {:ok, data} = JSON.decode(json_string)
      assert is_map(data)
      assert data["name"] == "test"
      assert data["value"] == 123
    end

    test "handles decoding errors gracefully" do
      invalid_json = "{invalid json"

      result = JSON.decode(invalid_json)
      assert {:error, %Vaultx.Base.Error{}} = result
    end
  end

  describe "decode!/1" do
    test "decodes valid JSON and returns data" do
      json_string = ~s({"name": "test", "value": 123})

      data = JSON.decode!(json_string)
      assert is_map(data)
      assert data["name"] == "test"
      assert data["value"] == 123
    end

    test "raises error for invalid JSON" do
      assert_raise Vaultx.Base.Error, fn ->
        JSON.decode!("{invalid json")
      end
    end
  end

  describe "library detection and selection" do
    test "current_library/0 returns available library" do
      current = JSON.current_library()
      assert current in [:elixir, :jason]
    end

    test "library_available?/1 checks library availability" do
      # At least one should be available in test environment
      assert JSON.library_available?(:elixir) or JSON.library_available?(:jason)
    end

    test "library_info/0 returns comprehensive information" do
      info = JSON.library_info()

      assert Map.has_key?(info, :current)
      assert Map.has_key?(info, :available)
      assert Map.has_key?(info, :elixir_available)
      assert Map.has_key?(info, :jason_available)

      assert info.current in [:elixir, :jason]
      assert is_list(info.available)
      assert is_boolean(info.elixir_available)
      assert is_boolean(info.jason_available)
    end
  end

  describe "environment variable configuration" do
    test "respects VAULTX_JSON_LIBRARY=elixir" do
      System.put_env("VAULTX_JSON_LIBRARY", "elixir")

      if JSON.library_available?(:elixir) do
        assert JSON.current_library() == :elixir
      end
    end

    test "respects VAULTX_JSON_LIBRARY=jason" do
      System.put_env("VAULTX_JSON_LIBRARY", "jason")

      if JSON.library_available?(:jason) do
        assert JSON.current_library() == :jason
      end
    end

    test "falls back to detection with invalid environment variable" do
      System.put_env("VAULTX_JSON_LIBRARY", "invalid")

      current = JSON.current_library()
      assert current in [:elixir, :jason]
    end
  end

  describe "edge cases" do
    test "handles empty data structures" do
      assert {:ok, "[]"} = JSON.encode([])
      assert {:ok, "{}"} = JSON.encode(%{})
    end

    test "handles nested data structures" do
      data = %{
        "users" => [
          %{"name" => "Alice", "age" => 30},
          %{"name" => "Bob", "age" => 25}
        ],
        "metadata" => %{"total" => 2}
      }

      assert {:ok, json_string} = JSON.encode(data)
      assert {:ok, decoded} = JSON.decode(json_string)
      assert decoded["users"] |> length() == 2
      assert decoded["metadata"]["total"] == 2
    end

    test "covers JSON library detection edge cases" do
      # Test that at least one library is available in our test environment
      assert JSON.library_available?(:elixir) or JSON.library_available?(:jason)

      # Test that the current library selection works
      current = JSON.current_library()
      assert current in [:elixir, :jason]

      # Test that library info includes the expected structure
      info = JSON.library_info()
      assert Map.has_key?(info, :elixir_available)
      assert Map.has_key?(info, :jason_available)

      # At least one should be available
      assert info.elixir_available or info.jason_available
    end
  end
end
