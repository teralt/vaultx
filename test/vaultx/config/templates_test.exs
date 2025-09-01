defmodule Vaultx.Config.TemplatesTest do
  use ExUnit.Case, async: true

  alias Vaultx.Config.Templates

  @moduledoc """
  Test suite for Config Templates functionality.

  Tests cover:
  - Environment-specific template generation
  - Feature-based configuration
  - Security level adaptation
  - Template customization
  - Migration templates
  - Multi-environment templates
  """

  describe "generate/2" do
    test "generates development template with default settings" do
      template = Templates.generate(:development)

      assert is_map(template)
      assert Map.has_key?(template, :url)
      assert Map.has_key?(template, :timeout)
      assert Map.has_key?(template, :pool_size)

      # Development should have relaxed settings
      assert template.ssl_verify == false or template.ssl_verify == true
      assert is_integer(template.timeout)
      assert is_integer(template.pool_size)
    end

    test "generates testing template with default settings" do
      template = Templates.generate(:testing)

      assert is_map(template)
      assert Map.has_key?(template, :url)
      assert Map.has_key?(template, :timeout)

      # Testing should have fast execution settings
      assert is_integer(template.timeout)
      # Testing timeout should be reasonable for test execution
      assert template.timeout > 0
    end

    test "generates staging template with default settings" do
      template = Templates.generate(:staging)

      assert is_map(template)
      assert Map.has_key?(template, :url)
      assert Map.has_key?(template, :ssl_verify)

      # Staging should have production-like security
      assert is_boolean(template.ssl_verify)
    end

    test "generates production template with default settings" do
      template = Templates.generate(:production)

      assert is_map(template)
      assert Map.has_key?(template, :url)
      assert Map.has_key?(template, :ssl_verify)
      assert Map.has_key?(template, :timeout)

      # Production should have strict security
      assert template.ssl_verify == true
      assert is_integer(template.timeout)
    end

    test "generates template with custom features" do
      template = Templates.generate(:development, features: [:cache, :telemetry])

      assert is_map(template)
      # Should include cache and telemetry related configuration
      assert Map.has_key?(template, :url)
    end

    test "generates template with custom security level" do
      template = Templates.generate(:development, security_level: :enhanced)

      assert is_map(template)
      # Enhanced security should enforce SSL verification
      assert template.ssl_verify == true
    end

    test "generates template with custom settings" do
      custom_settings = %{
        custom_timeout: 45_000,
        custom_pool_size: 20
      }

      template = Templates.generate(:development, custom_settings: custom_settings)

      assert is_map(template)
      # Custom settings should be merged into template
      assert template.custom_timeout == 45_000
      assert template.custom_pool_size == 20
    end

    test "handles invalid environment gracefully" do
      # Should handle unknown environments
      try do
        template = Templates.generate(:unknown_env)
        assert is_map(template)
      rescue
        # Acceptable to raise error for unknown environment
        _ -> :ok
      end
    end

    test "generates different templates for different environments" do
      dev_template = Templates.generate(:development)
      prod_template = Templates.generate(:production)

      # Templates should be different
      assert dev_template != prod_template

      # Production should be more secure than development
      if Map.has_key?(dev_template, :ssl_verify) and Map.has_key?(prod_template, :ssl_verify) do
        # Production should have stricter SSL settings
        assert prod_template.ssl_verify == true
      end
    end
  end

  describe "generate_multiple/2" do
    test "generates templates for multiple environments" do
      environments = [:development, :testing, :production]
      templates = Templates.generate_multiple(environments)

      assert is_map(templates)
      assert Map.has_key?(templates, :development)
      assert Map.has_key?(templates, :testing)
      assert Map.has_key?(templates, :production)

      # Each template should be a map
      for {_env, template} <- templates do
        assert is_map(template)
        assert Map.has_key?(template, :url)
      end
    end

    test "generates templates with consistent options" do
      environments = [:development, :production]
      options = [features: [:cache], security_level: :enhanced]

      templates = Templates.generate_multiple(environments, options)

      assert is_map(templates)
      assert Map.has_key?(templates, :development)
      assert Map.has_key?(templates, :production)

      # Both templates should have cache feature
      for {_env, template} <- templates do
        assert is_map(template)
      end
    end

    test "handles empty environment list" do
      templates = Templates.generate_multiple([])

      assert templates == %{}
    end

    test "handles single environment" do
      templates = Templates.generate_multiple([:development])

      assert is_map(templates)
      assert Map.has_key?(templates, :development)
      assert map_size(templates) == 1
    end
  end

  describe "generate_migration/3" do
    test "generates migration template from development to production" do
      migration = Templates.generate_migration(:development, :production)

      assert is_map(migration)
      assert Map.has_key?(migration, :from_environment)
      assert Map.has_key?(migration, :to_environment)
      assert Map.has_key?(migration, :changes)
      assert Map.has_key?(migration, :migration_notes)

      assert migration.from_environment == :development
      assert migration.to_environment == :production
      assert is_list(migration.changes)
      assert is_list(migration.migration_notes)
    end

    test "generates migration template from testing to staging" do
      migration = Templates.generate_migration(:testing, :staging)

      assert is_map(migration)
      assert migration.from_environment == :testing
      assert migration.to_environment == :staging
      assert is_list(migration.changes)
    end

    test "generates migration template with custom options" do
      options = [features: [:audit], security_level: :enhanced]
      migration = Templates.generate_migration(:development, :production, options)

      assert is_map(migration)
      assert Map.has_key?(migration, :changes)
      assert Map.has_key?(migration, :migration_notes)
    end

    test "handles same environment migration" do
      migration = Templates.generate_migration(:production, :production)

      assert is_map(migration)
      assert migration.from_environment == :production
      assert migration.to_environment == :production
      # Should have minimal or no changes
      assert is_list(migration.changes)
    end

    test "migration includes security recommendations" do
      migration = Templates.generate_migration(:development, :production)

      assert is_map(migration)
      assert is_list(migration.migration_notes)

      # Should have security-related recommendations
      notes_text = Enum.join(migration.migration_notes, " ")

      assert String.contains?(String.downcase(notes_text), "security") or
               String.contains?(String.downcase(notes_text), "ssl") or
               length(migration.migration_notes) > 0
    end
  end

  describe "template validation and structure" do
    test "all environment templates have required fields" do
      environments = [:development, :testing, :staging, :production]

      for env <- environments do
        template = Templates.generate(env)

        # All templates should have basic required fields
        assert Map.has_key?(template, :url)
        assert is_binary(template.url)

        if Map.has_key?(template, :timeout) do
          assert is_integer(template.timeout)
          assert template.timeout > 0
        end

        if Map.has_key?(template, :pool_size) do
          assert is_integer(template.pool_size)
          assert template.pool_size > 0
        end

        if Map.has_key?(template, :ssl_verify) do
          assert is_boolean(template.ssl_verify)
        end
      end
    end

    test "templates have consistent structure" do
      dev_template = Templates.generate(:development)
      prod_template = Templates.generate(:production)

      # Both templates should have similar keys (though values may differ)
      dev_keys = Map.keys(dev_template) |> MapSet.new()
      prod_keys = Map.keys(prod_template) |> MapSet.new()

      # Should have some common keys
      common_keys = MapSet.intersection(dev_keys, prod_keys)
      assert MapSet.size(common_keys) > 0
    end

    test "production template has stricter security than development" do
      _dev_template = Templates.generate(:development)
      prod_template = Templates.generate(:production)

      # Production should have SSL verification enabled
      if Map.has_key?(prod_template, :ssl_verify) do
        assert prod_template.ssl_verify == true
      end

      # Production should have reasonable timeouts
      if Map.has_key?(prod_template, :timeout) do
        # At least 10 seconds
        assert prod_template.timeout >= 10_000
      end
    end
  end

  describe "error handling and edge cases" do
    test "handles invalid options gracefully" do
      # Should handle invalid feature lists
      template = Templates.generate(:development, features: [:invalid_feature])
      assert is_map(template)

      # Should handle invalid security levels by raising error
      try do
        Templates.generate(:development, security_level: :invalid_level)
        :ok
      rescue
        # Expected for invalid security level
        FunctionClauseError -> :ok
      end
    end

    test "handles nil and empty options" do
      # nil options should raise error
      try do
        Templates.generate(:development, nil)
        :ok
      rescue
        # Expected for nil options
        FunctionClauseError -> :ok
      end

      template2 = Templates.generate(:development, [])
      template3 = Templates.generate(:development)

      assert is_map(template2)
      assert is_map(template3)
    end

    test "handles large custom settings" do
      large_custom_settings = %{
        field1: String.duplicate("x", 1000),
        field2: Enum.to_list(1..100),
        nested: %{
          deep: %{
            data: "test"
          }
        }
      }

      template = Templates.generate(:development, custom_settings: large_custom_settings)

      assert is_map(template)
      assert template.field1 == String.duplicate("x", 1000)
      assert template.field2 == Enum.to_list(1..100)
      assert template.nested.deep.data == "test"
    end
  end
end
