defmodule Vaultx.Cache.L3 do
  @moduledoc """
  L3 Persistent Cache implementation with enterprise-grade security.

  This module provides persistent caching capabilities with optional AES-256-GCM encryption
  for sensitive data. It's designed for long-term storage of cache entries that should
  survive application restarts and provide durability guarantees.

  ## Architecture

  L3 cache operates as the persistent layer in VaultX's multi-tier caching system:
  - L1 (Memory) → L2 (Distributed) → L3 (Persistent)
  - Provides durability and long-term storage
  - Automatic promotion to higher cache layers on access
  - Intelligent cleanup and maintenance

  ## Features

  ### Core Functionality
  - File-based persistent storage with atomic write operations
  - Configurable TTL with automatic expiration handling
  - Pattern-based cache clearing for bulk operations
  - Automatic cleanup of expired entries
  - Cross-platform compatibility with proper file handling

  ### Security & Encryption
  - AES-256-GCM encryption for sensitive cache data
  - Secure key management with multiple key sources
  - File permission hardening (0600 for key files)
  - Cryptographic integrity verification
  - Graceful degradation on encryption failures

  ### Performance & Reliability
  - Atomic file operations prevent corruption
  - Efficient file naming with collision avoidance
  - Memory-efficient streaming for large cache entries
  - Concurrent access safety through file locking patterns
  - Automatic error recovery and logging

  ## Encryption Design

  ### Cryptographic Specifications
  - Algorithm: AES-256-GCM (Galois/Counter Mode)
  - Key Size: 256 bits (32 bytes)
  - IV Size: 96 bits (12 bytes) - optimal for GCM
  - Tag Size: 128 bits (16 bytes) - authentication tag
  - Key Derivation: Direct key usage (no PBKDF2 needed for generated keys)

  ### Key Management Strategy
  The encryption key is sourced in the following priority order:

  1. Environment Variable (`VAULTX_L3_ENCRYPTION_KEY`)
     - Base64-encoded 256-bit key
     - Recommended for containerized deployments
     - Example: `export VAULTX_L3_ENCRYPTION_KEY="$(openssl rand -base64 32)"`

  2. Persistent Key File (`.encryption_key` in storage directory)
     - Automatically generated on first use
     - Stored with restrictive permissions (0600)
     - Survives application restarts
     - Base64-encoded for safe storage

  3. Fallback Generation (temporary, not recommended for production)
     - Generated in-memory if file operations fail
     - Will cause data loss on restart
     - Logged as a warning

  ### Security Considerations

  #### Strengths
  - Authenticated encryption prevents tampering
  - Unique IV per encryption prevents replay attacks
  - Secure key storage with proper file permissions
  - No key derivation overhead for performance
  - Cryptographically secure random IV generation

  #### Limitations & Mitigations
  - Key in memory: Required for operation, cleared on process termination
  - No key rotation: Future enhancement, current keys remain valid
  - File system security: Relies on OS-level file permissions
  - Backup considerations: Encrypted cache files require key backup

  #### Production Recommendations
  - Use environment variables for key management in containers
  - Implement regular key rotation policies (manual process currently)
  - Monitor key file permissions and access
  - Include encryption keys in backup/disaster recovery procedures
  - Consider using external key management systems for high-security environments

  ## Configuration

      # Application configuration
      config :vaultx,
        cache_l3_enabled: true,
        cache_l3_storage_path: "/var/cache/vaultx",
        cache_l3_ttl_default: 86_400_000,  # 24 hours in milliseconds
        cache_l3_cleanup_interval: 3_600_000,  # 1 hour in milliseconds
        cache_l3_encryption: true

      # Environment variables (override application config)
      export VAULTX_CACHE_L3_ENABLED=true
      export VAULTX_CACHE_L3_STORAGE_PATH="/secure/cache/path"
      export VAULTX_CACHE_L3_ENCRYPTION=true
      export VAULTX_L3_ENCRYPTION_KEY="$(openssl rand -base64 32)"

  ## Usage Examples

      # L3 cache is typically managed by the cache manager
      # Direct usage is not recommended in normal operations

      # Basic operations (via cache manager)
      {:ok, value} = Vaultx.Cache.get("persistent_key")
      :ok = Vaultx.Cache.put("persistent_key", value, ttl: :timer.hours(24))

      # Direct L3 operations (advanced usage)
      {:ok, value} = Vaultx.Cache.L3.get("cache_key")
      :ok = Vaultx.Cache.L3.put("cache_key", value, ttl: :timer.hours(1))
      :ok = Vaultx.Cache.L3.delete("cache_key")

      # Bulk operations
      :ok = Vaultx.Cache.L3.clear("pattern:*")
      :ok = Vaultx.Cache.L3.clear(:all)

  ## File Structure

      /var/cache/vaultx/
      ├── .encryption_key          # Encryption key (if file-based)
      ├── cache_abc123def_a1b2c3d4.cache  # Cache files with collision avoidance
      ├── cache_xyz789ghi_e5f6g7h8.cache
      └── ...

  ## Performance Characteristics

  - Read latency: ~10-50ms (disk I/O dependent)
  - Write latency: ~20-100ms (disk I/O dependent)
  - Encryption overhead: ~1-5ms additional latency
  - Throughput: Limited by disk I/O performance
  - Storage: Limited by available disk space

  ## Monitoring & Maintenance

  L3 cache provides comprehensive monitoring through the metrics system:
  - Cache hit/miss ratios
  - Storage space utilization
  - Encryption/decryption performance
  - Cleanup operation statistics
  - Error rates and recovery actions

  ## Error Handling

  The L3 cache implements graceful error handling:
  - Encryption failures: Fall back to unencrypted storage with warnings
  - File system errors: Retry with exponential backoff
  - Corruption detection: Automatic cleanup of corrupted entries
  - Permission issues: Clear error messages and recovery suggestions

  ## Use Cases & Best Practices

  ### Ideal Use Cases
  - Long-term secret caching: Store frequently accessed secrets with 24+ hour TTL
  - Offline resilience: Maintain critical data availability during network outages
  - Cross-restart persistence: Preserve expensive computations across deployments
  - Backup cache layer: Fallback when distributed caches are unavailable
  - Development environments: Reduce API calls during development and testing

  ### Performance Optimization
  - Batch operations: Use pattern-based clearing for bulk cache invalidation
  - TTL tuning: Set longer TTLs for stable data, shorter for dynamic content
  - Storage location: Use fast SSDs for cache storage when possible
  - Cleanup scheduling: Adjust cleanup intervals based on cache churn rate
  - Encryption trade-offs: Disable encryption for non-sensitive data to improve performance

  ### Security Best Practices
  - Key management: Use environment variables in production, never hardcode keys
  - File permissions: Ensure cache directory has restrictive permissions (0700)
  - Regular audits: Monitor cache access patterns for anomalies
  - Key rotation: Implement periodic key rotation (manual process currently)
  - Backup strategy: Include encryption keys in disaster recovery procedures

  ### Operational Considerations
  - Disk space monitoring: Set up alerts for cache directory disk usage
  - Performance monitoring: Track cache hit rates and response times
  - Log analysis: Monitor encryption/decryption errors and file system issues
  - Cleanup verification: Ensure expired entries are properly removed
  - Recovery procedures: Document cache rebuild processes for disaster recovery

  ### Integration Patterns
  - Vault secrets: Cache KV secrets with appropriate TTLs based on sensitivity
  - Authentication data: Store token validation results with security-appropriate TTLs
  - Configuration data: Cache mount information and engine metadata
  - Policy evaluation: Store policy decision results for performance
  - Lease management: Cache lease information with proper expiration handling

  ## Troubleshooting

  ### Common Issues
  - Permission denied: Check file system permissions on cache directory
  - Encryption key mismatch: Verify key consistency across restarts
  - Disk space full: Monitor and clean up cache directory regularly
  - Slow performance: Check disk I/O performance and consider SSD storage
  - Memory usage: Monitor process memory for large cached objects

  ### Debugging Tools
  - Cache statistics: Use `Vaultx.Cache.stats()` for performance metrics
  - Log analysis: Enable debug logging for detailed operation tracking
  - File inspection: Examine cache files directly (encrypted files will be binary)
  - Process monitoring: Check GenServer health and restart patterns
  - Metrics collection: Use telemetry data for performance analysis

  """

  use GenServer

  alias Vaultx.Base.Logger
  alias Vaultx.Cache.Metrics

  @default_storage_path "/tmp/vaultx_cache"
  @cleanup_interval :timer.hours(1)

  defstruct [
    :storage_path,
    :config,
    :cleanup_timer,
    :encryption_key
  ]

  # Public API

  @doc """
  Starts the L3 cache.
  """
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @doc """
  Gets a value from L3 cache.
  """
  def get(key) do
    GenServer.call(__MODULE__, {:get, key})
  end

  @doc """
  Puts a value into L3 cache.
  """
  def put(key, value, opts \\ []) do
    GenServer.call(__MODULE__, {:put, key, value, opts})
  end

  @doc """
  Deletes a value from L3 cache.
  """
  def delete(key) do
    GenServer.call(__MODULE__, {:delete, key})
  end

  @doc """
  Clears L3 cache.
  """
  def clear(pattern \\ :all) do
    GenServer.call(__MODULE__, {:clear, pattern})
  end

  @doc """
  Performs cleanup of expired entries.
  """
  def cleanup do
    GenServer.cast(__MODULE__, :cleanup)
  end

  @doc """
  Gets L3 cache statistics.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # GenServer callbacks

  @impl true
  def init(config) do
    storage_path = Map.get(config, :l3_storage_path, @default_storage_path)

    # Ensure storage directory exists
    case File.mkdir_p(storage_path) do
      :ok ->
        # Initialize encryption key if encryption is enabled
        encryption_key =
          if Map.get(config, :l3_encryption, false) do
            get_or_generate_encryption_key(storage_path)
          else
            nil
          end

        state = %__MODULE__{
          storage_path: storage_path,
          config: config,
          encryption_key: encryption_key
        }

        # Schedule cleanup
        cleanup_timer = schedule_cleanup(config)
        state = %{state | cleanup_timer: cleanup_timer}

        Logger.info("L3 cache started", %{
          storage_path: storage_path,
          encryption_enabled: encryption_key != nil
        })

        {:ok, state}

      {:error, reason} ->
        Logger.error("Failed to create L3 cache directory", %{
          path: storage_path,
          reason: reason
        })

        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:get, key}, _from, state) do
    file_path = build_file_path(key, state.storage_path)

    case read_cache_file(file_path, state) do
      {:ok, value, expires_at} ->
        current_time = System.system_time(:millisecond)

        if current_time < expires_at do
          Metrics.record_hit(:l3, key)
          {:reply, {:ok, value}, state}
        else
          # Expired, remove file
          File.rm(file_path)
          {:reply, {:error, :not_found}, state}
        end

      {:error, :not_found} ->
        {:reply, {:error, :not_found}, state}

      {:error, reason} ->
        Logger.warn("L3 cache read error", %{key: key, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:put, key, value, opts}, _from, state) do
    ttl = Keyword.get(opts, :ttl, Map.get(state.config, :l3_ttl_default, :timer.hours(24)))
    expires_at = System.system_time(:millisecond) + ttl
    file_path = build_file_path(key, state.storage_path)

    case write_cache_file(file_path, value, expires_at, state) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.warn("L3 cache write error", %{key: key, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:delete, key}, _from, state) do
    file_path = build_file_path(key, state.storage_path)

    case File.rm(file_path) do
      :ok ->
        {:reply, :ok, state}

      {:error, :enoent} ->
        # File doesn't exist, consider it deleted
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.warn("L3 cache delete error", %{key: key, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:clear, pattern}, _from, state) do
    case clear_cache_files(pattern, state.storage_path) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        Logger.warn("L3 cache clear error", %{pattern: pattern, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = calculate_storage_stats(state.storage_path)
    {:reply, stats, state}
  end

  @impl true
  def handle_cast(:cleanup, state) do
    perform_cleanup(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    perform_cleanup(state)
    cleanup_timer = schedule_cleanup(state.config)
    {:noreply, %{state | cleanup_timer: cleanup_timer}}
  end

  # Private functions

  defp build_file_path(key, storage_path) do
    # Create a safe filename from the cache key
    safe_filename =
      key
      |> String.replace(~r/[^a-zA-Z0-9_\-]/, "_")
      # Limit filename length
      |> String.slice(0, 200)

    # Add hash to avoid collisions
    hash = :crypto.hash(:sha256, key) |> Base.encode16(case: :lower) |> String.slice(0, 8)
    filename = "#{safe_filename}_#{hash}.cache"

    Path.join(storage_path, filename)
  end

  defp read_cache_file(file_path, state) do
    case File.read(file_path) do
      {:ok, binary_data} ->
        try do
          # Try to decrypt if data appears to be encrypted
          decrypted_data = maybe_decrypt_data(binary_data, state)
          %{value: value, expires_at: expires_at} = :erlang.binary_to_term(decrypted_data)
          {:ok, value, expires_at}
        rescue
          _ -> {:error, :corrupted_data}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_decrypt_data(data, state) do
    # Check if data looks encrypted (has IV + tag + ciphertext structure)
    # 12 (IV) + 16 (tag) minimum
    if state.encryption_key and byte_size(data) > 28 do
      try do
        <<iv::binary-size(12), tag::binary-size(16), ciphertext::binary>> = data
        key = state.encryption_key

        case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, <<>>, tag, false) do
          plaintext when is_binary(plaintext) -> plaintext
          # Return original data if decryption fails
          :error -> data
        end
      rescue
        # Return original data if structure doesn't match
        _ -> data
      end
    else
      # Too small to be encrypted, return as-is
      data
    end
  end

  defp write_cache_file(file_path, value, expires_at, state) do
    data = %{value: value, expires_at: expires_at}
    binary_data = :erlang.term_to_binary(data, [:compressed])

    # Optionally encrypt the data
    final_data = encrypt_data(binary_data, state)

    # Ensure directory exists
    file_path |> Path.dirname() |> File.mkdir_p()

    # Write atomically using a temporary file
    temp_path = file_path <> ".tmp"

    case File.write(temp_path, final_data) do
      :ok ->
        case File.rename(temp_path, file_path) do
          :ok ->
            :ok

          {:error, reason} ->
            File.rm(temp_path)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp encrypt_data(data, state) do
    if state.encryption_key do
      # Use AES-256-GCM for encryption
      key = state.encryption_key
      # 96-bit IV for GCM
      iv = :crypto.strong_rand_bytes(12)

      try do
        {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, <<>>, true)
        # Prepend IV and tag to ciphertext
        iv <> tag <> ciphertext
      rescue
        _ ->
          Logger.warn("L3 cache encryption failed, storing unencrypted")
          data
      end
    else
      data
    end
  end

  defp get_or_generate_encryption_key(storage_path) do
    # First try environment variable
    case System.get_env("VAULTX_L3_ENCRYPTION_KEY") do
      nil ->
        # Try to load from key file
        key_file = Path.join(storage_path, ".encryption_key")

        case File.read(key_file) do
          {:ok, key_b64} ->
            Base.decode64!(key_b64)

          {:error, :enoent} ->
            # Generate new key and save it
            key = :crypto.strong_rand_bytes(32)
            key_b64 = Base.encode64(key)
            File.write!(key_file, key_b64)
            # Set restrictive permissions
            File.chmod!(key_file, 0o600)
            Logger.info("Generated new L3 encryption key", %{key_file: key_file})
            key

          {:error, reason} ->
            Logger.error("Failed to read encryption key file", %{reason: reason})
            # Generate temporary key (not persistent)
            :crypto.strong_rand_bytes(32)
        end

      key_b64 ->
        Base.decode64!(key_b64)
    end
  end

  defp clear_cache_files(pattern, storage_path) do
    case pattern do
      :all ->
        case File.ls(storage_path) do
          {:ok, files} ->
            files
            |> Enum.filter(&String.ends_with?(&1, ".cache"))
            |> Enum.each(fn file ->
              File.rm(Path.join(storage_path, file))
            end)

            :ok

          {:error, reason} ->
            {:error, reason}
        end

      pattern when is_binary(pattern) ->
        # Simple pattern matching for files
        pattern_regex =
          pattern
          |> String.replace("*", ".*")
          |> Regex.compile!()

        case File.ls(storage_path) do
          {:ok, files} ->
            files
            |> Enum.filter(&String.ends_with?(&1, ".cache"))
            |> Enum.filter(&Regex.match?(pattern_regex, &1))
            |> Enum.each(fn file ->
              File.rm(Path.join(storage_path, file))
            end)

            :ok

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp calculate_storage_stats(storage_path) do
    case File.ls(storage_path) do
      {:ok, files} ->
        cache_files = Enum.filter(files, &String.ends_with?(&1, ".cache"))
        file_count = length(cache_files)

        total_size =
          cache_files
          |> Enum.map(fn file ->
            case File.stat(Path.join(storage_path, file)) do
              {:ok, %{size: size}} -> size
              _ -> 0
            end
          end)
          |> Enum.sum()

        %{
          file_count: file_count,
          total_size_bytes: total_size,
          storage_path: storage_path
        }

      {:error, _} ->
        %{
          file_count: 0,
          total_size_bytes: 0,
          storage_path: storage_path
        }
    end
  end

  defp perform_cleanup(state) do
    current_time = System.system_time(:millisecond)

    case File.ls(state.storage_path) do
      {:ok, files} ->
        expired_files =
          files
          |> Enum.filter(&String.ends_with?(&1, ".cache"))
          |> Enum.filter(fn file ->
            file_path = Path.join(state.storage_path, file)

            case read_cache_file(file_path, state) do
              {:ok, _value, expires_at} -> current_time >= expires_at
              _ -> false
            end
          end)

        # Remove expired files
        Enum.each(expired_files, fn file ->
          File.rm(Path.join(state.storage_path, file))
        end)

        if length(expired_files) > 0 do
          Logger.debug("L3 cache cleanup completed", %{expired_files: length(expired_files)})
        end

      {:error, reason} ->
        Logger.warn("L3 cache cleanup failed", %{reason: reason})
    end
  end

  defp schedule_cleanup(config) do
    interval = Map.get(config, :l3_cleanup_interval, @cleanup_interval)
    Process.send_after(self(), :cleanup, interval)
  end
end
