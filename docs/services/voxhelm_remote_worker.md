# Native Voxhelm remote worker

`VoxhelmRemoteWorkerConfig` / `deploy_voxhelm_remote_worker` ports the authoritative ops-library role at `56495f75` (2.75.1). It supports the existing Darwin/launchd contract. The owned ARM fixture passed on `cd4ee3e7920232aabcf142971bec96e044611f55`; inventory rollout is separate.

The original existing-user contract is retained: the declared account/home must already exist. Its pinned public PyPI `voxhelm` tool, selected Python, extras and install transcript determine whether installation is owed. A matching tool environment is retained, including patched certifi/trust bytes. `force_install` deliberately requests installation; package/index selection stays on public PyPI with `--no-sources`.

Parakeet retains its separate Python/tool version and exact model revision marker. New or deliberately changed model downloads are verified before replacement. The optional ad-analysis profile retains its pinned window model, whisper/ffprobe executables and configured source-link behavior. The launcher retains caffeinate, declared owner/group, public endpoint binding and the role's environment.

`enabled=False` skips the role, including launchd; it does not stop or delete a previously deployed worker. When enabled, manage/start flags retain the existing launchd behavior. Installation and configuration changes may restart the managed worker; a matching running deployment is not refused because it exists or is busy. As in the role, a changed runtime, model or file is published while the worker keeps running, then the worker is restarted (and its launchd job reloaded only when the plist changed). A persisted restart intent keeps that restart owed if a later step fails, so a rejected download leaves the running worker untouched and the next successful deployment restarts it once. No audio, transcription or inference is invoked by deployment qualification.

`preserved_artifacts` describes existing bytes by path, file/link type, inode, size, mtime and ownership. Its historical pin is **continuity input, not a cryptographic integrity attestation**. Matching probes read no model body and create no marker or staging. An actual changed/new artifact is fully checksum-verified and records provenance after publication. A native record for a path takes precedence over the initial mapping, including a later rollback. Existing model bytes are never claimed rehashed by a no-op.

Homebrew and its selected owner remain prerequisites. Missing declared formulae are installed; normal deployment does not upgrade existing formulae. Presence uses the role's per-formula `brew list --versions` check, which also resolves renamed formulae such as `whisper-cpp` (now `whisper.cpp`). The native uv base API is a separate composition step where the playbook included it. 

```python
from ops_deploy.services.voxhelm_remote_worker import VoxhelmRemoteWorkerConfig, deploy_voxhelm_remote_worker

cfg = VoxhelmRemoteWorkerConfig(
    voxhelm_remote_worker_service_user="worker",
    voxhelm_remote_worker_base_url="https://control.example.test",
    voxhelm_remote_worker_artifact_s3_endpoint_url="https://s3.example.test",
)
deploy_voxhelm_remote_worker(cfg, prepared_secret_values)
```

Secrets are a separate mapping, never config/argv/host data. The mapping uses these original role variable names:

- `voxhelm_remote_worker_token`
- `voxhelm_remote_worker_huggingface_token`
- `voxhelm_remote_worker_artifact_s3_access_key_id`
- `voxhelm_remote_worker_artifact_s3_secret_access_key`

Configuration retains the original public variable names. Computed defaults below resolve from other configured inputs before connection.

| Input | Default |
| --- | --- |
| `preserved_artifacts` | `{}` |
| `inventory_hostname` | `"runner"` |
| `voxhelm_remote_worker_enabled` | `true` |
| `voxhelm_remote_worker_service_user` | `"CHANGEME"` |
| `voxhelm_remote_worker_service_group` | `"staff"` |
| `voxhelm_remote_worker_service_home` | `"/Users/{{ voxhelm_remote_worker_service_user }}"` |
| `voxhelm_remote_worker_work_dir` | `"{{ voxhelm_remote_worker_service_home }}/Library/Application Support/voxhelm-remote-worker"` |
| `voxhelm_remote_worker_config_dir` | `"/etc/voxhelm-remote-worker"` |
| `voxhelm_remote_worker_env_file` | `"{{ voxhelm_remote_worker_config_dir }}/worker.env"` |
| `voxhelm_remote_worker_log_dir` | `"/var/log/voxhelm-remote-worker"` |
| `voxhelm_remote_worker_stdout_log` | `"{{ voxhelm_remote_worker_log_dir }}/worker.log"` |
| `voxhelm_remote_worker_stderr_log` | `"{{ voxhelm_remote_worker_log_dir }}/worker.err.log"` |
| `voxhelm_remote_worker_install_transcript_path` | `"{{ voxhelm_remote_worker_log_dir }}/install-transcript.log"` |
| `voxhelm_remote_worker_launcher_path` | `"{{ voxhelm_remote_worker_config_dir }}/worker-launcher.sh"` |
| `voxhelm_remote_worker_uv_bin` | `"/usr/local/bin/uv"` |
| `voxhelm_remote_worker_python_version` | `"3.14.8"` |
| `voxhelm_remote_worker_public_index_url` | `"https://pypi.org/simple"` |
| `voxhelm_remote_worker_package_name` | `"voxhelm"` |
| `voxhelm_remote_worker_package_version` | `"0.1.0"` |
| `voxhelm_remote_worker_package_extras` | `["diarization"]` |
| `voxhelm_remote_worker_binary_path` | `"{{ voxhelm_remote_worker_service_home }}/.local/bin/voxhelm-remote-worker"` |
| `voxhelm_remote_worker_force_install` | `false` |
| `voxhelm_remote_worker_base_url` | `""` |
| `voxhelm_remote_worker_id` | `"atlas"` |
| `voxhelm_remote_worker_hostname` | `"{{ inventory_hostname }}"` |
| `voxhelm_remote_worker_allowed_url_hosts` | `[]` |
| `voxhelm_remote_worker_private_url_hosts` | `[]` |
| `voxhelm_remote_worker_poll_seconds` | `5` |
| `voxhelm_remote_worker_http_timeout_seconds` | `60` |
| `voxhelm_remote_worker_heartbeat_interval_seconds` | `60` |
| `voxhelm_remote_worker_log_level` | `"INFO"` |
| `voxhelm_remote_worker_caffeinate_enabled` | `true` |
| `voxhelm_remote_worker_caffeinate_bin` | `"/usr/bin/caffeinate"` |
| `voxhelm_remote_worker_caffeinate_args` | `["-i", "-m", "-s"]` |
| `voxhelm_remote_worker_launchd_label` | `"de.wersdoerfer.voxhelm-remote-worker"` |
| `voxhelm_remote_worker_launchd_plist_path` | `"/Library/LaunchDaemons/{{ voxhelm_remote_worker_launchd_label }}.plist"` |
| `voxhelm_remote_worker_launchd_keepalive` | `true` |
| `voxhelm_remote_worker_launchd_manage_state` | `true` |
| `voxhelm_remote_worker_launchd_start_service` | `true` |
| `voxhelm_remote_worker_launchd_path` | `"/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"` |
| `voxhelm_remote_worker_brew_bin` | `""` |
| `voxhelm_remote_worker_brew_user` | `""` |
| `voxhelm_remote_worker_brew_update` | `false` |
| `voxhelm_remote_worker_brew_packages` | `["ffmpeg"]` |
| `voxhelm_remote_worker_stt_backend` | `"mlx"` |
| `voxhelm_remote_worker_stt_fallback_backend` | `"whispercpp"` |
| `voxhelm_remote_worker_mlx_model` | `"mlx-community/whisper-large-v3-mlx"` |
| `voxhelm_remote_worker_whispercpp_model` | `"ggml-large-v3.bin"` |
| `voxhelm_remote_worker_whispercpp_model_source` | `""` |
| `voxhelm_remote_worker_whispercpp_bin` | `"/opt/homebrew/bin/whisper-cli"` |
| `voxhelm_remote_worker_whispercpp_processors` | `4` |
| `voxhelm_remote_worker_whisperkit_enabled` | `false` |
| `voxhelm_remote_worker_whisperkit_base_url` | `"http://127.0.0.1:50060/v1"` |
| `voxhelm_remote_worker_whisperkit_model` | `"large-v3-v20240930"` |
| `voxhelm_remote_worker_stt_debug_logging` | `false` |
| `voxhelm_remote_worker_ffmpeg_bin` | `"/opt/homebrew/bin/ffmpeg"` |
| `voxhelm_remote_worker_model_cache_dir` | `"{{ voxhelm_remote_worker_service_home }}/Library/Caches/voxhelm/models"` |
| `voxhelm_remote_worker_parakeet_enabled` | `false` |
| `voxhelm_remote_worker_parakeet_package_version` | `"0.5.3"` |
| `voxhelm_remote_worker_parakeet_python_version` | `"3.13"` |
| `voxhelm_remote_worker_parakeet_bin` | `"{{ voxhelm_remote_worker_service_home }}/.local/bin/parakeet-mlx"` |
| `voxhelm_remote_worker_parakeet_model_repo` | `"mlx-community/parakeet-tdt-0.6b-v3"` |
| `voxhelm_remote_worker_parakeet_model_revision` | `"ed2b7e8c15f9aaa0b5772e2efb986255eaef7e15"` |
| `voxhelm_remote_worker_parakeet_model_sha256` | `"05e01c7f396c298cf7d23f61da7b504adeab698f0aaeafd9c82d198625464592"` |
| `voxhelm_remote_worker_parakeet_model_root` | `"{{ voxhelm_remote_worker_model_cache_dir }}/parakeet"` |
| `voxhelm_remote_worker_parakeet_model_dir` | `"{{ voxhelm_remote_worker_parakeet_model_root }}/{{ voxhelm_remote_worker_parakeet_model_revision }}"` |
| `voxhelm_remote_worker_parakeet_model_name` | `"parakeet-tdt-0.6b-v3"` |
| `voxhelm_remote_worker_parakeet_chunk_seconds` | `600` |
| `voxhelm_remote_worker_parakeet_overlap_seconds` | `30` |
| `voxhelm_remote_worker_parakeet_max_sentence_seconds` | `""` |
| `voxhelm_remote_worker_parakeet_timeout_seconds` | `1800` |
| `voxhelm_remote_worker_ad_analysis_enabled` | `false` |
| `voxhelm_remote_worker_ad_analysis_brew_packages` | `["whisper-cpp", "ffmpeg"]` |
| `voxhelm_remote_worker_window_model` | `"ggml-large-v3-turbo.bin"` |
| `voxhelm_remote_worker_window_model_url` | `"https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/ggml-large-v3-turbo.bin"` |
| `voxhelm_remote_worker_window_model_sha256` | `"1fc70f774d38eb169993ac391eea357ef47c88757ef72ee5943879b7e8e2bc69"` |
| `voxhelm_remote_worker_window_model_source` | `""` |
| `voxhelm_remote_worker_window_timeout_seconds` | `120` |
| `voxhelm_remote_worker_ffprobe_bin` | `"/opt/homebrew/bin/ffprobe"` |
| `voxhelm_remote_worker_diarization_backend` | `"pyannote"` |
| `voxhelm_remote_worker_pyannote_model` | `"pyannote/speaker-diarization-3.1"` |
| `voxhelm_remote_worker_pyannote_device` | `"auto"` |
| `voxhelm_remote_worker_artifact_backend` | `"s3"` |
| `voxhelm_remote_worker_artifact_bucket` | `"voxhelm"` |
| `voxhelm_remote_worker_artifact_prefix` | `"voxhelm"` |
| `voxhelm_remote_worker_artifact_s3_endpoint_url` | `""` |
| `voxhelm_remote_worker_artifact_s3_region` | `"us-east-1"` |
| `voxhelm_remote_worker_artifact_s3_force_path_style` | `true` |
