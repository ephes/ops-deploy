# Native Voxhelm control plane

`VoxhelmConfig` / `deploy_voxhelm` ports the authoritative ops-library role at `56495f75` (2.75.1). It supports the existing Darwin/launchd contract. Native qualification of this implementation is pending.

This API retains the root-owned control plane, optional local worker, Wyoming and WhisperKit sidecars, shared model layout and periodic pruning configuration. False sidecar flags leave their previous deployment unmanaged, matching the role. Pruning is different: disabling it while launchd management is enabled unloads it and removes its plist/script. Enabling it loads the configured interval/calendar schedule with `RunAtLoad=false`; deployment never kickstarts pruning.

The selected Python version and source package metadata are inspected before any dependency sync. A current environment is retained, including patched certifi/trust bytes. Deliberate source/runtime changes select the original frozen uv sync and appropriate restarts; as in the role, running units keep serving during the sync and are restarted afterwards, and a pending marker keeps that restart owed if the sync fails. Database migration and bootstrap precede launchd convergence. Bootstrap uses the actual Django password checker with `setter=None` against read-only SQLite; matching password/email/flags cause no `set_password` or save and preserve IDs, hash and timestamps. Password input uses the existing redacted stdin probe/operation primitives.

`source_preservation_revision` with `source_overrides` can retain explicitly supplied public blobs for one exact clean controller revision. The checksum rsync protects those paths, and ordinary file operations retain the supplied bytes. A changed revision or deliberately edited working tree automatically resumes ordinary rsync/update behavior; there is no source cache or permanent source hold.

`preserved_artifacts` describes existing bytes by path, file/link type, inode, size, mtime and ownership. Its historical pin is **continuity input, not a cryptographic integrity attestation**. Matching probes read no model body and create no marker or staging. A changed/new artifact with a configured pin (every Kokoro artifact, and the whisper.cpp model when `voxhelm_whispercpp_model_sha256` is set) is fully checksum-verified before replacement and records provenance after publication. As in the role, the whisper.cpp model without that pin (the default) and Piper voices (`piper.download_voices`, upstream unpinned) are downloaded **without** checksum verification or provenance; set the pin to require verification. A native record for a path takes precedence over the initial mapping, including a later rollback. Existing model bytes are never claimed rehashed by a no-op.

Homebrew and its selected owner remain prerequisites. Missing declared formulae are installed; normal deployment does not upgrade existing formulae. Presence uses the role's per-formula `brew list --versions` check, which also resolves renamed formulae such as `whisper-cpp` (now `whisper.cpp`). The native uv base API is a separate composition step where the playbook included it. Source sync uses the existing `sync_tree` checksum dry-run, explicit already-installed modern `remote_rsync_path` (default `/opt/homebrew/bin/rsync`) and a real preceding preparation operation for a fresh destination. Existing excluded data, virtualenvs and Git metadata are preserved.

```python
from ops_deploy.services.voxhelm import VoxhelmConfig, deploy_voxhelm

cfg = VoxhelmConfig(voxhelm_source_path="/workspaces/voxhelm", voxhelm_bootstrap_operator_username="operator")
deploy_voxhelm(cfg, prepared_secret_values)
```

Secrets are a separate mapping, never config/argv/host data. The mapping uses these original role variable names:

- `voxhelm_worker_tokens_env`
- `voxhelm_huggingface_token`
- `voxhelm_artifact_s3_access_key_id`
- `voxhelm_artifact_s3_secret_access_key`
- `voxhelm_django_secret_key`
- `voxhelm_bearer_tokens_env`
- `voxhelm_bootstrap_operator_password`

Configuration retains the original public variable names. Computed defaults below resolve from other configured inputs before connection.

| Input | Default |
| --- | --- |
| `remote_rsync_path` | `"/opt/homebrew/bin/rsync"` |
| `preserved_artifacts` | `{}` |
| `voxhelm_whispercpp_model_sha256` | `""` |
| `source_preservation_revision` | `""` |
| `source_overrides` | `{}` |
| `inventory_hostname` | `"runner"` |
| `voxhelm_service_name` | `"voxhelm"` |
| `voxhelm_source_path` | `""` |
| `voxhelm_sync_excludes` | `[".vault_password", ".git", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__", "db.sqlite3", "var"]` |
| `voxhelm_app_dir` | `"/opt/apps/voxhelm/site"` |
| `voxhelm_config_dir` | `"/etc/voxhelm"` |
| `voxhelm_log_dir` | `"/var/log/voxhelm"` |
| `voxhelm_start_script_path` | `"{{ voxhelm_app_dir }}/start.sh"` |
| `voxhelm_worker_script_path` | `"{{ voxhelm_app_dir }}/worker.sh"` |
| `voxhelm_wyoming_stt_script_path` | `"{{ voxhelm_app_dir }}/wyoming-stt.sh"` |
| `voxhelm_whisperkit_script_path` | `"{{ voxhelm_app_dir }}/whisperkit.sh"` |
| `voxhelm_prune_script_path` | `"{{ voxhelm_app_dir }}/prune.sh"` |
| `voxhelm_uv_bin` | `"/usr/local/bin/uv"` |
| `voxhelm_python_version` | `"3.14.8"` |
| `voxhelm_bind_host` | `"0.0.0.0"` |
| `voxhelm_app_port` | `8787` |
| `voxhelm_uvicorn_log_level` | `"info"` |
| `voxhelm_task_backend` | `"django_tasks_db.backend.DatabaseBackend"` |
| `voxhelm_task_queue` | `"default"` |
| `voxhelm_transcription_execution_mode` | `"django_tasks"` |
| `voxhelm_remote_worker_lease_seconds` | `1800` |
| `voxhelm_remote_worker_poll_seconds` | `5` |
| `voxhelm_remote_worker_max_attempts` | `3` |
| `voxhelm_worker_enabled` | `true` |
| `voxhelm_worker_interval_seconds` | `1` |
| `voxhelm_worker_label` | `"de.wersdoerfer.voxhelm-worker"` |
| `voxhelm_worker_plist_path` | `"/Library/LaunchDaemons/{{ voxhelm_worker_label }}.plist"` |
| `voxhelm_worker_stdout_log` | `"{{ voxhelm_log_dir }}/voxhelm-worker.log"` |
| `voxhelm_worker_stderr_log` | `"{{ voxhelm_log_dir }}/voxhelm-worker.err.log"` |
| `voxhelm_wyoming_stt_enabled` | `true` |
| `voxhelm_wyoming_stt_label` | `"de.wersdoerfer.voxhelm-wyoming-stt"` |
| `voxhelm_wyoming_stt_plist_path` | `"/Library/LaunchDaemons/{{ voxhelm_wyoming_stt_label }}.plist"` |
| `voxhelm_wyoming_stt_stdout_log` | `"{{ voxhelm_log_dir }}/voxhelm-wyoming-stt.log"` |
| `voxhelm_wyoming_stt_stderr_log` | `"{{ voxhelm_log_dir }}/voxhelm-wyoming-stt.err.log"` |
| `voxhelm_prune_enabled` | `false` |
| `voxhelm_prune_dry_run` | `true` |
| `voxhelm_prune_interval_seconds` | `3600` |
| `voxhelm_prune_daily_time` | `""` |
| `voxhelm_prune_label` | `"de.wersdoerfer.voxhelm-prune"` |
| `voxhelm_prune_plist_path` | `"/Library/LaunchDaemons/{{ voxhelm_prune_label }}.plist"` |
| `voxhelm_prune_stdout_log` | `"{{ voxhelm_log_dir }}/voxhelm-prune.log"` |
| `voxhelm_prune_stderr_log` | `"{{ voxhelm_log_dir }}/voxhelm-prune.err.log"` |
| `voxhelm_source_artifact_retention_seconds` | `""` |
| `voxhelm_job_metadata_retention_seconds` | `""` |
| `voxhelm_staged_input_retention_seconds` | `""` |
| `voxhelm_wyoming_stt_max_audio_seconds` | `""` |
| `voxhelm_private_url_hosts` | `[]` |
| `voxhelm_batch_max_download_bytes` | `536870912` |
| `voxhelm_ffmpeg_bin` | `"/opt/homebrew/bin/ffmpeg"` |
| `voxhelm_stt_backend` | `"whispercpp"` |
| `voxhelm_stt_fallback_backend` | `"mlx"` |
| `voxhelm_known_speaker_stt_backend` | `""` |
| `voxhelm_stt_debug_logging` | `false` |
| `voxhelm_diarization_backend` | `"none"` |
| `voxhelm_pyannote_model` | `"pyannote/speaker-diarization-3.1"` |
| `voxhelm_pyannote_device` | `"auto"` |
| `voxhelm_uv_extras` | `[]` |
| `voxhelm_tts_backend` | `"piper"` |
| `voxhelm_tts_max_input_chars` | `5000` |
| `voxhelm_model_cache_dir` | `"{{ voxhelm_app_dir }}/var/models"` |
| `voxhelm_piper_voice_dir` | `"{{ voxhelm_app_dir }}/var/piper"` |
| `voxhelm_piper_voices` | `["en_US-lessac-medium", "de_DE-thorsten-high"]` |
| `voxhelm_piper_default_voice` | `"en_US-lessac-medium"` |
| `voxhelm_piper_language_voices` | `{"en": "en_US-lessac-medium", "en_US": "en_US-lessac-medium", "de": "de_DE-thorsten-high", "de_DE": "de_DE-thorsten-high"}` |
| `voxhelm_tts_kokoro_enabled` | `false` |
| `voxhelm_tts_language_routing_enabled` | `false` |
| `voxhelm_kokoro_model_dir` | `"{{ voxhelm_app_dir }}/var/kokoro"` |
| `voxhelm_kokoro_models` | `{"kokoro-af_heart": {"model_file": "kokoro-v1.0.onnx", "voicepack_file": "voices-v1.0.bin", "voicepack_key": "af_heart", "phoneme_language": "en-us"}, "kokoro-martin": {"model_file": "kokoro-martin.onnx", "voicepack_file": "voices-martin.npz", "voicepack_key": "martin", "phoneme_language": "de"}}` |
| `voxhelm_kokoro_default_voice` | `""` |
| `voxhelm_tts_language_voices` | `{"de": "de_DE-thorsten-high", "en": "en_US-lessac-medium"}` |
| `voxhelm_espeak_library` | `"/opt/homebrew/lib/libespeak-ng.dylib"` |
| `voxhelm_kokoro_artifacts` | `[{"url": "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/kokoro-v1.0.onnx", "sha256": "7d5df8ecf7d4b1878015a32686053fd0eebe2bc377234608764cc0ef3636a6c5", "dest": "kokoro-v1.0.onnx"}, {"url": "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/kokoro-v1.0.int8.onnx", "sha256": "6e742170d309016e5891a994e1ce1559c702a2ccd0075e67ef7157974f6406cb", "dest": "kokoro-v1.0.int8.onnx"}, {"url": "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/voices-v1.0.bin", "sha256": "bca610b8308e8d99f32e6fe4197e7ec01679264efed0cac9140fe9c29f1fbf7d", "dest": "voices-v1.0.bin"}, {"url": "https://huggingface.co/Godelaune/Kokoro-82M-ONNX-German-Martin/resolve/main/kokoro-martin.onnx", "sha256": "c302f1d8bc7adf40a842cb550e18c39a5026bdb1afdd29dbb700b501cb49276b", "dest": "kokoro-martin.onnx"}, {"url": "https://huggingface.co/Godelaune/Kokoro-82M-ONNX-German-Martin/resolve/main/voices-martin.npz", "sha256": "5b9c8553398d7abf67498ce500c186cefaa7b68fed3e3d415da5380670105acd", "dest": "voices-martin.npz"}]` |
| `voxhelm_wyoming_stt_host` | `"0.0.0.0"` |
| `voxhelm_wyoming_stt_port` | `10300` |
| `voxhelm_wyoming_stt_backend` | `"mlx"` |
| `voxhelm_wyoming_stt_model` | `""` |
| `voxhelm_wyoming_stt_language` | `""` |
| `voxhelm_wyoming_stt_languages` | `["de", "en"]` |
| `voxhelm_wyoming_stt_prompt` | `""` |
| `voxhelm_wyoming_stt_normalize_transcript` | `true` |
| `voxhelm_wyoming_samples_per_chunk` | `1024` |
| `voxhelm_lane_scheduler_enabled` | `true` |
| `voxhelm_lane_scheduler_dir` | `"{{ voxhelm_app_dir }}/var/lane-scheduler"` |
| `voxhelm_lane_scheduler_stale_seconds` | `1800` |
| `voxhelm_lane_scheduler_interactive_slots` | `1` |
| `voxhelm_lane_scheduler_non_interactive_slots` | `1` |
| `voxhelm_artifact_backend` | `"filesystem"` |
| `voxhelm_artifact_root` | `"{{ voxhelm_app_dir }}/var/artifacts"` |
| `voxhelm_artifact_bucket` | `"voxhelm"` |
| `voxhelm_artifact_prefix` | `"voxhelm"` |
| `voxhelm_artifact_s3_endpoint_url` | `""` |
| `voxhelm_artifact_s3_region` | `"us-east-1"` |
| `voxhelm_artifact_s3_force_path_style` | `true` |
| `voxhelm_bootstrap_operator_username` | `"CHANGEME"` |
| `voxhelm_bootstrap_operator_email` | `""` |
| `voxhelm_allowed_hosts` | `["studio.tailde2ec.ts.net", "studio", "localhost", "127.0.0.1"]` |
| `voxhelm_csrf_trusted_origins` | `[]` |
| `voxhelm_mlx_model` | `"mlx-community/whisper-large-v3-mlx"` |
| `voxhelm_whispercpp_model` | `"ggml-large-v3.bin"` |
| `voxhelm_whispercpp_model_url` | `"https://huggingface.co/ggerganov/whisper.cpp/resolve/main/{{ voxhelm_whispercpp_model }}"` |
| `voxhelm_whispercpp_bin` | `"/opt/homebrew/bin/whisper-cli"` |
| `voxhelm_whispercpp_processors` | `4` |
| `voxhelm_whisperkit_enabled` | `false` |
| `voxhelm_whisperkit_cli_bin` | `"/opt/homebrew/bin/whisperkit-cli"` |
| `voxhelm_whisperkit_host` | `"127.0.0.1"` |
| `voxhelm_whisperkit_port` | `50060` |
| `voxhelm_whisperkit_base_url` | `"http://127.0.0.1:{{ voxhelm_whisperkit_port }}/v1"` |
| `voxhelm_whisperkit_model` | `"large-v3-v20240930"` |
| `voxhelm_whisperkit_audio_encoder_compute_units` | `"cpuAndGPU"` |
| `voxhelm_whisperkit_text_decoder_compute_units` | `"cpuAndGPU"` |
| `voxhelm_whisperkit_concurrent_worker_count` | `8` |
| `voxhelm_whisperkit_chunking_strategy` | `"vad"` |
| `voxhelm_whisperkit_timeout_seconds` | `900` |
| `voxhelm_whisperkit_label` | `"de.wersdoerfer.voxhelm-whisperkit"` |
| `voxhelm_whisperkit_plist_path` | `"/Library/LaunchDaemons/{{ voxhelm_whisperkit_label }}.plist"` |
| `voxhelm_whisperkit_stdout_log` | `"{{ voxhelm_log_dir }}/voxhelm-whisperkit.log"` |
| `voxhelm_whisperkit_stderr_log` | `"{{ voxhelm_log_dir }}/voxhelm-whisperkit.err.log"` |
| `voxhelm_brew_bin` | `""` |
| `voxhelm_brew_user` | `""` |
| `voxhelm_brew_update` | `false` |
| `voxhelm_allowed_url_hosts` | `[]` |
| `voxhelm_trusted_http_hosts` | `[]` |
| `voxhelm_max_upload_bytes` | `26214400` |
| `voxhelm_max_url_download_bytes` | `134217728` |
| `voxhelm_url_fetch_timeout_seconds` | `60` |
| `voxhelm_launchd_label` | `"de.wersdoerfer.voxhelm"` |
| `voxhelm_launchd_plist_path` | `"/Library/LaunchDaemons/{{ voxhelm_launchd_label }}.plist"` |
| `voxhelm_launchd_path` | `"/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"` |
| `voxhelm_launchd_keepalive` | `true` |
| `voxhelm_launchd_manage_state` | `true` |
| `voxhelm_launchd_start_service` | `true` |
| `voxhelm_launchd_stdout_log` | `"{{ voxhelm_log_dir }}/voxhelm.log"` |
| `voxhelm_launchd_stderr_log` | `"{{ voxhelm_log_dir }}/voxhelm.err.log"` |
| `voxhelm_healthcheck_enabled` | `true` |
| `voxhelm_healthcheck_url` | `"http://127.0.0.1:{{ voxhelm_app_port }}/v1/health"` |
| `voxhelm_healthcheck_retries` | `15` |
| `voxhelm_healthcheck_delay` | `2` |
