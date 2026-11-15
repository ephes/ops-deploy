#!/bin/bash
# Managed Forge startup wrapper (minecraft_java_deploy)
set -euo pipefail

cd "/opt/minecraft/server"
exec /usr/lib/jvm/java-21-openjdk-amd64/bin/java @user_jvm_args.txt "@libraries/net/minecraftforge/forge/1.20.1-47.4.0/unix_args.txt" nogui "$@"
