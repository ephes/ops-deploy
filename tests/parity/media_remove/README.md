# Original media removal sources

These public role/default/handler snapshots are exact ops-library originals at
`cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641`, independently byte-compared before
copying. The manifest records each original path and SHA256. They document the
finite removal contract without changing the global deploy-default census.

The public implementation deliberately gates Navidrome/Jellyfin unconditional
daemon reload to actual unit removal. MeTube retains its two change-triggered
handlers at task completion. Account removal preserves original home deletion;
genuine account/group errors remain failures. No media target is inferred from
deploy defaults that the removal role does not reference.
