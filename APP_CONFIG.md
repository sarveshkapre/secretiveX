# App Configuration

Use this guide to configure SecretiveX with apps and shells.

## Shell Configuration

1. Ensure your shell exports `SSH_AUTH_SOCK` to the SecretiveX agent socket.
2. Restart your shell session.
3. Verify with:
   - `echo $SSH_AUTH_SOCK`
   - `ssh-add -L`

## App Configuration

1. Confirm the app supports `SSH_AUTH_SOCK` or custom SSH agent paths.
2. Point it to the same agent socket used by your shell.
3. Validate with a test SSH operation and confirm key usage in SecretiveX logs.

For troubleshooting, see `FAQ.md`.
