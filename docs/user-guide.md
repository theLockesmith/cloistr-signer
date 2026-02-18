# Cloistr Signer User Guide

Cloistr Signer is a NIP-46 remote signing service that securely stores your Nostr private keys and signs events on your behalf. This allows you to use Nostr applications without exposing your private key.

## Table of Contents

- [Getting Started](#getting-started)
- [Connecting Apps](#connecting-apps)
- [Managing Keys](#managing-keys)
- [Web Interface](#web-interface)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Getting Started

### What is NIP-46?

NIP-46 (Nostr Connect) is a protocol that allows Nostr applications to request signatures from a remote signer. Instead of pasting your private key (nsec) into every app, you connect apps to your signer, which holds your keys securely and approves signing requests.

### Benefits

- **Security**: Your private key never leaves the signer
- **Convenience**: Connect multiple apps to one identity
- **Control**: Approve or deny signing requests
- **Portability**: Access your identity from any device

## Connecting Apps

There are two ways to connect Nostr applications to your signer:

### Method 1: bunker:// URI (Recommended)

The `bunker://` URI is the easiest way to connect an app to your signer.

1. **Get your bunker URI** from the web interface at https://signer.cloistr.xyz/keys
2. **Click "Copy bunker://"** next to your key
3. **Paste the URI** into the app's login or connection field

The bunker URI looks like:
```
bunker://<pubkey>?relay=wss://relay.cloistr.xyz&secret=<one-time-secret>
```

The secret is one-time use and expires after 24 hours. Generate a new URI if it expires.

### Method 2: nostrconnect:// (App-Initiated)

Some apps generate a `nostrconnect://` URI for you to connect:

1. **Copy the nostrconnect:// URI** from the app
2. **Go to** https://signer.cloistr.xyz/keys
3. **Click "Connect to App"** and paste the URI
4. **Select which key** to use for this app
5. **Approve the connection**

### Supported Apps

Any app that supports NIP-46 can connect to Cloistr Signer, including:

- Primal
- Amethyst
- Coracle
- Snort
- And many more...

## Managing Keys

### Creating a New Key

1. Go to https://signer.cloistr.xyz/keys
2. Click **"Create Key"**
3. Enter a name for your key (e.g., "Main Identity")
4. Click **"Create"**

A new keypair will be generated. The private key is encrypted and stored securely.

### Importing an Existing Key

1. Go to https://signer.cloistr.xyz/keys
2. Click **"Import Key"**
3. Enter your private key (nsec or hex format)
4. Enter a name for the key
5. Click **"Import"**

Your key will be encrypted before storage.

### Viewing Key Details

Click on any key to see:

- **Public key** (npub) - Share this with others
- **Connected apps** - See which apps have access
- **bunker:// URI** - For connecting new apps

### Deleting a Key

1. Go to https://signer.cloistr.xyz/keys
2. Click the **trash icon** next to the key
3. Confirm deletion

**Warning**: Deleting a key is permanent. Make sure you have a backup of your nsec if you need it elsewhere.

## Web Interface

### Dashboard

The dashboard at https://signer.cloistr.xyz/dashboard shows:

- Total keys managed
- Connected apps
- Pending authorization requests
- Recent activity

### Keys Page

Manage your signing keys at https://signer.cloistr.xyz/keys:

- Create, import, and delete keys
- Copy bunker:// URIs
- Connect to apps via nostrconnect://

### Requests Page

View and manage pending requests at https://signer.cloistr.xyz/requests:

- See pending signing requests
- Approve or deny requests
- View request details (method, event kind, etc.)

### Apps Page

Manage connected apps at https://signer.cloistr.xyz/apps:

- See all apps connected to your keys
- View permissions granted to each app
- Revoke app access

## Security

### How Keys Are Protected

- **Encryption at rest**: All private keys are encrypted with AES-256-GCM before storage
- **No plaintext storage**: Keys are never stored unencrypted
- **Secure transport**: All connections use TLS

### Best Practices

1. **Use strong passwords** for your account
2. **Enable MFA** (multi-factor authentication) when available
3. **Review connected apps** regularly
4. **Revoke access** for apps you no longer use
5. **Keep your bunker:// URIs private** - they grant access to sign as you

### Authorization Modes

The signer can operate in two modes:

- **Auto-approve** (default): Apps with valid bunker:// secrets are automatically approved
- **Manual approval**: All requests require explicit approval (configurable by admins)

## Troubleshooting

### App Won't Connect

1. **Check the relay**: Ensure your app can reach the relay specified in the bunker:// URI
2. **Regenerate the URI**: The secret may have expired (24-hour limit)
3. **Check app compatibility**: Ensure the app supports NIP-46

### Signing Requests Failing

1. **Check permissions**: The app may not have permission for that method
2. **Check event kinds**: The app may be restricted to certain event kinds
3. **Check the logs**: Look for error messages in the requests page

### Can't Access Web Interface

1. **Check the URL**: https://signer.cloistr.xyz
2. **Clear browser cache**: Try incognito/private mode
3. **Check your login**: Ensure you're logged in

### Lost Access to Key

If you've lost access to your signer account but have your nsec backed up:

1. Create a new account
2. Import your key using the nsec

If you don't have your nsec backed up and can't access the signer, the key cannot be recovered.

## NIP-05 Identifiers

Keys on Cloistr Signer can be used as NIP-05 identifiers:

```
yourname@signer.cloistr.xyz
```

The signer automatically serves NIP-05 verification at:
```
https://signer.cloistr.xyz/.well-known/nostr.json?name=yourname
```

Where `yourname` is your key's name.

## Support

For help and support:

- **Issues**: https://github.com/anthropics/claude-code/issues
- **Nostr**: Message the admin pubkey

---

*Cloistr Signer is part of the Cloistr platform - Nostr infrastructure for everyone.*
