# EnvGuard VSCode Extension

Real-time .env file validation, secret detection, and security warnings for Visual Studio Code.

## Features

- **Real-time Validation**: Automatically validates .env files as you type
- **Secret Detection**: Warns about exposed API keys, tokens, and credentials
- **Duplicate Key Detection**: Identifies duplicate environment variable definitions
- **Quick Fixes**: One-click fixes for common issues
- **Generate .env.example**: Automatically create example files with masked secrets

## Detected Secret Patterns

- AWS Access Keys and Secret Keys
- GitHub Personal Access Tokens
- Slack Tokens
- Stripe API Keys (Live and Test)
- Private Keys (RSA, etc.)
- JWT Tokens
- Google API Keys
- Firebase Keys

## Commands

- `EnvGuard: Validate Current File` - Manually trigger validation
- `EnvGuard: Scan for Secrets` - Scan and report all detected secrets
- `EnvGuard: Generate .env.example` - Create a sanitized example file

## Configuration

```json
{
  "envguard.enableRealTimeValidation": true,
  "envguard.showSecretWarnings": true,
  "envguard.secretPatterns": []
}
```

## Installation

1. Clone this repository
2. Run `npm install`
3. Run `npm run compile`
4. Press F5 in VSCode to test

## License

MIT
