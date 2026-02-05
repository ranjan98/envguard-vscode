import * as vscode from 'vscode';

const SECRET_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key', pattern: /[A-Za-z0-9/+=]{40}/ },
  { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36}/ },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z-]+/ },
  { name: 'Stripe Live Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24,}/ },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/ },
  { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/ },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Firebase Key', pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/ },
];

const SECRET_KEYWORDS = [
  'password', 'secret', 'token', 'api_key', 'apikey',
  'auth', 'private', 'credential', 'key'
];

let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
  console.log('EnvGuard activated');

  diagnosticCollection = vscode.languages.createDiagnosticCollection('envguard');
  context.subscriptions.push(diagnosticCollection);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('envguard.validate', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor && isEnvFile(editor.document)) {
        validateDocument(editor.document);
        vscode.window.showInformationMessage('EnvGuard: Validation complete');
      } else {
        vscode.window.showWarningMessage('EnvGuard: Not an .env file');
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('envguard.scanSecrets', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor && isEnvFile(editor.document)) {
        const secrets = scanForSecrets(editor.document);
        if (secrets.length > 0) {
          vscode.window.showWarningMessage(
            `EnvGuard: Found ${secrets.length} potential secret(s)!`
          );
        } else {
          vscode.window.showInformationMessage('EnvGuard: No secrets detected');
        }
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('envguard.generateExample', async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor && isEnvFile(editor.document)) {
        await generateEnvExample(editor.document);
      }
    })
  );

  // Real-time validation
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (isEnvFile(event.document)) {
        validateDocument(event.document);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => {
      if (isEnvFile(document)) {
        validateDocument(document);
      }
    })
  );

  // Validate all open .env files
  vscode.workspace.textDocuments.forEach((document) => {
    if (isEnvFile(document)) {
      validateDocument(document);
    }
  });

  // Code actions for quick fixes
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { pattern: '**/.env*' },
      new EnvGuardCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );
}

function isEnvFile(document: vscode.TextDocument): boolean {
  const fileName = document.fileName.toLowerCase();
  return fileName.includes('.env');
}

interface EnvVariable {
  key: string;
  value: string;
  line: number;
  range: vscode.Range;
}

function parseEnvDocument(document: vscode.TextDocument): EnvVariable[] {
  const variables: EnvVariable[] = [];

  for (let i = 0; i < document.lineCount; i++) {
    const line = document.lineAt(i);
    const text = line.text.trim();

    if (!text || text.startsWith('#')) continue;

    const match = text.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (match) {
      const [, key, rawValue] = match;
      let value = rawValue.trim();

      // Remove quotes
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }

      variables.push({
        key,
        value,
        line: i,
        range: line.range
      });
    }
  }

  return variables;
}

function validateDocument(document: vscode.TextDocument): void {
  const config = vscode.workspace.getConfiguration('envguard');
  if (!config.get('enableRealTimeValidation', true)) return;

  const diagnostics: vscode.Diagnostic[] = [];
  const variables = parseEnvDocument(document);
  const showSecretWarnings = config.get('showSecretWarnings', true);

  for (const variable of variables) {
    // Check for empty values
    if (variable.value === '') {
      diagnostics.push(
        new vscode.Diagnostic(
          variable.range,
          `${variable.key} has an empty value`,
          vscode.DiagnosticSeverity.Warning
        )
      );
    }

    // Check for secrets
    if (showSecretWarnings) {
      const secretType = detectSecret(variable.key, variable.value);
      if (secretType) {
        const diagnostic = new vscode.Diagnostic(
          variable.range,
          `Potential secret detected: ${secretType}. Consider using a secrets manager.`,
          vscode.DiagnosticSeverity.Warning
        );
        diagnostic.code = 'secret-detected';
        diagnostic.source = 'EnvGuard';
        diagnostics.push(diagnostic);
      }
    }

    // Check for inline comments (common mistake)
    if (variable.value.includes(' #') && !variable.value.startsWith('"')) {
      diagnostics.push(
        new vscode.Diagnostic(
          variable.range,
          `Inline comment detected. This may not work as expected. Wrap value in quotes if # is part of the value.`,
          vscode.DiagnosticSeverity.Information
        )
      );
    }

    // Check for unquoted special characters
    if (/[&|;<>$`\\]/.test(variable.value) && !variable.value.startsWith('"') && !variable.value.startsWith("'")) {
      diagnostics.push(
        new vscode.Diagnostic(
          variable.range,
          `Value contains special characters. Consider wrapping in quotes.`,
          vscode.DiagnosticSeverity.Information
        )
      );
    }
  }

  // Check for duplicate keys
  const keyCount = new Map<string, number[]>();
  variables.forEach(v => {
    const lines = keyCount.get(v.key) || [];
    lines.push(v.line);
    keyCount.set(v.key, lines);
  });

  keyCount.forEach((lines, key) => {
    if (lines.length > 1) {
      lines.forEach(lineNum => {
        const line = document.lineAt(lineNum);
        diagnostics.push(
          new vscode.Diagnostic(
            line.range,
            `Duplicate key: ${key} (also on line ${lines.filter(l => l !== lineNum).map(l => l + 1).join(', ')})`,
            vscode.DiagnosticSeverity.Error
          )
        );
      });
    }
  });

  diagnosticCollection.set(document.uri, diagnostics);
}

function detectSecret(key: string, value: string): string | null {
  // Check against known patterns
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(value)) {
      return name;
    }
  }

  // Check for likely secrets based on key name
  const lowerKey = key.toLowerCase();
  const hasSecretKeyword = SECRET_KEYWORDS.some(kw => lowerKey.includes(kw));
  const hasEnoughEntropy = value.length > 16 && /[A-Za-z0-9+/=]/.test(value);

  if (hasSecretKeyword && hasEnoughEntropy) {
    return 'Likely secret (high-entropy value with sensitive key name)';
  }

  return null;
}

function scanForSecrets(document: vscode.TextDocument): string[] {
  const variables = parseEnvDocument(document);
  const secrets: string[] = [];

  for (const variable of variables) {
    const secretType = detectSecret(variable.key, variable.value);
    if (secretType) {
      secrets.push(`${variable.key}: ${secretType}`);
    }
  }

  return secrets;
}

async function generateEnvExample(document: vscode.TextDocument): Promise<void> {
  const variables = parseEnvDocument(document);
  let output = '# Generated by EnvGuard\n';
  output += `# Template from ${document.fileName.split('/').pop()}\n\n`;

  for (const variable of variables) {
    let placeholder = variable.value;
    const secretType = detectSecret(variable.key, variable.value);

    if (secretType) {
      placeholder = `your-${variable.key.toLowerCase().replace(/_/g, '-')}-here`;
    } else if (/^\d+$/.test(variable.value)) {
      // Keep numeric values
      placeholder = variable.value;
    } else if (variable.value === 'true' || variable.value === 'false') {
      // Keep boolean values
      placeholder = variable.value;
    } else if (variable.value.includes('://')) {
      // URL - keep protocol
      const [protocol] = variable.value.split('://');
      placeholder = `${protocol}://your-url-here`;
    }

    output += `${variable.key}=${placeholder}\n`;
  }

  const dir = document.uri.fsPath.replace(/[^/\\]+$/, '');
  const examplePath = vscode.Uri.file(dir + '.env.example');

  await vscode.workspace.fs.writeFile(examplePath, Buffer.from(output, 'utf-8'));
  vscode.window.showInformationMessage(`EnvGuard: Created ${examplePath.fsPath}`);

  const doc = await vscode.workspace.openTextDocument(examplePath);
  await vscode.window.showTextDocument(doc);
}

class EnvGuardCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'EnvGuard') continue;

      const line = document.lineAt(range.start.line);
      const text = line.text;

      // Quick fix: wrap value in quotes
      if (diagnostic.message.includes('special characters') ||
          diagnostic.message.includes('Inline comment')) {
        const match = text.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
        if (match) {
          const [, key, value] = match;
          const action = new vscode.CodeAction(
            'Wrap value in quotes',
            vscode.CodeActionKind.QuickFix
          );
          action.edit = new vscode.WorkspaceEdit();
          action.edit.replace(
            document.uri,
            line.range,
            `${key}="${value}"`
          );
          actions.push(action);
        }
      }

      // Quick fix: mask secret
      if (diagnostic.code === 'secret-detected') {
        const action = new vscode.CodeAction(
          'Replace with placeholder',
          vscode.CodeActionKind.QuickFix
        );
        const match = text.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
        if (match) {
          const [, key] = match;
          action.edit = new vscode.WorkspaceEdit();
          action.edit.replace(
            document.uri,
            line.range,
            `${key}=your-${key.toLowerCase().replace(/_/g, '-')}-here`
          );
          actions.push(action);
        }
      }
    }

    return actions;
  }
}

export function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
}
