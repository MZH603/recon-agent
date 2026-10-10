// Real frontend entrypoints with a local bridge fixture; no internal module imports.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {stripVTControlCharacters} from 'node:util';

for (const [entry, event, marker] of [
  ['app.mjs', {type: 'note', text: 'session-smoke-ready'}, 'session-smoke-ready'],
  ['setup-app.mjs', {type: 'defaults', target: 'setup-smoke.invalid',
    api_base: 'http://127.0.0.1:1/v1', model: 'fixture', key_available: false}, 'setup-smoke.invalid'],
]) {
  test(`${entry} starts, authenticates, renders and exits`, {timeout: 20000}, async t => {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    let socket;
    let hello;
    let stdout = '';
    let stderr = '';
    let shutdown = false;
    const token = 'local-smoke-token';
    const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP']);
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toUpperCase())));
    Object.assign(env, {RECON_TUI_PORT: String(server.address().port), RECON_TUI_TOKEN: token, TERM: 'xterm-256color'});
    server.on('connection', client => {
      socket = client;
      let pending = '';
      client.on('error', () => {});
      client.on('data', bytes => {
        pending += bytes.toString('utf8');
        const index = pending.indexOf('\n');
        if (index < 0 || hello) return;
        hello = JSON.parse(pending.slice(0, index));
        client.write(JSON.stringify(event) + '\n');
      });
    });
    const child = spawn(process.execPath, [fileURLToPath(new URL(`../../cli/tui/${entry}`, import.meta.url))],
      {env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
    t.after(() => {
      if (!shutdown) t.diagnostic(`hello=${JSON.stringify(hello)} stdout=${JSON.stringify(stdout)} stderr=${stderr}`);
      child.stdin.destroy();
      if (child.exitCode === null) child.kill();
      socket?.destroy();
      server.close();
    });
    child.stdout.on('data', bytes => {
      stdout += bytes.toString('utf8');
      if (!shutdown && stripVTControlCharacters(stdout).includes(marker)) {
        shutdown = true;
        socket.write(JSON.stringify({type: 'shutdown', code: 0}) + '\n');
      }
    });
    child.stderr.on('data', bytes => {stderr += bytes.toString('utf8');});
    const code = await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error(
        `Frontend did not render/exit. hello=${JSON.stringify(hello)} stdout=${stdout} stderr=${stderr}`)), 15000);
      t.after(() => clearTimeout(deadline));
      child.once('error', reject);
      child.once('close', resolve);
    });
    assert.equal(code, 0, stdout + stderr);
    assert.deepEqual(hello, {type: 'hello', token});
    assert.ok(shutdown && stripVTControlCharacters(stdout).includes(marker), stdout + stderr);
  });
}
