// Minimal hand-rolled MCP stdio server harness for test fixtures. No
// @modelcontextprotocol/sdk dependency, so fixtures need nothing beyond a
// system `node` binary. Handles just enough of the protocol for mcp-x-ray's
// static introspection pass: initialize, and the three *_list methods.
const readline = require('readline');

function runServer({ name, version, tools = [], prompts = [], resources = [] }) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  function send(msg) {
    process.stdout.write(JSON.stringify(msg) + '\n');
  }

  rl.on('line', (line) => {
    line = line.trim();
    if (!line) return;
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      return;
    }
    if (req.id === undefined) return; // notification, nothing to reply to

    switch (req.method) {
      case 'initialize':
        send({
          jsonrpc: '2.0',
          id: req.id,
          result: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            serverInfo: { name, version },
          },
        });
        break;
      case 'tools/list':
        send({ jsonrpc: '2.0', id: req.id, result: { tools } });
        break;
      case 'prompts/list':
        send({ jsonrpc: '2.0', id: req.id, result: { prompts } });
        break;
      case 'resources/list':
        send({ jsonrpc: '2.0', id: req.id, result: { resources } });
        break;
      default:
        send({
          jsonrpc: '2.0',
          id: req.id,
          error: { code: -32601, message: `method not found: ${req.method}` },
        });
    }
  });
}

module.exports = { runServer };
