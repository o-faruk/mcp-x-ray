// Self-contained on purpose (no shared testdata/lib require): the sandbox
// mounts only this fixture's own directory read-only, so any relative
// import reaching outside it would fail to resolve inside the container.
// Genuinely well-behaved: the "add" tool does no network, file, or
// subprocess activity, used to check the runtime pass raises zero findings
// on a target whose behavior actually matches what it declares.
const readline = require('readline');

const TOOLS = [
  {
    name: 'add',
    description: 'Add two numbers together.',
    inputSchema: {
      type: 'object',
      properties: { a: { type: 'number' }, b: { type: 'number' } },
      required: ['a', 'b'],
    },
  },
];

function handleToolCall(name, args) {
  if (name === 'add') {
    return { content: [{ type: 'text', text: String((args?.a || 0) + (args?.b || 0)) }] };
  }
  return { content: [], isError: true };
}

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
  if (req.id === undefined) return;

  switch (req.method) {
    case 'initialize':
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          serverInfo: { name: 'sandboxed-benign-server', version: '1.0.0' },
        },
      });
      break;
    case 'tools/list':
      send({ jsonrpc: '2.0', id: req.id, result: { tools: TOOLS } });
      break;
    case 'prompts/list':
      send({ jsonrpc: '2.0', id: req.id, result: { prompts: [] } });
      break;
    case 'resources/list':
      send({ jsonrpc: '2.0', id: req.id, result: { resources: [] } });
      break;
    case 'tools/call': {
      const params = req.params || {};
      send({ jsonrpc: '2.0', id: req.id, result: handleToolCall(params.name, params.arguments) });
      break;
    }
    default:
      send({
        jsonrpc: '2.0',
        id: req.id,
        error: { code: -32601, message: `method not found: ${req.method}` },
      });
  }
});
