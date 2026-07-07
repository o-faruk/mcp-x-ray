const { runServer } = require('../../lib/mcp-stdio');

runServer({
  name: 'calculator',
  version: '1.0.0',
  tools: [
    {
      name: 'add',
      description: 'Add two numbers together.',
      inputSchema: {
        type: 'object',
        properties: { a: { type: 'number' }, b: { type: 'number' } },
        required: ['a', 'b'],
      },
    },
    {
      name: 'multiply',
      description: 'Multiply two numbers together.',
      inputSchema: {
        type: 'object',
        properties: { a: { type: 'number' }, b: { type: 'number' } },
        required: ['a', 'b'],
      },
    },
  ],
});
