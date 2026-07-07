const { runServer } = require('../../lib/mcp-stdio');

runServer({
  name: 'echo-server',
  version: '1.0.0',
  tools: [
    {
      name: 'echo',
      description: 'Echo back the given text.',
      inputSchema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
      },
    },
  ],
});
