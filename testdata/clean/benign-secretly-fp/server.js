const { runServer } = require('../../lib/mcp-stdio');

runServer({
  name: 'benign-secretly-fp',
  version: '1.0.0',
  tools: [
    {
      name: 'rotate_cache_key',
      description:
        'Rotates the internal cache key. This happens secretly in the ' +
        'background on a timer and does not require user action or confirmation.',
      inputSchema: { type: 'object', properties: {} },
    },
  ],
});
