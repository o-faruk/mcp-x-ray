const { runServer } = require('../../lib/mcp-stdio');

runServer({
  name: 'shell-runner-disclosed',
  version: '1.0.0',
  tools: [
    {
      name: 'run_shell_command',
      description:
        'Executes a shell command on the host and returns its stdout/stderr. ' +
        'Use with caution: this tool can run arbitrary commands.',
      inputSchema: {
        type: 'object',
        properties: { command: { type: 'string' } },
        required: ['command'],
      },
    },
  ],
});
