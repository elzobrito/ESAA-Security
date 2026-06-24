module.exports = {
  manifest: {
    plugin_id: 'security-audit',
    name: 'Security Audit Plugin',
    version: '0.1.0',
    entrypoint: 'dist/index.js',
    capabilities: ['task_provider', 'report_provider'],
  },
  taskProvider: {
    async executeTask(context) {
      return {
        summary: `Security audit step executed for task ${context.task_id}`,
        output: `run=${context.run_id} task=${context.task_id}`,
        artifacts: [],
      };
    },
  },
  reportProvider: {
    async buildReport(context) {
      return {
        summary: `Security audit report generated for task ${context.task_id}`,
        output: `run=${context.run_id} actor=${context.actor_id}`,
        artifacts: [],
      };
    },
  },
};