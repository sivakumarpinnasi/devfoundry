import { Command } from 'commander';
import { evaluateProject } from '@devfoundry/core';
import { formatDoctorReport } from '@devfoundry/reporter';

export function runCLI(): void {
  const program = new Command();

  program
    .name('foundry')
    .description('DevFoundry CLI')
    .version('0.1.0');

  program
    .command('doctor')
    .description('Run project doctor diagnostics')
    .action(() => {
      const evaluation = evaluateProject();
      const report = formatDoctorReport(evaluation);
      console.log(report);
    });

  program.parse();
}
