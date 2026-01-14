import { cre, Runner, type Runtime, hostBindings } from "@chainlink/cre-sdk";
import attestations from './test_attestations_response.json' assert { type: 'json' };
import query from './test_query_response.json' assert { type: 'json' };

type Config = {
  schedule: string;
};

const onCronTrigger = (runtime: Runtime<Config>): string => {
  const attestationsString = JSON.stringify(attestations);
  const queryString = JSON.stringify(query);
  const result = hostBindings.proofOfSqlVerify(queryString, attestationsString);
  return JSON.stringify(result);
};

const initWorkflow = (config: Config) => {
  const cron = new cre.capabilities.CronCapability();

  return [
    cre.handler(
      cron.trigger(
        { schedule: config.schedule }
      ), 
      onCronTrigger
    ),
  ];
};

export async function main() {
  const runner = await Runner.newRunner<Config>();
  await runner.run(initWorkflow);
}

main();
