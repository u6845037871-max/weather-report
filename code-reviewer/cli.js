#!/usr/bin/env node
import fs from 'fs';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { runScanner } from './scanner.js';
import { runComparison } from './epss-comparison.js';


const CONFIG_FILE = './config.json';
let config;
const isCI = process.env.GITHUB_ACTIONS === "true";

// Helper function to extract command line arguments (e.g., node script.js --mode strict)
const getCliArg = (argName) => {
  const argIndex = process.argv.indexOf(argName);
  if (argIndex > -1 && process.argv.length > argIndex + 1) {
    return process.argv[argIndex + 1];
  }
  return null;
};

if (fs.existsSync(CONFIG_FILE)) {
  config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
} else {
  const epss = 0.7;
  config = {
    weights: { epss, snyk: 1 - epss },
    thresholds: {
      avgThreshold: 0.055,
      criticalThreshold: 0.3,
      cvssCutoff: 7,
      severityCounts: {
        critical: 1,
        high: 2,
        medium: 5,
        low: null
      }
    }
  };
}

async function main() {

  console.log(chalk.blue.bold("=== Digital PR Code Reviewer CLI ==="));

  const { choice } = await inquirer.prompt({
    type: 'list',
    name: 'choice',
    message: 'Select an action:',
    choices: [
      'Configure thresholds & weights',
      'Run PR scan',
      'Exit'
    ]
  });

  if (choice === 'Configure thresholds & weights') {
    await configure();
    return main();
  }
  else if (choice === 'Run PR scan') {
    await runReview();
    process.exit(0);
  }
  else { process.exit(); }
}

// --- Configure thresholds & weights ---
// Accepts a mode string when called from CI/CD to bypass inquirer.
async function configure(modeOverride = null) {
  let mode;

  // 1. Determine mode: use override (CI) or prompt (interactive)
  if (modeOverride) {
    mode = modeOverride;
  } else {
    const result = await inquirer.prompt({
      type: 'list',
      name: 'mode',
      message: 'Select operating mode:',
      choices: ['Loose', 'Strict', 'Custom']
    });
    mode = result.mode;
  }

  const normalizedMode = mode.toLowerCase();

  // 2. Apply Predefined threshold values
  if (normalizedMode === 'strict') {
    config.thresholds.avgThreshold = 0.0001;
    config.thresholds.criticalThreshold = 0.0001;
    config.thresholds.cvssCutoff = 1;
    config.thresholds.severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    console.log(chalk.red("Strict mode enabled, system will be very conservative."));

  } else if (normalizedMode === 'loose') {
    config.thresholds.avgThreshold = 1.0;
    config.thresholds.criticalThreshold = 1.0;
    config.thresholds.cvssCutoff = 10;
    config.thresholds.severityCounts = { critical: 3, high: 5, medium: 8, low: null };
    console.log(chalk.yellow("Loose mode enabled, system will be more permissive."));

  } else if (normalizedMode === 'custom') {
    if (modeOverride) {
      // CI Custom: read specific thresholds from ENV vars
      // config.thresholds.avgThreshold = parseFloat(process.env.AVG_THRESHOLD) || 0.05;
      // config.thresholds.criticalThreshold = parseFloat(process.env.CRITICAL_THRESHOLD) || 0.3;
      // config.thresholds.cvssCutoff = parseFloat(process.env.CVSS_CUTOFF) || 7;
      console.log(chalk.cyan("Custom mode running. Using thresholds loaded from config.json."));
    } else {
      // Interactive Custom: prompt for manual configuration
      const answers = await inquirer.prompt([
        {
          type: 'input', name: 'epssWeight', message: 'EPSS weight (0-1):', default: config.weights.epss, validate: (value) => {
            const num = parseFloat(value);
            if (isNaN(num) || num < 0 || num > 1) return "Enter a number between 0 and 1";
            return true;
          }
        },
        { type: 'input', name: 'epssCutoff', message: 'EPSS cutoff (0-1):', default: config.thresholds.avgThreshold },
        { type: 'input', name: 'epssCritical', message: 'EPSS Critical (0-1):', default: config.thresholds.criticalThreshold },
        { type: 'input', name: 'cvssCutoff', message: 'CVSS cutoff (0-10):', default: config.thresholds.cvssCutoff },
        { type: 'input', name: 'nOfCriticals', message: 'Count of critical severities', default: config.thresholds.severityCounts.critical },
        { type: 'input', name: 'nOfHighs', message: 'Count of high severities', default: config.thresholds.severityCounts.high },
        { type: 'input', name: 'nOfMediums', message: 'Count of medium severities', default: config.thresholds.severityCounts.medium },
        { type: 'input', name: 'nOfLows', message: 'Count of low severities', default: config.thresholds.severityCounts.low },
      ]);

      // Update config from custom answers
      const epssWeight = parseFloat(answers.epssWeight);
      config.weights.epss = epssWeight;
      config.weights.snyk = 1 - epssWeight;
      config.thresholds.avgThreshold = parseFloat(answers.epssCutoff);
      config.thresholds.criticalThreshold = parseFloat(answers.epssCritical);
      config.thresholds.cvssCutoff = parseFloat(answers.cvssCutoff);
      config.thresholds.severityCounts.critical = parseFloat(answers.nOfCriticals);
      config.thresholds.severityCounts.high = parseFloat(answers.nOfHighs);
      config.thresholds.severityCounts.medium = parseFloat(answers.nOfMediums);
      config.thresholds.severityCounts.low = parseFloat(answers.nOfLows);
    }
  }

  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  console.log(chalk.green("✅ Configuration saved!"));

  return;
}


async function runReview() {
  const path = isCI ? (process.env.PR_PATH || getCliArg('--path') || '.') : (await inquirer.prompt({
    type: 'input',
    name: 'path',
    message: 'Path to PR files or branch:',
    default: '.'
  })).path;


  console.log(chalk.yellow("Running scanner..."));
  const scanResult = await runScanner(path);

  console.log(chalk.yellow("Comparing vulnerabilities..."));
  const { decision, reason, avgScore } = runComparison(
    "snyk-report.json",
    scanResult,
    "epss-plain-table.txt",
    config
  );

  // --- Print everything at once ---
  console.log("\n" + chalk.blue.bold("=== Digital PR Review Summary ==="));
  console.log(`Total vulnerabilities: ${scanResult.totalVulnerabilities}`);
  console.log(`PR Decision: ${decision === 'REJECT' ? chalk.red(decision) : chalk.green(decision)}`);
  if (reason) console.log(`Reason: ${chalk.red(reason)}`);
  console.log(`Average Vulnerability Score: ${avgScore.toFixed(6)}`);
  console.log(chalk.green("✅ Digital PR report saved to final-report.txt"));
  console.log(chalk.green("✅ Plain text comparison table saved to epss-plain-table.txt"));
}

// --- Entry ---
if (isCI) {
  console.log(chalk.blue.bold("CI environment detected"));

  // 1. Try to read mode from command-line argument (--mode loose)
  let mode = getCliArg('--mode');

  // 2. Fall back to environment variable (REVIEW_MODE=loose)
  if (!mode) {
    mode = process.env.REVIEW_MODE;
  }

  // 3. Fall back to a default mode
  if (!mode) {
    mode = 'Loose';
  }

  console.log(chalk.blue(`Selected Review Mode: ${mode.toUpperCase()}`));

  // Apply configuration based on the determined mode
  await configure(mode);

  // Now run the review with the determined configuration
  runReview();
} else {
  main();
}
