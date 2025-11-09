import fs from 'fs';

// --- Safe JSON reader to handle UTF-8 + BOM + CRLF issues ---
function readJsonFile(filePath) {
  const buffer = fs.readFileSync(filePath);

  let content;
  // Check for UTF-16 LE BOM
  if (buffer[0] === 0xff && buffer[1] === 0xfe) {
    content = buffer.toString('utf16le');
  }
  // Check for UTF-16 BE BOM
  else if (buffer[0] === 0xfe && buffer[1] === 0xff) {
    content = buffer.toString('utf16be');
  }
  // Check for UTF-8 BOM
  else if (buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    content = buffer.toString('utf8').substring(1); // Remove BOM
  }
  // Default to UTF-8
  else {
    content = buffer.toString('utf8');
  }

  // Clean up the content
  content = content
    .replace(/^\uFEFF/, '') // Remove BOM if present
    .replace(/\r\n/g, '\n') // Normalize line endings
    .replace(/\r/g, '\n')   // Convert remaining \r to \n
    .trim();                // Remove leading/trailing whitespace

  // Additional cleanup for common JSON issues
  content = content
    .replace(/,(\s*[}\]])/g, '$1') // Remove trailing commas
    .replace(/[\x00-\x1F\x7F-\x9F]/g, ''); // Remove control characters

  try {
    return JSON.parse(content);
  } catch (error) {
    console.error(`❌ JSON parsing error in ${filePath}:`);
    console.error(`Error: ${error.message}`);

    // Show first few characters for debugging
    const preview = content.substring(0, 200).replace(/\n/g, '\\n');
    console.error(`Content preview: "${preview}..."`);

    // Try to identify the issue
    if (content.includes('\0')) {
      console.error('⚠️  File contains null bytes, possible binary/encoding issue');
    }
    if (!content.startsWith('{') && !content.startsWith('[')) {
      console.error('⚠️  File doesn\'t start with { or [, might not be JSON');
    }

    throw new Error(`Invalid JSON in ${filePath}: ${error.message}`);
  }
}

/**
 * Safely converts a value to a finite number, otherwise returns 0.
 * This avoids calling .toFixed on non-number values.
 */
function numOrZero(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Format a numeric value as a string with fixed decimals.
 */
function fmt(value, decimals = 5) {
  return numOrZero(value).toFixed(decimals);
}

export function runComparison(
  snykFile = "snyk-report.json",
  scannerData,
  outputFile = "epss-plain-table.txt",
  config
) {
  // --- Load Snyk report using safe JSON reader ---
  const snykReport = readJsonFile(snykFile);
  const snykVulnerabilities = snykReport.vulnerabilities || [];
  // console.log("scannerData",scannerData);
  // --- Build EPSS dictionary from scannerData ---
  const epssData = {};
  for (const vuln of scannerData.vulnerabilities) {
    if (vuln.metric === "EPSS" && vuln.cve) {
      epssData[vuln.cve] = {
        epss: numOrZero(vuln.epss),
        percentile: numOrZero(vuln.percentile)
      };
    }
  }

  // --- Build Snyk dictionary ---
  const snykData = {};
  for (const vuln of snykVulnerabilities) {
    const cves = vuln.identifiers?.CVE || [];
    for (const cve of cves) {
      snykData[cve] = {
        cvss: numOrZero(vuln.cvssSources?.[0]?.baseScore),
        probability: numOrZero(vuln.epssDetails?.probability),
        percentile: numOrZero(vuln.epssDetails?.percentile)
      };
    }
  }
  // console.log("snykData", snykData);

  //  --- Collect rows as formatted strings (safe numeric formatting) ---
  const rows = [];
  let totalScore = 0;
  let count = 0;
  // console.log("scannerData", scannerData);
  for (const vuln of scannerData.vulnerabilities || []) {
    if (!vuln.cve) continue;

    const cve = String(vuln.cve);
    const e = epssData[cve] || {};
    const s = snykData[cve] || {};

    const epssScore = e.epss || 0;
    const epssPercentile = e.percentile || 0;
    const snykProb = s.probability || 0;
    const snykPercentile = s.percentile || 0;

    const cvss = vuln?.cvss || "-";

    const vulnScore = config.weights.epss * epssScore + config.weights.snyk * snykProb;
    totalScore += vulnScore;
    count++;

    rows.push([
      cve,
      fmt(snykPercentile, 5),
      fmt(epssPercentile, 5),
      fmt(snykProb, 5),
      fmt(epssScore, 5),
      numOrZero(vulnScore).toFixed(6),
      cvss
    ]);
  }

  // --- Build dynamic table ---
  const headers = [
    "CVE",
    "Snyk %",
    "EPSS % (Percentile)",
    "Snyk Prob",
    "EPSS Score",
    "Vulnerability Score",
    "CVSS"
  ];

  // Compute column widths (use header length and each row's string lengths)
  const colWidths = headers.map((h, i) => {
    const maxInRows = rows.length
      ? Math.max(...rows.map(r => String(r[i] ?? "").length))
      : 0;
    return Math.max(h.length, maxInRows);
  });

  const formatRow = (row) =>
    row.map((cell, i) => String(cell ?? "").padEnd(colWidths[i])).join(" | ");

  const separator = colWidths.map(w => "-".repeat(w)).join("-|-");

  const table =
    formatRow(headers) +
    "\n" +
    separator +
    "\n" +
    rows.map(formatRow).join("\n");


  // --- Decision logic ---
  const avgScore = count > 0 ? totalScore / count : 0;
  let decision = "ACCEPT";
  let rejectReason = "";
  // console.log("rows", rows);
  // console.log("rows[0]", rows[0]);

  // for (const row of rows) {
  //   const vulnScore = parseFloat(row[5]);   // Vulnerability Score
  //   const epssScore = parseFloat(row[4]);   // EPSS Score column
  //   const cvssScore = parseFloat(row[6]);   // CVSS column (may be "-")
  //   console.log("vulnScore", vulnScore);
  //   // Rule 1: Critical vulnerability score
  //   if (vulnScore > config.thresholds.criticalThreshold) {
  //     decision = "REJECT";
  //     rejectReason = `High Vulnerability Score (combined metric) on CVE: ${row[0]}`;
  //     break;
  //   }

  //   // Rule 2: EPSS + CVSS cutoff
  //   if (
  //     vulnScore > config.thresholds.avgThreshold &&
  //     cvssScore > config.thresholds.cvssCutoff
  //   ) {
  //     decision = "REJECT";
  //     rejectReason = `EPSS (${vulnScore}) and CVSS (${cvssScore}) too high for CVE: ${row[0]}`;
  //     break;
  //   }
  // }

  // 3. Reject if any severity exceeds threshold
  if (decision === "ACCEPT") {
    const counts = scannerData.codeSeverityCounts || {};
    const thresholds = config.thresholds.codeSeverityCounts || {};

    for (const sev of ['high', 'medium', 'low']) {
      const count = counts[sev] || 0;
      const maxAllowed = thresholds[sev];

      if (maxAllowed !== null && maxAllowed !== undefined && count > maxAllowed) {
        decision = "REJECT";
        rejectReason = `Too many ${sev.toUpperCase()} vulnerabilities: ${count} (max allowed ${maxAllowed})`;
        break;  // stop at first violation
      }
    }
  }

  // Rule 4: Average EPSS threshold
  // if (decision === "ACCEPT" && avgScore > config.thresholds.avgThreshold) {
  //   decision = "REJECT";
  //   rejectReason = `Average EPSS too high (${avgScore.toFixed(6)})`;
  // }




  let reportContent = `Digital PR Code Review Report
  ==============================

  Total vulnerabilities: ${count}
  Average Vulnerability Score: ${avgScore.toFixed(6)}

  Explanation: 
  The average vulnerability score is a weighted combination of EPSS (Exploit Prediction Scoring System) probability
  and Snyk-reported probability for all detected vulnerabilities in this PR.
  It represents the overall risk level: higher values indicate higher likelihood of exploitation.

  PR Decision: ${decision}
  Reason: ${rejectReason || 'N/A'}
  avgThreshold: ${config.thresholds.avgThreshold}
  `;
  let finalReport = "final PR report.txt";
  // Optional: append the detailed table
  reportContent += "\n\n" + table;

  // Write to file with explicit UTF-8 encoding
  if (finalReport) {
    fs.writeFileSync(finalReport, reportContent, { encoding: 'utf-8' });
    console.log(`✅ Digital PR report saved to ${finalReport}`);
  }

  // --- Write table to file with explicit UTF-8 encoding ---
  if (outputFile) {
    fs.writeFileSync(outputFile, table, { encoding: 'utf-8' });
    console.log(`✅ Plain text comparison table saved to ${outputFile}`);
  }

  return { decision, reason: rejectReason, avgScore, table };
}
