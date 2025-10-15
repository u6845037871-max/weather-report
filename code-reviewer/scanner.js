// scanner.js
import fs from 'fs';
import path from 'path';
import { execSync } from "child_process";


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

// --- Safe UTF-8 JSON writer ---
function writeJsonFile(filePath, data) {
  const jsonString = JSON.stringify(data, null, 2);
  // Explicitly specify UTF-8 encoding
  fs.writeFileSync(filePath, jsonString, { encoding: 'utf8' });
}

// --- Exported function for CLI ---
export async function runScanner(projectPath = ".") {

  // Ensure output directory exists
  const outputDir = path.join(projectPath, "code-reviewer");
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const snykCodeReportTxt = path.join(outputDir, "snyk-code-report.txt");

  try {
    // Run Snyk Code Test and capture both stdout and stderr
    const output = execSync(`snyk code test "${projectPath}"`, { encoding: "utf8" });
    fs.writeFileSync(snykCodeReportTxt, output, { encoding: "utf8" });
    console.log(`✅ Snyk code test completed and saved to ${snykCodeReportTxt}`);
  } catch (error) {
    // Write even if Snyk fails (it often returns non-zero on vulnerabilities)
    fs.writeFileSync(snykCodeReportTxt, error.stdout || error.message, { encoding: "utf8" });
  }
  // Load Snyk report
  const snykFile = path.join(projectPath, "snyk-report.json");
  if (!fs.existsSync(snykFile)) {
    throw new Error(`Could not find snyk-report.json in ${projectPath}`);
  }

  const report = readJsonFile(snykFile);
  const vulnerabilities = report.vulnerabilities || [];
  if (!Array.isArray(vulnerabilities)) {
    throw new Error("Expected snyk-report.json to contain vulnerabilities array.");
  }
  // console.log('vulnerabilities', vulnerabilities);
  const seenCVEs = new Set();
  const result = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  // Prepare text report
  const outputFile = path.join(projectPath, "epss-report.txt");

  let reportContent = '';

  // Fetch EPSS for each CVE
  async function fetchEPSS(cve) {
    if (!cve) return null; // no CVE = no EPSS
    try {
      const url = `https://api.first.org/data/v1/epss?cve=${cve}`;
      const res = await fetch(url);
      const data = await res.json();
      return data.data?.[0] || null;
    } catch (err) {
      console.error(`❌ Failed to fetch EPSS for ${cve}:`, err.message);
      return null;
    }
  }

  let totalVulnerabilities = 0;

  // classify CVSS into severity
  function classifyCVSS(score) {
    if (score === null || score === undefined) return null;
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }
  // console.log("vulnerabilities", vulnerabilities);
  for (const vuln of vulnerabilities) {
    const cves = vuln.identifiers?.CVE || [];
    const cvssScore = vuln.cvssSources?.[0]?.baseScore || null;
    const targets = cves.length > 0 ? cves : [null];

    for (const cve of targets) {
      if (cve && seenCVEs.has(cve)) continue;
      if (cve) seenCVEs.add(cve);
      totalVulnerabilities++;

      const epssData = await fetchEPSS(cve);

      let severity;
      let metricUsed;
      let epssScore = epssData ? parseFloat(epssData.epss) : null;

      if (epssScore !== null && !isNaN(epssScore)) {
        // --- EPSS-based classification ---
        if (epssScore >= 0.5) severity = "critical";
        else if (epssScore >= 0.3) severity = "high";
        else if (epssScore >= 0.1) severity = "medium";
        else severity = "low";
        metricUsed = "EPSS";
      } else {
        // --- CVSS fallback ---
        severity = classifyCVSS(cvssScore);
        metricUsed = "CVSS";
      }

      if (severity) severityCounts[severity]++;

      // --- Report text formatting ---
      if (metricUsed === "EPSS") {
        reportContent += `
✗ [${severity.toUpperCase()}] ${vuln.title}
   Package: ${vuln.moduleName} (${vuln.version})
   CVE: ${cve || "N/A"}
   EPSS Score: ${epssData.epss} | Percentile: ${epssData.percentile}
   CVSS Score: ${vuln.cvssScore || "N/A"}
   🔗 ${vuln.references[0]?.url || "No reference"}
   ------------------------------------------------
`;
      } else {
        reportContent += `
✗ [${severity.toUpperCase()}] ${vuln.title}
   Package: ${vuln.moduleName} (${vuln.version})
   CVE: ${cve || "N/A"}
   CVSS Score: ${cvssScore || "N/A"} → Severity: ${severity}
   🔗 ${vuln.references[0]?.url || "No reference"}
   ------------------------------------------------
`;
      }

      result.push({
        moduleName: vuln.moduleName,
        title: vuln.title,
        cve,
        epss: epssData?.epss || null,
        percentile: epssData?.percentile || null,
        cvss: cvssScore,
        severity,
        references: vuln.references || [],
        metric: metricUsed,
      });
    }
  }


  // Summary
  // const summary = `\n🔴 Total vulnerabilities found: ${totalVulnerabilities}\n`;
  // console.log(summary);
  // reportContent += summary;

  // Severity summary
  const severitySummary = `
  Severity counts (CVSS fallback):
    Critical: ${severityCounts.critical}
    High:     ${severityCounts.high}
    Medium:   ${severityCounts.medium}
    Low:      ${severityCounts.low}
  `;
  console.log(severitySummary);
  reportContent += severitySummary;

  // Write text report (explicitly UTF-8)
  fs.writeFileSync(outputFile, reportContent, { encoding: 'utf8' });
  console.log(`✅ EPSS report saved to ${outputFile}`);

  // Create the final result object
  const finalResult = {
    totalVulnerabilities: result.length,
    vulnerabilities: result,
    severityCounts,
    reportFile: outputFile,
  };

  // Write JSON report in UTF-8
  // writeJsonFile(jsonOutputFile, finalResult);
  // console.log(`✅ JSON report saved to ${jsonOutputFile} (UTF-8 encoding)`);

  // Return JSON for CLI
  return finalResult;
}
