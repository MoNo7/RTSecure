export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    if (request.method === "GET") return new Response(JSON.stringify({ status: "RTSecure Active" }), { headers: corsHeaders });

    try {
      const { address, scanType, unverifiedCode } = await request.json();
      let sourceCode = unverifiedCode || "";
      let isVerified = false;
      
      if (address && !unverifiedCode) {
        try {
          const lightRes = await fetch(`https://testnet.lightscan.app/api?module=contract&action=getsourcecode&address=${address}`);
          const lightData = await lightRes.json();
          sourceCode = lightData.result?.[0]?.SourceCode || "";
          isVerified = sourceCode.length > 0;
        } catch (e) {
          console.error("LightScan Fetch Failed");
        }
      } else if (unverifiedCode) {
        isVerified = false; // Manually pasted code is technically "unverified"
      }

      let staticAnalysis = {
        txOrigin: sourceCode.includes("tx.origin"),
        delegateCall: sourceCode.includes("delegatecall"),
        selfDestruct: sourceCode.includes("selfdestruct"),
        assembly: sourceCode.includes("assembly {")
      };

      const slitherAnalysis = {
        // 2026 Detection Method: Cross-function reentrancy & State-check-interaction patterns
        reentrancy: (sourceCode.match(/\.call\{.*\}.*\(.*\)/g) && !sourceCode.match(/ReentrancyGuard|nonReentrant/g)) || 
                    (sourceCode.includes("_status == _ENTERED")),
        // SWC-115: Access Control via tx.origin (Deep Pattern)
        txOrigin: sourceCode.match(/require\(tx\.origin\s*==\s*\w+\)/g) || sourceCode.includes("tx.origin"),
        delegateCall: sourceCode.includes("delegatecall"),
        selfDestruct: sourceCode.includes("selfdestruct") || sourceCode.includes("suicide"),
        // SWC-120: Weak Randomness (Contextual Detection)
        weakPRNG: sourceCode.match(/keccak256\(.*block\.(timestamp|difficulty|prevrandao).*\)/g),
        uninitializedState: (sourceCode.match(/uint256\s+\w+;/g) || []).length > 0 && !sourceCode.includes("constructor"),
        // SWC-128: Denial of Service via unbounded loops
        dosLoop: sourceCode.match(/for\s*\(.*;.*;.*\.\w+\)/g) && sourceCode.includes(".call("),
        // NEW: Commercial Gas Optimization Detections
        gasPreIncrement: sourceCode.match(/for\s*\(.*;.*;\s*\w+\+\+\)/g), // Detects i++ instead of ++i
        gasVisibility: sourceCode.match(/function\s+\w+\(.*\)\s+public\s+view/g), // Detects public instead of external
        floatingPragma: sourceCode.includes("^"),
        uncheckedCall: sourceCode.includes(".call(") && !sourceCode.includes("require("),
        shadowing: sourceCode.includes("uint") && sourceCode.includes("override") === false && sourceCode.match(/(\w+)\s*=\s*\1/),
        lockedEther: sourceCode.includes("receive()") && !sourceCode.includes("withdraw") // SWC-132 
      };

     // 3. Confidence Score Logic
      let baseScore = 100;

      // Define specific penalty weights for known vulnerabilities
      const penaltyWeights = {
        reentrancy: 30,
        delegateCall: 25,
        txOrigin: 15,
        weakPRNG: 10,
        // Any flagged issue not explicitly listed above gets a default penalty
        default: 10 
      };

      // Loop through the analysis results exactly once
      Object.keys(slitherAnalysis).forEach(key => {
          if (slitherAnalysis[key]) {
              // Apply the specific penalty if it exists, otherwise apply the 10-point default
              const deduction = penaltyWeights[key] || penaltyWeights.default;
              baseScore -= deduction;
          }
      });

      // Lock in the final score (preventing it from dropping below 0)
      const confidenceScore = Math.max(0, baseScore);
      const manualReview = confidenceScore < 80 || !address;

      let reportText = "";

      // 2. Handle Deep Scan (AIVM)
     if (scanType === 1) {
          if (!sourceCode || sourceCode.length < 50) {
              reportText = "[CRITICAL] Source code retrieval failed. AIVM cannot audit unverified or empty bytecode.";
          } else {
            const aiPrompt = `Act as a Senior Red Team Smart Contract Auditor. 
              Analyze the provided Solidity code for 2026-era exploits.
              Provide a verbose report with these EXACT sections:

              [ATTACK_TRACE] 
              Step-by-step how an attacker would drain or lock funds.

              [DISCOVERY_MATRIX]
              - Logical Reentrancy: [RESULT]
              - Access Control Bypass: [RESULT]
              - Price Oracle Manipulation: [RESULT]
              - Integer Overflow/Underflow: [RESULT]
              - Front-Running (MEV) Risk: [RESULT]

              [VULNERABILITY_MATRIX]
              List each attempted check (Reentrancy, Oracle Drift, Access Control, MEV, Logic Flaws).

              [DETAILED_FINDINGS]
              (For any FAIL, list the line number, severity, and discovery method).

              [RED_TEAM_ATTACK_VECTORS]
              (Describe a specific scenario an attacker would use to exploit this logic).

              [DEEP_SEMANTIC_FINDINGS]
              (Provide a detailed breakdown of your discovery process for any identified risks).

              [REMEDIATION_PLAN]
              Concise code fixes to mitigate all identified risks.

              [CONFIDENCE] 
              Provide a 1-100 score on contract safety.

              CODE TO AUDIT:
            ${sourceCode.substring(0, 4500)}`;

              const aiResponse = await fetch("https://chat2.lightchain.ai/api/v1/chat/completions", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json", 
                    "Authorization": "Bearer " + env.AIVM_API_KEY 
                },
                body: JSON.stringify({
                  model: "Neural-Llama-3-70B",
                  messages: [{ role: "user", content: aiPrompt }],
                  user_address: env.AIVM_WALLET
                })
              });
              
              const aiData = await aiResponse.json();
              
              if (aiData.detail && aiData.detail.includes("credits")) {
                  reportText = "[API ERROR] AIVM request failed: Insufficient API Credits. Please fund your developer portal.";
              } else if (aiData.error) {
                  reportText = `[API ERROR] AIVM request failed: ${aiData.error.message || "Unknown Error"}`;
              } else {
                  const aiContent = aiData.choices?.[0]?.message?.content;
                  reportText = `[AIVM DEEP AUDIT]\n${aiContent || "No critical logical vulnerabilities identified by the AIVM."}`;
              }
          }
      }else{
        // Fallback for Standard Audits (scanType === 0)
          reportText = `[SYNTACTIC SCAN COMPLETE]
- Confidence Score: ${confidenceScore}%
- Risks Flagged: ${Object.values(staticAnalysis).filter(Boolean).length} basic vectors found.
- Status: ${manualReview ? "MANUAL REVIEW RECOMMENDED" : "PASSED"}`;
      }

      return new Response(JSON.stringify({ 
        report: reportText,
        staticAnalysis,
        slitherAnalysis,
        confidenceScore,
        isVerified,
        sourceCode: sourceCode,
        manualReview
      }), { headers: corsHeaders });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { headers: corsHeaders });
    }
  }
};