/**
 * Bangladesh Police Master Directory & Intelligent Fuzzy Matcher Service
 * Developed for SAFE BD (shurokhaAI)
 *
 * Source: Official Nationwide Bangladesh Police Directory
 * Covers:
 * - 641 Thanas (Police Stations) nationwide across all 8 Divisions/Ranges and 8 Metropolitan Commissionerates
 * - Every Officer-in-Charge (OC) New Official Number (01320-XXXXXX) + Old Number
 * - 24/7 Duty Officers, Investigation Inspectors, Operations Inspectors
 * - Official T&T Landlines, Police Gov Emails
 * - All 64 Districts with SP Offices & Control Rooms
 * - Robust Fuzzy Matching (Levenshtein + Token Scoring) for Typos & Spelling Mistakes
 */

const fs = require('fs');
const path = require('path');

let database = { thanas: [], districts: {}, hqContacts: [] };

try {
  const dbPath = path.join(__dirname, 'data', 'bangladesh_police_master.json');
  if (fs.existsSync(dbPath)) {
    database = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
    console.log(`[POLICE_DIRECTORY] Loaded ${database.thanas?.length || 0} thanas and ${Object.keys(database.districts || {}).length} districts.`);
  } else {
    console.warn(`[POLICE_DIRECTORY] Database file not found at: ${dbPath}`);
  }
} catch (err) {
  console.error('[POLICE_DIRECTORY] Failed to load police master database:', err.message);
}

// Levenshtein distance for fuzzy matching typos
function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function stringSimilarity(s1, s2) {
  const longer = s1.length > s2.length ? s1 : s2;
  const shorter = s1.length > s2.length ? s2 : s1;
  if (longer.length === 0) return 1.0;
  return (longer.length - levenshtein(longer, shorter)) / longer.length;
}

// Normalize and clean query into search tokens
function normalizeQuery(q) {
  return q
    .toLowerCase()
    .replace(/[^\w\s\u0980-\u09FF]/gi, ' ')
    .replace(/\b(give|me|the|number|phone|mobile|contact|of|what|is|thana|police|station|ps|model|oc|officer|in|charge|duty|investigation|ops|operations|please|bhai|vai|koto|ki|details|all)\b/gi, ' ')
    .replace(/\b(নাম্বার|ফোন|ওসি|থানার|থানা|পুলিশ|দাও|কত|যোগাযোগ|বলুন|দিন|সব|নাম্বারগুলো)\b/gi, ' ')
    .trim()
    .replace(/\s+/g, ' ');
}

/**
 * Main query resolver:
 * Matches thana by exact token, multi-token, alias, or fuzzy Levenshtein match.
 */
function resolvePoliceQuery(rawQuery) {
  if (!rawQuery || typeof rawQuery !== 'string' || !rawQuery.trim()) return null;
  const originalQ = rawQuery.trim();
  const qLower = originalQ.toLowerCase();
  const isBangla = /[\u0980-\u09FF]/.test(originalQ);
  const cleanQ = normalizeQuery(originalQ);

  const tokens = cleanQ.split(' ').filter(t => t.length >= 2);

  let bestMatch = null;
  let bestScore = 0;
  let isTypoCorrection = false;
  let matchedDistrictContext = null;

  // 1. Detect if a specific district is mentioned
  for (const distKey of Object.keys(database.districts || {})) {
    const dLower = distKey.toLowerCase();
    if (qLower.includes(dLower) || (database.districts[distKey].bnName && originalQ.includes(database.districts[distKey].bnName))) {
      matchedDistrictContext = distKey;
      break;
    }
  }

  // 2. Exact Name, Alias, and Token Match
  for (const thana of database.thanas) {
    const thanaNameLower = thana.name.toLowerCase();
    const thanaBn = thana.bnName || '';

    let score = 0;
    if (cleanQ === thanaNameLower || (thanaBn && cleanQ === thanaBn)) {
      score = 150;
    } else if (thana.keywords && thana.keywords.includes(cleanQ)) {
      score = 140;
    } else {
      let matchedTokens = 0;
      for (const tok of tokens) {
        if (tok.length < 2) continue;
        if (thanaNameLower.split(/\s+/).includes(tok) || (thana.keywords && thana.keywords.includes(tok))) {
          matchedTokens += 2;
        } else if (thanaNameLower.includes(tok)) {
          matchedTokens += 1;
        }
      }
      if (matchedTokens > 0) {
        score = 60 + (matchedTokens * 20);
      }
    }

    if (score > 0) {
      // Bonus if user query also specifies this thana's district
      if (matchedDistrictContext && thana.district.toLowerCase() === matchedDistrictContext.toLowerCase()) {
        score += 25;
      }
      if (score > bestScore) {
        bestScore = score;
        bestMatch = thana;
        isTypoCorrection = false;
      }
    }
  }

  // 3. Typo / Fuzzy Match (Levenshtein & Trigram Similarity)
  if (bestScore < 85 && tokens.length > 0) {
    for (const thana of database.thanas) {
      const thanaNameLower = thana.name.toLowerCase();
      for (const tok of tokens) {
        if (tok.length < 3) continue;

        // Similarity against thana name
        const sim = stringSimilarity(tok, thanaNameLower);
        let distBonus = 0;
        if (matchedDistrictContext && thana.district.toLowerCase() === matchedDistrictContext.toLowerCase()) {
          distBonus = 0.15;
        }

        const totalSim = sim + distBonus;
        if (totalSim >= 0.72 && totalSim * 85 > bestScore) {
          bestScore = totalSim * 85;
          bestMatch = thana;
          isTypoCorrection = (sim < 0.99);
        }

        // Similarity against thana keywords
        if (thana.keywords) {
          for (const kw of thana.keywords) {
            if (kw.length < 3) continue;
            const kwSim = stringSimilarity(tok, kw.toLowerCase());
            if (kwSim >= 0.75 && kwSim * 85 > bestScore) {
              bestScore = kwSim * 85;
              bestMatch = thana;
              isTypoCorrection = (kwSim < 0.99);
            }
          }
        }
      }
    }
  }

  // 4. District-Level Directory (e.g. "Bogura police", "Sylhet SP", "SP of Cox's Bazar")
  if (!bestMatch && matchedDistrictContext) {
    const distObj = database.districts[matchedDistrictContext];
    if (distObj) {
      return formatDistrictResponse(distObj, isBangla);
    }
  }

  if (!bestMatch) return null;

  return formatThanaResponse(bestMatch, originalQ, isTypoCorrection, isBangla);
}

/**
 * Formats a comprehensive thana response:
 * - Always takes the New Number (01320-XXXXXX)
 * - Returns the specific requested officer highlighted
 * - AND returns ALL other numbers regarding that thana (Duty Officer, Investigation, Operations, Landline, Email)
 * - Clickable tel: links for 1-tap call
 */
function formatThanaResponse(t, userQuery, isTypoCorrection, isBangla) {
  const cleanOc = (t.oc.newNumber || t.oc.currentNumber || '').replace(/\D/g, '');
  const cleanDuty = t.dutyOfficer ? (t.dutyOfficer.newNumber || t.dutyOfficer.currentNumber || '').replace(/\D/g, '') : '';
  const cleanInvest = t.investigation ? (t.investigation.newNumber || t.investigation.currentNumber || '').replace(/\D/g, '') : '';
  const cleanOps = t.operations ? (t.operations.newNumber || t.operations.currentNumber || '').replace(/\D/g, '') : '';
  const cleanLandline = (t.oc.landline || '').replace(/[^0-9]/g, '');

  const qLower = (userQuery || '').toLowerCase();
  const askedForDuty = qLower.includes('duty') || qLower.includes('ডিউটি');
  const askedForInvest = qLower.includes('invest') || qLower.includes('তদন্ত');
  const askedForOps = qLower.includes('ops') || qLower.includes('অপারেশন');

  let text = '';
  const typoNote = isTypoCorrection
    ? (isBangla ? `*(বানান সংশোধিত: **${t.bnName || t.name} থানা** এর তথ্য দেওয়া হলো)*\n\n` : `*(Nearest match for "${userQuery}": **${t.name} Thana**)*\n\n`)
    : '';

  if (isBangla) {
    text = `${typoNote}👮 **${t.bnName ? t.bnName + ' (' + t.name + ')' : t.name} থানা — বাংলাদেশ পুলিশ**\n` +
      `🏢 **ইউনিট/জেলা:** ${t.districtBn || t.district} (${t.unit})\n` +
      `📍 **বিভাগ/রেঞ্জ:** ${t.division}\n\n` +
      `📞 **থানার সকল জরুরি সরকারি ফোন নাম্বারসমূহ (অফিসিয়াল নতুন সিরিজ):**\n` +
      `• **অফিসার ইনচার্জ (OC):** [${t.oc.newNumber || t.oc.currentNumber}](tel:${cleanOc}) ${t.oc.newNumber && t.oc.currentNumber ? `*(পূর্বের: ${t.oc.currentNumber})*` : ''}\n` +
      (t.dutyOfficer ? `• **ডিউটি অফিসার (Duty Officer - ২৪ ঘণ্টা হেল্পলাইন):** [${t.dutyOfficer.newNumber || t.dutyOfficer.currentNumber}](tel:${cleanDuty})\n` : '') +
      (t.investigation ? `• **পুলিশ পরিদর্শক (তদন্ত / Investigation):** [${t.investigation.newNumber || t.investigation.currentNumber}](tel:${cleanInvest})\n` : '') +
      (t.operations ? `• **পুলিশ পরিদর্শক (অপারেশনস / Operations):** [${t.operations.newNumber || t.operations.currentNumber}](tel:${cleanOps})\n` : '') +
      (t.oc.landline ? `• **সরকারি টিঅ্যান্ডটি ল্যান্ডলাইন:** [${t.oc.landline}](tel:${cleanLandline})\n` : '') +
      (t.oc.email ? `• **অফিসিয়াল পুলিশ ইমেইল:** \`${t.oc.email}\`\n` : '') +
      `• **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999) (তাৎক্ষণিক পুলিশ dispatch ২৪ ঘণ্টা)\n\n` +
      `💡 *পরামর্শ: নাম্বারে সরাসরি ট্যাপ করে ওসির সাথে বা ২৪/৭ ডিউটি অফিসারের সাথে কথা বলুন এবং আপনার সুনির্দিষ্ট অবস্থান জানান।*`;
  } else {
    text = `${typoNote}👮 **${t.name} Thana — Bangladesh Police**\n` +
      `🏢 **Unit / District:** ${t.district} (${t.unit})\n` +
      `📍 **Division / Range:** ${t.division}\n\n` +
      `📞 **All Official Emergency Numbers for this Thana (New Official Series):**\n` +
      `• **Officer-in-Charge (OC):** [${t.oc.newNumber || t.oc.currentNumber}](tel:${cleanOc}) ${t.oc.newNumber && t.oc.currentNumber ? `*(Old: ${t.oc.currentNumber})*` : ''}\n` +
      (t.dutyOfficer ? `• **Duty Officer (24/7 Helpline):** [${t.dutyOfficer.newNumber || t.dutyOfficer.currentNumber}](tel:${cleanDuty})\n` : '') +
      (t.investigation ? `• **Inspector (Investigation):** [${t.investigation.newNumber || t.investigation.currentNumber}](tel:${cleanInvest})\n` : '') +
      (t.operations ? `• **Inspector (Operations):** [${t.operations.newNumber || t.operations.currentNumber}](tel:${cleanOps})\n` : '') +
      (t.oc.landline ? `• **Official T&T Landline:** [${t.oc.landline}](tel:${cleanLandline})\n` : '') +
      (t.oc.email ? `• **Official Police Email:** \`${t.oc.email}\`\n` : '') +
      `• **National Emergency Service:** [999](tel:999) (Immediate Police Dispatch 24/7)\n\n` +
      `💡 *Guidance: Tap any number to call directly. State your situation and exact location to the officer for emergency dispatch.*`;
  }

  // Highlight primary source in sources array
  const primaryTitle = askedForDuty
    ? `${t.name} Duty Officer (24/7)`
    : (askedForInvest ? `${t.name} Investigation` : `${t.name} OC Line`);
  const primaryUrl = askedForDuty
    ? (cleanDuty ? `tel:${cleanDuty}` : `tel:${cleanOc}`)
    : `tel:${cleanOc}`;

  return {
    text,
    sources: [
      { title: primaryTitle, url: primaryUrl },
      { title: `${t.name} Duty Officer (24/7)`, url: cleanDuty ? `tel:${cleanDuty}` : 'tel:999' },
      { title: "National 999 CAD Dispatch", url: "tel:999" }
    ],
    thana: t
  };
}

function formatDistrictResponse(d, isBangla) {
  const cleanSp = (d.spNumber || '').replace(/\D/g, '');
  const cleanCtrl = (d.controlRoom || '').replace(/\D/g, '');
  const cleanLandline = (d.landline || '').replace(/[^0-9]/g, '');

  const thanaList = (d.thanas || []).slice(0, 10).map(th => `• **${th.name}:** [${th.ocNumber}](tel:${(th.ocNumber || '').replace(/\D/g, '')})`).join('\n');

  let text = '';
  if (isBangla) {
    text = `🏢 **জেলা পুলিশ ${d.bnName || d.name} (District Police ${d.name})**\n\n` +
      `📞 **জেলা পুলিশ হেডকোয়ার্টার্স ও কন্ট্রোল রুম (নতুন সরকারি সিরিজ):**\n` +
      (d.spNumber ? `• **পুলিশ সুপার (SP ${d.name}):** [${d.spNumber}](tel:${cleanSp})\n` : '') +
      (d.controlRoom ? `• **জেলা কন্ট্রোল রুম (২৪ ঘণ্টা):** [${d.controlRoom}](tel:${cleanCtrl})\n` : '') +
      (d.landline ? `• **টিঅ্যান্ডটি ল্যান্ডলাইন:** [${d.landline}](tel:${cleanLandline})\n` : '') +
      `• **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999)\n\n` +
      (thanaList ? `🏛️ **${d.name} জেলার প্রধান থানাসমূহের ওসির সরাসরি নাম্বার:**\n${thanaList}\n\n` : '') +
      `নির্দিষ্ট কোনো থানার সকল নাম্বার ও ডিউটি অফিসারের সাথে কথা বলতে থানার নাম লিখুন।`;
  } else {
    text = `🏢 **District Police ${d.name} (${d.bnName || d.name})**\n\n` +
      `📞 **District Police Headquarters & Control Room (New Official Series):**\n` +
      (d.spNumber ? `• **Superintendent of Police (SP):** [${d.spNumber}](tel:${cleanSp})\n` : '') +
      (d.controlRoom ? `• **District Control Room (24/7):** [${d.controlRoom}](tel:${cleanCtrl})\n` : '') +
      (d.landline ? `• **Official T&T Landline:** [${d.landline}](tel:${cleanLandline})\n` : '') +
      `• **National Emergency Service:** [999](tel:999)\n\n` +
      (thanaList ? `🏛️ **Police Stations (Thanas) in ${d.name} District:**\n${thanaList}\n\n` : '') +
      `Reply with any specific Thana name for 24/7 Duty Officer, Investigation, and Operations numbers.`;
  }

  return {
    text,
    sources: [
      { title: `SP ${d.name} Office`, url: cleanSp ? `tel:${cleanSp}` : 'tel:999' },
      { title: `${d.name} Police Control Room`, url: cleanCtrl ? `tel:${cleanCtrl}` : 'tel:999' },
      { title: "National 999 CAD Dispatch", url: "tel:999" }
    ],
    district: d
  };
}

module.exports = {
  resolvePoliceQuery,
  formatThanaResponse,
  formatDistrictResponse,
  database
};
