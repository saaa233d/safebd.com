/**
 * shurokhaAI Conversational & Emergency Intelligence Engine
 * Developed for SAFE BD
 *
 * Provides a human-like, ChatGPT-style conversational assistant for:
 * 1. Medical guidance (fevers, acute illness, first aid, Shastho Batayan 16263, emergency doctor triage)
 * 2. Eve teasing, harassment, stalking protection & immediate nearby Thana routing
 * 3. Snatching, mugging, robbery response & GD filing guidance
 * 4. Comprehensive nearby hospital & ambulance discovery across Dhaka & Bangladesh
 * 5. Official nationwide Thana (Police Station) & OC directory matching
 * 6. Blood Lifeline (রক্তবন্ধু) navigation & emergency blood donor assistance
 * 7. Polite, human deflection of off-topic / irrelevant subjects
 * 8. Multi-turn dialogue context retention (extracts user's location & context from previous messages)
 */

const policeDirectory = require('./policeDirectoryService');
const hospitalDirectory = require('./hospitalDirectoryService');

// Known locations dictionary for intelligent location extraction across messages
const KNOWN_LOCATIONS = [
  // Dhaka Major Neighborhoods
  { name: "Dhanmondi", bn: "ধানমন্ডি", aliases: ["dhanmondi", "ধানমন্ডি", "lalmatia", "লালমাটিয়া", "kalabagan", "কলাবাগান", "shankar", "শংকর", "zigatola", "জিগাতলা", "panthapath", "পান্থপথ", "green road", "গ্রিন রোড"] },
  { name: "Mirpur", bn: "মিরপুর", aliases: ["mirpur", "মিরপুর", "pallabi", "পল্লবী", "kafrul", "কাফরুল", "shewrapara", "শেওড়াপাড়া", "kazipara", "কাজীপিাড়া", "rokeya sarani", "rokya sarani"] },
  { name: "Uttara", bn: "উত্তরা", aliases: ["uttara", "উত্তরা", "airport", "বিমানবন্দর", "turag", "তুরাগ", "dakshinkhan", "দক্ষিণখান", "uttarkhan", "উত্তরখান", "tongi", "টঙ্গী"] },
  { name: "Gulshan", bn: "গুলশান", aliases: ["gulshan", "গুলশান", "banani", "বনানী", "baridhara", "বারিধারা", "niketan", "নিকেতন", "mohakhali dohs"] },
  { name: "Mohakhali", bn: "মহাখালী", aliases: ["mohakhali", "মহাখালী", "tb gate", "টিবি গেট", "wireless", "ওয়ারলেস"] },
  { name: "Mohammadpur", bn: "মোহাম্মদপুর", aliases: ["mohammadpur", "মোহাম্মদপুর", "adabor", "আদাবর", "shyamoli", "শ্যামলী", "kallyanpur", "কল্যাণপুর", "bosila", "বসিলা", "asad gate", "আসাদ গেট"] },
  { name: "Shahbagh", bn: "শাহবাগ", aliases: ["shahbagh", "শাহবাগ", "ramna", "রমনা", "dhaka university", "ঢাকা বিশ্ববিদ্যালয়", "du", "ঢাবি", "paribagh", "পরিবাগ", "katabon", "কাটাবন"] },
  { name: "Old Dhaka", bn: "পুরান ঢাকা", aliases: ["old dhaka", "পুরান ঢাকা", "sadarghat", "সদরঘাট", "kotwali", "কোতোয়ালী", "sutrapur", "সূত্রাপুর", "lalbagh", "লালবাগ", "chawkbazar", "চকবাজার", "armanitola", "babubazar", "বাবু বাজার", "mitford", "মিটফোর্ড", " বংশাল", "bangshal"] },
  { name: "Badda", bn: "বাড্ডা", aliases: ["badda", "বাড্ডা", "vatara", "ভাটারা", "bashundhara", "বসুন্ধরা", "aftabnagar", "আফতাবনগর", "merul", "মেরুল"] },
  { name: "Rampura", bn: "রামপুরা", aliases: ["rampura", "রামপুরা", "banasree", "বনশ্রী", "malibagh", "মালিবাগ", "mouchak", "মৌচাক", "shantinagar", "শান্তিনগর"] },
  { name: "Khilgaon", bn: "খিলগাঁও", aliases: ["khilgaon", "খিলগাঁও", "goran", "গোড়ান", "sipahibag", "সিপাহীবাগ", "basabo", "বাসাবো", "mugda", "মুগদা"] },
  { name: "Motijheel", bn: "মতিঝিল", aliases: ["motijheel", "মতিঝিল", "paltan", "পল্টন", "dilkusha", "দিলকুশা", "fakirapool", "ফকিরাপুল", "kakrail", "কাকরাইল", "segunbagicha", "সেগুনবাগিচা"] },
  { name: "Jatrabari", bn: "যাত্রাবাড়ী", aliases: ["jatrabari", "যাত্রাবাড়ী", "sayedabad", "সায়েদাবাদ", "demra", "ডেমরা", "dhalpur", "ধলপুর", "gandaria", "গেন্ডারিয়া", "wari", "ওয়ারী", "kadamtali", "কদমতলী"] },
  { name: "Savar", bn: "সাভার", aliases: ["savar", "সাভার", "ashulia", "আশুলিয়া", "dhamrai", "ধামরাই", "hemayetpur", "হেমায়েতপুর"] },
  { name: "Gazipur", bn: "গাজীপুর", aliases: ["gazipur", "গাজীপুর", "joydebpur", "জয়দেবপুর", "board bazar", "বোর্ড বাজার", "konabari", "কোনাবাড়ী"] },
  { name: "Narayanganj", bn: "নারায়ণগঞ্জ", aliases: ["narayanganj", "নারায়ণগঞ্জ", "chasara", "চাষাড়া", "siddhirganj", "সিদ্ধিরগঞ্জ", "fatullah", "ফতুল্লা", "kanchpur", "কাঁচপুর"] },

  // Divisional Cities
  { name: "Chittagong", bn: "চট্টগ্রাম", aliases: ["chittagong", "চট্টগ্রাম", "chattogram", "agrabad", "অগ্রাবাদ", "panchlaish", "পাঁচলাইশ", "halishahar", "হালিশহর", "khulshi", "খুলশী", "kotwali ctg"] },
  { name: "Sylhet", bn: "সিলেট", aliases: ["sylhet", "সিলেট", "zindabazar", "জিন্দাবাজার", "amberkhana", "আম্বরখানা", "upashahar", "উপশহর"] },
  { name: "Rajshahi", bn: "রাজশাহী", aliases: ["rajshahi", "রাজশাহী", "saheb bazar", "সাহেব বাজার", "motihar", "মতিহার", "boalia", "বোয়ালিয়া"] },
  { name: "Khulna", bn: "খুলনা", aliases: ["khulna", "খুলনা", "sonadanga", "সোনাডাঙ্গা", "khalishpur", "খালিশপুর", "daulatpur", "দৌলতপুর"] },
  { name: "Barishal", bn: "বরিশাল", aliases: ["barishal", "বরিশাল", "rupatali", "রুপাতলী", "natun bazar", "নতুন বাজার"] },
  { name: "Rangpur", bn: "রংপুর", aliases: ["rangpur", "রংপুর", "dhap", "ধাপ", "jahaj company", "জাহাজ কোম্পানি"] },
  { name: "Mymensingh", bn: "ময়মনসিংহ", aliases: ["mymensingh", "ময়মনসিংহ", "ganginar par", "গাঙ্গিনার পাড়", "charpara", "চরপাড়া"] },
  { name: "Comilla", bn: "কুমিল্লা", aliases: ["comilla", "কুমিল্লা", "cumilla", "kandirpar", "কান্দিরপাড়"] },
  { name: "Cox's Bazar", bn: "কক্সবাজার", aliases: ["cox's bazar", "coxs bazar", "কক্সবাজার", "kolatoli", "কলাতলী", "laboni", "লাবণী"] }
];

/**
 * Extracts location mentioned in user message or dialogue history
 * Intelligently handles Bengali case suffixes (ে, তে, য়, য়ে, র, ের) and English prepositions
 */
function extractLocation(message, history = []) {
  const allTexts = [];
  if (message) allTexts.push(message);

  // Check recent user messages in history in reverse order
  if (Array.isArray(history)) {
    const userHistory = history.filter(h => h.role === 'user').slice(-4).reverse();
    userHistory.forEach(h => {
      if (h && h.text) allTexts.push(h.text);
    });
  }

  for (const text of allTexts) {
    const tLower = text.toLowerCase();
    for (const loc of KNOWN_LOCATIONS) {
      for (const alias of loc.aliases) {
        // Build regex that matches the alias directly OR with Bengali inflections (ে, তে, য়, য়ে, র, ের)
        // Also supports English suffixes like 's or word boundaries
        const regexStr = `(?:\\b|[\\s,.])${alias}(?:ে|তে|য়|য়ে|র|ের|'s|s)?(?:\\b|[\\s,.!?]|$)`;
        try {
          const pattern = new RegExp(regexStr, 'i');
          if (pattern.test(` ${tLower} `)) {
            return loc;
          }
        } catch (e) {
          if (tLower.includes(alias)) {
            return loc;
          }
        }
      }
    }
  }

  return null;
}

/**
 * Detects if the query is strictly off-topic / irrelevant to safety, emergency, medical, thana, legal
 */
function isOffTopicQuery(qLower) {
  // Sports & Entertainment (English & Bengali)
  const sports = /\b(cricket|football|messi|ronaldo|ipl|bpl|fifa|world cup|champions league|psl|goal|virat kohli|shakib)\b|ক্রিকেট|ফুটবল|মেসি|রোনালদো|বিশ্বকাপ|আইপিএল|বিপিএল|খেলা|গোল/i;
  const entertainment = /\b(movie|cinema|actor|actress|hollywood|bollywood|natok|hero alam|song|lyrics|gan shunao|joke|chotkula|koutuk)\b|সিনেমা|মুভি|নাটক|অভিনেতা|নায়ক|গান শোনাও|কৌতুক|জোকস/i;
  
  // Academic / Coding / Cooking / Random trivia (English & Bengali)
  const coding = /\b(python code|javascript|html code|write a function|c\+\+|sql query|binary tree|algorithm|write an essay|homework|math equation|calculus|algebra)\b|প্রোগ্রামিং|কোডিং|রচনা লেখ|অংক করে দাও|হোমওয়ার্ক/i;
  const cooking = /\b(recipe|ranna|biryani recipe|how to cook|cake recipe|khichuri ranna|pizza|cooking)\b|রেসিপি|বিরিয়ানি|বিরিয়ানি|রান্না|রান্নার নিয়ম|পিজ্জা/i;
  const randomTrivia = /\b(capital of france|who is the president of usa|largest ocean|highest mountain|who invented|distance between earth and moon)\b|ফ্রান্সের রাজধানী|আমেরিকার প্রেসিডেন্ট|পৃথিবীর সবচেয়ে বড়/i;

  if (sports.test(qLower) || entertainment.test(qLower) || coding.test(qLower) || cooking.test(qLower) || randomTrivia.test(qLower)) {
    // Ensure it doesn't also contain emergency words
    const hasEmergency = /police|thana|accident|hospital|help|sos|fever|bleed|fire|emergency|ডাক্তার|হাসপাতাল|থানা|পুলিশ|বিপদ/i.test(qLower);
    return !hasEmergency;
  }
  return false;
}

/**
 * Main conversational engine that understands context, intent, and dialogue history
 */
async function processShurokhaChat(userMessage, history = []) {
  const originalQ = userMessage.trim();
  const qLower = originalQ.toLowerCase();
  const isBangla = /[\u0980-\u09FF]/.test(originalQ);

  // Extract location from current message or previous turns
  const detectedLocation = extractLocation(originalQ, history);
  const locationName = detectedLocation ? detectedLocation.name : null;
  const locationBn = detectedLocation ? detectedLocation.bn : null;

  // Retrieve previous bot topic if user is continuing a topic (e.g. user previously asked about eve teasing or fever)
  let lastTopic = null;
  if (Array.isArray(history) && history.length > 0) {
    const lastExchange = history.slice(-3);
    for (const msg of lastExchange) {
      const text = (msg.text || '').toLowerCase();
      if (/eve\s*teas|stalk|harass|উত্ত্যক্ত|ইভটিজিং/.test(text)) lastTopic = 'EVE_TEASING';
      else if (/snatch|mug|rob|ছিনতাই|ডাকাতি|ব্যাগ|মোবাইল চুরি/.test(text)) lastTopic = 'SNATCHING';
      else if (/fever|জ্বর|headache|stomach|অসুস্থ|sick|doctor|চিকিৎসা/.test(text)) lastTopic = 'MEDICAL';
      else if (/hospital|হাসপাতাল|clinic|অ্যাম্বুলেন্স/.test(text)) lastTopic = 'HOSPITAL';
    }
  }

  // ─── 0. STRICT OFF-TOPIC / IRRELEVANT FILTER ──────────────────────────────
  if (isOffTopicQuery(qLower)) {
    if (isBangla) {
      return {
        text: `আমি **shurokhaAI**, SAFE BD-এর নাগরিক নিরাপত্তা ও জরুরি স্বাস্থ্য সেবা এআই। 🛡️\n\nআমি আনন্দের সাথে আপনার সাথে কথা বলতে চাই, তবে আমি শুধুমাত্র **জরুরি নাগরিক সুরক্ষা, ডাক্তার ও প্রাথমিক চিকিৎসা পরামর্শ (জ্বর, দুর্ঘটনা), নিকটবর্তী হাসপাতাল ও অ্যাম্বুলেন্স তালিকা, এবং বাংলাদেশের যেকোনো থানার পুলিশের সাথে তাৎক্ষণিক যোগাযোগ** করিয়ে দেওয়ার জন্য বিশেষভাবে প্রস্তুত।\n\nআপনার কি কোনো স্বাস্থ্য পরামর্শ, নিকটবর্তী হাসপাতাল, বা কোনো এলাকার থানার ওসির জরুরি নাম্বার প্রয়োজন? অনুগ্রহ করে লিখুন!`,
        sources: [
          { title: "জাতীয় জরুরি সেবা ৯৯৯", url: "tel:999" },
          { title: "স্বাস্থ্য বাতায়ন ১৬২৬৩", url: "tel:16263" }
        ],
        poweredBy: "shurokhaAI Safety Guardrail"
      };
    } else {
      return {
        text: `Hello! I am **shurokhaAI**, SAFE BD's dedicated 24/7 Citizen Safety & Emergency Health Companion. 🛡️\n\nWhile I would love to chat, I am exclusively dedicated to keeping you safe and healthy in Bangladesh — providing **immediate medical first-aid guidance (fevers, accidents, acute illnesses), finding nearby hospitals & 24/7 ambulances, and connecting you with the exact Police Thana & Officer-in-Charge (OC)** across all 64 districts.\n\nDo you need medical advice, a list of nearby hospitals, or police station contacts for your area? Please let me know how I can help!`,
        sources: [
          { title: "National Emergency Helpline 999", url: "tel:999" },
          { title: "24/7 Doctor Consultation 16263", url: "tel:16263" }
        ],
        poweredBy: "shurokhaAI Safety Guardrail"
      };
    }
  }

  // ─── 1. EVE TEASING / STALKING / HARASSMENT ──────────────────────────────
  const isEveTeasing = /eve\s*teas|stalk|follow(?:ing|ed)?\s*me|harass|উত্ত্যক্ত|ইভটিজিং|পিছু নিয়েছে|উত্ত্যক্তকারী|বখাটে|মেয়েদের হয়রানি|পিছু নিচ্ছে/.test(qLower) || 
    (lastTopic === 'EVE_TEASING' && detectedLocation);

  if (isEveTeasing) {
    if (detectedLocation) {
      // User is in a known location or just provided their location!
      const thanaMatch = policeDirectory.resolvePoliceQuery(detectedLocation.name);
      if (isBangla) {
        let text = `🚨 **শান্ত থাকুন, আপনি একা নন — আমি আপনার সুরক্ষায় সাথে আছি!**\n\n` +
          `📍 **আপনার বর্তমান এলাকা:** ${locationBn || detectedLocation.name}\n\n` +
          `১. **অবিলম্বে নিরাপদ আশ্রয়ে যান:** রাস্তায় একা দাঁড়িয়ে থাকবেন না। দ্রুত নিকটস্থ জনবহুল স্থান, ফার্মেসি, ব্যাংক, সুপারশপ বা মেট্রো স্টেশনের ভেতরে গিয়ে দাঁড়ান।\n` +
          `২. **নিকটস্থ থানা ও পুলিশ কর্মকর্তাদের সরাসরি যোগাযোগ:**\n`;
        
        if (thanaMatch && thanaMatch.text) {
          text += `\n${thanaMatch.text}\n\n`;
        } else {
          text += `• **নিকটস্থ থানা পুলিশ:** ডিএমপি কন্ট্রোল রুম [01713-398311](tel:01713398311)\n• **জাতীয় জরুরি পুলিশ dispatch:** [৯৯৯](tel:999)\n\n`;
        }

        text += `৩. **জরুরি হটলাইনসমূহ:**\n` +
          `• **জাতীয় জরুরি সেবা (পুলিশ পেট্রোল পাঠানো):** [৯৯৯](tel:999) (তাৎক্ষণিক পুলিশ গাড়ি পাঠাতে বলুন)\n` +
          `• **নারী ও শিশু নির্যাতন প্রতিরোধ হেল্পলাইন:** [১০৯](tel:109) (টোল-ফ্রি ২৪ ঘণ্টা)\n` +
          `• **পুলিশ সাইবার সাপোর্ট ফর উইমেন (PCSW):** [01320-000888](tel:01320000888)\n\n` +
          `💡 *টিপ: আমাদের অ্যাপের ম্যাপে **Walk With Me** চালু করে পরিবারকে আপনার লাইভ গতিবিধি দেখান অথবা বেশি সংকটপূর্ণ মনে হলে লাল **SOS বোতামটি** ৩ বার চাপুন।*`;

        return {
          text,
          sources: thanaMatch?.sources || [{ title: "National 999 CAD Dispatch", url: "tel:999" }],
          poweredBy: "shurokhaAI Emergency Police Dispatch Engine"
        };
      } else {
        let text = `🚨 **Stay calm, you are not alone — I am right here with you!**\n\n` +
          `📍 **Your Detected Location:** ${detectedLocation.name}\n\n` +
          `1. **Move to Safety Immediately:** Do not confront the harassers alone. Walk briskly into the nearest well-lit, crowded place (a pharmacy, supermarket, bank, or metro station with security).\n` +
          `2. **Contact Your Nearest Police Station (Thana):**\n`;

        if (thanaMatch && thanaMatch.text) {
          text += `\n${thanaMatch.text}\n\n`;
        } else {
          text += `• **Nearest Police Dispatch:** DMP Control Room [01713-398311](tel:01713398311)\n• **Emergency Police CAD:** [999](tel:999)\n\n`;
        }

        text += `3. **Key Emergency Protection Lines:**\n` +
          `• **National Emergency Service (Immediate Police Patrol):** [999](tel:999) (State your exact location to dispatch officers)\n` +
          `• **National Helpline for Violence Against Women:** [109](tel:109) (Toll-Free 24/7)\n` +
          `• **Police Cyber Support for Women (PCSW):** [01320-000888](tel:01320000888) (Call / WhatsApp)\n\n` +
          `💡 *Tip: Activate Safe BD's **Walk With Me** feature on the Map tab to stream your live journey to trusted family, or press the Red **SOS Button** 3 times if in direct danger.*`;

        return {
          text,
          sources: thanaMatch?.sources || [{ title: "National 999 CAD Dispatch", url: "tel:999" }],
          poweredBy: "shurokhaAI Emergency Police Dispatch Engine"
        };
      }
    } else {
      // Location is not yet known — ask for location with high empathy!
      if (isBangla) {
        return {
          text: `🚨 **শান্ত থাকুন, ভয় পাবেন না — আমি আপনার পাশেই আছি!**\n\n` +
            `আপনি যাতে শতভাগ নিরাপদে থাকতে পারেন, তার জন্য এখনই এই পদক্ষেপগুলো নিন:\n` +
            `১. **নিরাপদ স্থানে যান:** একা নির্জন রাস্তায় না থেকে দ্রুত নিকটস্থ আলোযুক্ত দোকান, বাজার বা জনাকীর্ণ স্থানে চলে যান। বখাটেদের সাথে তর্কে জড়াবেন না।\n` +
            `২. **আপনার বর্তমান অবস্থান আমাকে জানান:** আপনি এখন **কোন এলাকায় বা কোন থানার কাছে আছেন?** (যেমন: *ধানমন্ডি, মিরপুর ১০, উত্তরা সেক্টর ৭, গুলশান* ইত্যাদি) — লিখলেই আমি আপনাকে নিকটস্থ থানার ওসির সরাসরি মোবাইল নাম্বার ও ডিউটি অফিসারের নাম্বার দিচ্ছি।\n` +
            `৩. **জরুরি পুলিশ ডাকতে:** যদি তারা পিছু না ছাড়ে, অবিলম্বে সরাসরি [৯৯৯](tel:999) এ কল করুন বা আমাদের লাল **SOS বোতামটি** চাপুন।\n` +
            `৪. **নারী সুরক্ষা হেল্পলাইন:** [১০৯](tel:109) (টোল-ফ্রি ২৪ ঘণ্টা)।\n\n` +
            `অনুগ্রহ করে আপনার বর্তমান এলাকার নামটি লিখুন, আমি তৎক্ষণাৎ থানার ঠিকানা ও ফোন নাম্বার দিচ্ছি।`,
          sources: [
            { title: "National Emergency Helpline 999", url: "tel:999" },
            { title: "Women Helpline 109", url: "tel:109" }
          ],
          poweredBy: "shurokhaAI Women Safety Protocol"
        };
      } else {
        return {
          text: `🚨 **Stay calm, breathe, and keep moving — you are NOT alone!**\n\n` +
            `Here is what you must do right now for your safety:\n` +
            `1. **Walk towards people:** Do not stop in dark or isolated areas. Step inside a busy shop, pharmacy, bank ATM booth, or restaurant where there are people and security guards.\n` +
            `2. **Tell me your location:** Which neighborhood or street are you at right now? (e.g., *Dhanmondi 27, Mirpur 10, Uttara Sector 4, Banani, etc.*) — Tell me, and I will instantly look up the **nearest Police Station (Thana), the Officer-in-Charge (OC) direct mobile number, and Duty Officer** so police can intervene.\n` +
            `3. **Immediate Dispatch:** If anyone is actively blocking or pursuing you, dial [999](tel:999) immediately or hold the Red SOS Button.\n` +
            `4. **National Women Helpline:** [109](tel:109) (Toll-Free 24/7).\n\n` +
            `Please reply with your current location so I can identify the exact nearby police station.`,
          sources: [
            { title: "National Emergency Service 999", url: "tel:999" },
            { title: "National Women Helpline 109", url: "tel:109" }
          ],
          poweredBy: "shurokhaAI Women Safety Protocol"
        };
      }
    }
  }

  // ─── 2. SNATCHING / MUGGING / ROBBERY ─────────────────────────────────────
  const isSnatching = /snatch|mug(?:ging|ged)?|rob(?:bery|bed)?|stole|churi|ছিনতাই|ডাকাতি|ব্যাগ টান|মোবাইল নিল|টাকা ছিনতাই|চুরি হয়েছে|ছিনতাইকারী/.test(qLower) ||
    (lastTopic === 'SNATCHING' && detectedLocation);

  if (isSnatching) {
    if (detectedLocation) {
      const thanaMatch = policeDirectory.resolvePoliceQuery(detectedLocation.name);
      if (isBangla) {
        let text = `🛡️ **আমি অত্যন্ত দুঃখিত এই অনাকাঙ্ক্ষিত ঘটনার জন্য। সবার আগে নিশ্চিত করুন আপনি শারীরিকভাবে নিরাপদ আছেন কিনা।**\n\n` +
          `📍 **ঘটনাস্থল / এলাকা:** ${locationBn || detectedLocation.name}\n\n` +
          `🚨 **তাৎক্ষণিক প্রয়োজনীয় পদক্ষেপ:**\n` +
          `১. **অবিলম্বে নিকটস্থ থানায় জিডি (GD) বা মামলা করুন:** ছিনতাইয়ের ঘটনায় দ্রুত থানায় অভিযোগ দায়ের করা অত্যন্ত গুরুত্বপূর্ণ।\n`;

        if (thanaMatch && thanaMatch.text) {
          text += `\n${thanaMatch.text}\n\n`;
        }

        text += `২. **সিম ও মোবাইল ব্যাংকিং বন্ধ করুন (যদি ফোন ছিনতাই হয়ে থাকে):**\n` +
          `   • **বিকাশ (bKash):** [16247](tel:16247) (অ্যাকাউন্ট সাময়িক ফ্রিজ করতে)\n` +
          `   • **নগদ (Nagad):** [16167](tel:16167)\n` +
          `   • **রকেট (Rocket):** [16216](tel:16216)\n` +
          `   • **সিম ব্লক করতে:** গ্রামীনফোন [121](tel:121), বাংলালিংক [121](tel:121), রবি [121](tel:121)\n` +
          `৩. **জিডিতে যা উল্লেখ করবেন:** মোবাইল ফোনের IMEI নাম্বার, ছিনতাইয়ের সঠিক সময় ও স্থান, এবং ছিনতাইকারীর কোনো শারীরিক বিবরণ বা বাইকের নাম্বার মনে থাকলে তা উল্লেখ করুন।\n` +
          `৪. **জরুরি পুলিশ পেট্রোল:** সরাসরি [৯৯৯](tel:999) এ কল করুন।`;

        return {
          text,
          sources: thanaMatch?.sources || [{ title: "National 999 Police Dispatch", url: "tel:999" }],
          poweredBy: "shurokhaAI Incident Response Engine"
        };
      } else {
        let text = `🛡️ **I am so sorry this happened to you! First, please take a deep breath — your physical safety is what matters most.**\n\n` +
          `📍 **Incident Area:** ${detectedLocation.name}\n\n` +
          `🚨 **Crucial Immediate Steps to Take:**\n` +
          `1. **Report to Nearest Police Station (Thana):** File a General Diary (GD) or FIR immediately so police can track the perpetrators.\n`;

        if (thanaMatch && thanaMatch.text) {
          text += `\n${thanaMatch.text}\n\n`;
        }

        text += `2. **Freeze Financial Accounts & SIMs (If Phone was Snatched):**\n` +
          `   • **bKash:** [16247](tel:16247) (Freeze your mobile wallet)\n` +
          `   • **Nagad:** [16167](tel:16167)\n` +
          `   • **Rocket:** [16216](tel:16216)\n` +
          `   • **Telecom SIM Lock:** Grameenphone [121](tel:121), Banglalink [121](tel:121), Robi [121](tel:121)\n` +
          `3. **Key Details for the GD/FIR:** Note the IMEI number (from device box), exact time, direction the snatchers fled, and vehicle/bike license plate if noticed.\n` +
          `4. **Immediate Police Alert:** Call [999](tel:999) toll-free.`;

        return {
          text,
          sources: thanaMatch?.sources || [{ title: "National 999 Police Dispatch", url: "tel:999" }],
          poweredBy: "shurokhaAI Incident Response Engine"
        };
      }
    } else {
      if (isBangla) {
        return {
          text: `🛡️ **আমি অত্যন্ত দুঃখিত এই ছিনতাইয়ের ঘটনার জন্য!** অনুগ্রহ করে শান্ত থাকুন — সবার আগে দেখুন আপনার শরীরে কোনো আঘাত বা রক্তপাত হয়েছে কিনা।\n\n` +
            `🚨 **এখনই যা করণীয়:**\n` +
            `১. **নিকটস্থ থানায় গিয়ে জিডি করুন:** পুলিশকে অবিলম্বে অবহিত করা জরুরি যাতে সিসিটিভি ফুটেজ সংগ্রহ করা যায়।\n` +
            `২. **আপনার এলাকা জানান:** ছিনতাইয়ের ঘটনাটি **কোন এলাকায় বা কোন রোডে ঘটেছে?** (যেমন: *ধানমন্ডি, মিরপুর, গুলশান, বাড্ডা* ইত্যাদি) জানালে আমি আপনাকে ওই এলাকার থানার ওসির ফোন নাম্বার ও সঠিক ঠিকানা দিচ্ছি।\n` +
            `৩. **ফোন ছিনতাই হলে দ্রুত মোবাইল ব্যাংকিং ব্লক করুন:** বিকাশ ([16247](tel:16247)), নগদ ([16167](tel:16167)), রকেট ([16216](tel:16216)) ও আপনার সিম অপারেটরের হেল্পলাইনে ([121](tel:121)) কল করে অ্যাকাউন্ট বন্ধ করুন।\n` +
            `৪. **জরুরি পুলিশ টহল:** সরাসরি [৯৯৯](tel:999) এ কল করুন।\n\n` +
            `ঘটনাটি কোন এলাকায় ঘটেছে অনুগ্রহ করে লিখুন।`,
          sources: [
            { title: "National Emergency 999", url: "tel:999" },
            { title: "bKash Emergency Lock 16247", url: "tel:16247" }
          ],
          poweredBy: "shurokhaAI Incident Response Engine"
        };
      } else {
        return {
          text: `🛡️ **I am so sorry to hear this! First, please ensure you are in a safe place and check if you sustained any injuries.**\n\n` +
            `🚨 **Immediate Actions to Take Right Now:**\n` +
            `1. **Visit the Nearest Police Station (Thana):** A General Diary (GD) or FIR must be lodged quickly so officers can review CCTV footage and track stolen property.\n` +
            `2. **Where did this happen?** Tell me the area or street name (e.g., *Dhanmondi, Uttara, Mirpur, Old Dhaka*), and I will provide the exact **nearest Police Thana, address, and OC direct phone number**.\n` +
            `3. **If your phone was taken, secure your accounts immediately:**\n` +
            `   • Call bKash ([16247](tel:16247)), Nagad ([16167](tel:16167)), or Rocket ([16216](tel:16216)) to freeze wallets.\n` +
            `   • Call your SIM operator ([121](tel:121)) to suspend the SIM card.\n` +
            `4. **Urgent Police Assistance:** Dial [999](tel:999) directly.\n\n` +
            `Which area or neighborhood did this happen in?`,
          sources: [
            { title: "National Emergency Helpline 999", url: "tel:999" },
            { title: "bKash Emergency Helpline 16247", url: "tel:16247" }
          ],
          poweredBy: "shurokhaAI Incident Response Engine"
        };
      }
    }
  }

  // ─── 3. MEDICAL GUIDANCE / FEVER / SICKNESS / DOCTOR ──────────────────────
  const isMedicalQuery = /fever|temperature|high fever|cold|cough|headache|stomach\s*ache|body\s*ache|dengue|ill|sick|doctor|consult|vomit|weakness|pain|জ্বর|মাথা\s*ব্যথা|পেট\s*ব্যথা|ঠাণ্ডা|কাশি|অসুস্থ|বমি|ডেঙ্গু|ডাক্তার|শরীর\s*খারাপ|গা\s*গরম|প্যারাসিটামল/.test(qLower) ||
    (lastTopic === 'MEDICAL' && detectedLocation);

  if (isMedicalQuery) {
    let hospitalRecommendations = null;
    if (detectedLocation) {
      const hospitals = hospitalDirectory.findHospitalsByLocation(detectedLocation.name, 3);
      if (hospitals && hospitals.length > 0) {
        hospitalRecommendations = hospitalDirectory.formatHospitalListResponse(hospitals, detectedLocation.name, isBangla);
      }
    }

    if (isBangla) {
      let text = `🩺 **আমি বুঝতে পারছি আপনি বা আপনার আপনজন অসুস্থ বোধ করছেন — নিজের যত্ন নিন, আমি আপনাকে পরামর্শ ও সহায়তা দিচ্ছি!**\n\n` +
        `🌡️ **জরুরি প্রাথমিক স্বাস্থ্য পরামর্শ:**\n` +
        `১. **প্রচুর পানি ও তরল গ্রহণ করুন:** খাওয়ার স্যালাইন (ORS), ডাবের পানি, স্যুপ এবং সাধারণ পানি বেশি করে পান করুন যাতে পানিশূন্যতা না হয়।\n` +
        `২. **শরীর স্পঞ্জ করা:** বরফ বা খুব ঠাণ্ডা পানি ব্যবহার করবেন না। সাধারণ তাপমাত্রার পানিতে সুতি কাপড় ভিজিয়ে কপাল, ঘাড় ও শরীরে আলতো করে জলপট্টি দিন।\n` +
        `৩. **প্যারাসিটামল সেবন:** জ্বর কমাতে প্রাপ্তবয়স্কদের ক্ষেত্রে চিকিৎসকের পরামর্শ অনুযায়ী সাধারণ প্যারাসিটামল (৫০০ মি.গ্রা.) গ্রহণ করা যেতে পারে। **ডেঙ্গু মৌসুমে ভুলেও অ্যাসপিরিন বা ব্যথানাশক (NSAIDs যেমন ব্রুফেন, ডাইক্লোফেনাক) সেবন করবেন না!**\n` +
        `৪. **বিনা মূল্যে সরকারি ডাক্তারের সাথে সরাসরি কথা বলুন:**\n` +
        `   • 📞 **স্বাস্থ্য বাতায়ন (DGHS):** [১৬২৬৩ (16263)](tel:16263) — টোল-ফ্রি ২৪ ঘণ্টা লাইসেন্সধারী সরকারি চিকিৎসকের সাথে সরাসরি পরামর্শ নিন।\n\n` +
        `⚠️ **জরুরি বিপদের লক্ষণ (অবিলম্বে হাসপাতালে যাওয়ার সংকেত):**\n` +
        `• জ্বর ১০৩° ফারেনহাইটের বেশি হলে বা না কমলে\n` +
        `• তীব্র পেট ব্যথা, অনবরত বমি বা নাক-দাঁত দিয়ে রক্তপাত (ডেঙ্গুর লক্ষণ)\n` +
        `• শ্বাসকষ্ট বা প্রচণ্ড বুকে চাপ অনুভূত হলে\n` +
        `👉 এই লক্ষণগুলো দেখা দিলে তাৎক্ষণিক অ্যাম্বুলেন্সের জন্য **[৯৯৯ (999)](tel:999)** এ কল করুন!\n\n`;

      if (hospitalRecommendations) {
        text += hospitalRecommendations.text;
      } else {
        text += `💡 *আপনি কোন এলাকায় থাকেন লিখলে (যেমন: **ধানমন্ডি, মিরপুর, উত্তরা, গুলশান, চট্টগ্রাম** ইত্যাদি), আমি আপনার নিকটবর্তী প্রধান হাসপাতাল ও অ্যাম্বুলেন্সের ফোন নাম্বার দিয়ে দেব।*`;
      }

      return {
        text,
        sources: [
          { title: "স্বাস্থ্য বাতায়ন ১৬২৬৩ (DGHS)", url: "tel:16263" },
          { title: "জাতীয় জরুরি অ্যাম্বুলেন্স ৯৯৯", url: "tel:999" }
        ],
        poweredBy: "shurokhaAI Health & Triage Engine"
      };
    } else {
      let text = `🩺 **I'm really sorry to hear you're feeling unwell! High fevers and sickness can be physically exhausting. Here is proper medical first-aid guidance:**\n\n` +
        `🌡️ **Immediate At-Home Steps:**\n` +
        `1. **Hydration is Priority:** Drink plenty of fluids (oral rehydration salts/saline, coconut water, fresh soup, clean water) to prevent dehydration.\n` +
        `2. **Sponging:** Use a soft washcloth soaked in regular room-temperature tap water (do NOT use cold ice water) on forehead, neck, and armpits to gradually lower body temperature.\n` +
        `3. **Fever Medication:** Standard Paracetamol (500mg/665mg) can be taken per standard dosage if not contraindicated. **CRITICAL WARNING:** During Dengue season in Bangladesh, NEVER take Aspirin, Brufen, or Diclofenac without a blood test, as they cause internal bleeding.\n` +
        `4. **Consult a Licensed Doctor 24/7 for Free:**\n` +
        `   • 📞 **DGHS Shastho Batayan:** [16263](tel:16263) — Official Bangladesh government helpline with registered medical doctors available 24/7.\n\n` +
        `⚠️ **Red Flag Symptoms (Seek Emergency Care Immediately):**\n` +
        `• Fever exceeding 103°F (39.4°C) or not responding to medication\n` +
        `• Severe persistent vomiting, severe abdominal pain, bleeding gums/nose (Dengue warning signs)\n` +
        `• Shortness of breath, chest pain, or confusion/drowsiness\n` +
        `👉 If any red flags appear, dial **[999](tel:999)** immediately for an emergency ambulance!\n\n`;

      if (hospitalRecommendations) {
        text += hospitalRecommendations.text;
      } else {
        text += `💡 *Which area or district do you live in? (e.g., **Dhanmondi, Uttara, Mirpur, Old Dhaka, Chittagong**, etc.) Tell me, and I will give you the nearest emergency hospitals and direct ambulance contacts.*`;
      }

      return {
        text,
        sources: [
          { title: "Shastho Batayan 16263 (DGHS)", url: "tel:16263" },
          { title: "National Emergency Ambulance 999", url: "tel:999" }
        ],
        poweredBy: "shurokhaAI Health & Triage Engine"
      };
    }
  }

  // ─── 4. HOSPITAL & AMBULANCE LOOKUP ───────────────────────────────────────
  const isHospitalQuery = /hospital|clinic|ambulance|nearest\s*hospital|hospital\s*near|হাসপাতাল|ক্লিনিক|অ্যাম্বুলেন্স|নিকটবর্তী\s*হাসপাতাল/.test(qLower) ||
    (lastTopic === 'HOSPITAL' && detectedLocation);

  if (isHospitalQuery) {
    if (detectedLocation) {
      const hospitals = hospitalDirectory.findHospitalsByLocation(detectedLocation.name, 4);
      if (hospitals && hospitals.length > 0) {
        const resp = hospitalDirectory.formatHospitalListResponse(hospitals, detectedLocation.name, isBangla);
        return {
          text: resp.text,
          sources: resp.sources,
          poweredBy: "Verified Bangladesh Hospital & Trauma Directory"
        };
      }
    }

    // Location not detected
    if (isBangla) {
      return {
        text: `🏥 **নিকটবর্তী জরুরি হাসপাতাল ও অ্যাম্বুলেন্স খুঁজে পেতে:**\n\n` +
          `আপনি **কোন এলাকা বা জেলায় অবস্থান করছেন?** অনুগ্রহ করে এলাকার নামটি লিখুন (যেমন: **ধানমন্ডি, মিরপুর, উত্তরা, গুলশান, মহাখালী, পুরান ঢাকা, সাভার, চট্টগ্রাম, রাজশাহী, সিলেট** ইত্যাদি)।\n\n` +
          `📞 **জাতীয় কেন্দ্রীয় জরুরি চিকিৎসা সেবা:**\n` +
          `• **জাতীয় জরুরি অ্যাম্বুলেন্স dispatch:** [৯৯৯](tel:999) (টোল-ফ্রি ২৪ ঘণ্টা — সারাদেশে তাৎক্ষণিক অ্যাম্বুলেন্স সমন্বয়)\n` +
          `• **সরকারি স্বাস্থ্য বাতায়ন (ডাক্তারের পরামর্শ):** [১৬২৬৩](tel:16263)\n` +
          `• **ঢাকা মেডিকেল কলেজ হাসপাতাল (DMCH জরুরি বিভাগ):** [02-55165088](tel:0255165088)\n` +
          `• **জাতীয় হৃদরোগ ইনস্টিটিউট (হার্ট ইমার্জেন্সি):** [02-9122560](tel:029122560)\n` +
          `• **জাতীয় বার্ন ও প্লাস্টিক সার্জারি ইনস্টিটিউট:** [02-223381001](tel:02223381001)\n\n` +
          `আপনার এলাকার নামটি লিখুন, আমি সবচেয়ে কাছের হাসপাতালগুলোর সরাসরি ফোন নাম্বার ও অ্যাম্বুলেন্স হটলাইন দিয়ে দিচ্ছি।`,
        sources: [
          { title: "National Emergency Ambulance 999", url: "tel:999" },
          { title: "Shastho Batayan 16263", url: "tel:16263" }
        ],
        poweredBy: "Verified Bangladesh Hospital Directory"
      };
    } else {
      return {
        text: `🏥 **To find the nearest emergency hospital & ambulance:**\n\n` +
          `Which **area, neighborhood, or district** are you located in? (e.g., **Dhanmondi, Uttara, Mirpur, Gulshan, Mohakhali, Old Dhaka, Savar, Chittagong, Sylhet**, etc.)\n\n` +
          `📞 **National Emergency Healthcare Helplines:**\n` +
          `• **National 999 CAD Ambulance Dispatch:** [999](tel:999) (24/7 toll-free dispatch across Bangladesh)\n` +
          `• **Shastho Batayan (Free Doctor Tele-Consultation):** [16263](tel:16263)\n` +
          `• **Dhaka Medical College Hospital (DMCH Trauma):** [02-55165088](tel:0255165088)\n` +
          `• **National Heart Institute (NICVD Acute Cardiac):** [02-9122560](tel:029122560)\n` +
          `• **National Burn & Plastic Surgery Institute:** [02-223381001](tel:02223381001)\n\n` +
          `Reply with your location, and I will list the verified hospitals and direct ambulance hotlines nearest to you.`,
        sources: [
          { title: "National Emergency 999", url: "tel:999" },
          { title: "Shastho Batayan 16263", url: "tel:16263" }
        ],
        poweredBy: "Verified Bangladesh Hospital Directory"
      };
    }
  }

  // ─── 5. EMERGENCY BLOOD LIFELINE / BLOOD DONOR ───────────────────────────
  const isBloodQuery = /blood|রক্ত|donat|donor|blood\s*group|a\+|b\+|o\+|ab\+|রক্তবন্ধু|রক্তদাতা|রক্তের প্রয়োজন/.test(qLower);
  if (isBloodQuery) {
    if (isBangla) {
      return {
        text: `🩸 **Safe BD জরুরি রক্তবন্ধু (Emergency Blood Lifeline):**\n\n` +
          `জরুরি রক্তের প্রয়োজনে Safe BD সরাসরি সাহায্য করতে প্রস্তুত!\n\n` +
          `১. **অ্যাপের রক্তবন্ধু ফিচারে যান:** হোম স্ক্রিনের **"আমি সাহায্য চাই" (I Need Help)** বোতামে ট্যাপ করে **"জরুরি রক্তবন্ধু"** নির্বাচন করুন। সেখানে আপনার কাঙ্ক্ষিত রক্তের গ্রুপ (A+, B+, O+, AB+, ইত্যাদি) ও জেলা নির্বাচন করে সরাসরি নিবন্ধিত রক্তদাতাদের কল বা হোয়াটসঅ্যাপ করতে পারবেন।\n` +
          `২. **জরুরি ব্লাড ব্যাংক হটলাইনসমূহ:**\n` +
          `   • **বাংলাদেশ রেড ক্রিসেন্ট সোসাইটি ব্লাড সেন্টার:** [02-9330188](tel:029330188)\n` +
          `   • **কোয়ান্টাম ল্যাব ব্লাড ব্যাংক (২৪ ঘণ্টা):** [01714-010869](tel:01714010869) / [02-9351969](tel:029351969)\n` +
          `   • **সন্ধানী কেন্দ্রীয় রক্তদান কেন্দ্র (DMCH):** [02-55165088](tel:0255165088)\n` +
          `   • **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999)\n\n` +
          `💡 *আপনিও রক্তদাতা হতে চাইলে প্রোফাইল এডিটে গিয়ে রক্তের গ্রুপ সেভ করে রক্তদাতা হিসেবে অপ্ট-ইন করতে পারেন — যা আজীবন ক্লাউড ডাটাবেজে স্থায়ীভাবে সংরক্ষিত থাকবে।*`,
        sources: [
          { title: "Quantum Foundation Blood Lab", url: "tel:01714010869" },
          { title: "Red Crescent Blood Center", url: "tel:029330188" }
        ],
        poweredBy: "Safe BD Blood Lifeline Engine"
      };
    } else {
      return {
        text: `🩸 **Safe BD Emergency Blood Lifeline (রক্তবন্ধু):**\n\n` +
          `If you or your patient needs blood urgently, here is how Safe BD connects you:\n\n` +
          `1. **Use Safe BD's Blood Lifeline:** Tap **"I Need Help"** on the home screen, then select **"Emergency Blood Lifeline"**. Filter by blood group (A+, B+, O+, AB+, etc.) and district to call or WhatsApp verified registered donors with 1 tap.\n` +
          `2. **24/7 Central Blood Bank Hotlines in Bangladesh:**\n` +
          `   • **Quantum Foundation Blood Center (24/7):** [01714-010869](tel:01714010869) / [02-9351969](tel:029351969)\n` +
          `   • **Bangladesh Red Crescent Society Blood Center:** [02-9330188](tel:029330188)\n` +
          `   • **Sandhani Central Blood Unit (DMCH):** [02-55165088](tel:0255165088)\n` +
          `   • **National Emergency Service:** [999](tel:999)\n\n` +
          `💡 *You can also register as a donor from your Citizen Profile tab — your blood group is permanently persisted to Supabase SQL.*`,
        sources: [
          { title: "Quantum Blood Lab Hotline", url: "tel:01714010869" },
          { title: "Red Crescent Blood Hotline", url: "tel:029330188" }
        ],
        poweredBy: "Safe BD Blood Lifeline Engine"
      };
    }
  }

  // ─── 6. GD (GENERAL DIARY) & LEGAL FILING ─────────────────────────────────
  const isGdQuery = /\bgd\b|general\s*diary|জিডি|মামলা|থানায় অভিযোগ|কীভাবে জিডি/.test(qLower);
  if (isGdQuery) {
    if (isBangla) {
      return {
        text: `📝 **থানায় জিডি (General Diary) করার নিয়মাবলী ও তথ্য:**\n\n` +
          `১. **অনলাইন জিডি (Online GD):** মোবাইল ফোন, পাসপোর্ট, সার্টিফিকেট বা জাতীয় পরিচয়পত্র হারালে সরাসরি বাংলাদেশ পুলিশের অনলাইন জিডি পোর্টাল (\`gd.police.gov.bd\`) বা অ্যাপের মাধ্যমে ঘরে বসেই জিডি করা যায়।\n` +
          `২. **সরাসরি থানায় জিডি (হুমকি, বিরোধ বা ছিনতাই):**\n` +
          `   • সাদা কাগজে সংশ্লিষ্ট থানার অফিসার ইনচার্জ (OC) বরাবর আবেদন লিখুন।\n` +
          `   • আপনার পূর্ণ নাম, জাতীয় পরিচয়পত্র (NID) নম্বর ও মোবাইল নম্বর দিন।\n` +
          `   • ঘটনার সঠিক তারিখ, সময় ও স্থানের বিবরণ স্পষ্টভাবে লিখুন।\n` +
          `   • হারানো জিনিসের ক্ষেত্রে (যেমন ফোন) IMEI নম্বর ও মডেল উল্লেখ করুন।\n` +
          `   • আবেদনপত্রের ২ কপি নিয়ে থানায় ডিউটি অফিসারের কাছে জমা দিন। ডিউটি অফিসার একটি কপিতে স্বাক্ষর ও সিল দিয়ে আপনাকে "GD ট্র্যাকিং কপি" ফেরত দেবেন। এটি যত্ন করে রাখবেন।\n\n` +
          `💡 *আপনার থানার নাম লিখুন, আমি সরাসরি ওই থানার ওসির ফোন নাম্বার ও ঠিকানা প্রদান করছি।*`,
        sources: [{ title: "Online GD Portal", url: "https://gd.police.gov.bd" }],
        poweredBy: "shurokhaAI Legal & GD Assistant"
      };
    } else {
      return {
        text: `📝 **How to File a GD (General Diary) with Bangladesh Police:**\n\n` +
          `1. **Online GD Portal:** For lost documents (National ID, Passport, Educational Certificates, or Mobile Phones), you can file directly online via \`gd.police.gov.bd\` without going to the station.\n` +
          `2. **Physical Thana GD (For Snatching, Threats, or Security Concerns):**\n` +
          `   • Address the application to the **Officer-in-Charge (OC)** of the police station where the incident occurred.\n` +
          `   • State your full name, Father's name, Address, NID number, and active mobile number.\n` +
          `   • Describe the incident with exact date, time, and location.\n` +
          `   • For lost/stolen phones, include the IMEI numbers and device serial number.\n` +
          `   • Submit 2 printed copies to the 24/7 Duty Officer at the Thana. The Duty Officer will sign, stamp, and hand you back one copy with an official GD Number.\n\n` +
          `💡 *Reply with your Thana or area name, and I will give you the direct OC mobile and 24/7 Duty Officer numbers immediately.*`,
        sources: [{ title: "Bangladesh Police Online GD", url: "https://gd.police.gov.bd" }],
        poweredBy: "shurokhaAI Legal & GD Assistant"
      };
    }
  }

  // ─── 7. DIRECT THANA / POLICE LOOKUP ──────────────────────────────────────
  const thanaQueryMatch = policeDirectory.resolvePoliceQuery(originalQ);
  if (thanaQueryMatch) {
    return {
      text: thanaQueryMatch.text,
      sources: thanaQueryMatch.sources || [],
      poweredBy: "Official Bangladesh Police Master Directory (01320 Series)"
    };
  }

  // ─── 8. GREETING / CASUAL CONVERSATION ────────────────────────────────────
  const isGreeting = /^(hi|hello|hey|সালাম|হ্যালো|হাই|assalamu|who are you|তুমি কে|কেমন আছ|how are you|kemon acho|ধন্যবাদ|thank you|thanks)\b/i.test(qLower);
  if (isGreeting) {
    if (isBangla) {
      return {
        text: `আসসালামু আলাইকুম! আমি **shurokhaAI**, SAFE BD-এর ২৪/৭ সার্বক্ষণিক নাগরিক সুরক্ষা ও জরুরি স্বাস্থ্য সেবা সহকারী। 🛡️\n\n` +
          `আমি আপনাকে যেভাবে সহায়তা করতে পারি:\n` +
          `• 🩺 **জরুরি স্বাস্থ্য ও প্রাথমিক চিকিৎসা:** জ্বর, ঠাণ্ডা, ডেঙ্গু, বা কোনো অসুস্থতায় করণীয় এবং লাইসেন্সধারী ডাক্তারের পরামর্শ ([১৬২৬৩](tel:16263))।\n` +
          `• 🏥 **নিকটবর্তী হাসপাতাল ও অ্যাম্বুলেন্স:** আপনার এলাকার নাম লিখলেই নিকটস্থ হাসপাতাল ও অ্যাম্বুলেন্সের সরাসরি নাম্বার।\n` +
          `• 👮 **বাংলাদেশের সকল থানা ও ওসির সরকারি নাম্বার:** যেকোনো এলাকা বা থানার নাম লিখলেই ওসির নতুন অফিসিয়াল (01320- সিরিজ) সরাসরি নাম্বার।\n` +
          `• 🚨 **ছিনতাই বা ইভটিজিংয়ের শিকার হলে:** তাৎক্ষণিক করণীয় ও নিকটস্থ থানায় অভিযোগ করার গাইডলাইন।\n` +
          `• 🩸 **জরুরি রক্তবন্ধু:** রক্তের গ্রুপ ও জেলা অনুযায়ী রক্তদাতা খোঁজা।\n\n` +
          `আপনার এখন কী সেবা বা পরামর্শ প্রয়োজন? আমাকে নির্দ্বিধায় বলুন!`,
        sources: [
          { title: "National Emergency Helpline 999", url: "tel:999" },
          { title: "Shastho Batayan 16263", url: "tel:16263" }
        ],
        poweredBy: "shurokhaAI Conversational Engine"
      };
    } else {
      return {
        text: `Hello! I am **shurokhaAI**, your 24/7 dedicated Citizen Safety & Emergency Health Companion from SAFE BD. 🛡️\n\n` +
          `Here is how I can assist you right now:\n` +
          `• 🩺 **Medical Guidance & First-Aid:** Fevers, sudden illness, dengue precautions, and free licensed doctor tele-consultation ([16263](tel:16263)).\n` +
          `• 🏥 **Nearby Hospitals & 24/7 Ambulances:** State your area, and I will list the verified emergency hospitals and ambulance dispatch lines.\n` +
          `• 👮 **All 641 Police Thanas & OC Contacts:** Official direct mobile numbers (new 01320- series) and 24/7 Duty Officers for any area in Bangladesh.\n` +
          `• 🚨 **Crisis Guidance:** Step-by-step assistance for eve teasing, stalking, snatching, or robbery.\n` +
          `• 🩸 **Emergency Blood Lifeline:** Connect with verified donors across all blood types.\n\n` +
          `How can I help you today? Please tell me what you need!`,
        sources: [
          { title: "National Emergency Service 999", url: "tel:999" },
          { title: "DGHS Shastho Batayan 16263", url: "tel:16263" }
        ],
        poweredBy: "shurokhaAI Conversational Engine"
      };
    }
  }

  // ─── 9. GENERAL HELPFUL FALLBACK ──────────────────────────────────────────
  if (isBangla) {
    return {
      text: `আমি আপনার কথাটি বুঝতে পেরেছি। **shurokhaAI** হিসেবে আমি আপনাকে নিম্নলিখিত সেবাগুলোতে তাৎক্ষণিক সাহায্য করতে পারি:\n\n` +
        `১. 🩺 **শারীরিক অসুস্থতা বা জ্বর:** আপনার কী সমস্যা হচ্ছে লিখুন, আমি করণীয় ও ডাক্তারের পরামর্শ দিচ্ছি।\n` +
        `২. 🏥 **নিকটবর্তী হাসপাতাল ও অ্যাম্বুলেন্স:** আপনার এলাকা বা থানার নাম লিখুন।\n` +
        `৩. 👮 **থানার ওসির ফোন নাম্বার ও ঠিকানা:** যেকোনো থানার নাম লিখুন (যেমন: *ধানমন্ডি, মিরপুর, গুলশান, বাড্ডা, কক্সবাজার* ইত্যাদি)।\n` +
        `৪. 🚨 **জরুরি ছিনতাই, বখাটেদের উৎপাত বা বিপদ:** তাৎক্ষণিক পদক্ষেপ ও পুলিশ প্রটোকল।\n` +
        `৫. 🩸 **রক্তের প্রয়োজন:** রক্তের গ্রুপ লিখলে রক্তদাতার তথ্য ও ব্লাড ব্যাংক লাইন পাবেন।\n\n` +
        `জরুরি সংকটে অবিলম্বে জাতীয় জরুরি সেবা **[৯৯৯ (999)](tel:999)** এ কল করুন। আপনার কী তথ্য বা সেবা প্রয়োজন অনুগ্রহ করে একটু বিস্তারিত লিখুন।`,
      sources: [
        { title: "জাতীয় জরুরি সেবা ৯৯৯", url: "tel:999" },
        { title: "স্বাস্থ্য বাতায়ন ১৬২৬৩", url: "tel:16263" }
      ],
      poweredBy: "shurokhaAI Conversational Engine"
    };
  } else {
    return {
      text: `I understand. As **shurokhaAI**, I am trained to assist you with the following essential safety & healthcare services:\n\n` +
        `1. 🩺 **Health Symptoms & Fevers:** Describe what you are experiencing, and I will provide home triage, precautions, and doctor access.\n` +
        `2. 🏥 **Nearest Hospital Directory:** Tell me your neighborhood or district, and I will list the verified emergency hospitals and 24/7 ambulances.\n` +
        `3. 👮 **Police Thana & OC Contacts:** Name any area or Thana (e.g., *Dhanmondi, Uttara, Mirpur, Banani, Chittagong, etc.*) to receive the direct OC and Duty Officer numbers.\n` +
        `4. 🚨 **Eve Teasing, Stalking, or Snatching:** Step-by-step guidance on reaching safety and lodging a GD/FIR.\n` +
        `5. 🩸 **Emergency Blood Donors:** Connect with verified donors via SAFE BD's Blood Lifeline.\n\n` +
        `For immediate life-threatening danger, dial **[999](tel:999)** right away. How can I assist you further?`,
      sources: [
        { title: "National Emergency Helpline 999", url: "tel:999" },
        { title: "DGHS Shastho Batayan 16263", url: "tel:16263" }
      ],
      poweredBy: "shurokhaAI Conversational Engine"
    };
  }
}

module.exports = {
  processShurokhaChat,
  extractLocation,
  isOffTopicQuery
};
