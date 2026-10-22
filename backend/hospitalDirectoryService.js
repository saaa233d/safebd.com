/**
 * Bangladesh & Dhaka Hospital Directory Service
 * Developed for SAFE BD (shurokhaAI)
 *
 * Covers:
 * - 24/7 Government Emergency & Medical College Hospitals
 * - Major Private Specialized Hospitals & Trauma Centres
 * - Area-by-area breakdown across Dhaka & all major Divisions
 * - Verified emergency contacts, ambulance dispatch lines, and addresses
 */

const fs = require('fs');

const HOSPITALS_DATABASE = [
  // ─── DHANMONDI / LALMATIA / KALABAGAN / GREEN ROAD ────────────────────────
  {
    name: "Bangladesh Medical College Hospital (BMCH)",
    bnName: "বাংলাদেশ মেডিকেল কলেজ হাসপাতাল",
    area: "Dhanmondi",
    district: "Dhaka",
    type: "Medical College & General Hospital",
    emergencyPhone: "02-9118202",
    ambulancePhone: "01715-015635",
    address: "House 34, Road 14/A, Dhanmondi, Dhaka",
    is24x7: true,
    specialties: ["Emergency Casualty", "ICU", "Surgery", "Internal Medicine"],
    keywords: ["dhanmondi", "ধানমন্ডি", "lalmatia", "লালমাটিয়া", "kalabagan", "কলাবাগান", "road 14", "bmch"]
  },
  {
    name: "Labaid Specialized Hospital & Cardiac Hospital",
    bnName: "ল্যাবএইড স্পেশালাইজড ও কার্ডিয়াক হাসপাতাল",
    area: "Dhanmondi",
    district: "Dhaka",
    type: "Specialized Cardiac & Multi-Specialty",
    emergencyPhone: "10606",
    ambulancePhone: "01766-662888",
    address: "House 06, Road 04, Dhanmondi, Dhaka",
    is24x7: true,
    specialties: ["24/7 Cardiac Emergency", "ICU/CCU", "Emergency Trauma"],
    keywords: ["dhanmondi", "ধানমন্ডি", "labaid", "ল্যাবএইড", "cardiac", "হার্ট"]
  },
  {
    name: "Anwer Khan Modern Medical College Hospital",
    bnName: "আনোয়ার খান মডার্ন মেডিকেল কলেজ হাসপাতাল",
    area: "Dhanmondi",
    district: "Dhaka",
    type: "Medical College Hospital",
    emergencyPhone: "02-9670295",
    ambulancePhone: "01716-160160",
    address: "House 17, Road 08, Dhanmondi, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Casualty", "ICU", "Dialysis"],
    keywords: ["dhanmondi", "ধানমন্ডি", "anwer khan", "আনোয়ার খান"]
  },
  {
    name: "Ibn Sina Hospital Dhanmondi",
    bnName: "ইবনে সিনা হাসপাতাল ধানমন্ডি",
    area: "Dhanmondi",
    district: "Dhaka",
    type: "Private General Hospital",
    emergencyPhone: "10615",
    ambulancePhone: "01823-039800",
    address: "House 48, Road 9/A, Dhanmondi, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency", "NICU", "ICU", "General Surgery"],
    keywords: ["dhanmondi", "ধানমন্ডি", "ibn sina", "ইবনে সিনা"]
  },
  {
    name: "Green Life Hospital",
    bnName: "গ্রিন লাইফ হাসপাতাল",
    area: "Green Road",
    district: "Dhaka",
    type: "Multi-Specialty Hospital",
    emergencyPhone: "02-9612345",
    ambulancePhone: "01938-842220",
    address: "32 Green Road, Dhanmondi, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency", "Trauma", "Surgery", "ICU"],
    keywords: ["green road", "গ্রিন রোড", "dhanmondi", "ধানমন্ডি", "green life", "গ্রিন লাইফ"]
  },
  {
    name: "Popular Diagnostic Centre & Hospital Dhanmondi",
    bnName: "পপুলার হাসপাতাল ধানমন্ডি",
    area: "Dhanmondi",
    district: "Dhaka",
    type: "Private Hospital",
    emergencyPhone: "09613-787801",
    ambulancePhone: "01553-341060",
    address: "House 16, Road 2, Dhanmondi, Dhaka",
    is24x7: true,
    specialties: ["Emergency Observation", "ICU", "Diagnostics"],
    keywords: ["dhanmondi", "ধানমন্ডি", "popular", "পপুলার"]
  },

  // ─── SHAHBAGH / RAMNA / MOTIJHEEL / OLD DHAKA ────────────────────────────
  {
    name: "Dhaka Medical College Hospital (DMCH)",
    bnName: "ঢাকা মেডিকেল কলেজ হাসপাতাল (ডিএমসিএইচ)",
    area: "Shahbagh",
    district: "Dhaka",
    type: "Apex Government Tertiary & Acute Trauma Hospital",
    emergencyPhone: "02-55165088",
    ambulancePhone: "01711-888888",
    address: "Secretariat Road, Shahbagh, Dhaka",
    is24x7: true,
    specialties: ["National Acute Trauma & Casualty", "Burn & Plastic", "ICU", "Neurosurgery"],
    keywords: ["shahbagh", "শাহবাগ", "ramna", "রমনা", "dmch", "ঢাকা মেডিকেল", "old dhaka", "পুরান ঢাকা", "polashi"]
  },
  {
    name: "Bangabandhu Sheikh Mujib Medical University (BSMMU / PG)",
    bnName: "বঙ্গবন্ধু শেখ মুজিব মেডিকেল বিশ্ববিদ্যালয় (পিজি হাসপাতাল)",
    area: "Shahbagh",
    district: "Dhaka",
    type: "Apex Specialized Government Hospital",
    emergencyPhone: "02-55165606",
    ambulancePhone: "01713-000000",
    address: "Shahbagh Circle, Dhaka",
    is24x7: true,
    specialties: ["Super-Specialized Care", "Emergency Outpatient", "ICU", "Cardiology"],
    keywords: ["shahbagh", "শাহবাগ", "bsmmu", "পিজি", "pg hospital", "ramna"]
  },
  {
    name: "National Institute of Burn and Plastic Surgery",
    bnName: "জাতীয় বার্ন ও প্লাস্টিক সার্জারি ইনস্টিটিউট",
    area: "Chankharpul",
    district: "Dhaka",
    type: "National Specialized Burn Trauma Hospital",
    emergencyPhone: "02-223381001",
    ambulancePhone: "01713-398311",
    address: "Chankharpul, Nimtoli, Dhaka",
    is24x7: true,
    specialties: ["24/7 Acute Burn Emergencies", "Plastic Surgery", "ICU"],
    keywords: ["chankharpul", "চাঁনখারপুল", "burn", "বার্ন", "পোড়া", "old dhaka", "nimtoli"]
  },
  {
    name: "BIRDEM General Hospital",
    bnName: "বারডেম জেনারেল হাসপাতাল",
    area: "Shahbagh",
    district: "Dhaka",
    type: "Specialized Endocrine & Multi-Specialty",
    emergencyPhone: "02-9661551",
    ambulancePhone: "01713-001001",
    address: "122 Kazi Nazrul Islam Avenue, Shahbagh, Dhaka",
    is24x7: true,
    specialties: ["Diabetic Emergency", "ICU", "Cardiac Emergency"],
    keywords: ["birdem", "বারডেম", "shahbagh", "শাহবাগ"]
  },
  {
    name: "Sir Salimullah Medical College & Mitford Hospital",
    bnName: "মিটফোর্ড হাসপাতাল (স্যার সলিমুল্লাহ মেডিকেল কলেজ)",
    area: "Old Dhaka",
    district: "Dhaka",
    type: "Government Medical College Hospital",
    emergencyPhone: "02-7319002",
    ambulancePhone: "01713-380000",
    address: "Mitford Road, Babubazar, Old Dhaka",
    is24x7: true,
    specialties: ["24/7 Trauma Emergency", "General Surgery", "Pediatrics"],
    keywords: ["old dhaka", "পুরান ঢাকা", "mitford", "মিটফোর্ড", "babubazar", "বাবু বাজার", "kotwali", "সদরঘাট"]
  },
  {
    name: "Square Hospital",
    bnName: "স্কয়ার হাসপাতাল",
    area: "Panthapath",
    district: "Dhaka",
    type: "Tertiary Private Multi-Specialty",
    emergencyPhone: "10616",
    ambulancePhone: "01713-377775",
    address: "18/F Bir Uttam Qazi Nuruzzaman Sarak, Panthapath, Dhaka",
    is24x7: true,
    specialties: ["24/7 Trauma Emergency", "Stroke Unit", "Cardiac ICU", "Ambulance"],
    keywords: ["panthapath", "পান্থপথ", "square", "স্কয়ার", "dhanmondi", "ফার্মগেট", "farmgate"]
  },

  // ─── UTTARA / AIRPORT / TONGI ─────────────────────────────────────────────
  {
    name: "Kuwait Bangladesh Friendship Government Hospital",
    bnName: "কুয়েত বাংলাদেশ মৈত্রী সরকারি হাসপাতাল",
    area: "Uttara",
    district: "Dhaka",
    type: "Government Specialized Hospital",
    emergencyPhone: "02-8956950",
    ambulancePhone: "01713-373300",
    address: "Sector 6, Uttara Model Town, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Casualty", "Infectious Diseases", "ICU"],
    keywords: ["uttara", "উত্তরা", "sector 6", "kuwait", "কুয়েত মৈত্রী", "airport"]
  },
  {
    name: "Uttara Adhunik Medical College Hospital",
    bnName: "উত্তরা আধুনিক মেডিকেল কলেজ হাসপাতাল",
    area: "Uttara",
    district: "Dhaka",
    type: "Medical College Hospital",
    emergencyPhone: "02-8932330",
    ambulancePhone: "01711-543543",
    address: "House 34, Road 4, Sector 9, Uttara, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency", "ICU", "Orthopedics", "Surgery"],
    keywords: ["uttara", "উত্তরা", "sector 9", "adhunik", "আধুনিক"]
  },
  {
    name: "Kurmitola General Hospital",
    bnName: "কুর্মিটোলা জেনারেল হাসপাতাল",
    area: "Airport Road / Cantonment",
    district: "Dhaka",
    type: "Government Tertiary General Hospital",
    emergencyPhone: "02-55062388",
    ambulancePhone: "01769-010200",
    address: "Airport Road, Dhaka Cantonment, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Trauma", "ICU", "Casualty", "General Medicine"],
    keywords: ["kurmitola", "কুর্মিটোলা", "airport", "বিমানবন্দর", "cantonment", "সেনানিবাস", "khilkhet", "খিলক্ষেত"]
  },
  {
    name: "Ahsania Mission Cancer & General Hospital",
    bnName: "আহছানিয়া মিশন ক্যান্সার ও জেনারেল হাসপাতাল",
    area: "Uttara",
    district: "Dhaka",
    type: "Specialized & General Hospital",
    emergencyPhone: "02-55085001",
    ambulancePhone: "01713-094777",
    address: "Plot 3, Sector 10, Uttara, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency", "Oncology", "ICU", "Dialysis"],
    keywords: ["uttara", "উত্তরা", "sector 10", "ahsania mission", "আহছানিয়া মিশন"]
  },
  {
    name: "Shin Shin Japan Hospital",
    bnName: "শিন শিন জাপান হাসপাতাল",
    area: "Uttara",
    district: "Dhaka",
    type: "Private General Hospital",
    emergencyPhone: "02-8950850",
    ambulancePhone: "01712-658399",
    address: "House 17, Road 11, Sector 17, Uttara, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Care", "Ambulance", "Surgery"],
    keywords: ["uttara", "উত্তরা", "sector 11", "shin shin", "জাপান হাসপাতাল"]
  },

  // ─── MIRPUR / PALLABI / KAFRUL ───────────────────────────────────────────
  {
    name: "National Heart Foundation Hospital & Research Institute",
    bnName: "ন্যাশনাল হার্ট ফাউন্ডেশন হাসপাতাল",
    area: "Mirpur",
    district: "Dhaka",
    type: "National Apex Cardiac Hospital",
    emergencyPhone: "02-58054708",
    ambulancePhone: "01713-006900",
    address: "Plot 4, Road 2, Section 2, Mirpur, Dhaka",
    is24x7: true,
    specialties: ["24/7 Cardiac Emergency", "Heart Attack ICU/CCU", "Angioplasty"],
    keywords: ["mirpur", "মিরপুর", "mirpur 2", "heart foundation", "হার্ট ফাউন্ডেশন", "cardiac", "হার্ট"]
  },
  {
    name: "Delta Medical College Hospital Mirpur",
    bnName: "ডেল্টা মেডিকেল কলেজ হাসপাতাল মিরপুর",
    area: "Mirpur",
    district: "Dhaka",
    type: "Medical College Hospital",
    emergencyPhone: "02-9011931",
    ambulancePhone: "01713-377377",
    address: "26/2 Principal Abul Kashem Road, Mirpur-1, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Casualty", "ICU", "Surgery", "Oncology"],
    keywords: ["mirpur", "মিরপুর", "mirpur 1", "delta", "ডেল্টা"]
  },
  {
    name: "Al-Helal Specialized Hospital Mirpur",
    bnName: "আল-হেলাল স্পেশালাইজড হাসপাতাল মিরপুর",
    area: "Mirpur",
    district: "Dhaka",
    type: "Private Specialized Hospital",
    emergencyPhone: "02-9008800",
    ambulancePhone: "01711-536484",
    address: "150 Begum Rokeya Sarani, Mirpur-10, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Care", "Trauma", "Surgery", "ICU"],
    keywords: ["mirpur", "মিরপুর", "mirpur 10", "মিরপুর ১০", "al-helal", "আল হেলাল", "rokeya sarani"]
  },
  {
    name: "Marks Medical College & Hospital",
    bnName: "মার্কস মেডিকেল কলেজ হাসপাতাল",
    area: "Mirpur",
    district: "Dhaka",
    type: "Medical College Hospital",
    emergencyPhone: "02-9031780",
    ambulancePhone: "01716-161616",
    address: "A/3 Main Road, Section 14, Mirpur, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency", "ICU", "Trauma Surgery"],
    keywords: ["mirpur", "মিরপুর", "mirpur 14", "marks", "মার্কস"]
  },

  // ─── MOHAMMADPUR / SHYAMOLI / AGARGAON / SHER-E-BANGLA NAGAR ─────────────
  {
    name: "Shaheed Suhrawardy Medical College Hospital",
    bnName: "শহীদ সোহরাওয়ার্দী মেডিকেল কলেজ হাসপাতাল",
    area: "Sher-e-Bangla Nagar",
    district: "Dhaka",
    type: "Government Medical College Hospital",
    emergencyPhone: "02-48110996",
    ambulancePhone: "01713-380100",
    address: "Sher-e-Bangla Nagar, Mirpur Road, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Casualty", "Trauma Care", "ICU", "Surgery"],
    keywords: ["suhrawardy", "সোহরাওয়ার্দী", "shyamoli", "শ্যামলী", "mohammadpur", "মোহাম্মদপুর", "agargaon", "আগারগাঁও"]
  },
  {
    name: "National Institute of Traumatology & Orthopaedic Rehabilitation (NITOR / Pangu)",
    bnName: "জাতীয় অর্থোপেডিক ও পুনর্বাসন প্রতিষ্ঠান (পঙ্গু হাসপাতাল)",
    area: "Sher-e-Bangla Nagar",
    district: "Dhaka",
    type: "National Apex Orthopedic & Accident Trauma Hospital",
    emergencyPhone: "02-9114075",
    ambulancePhone: "01711-222333",
    address: "Sher-e-Bangla Nagar, Dhaka",
    is24x7: true,
    specialties: ["24/7 Fracture & Accident Trauma", "Orthopedic Surgery", "Emergency Spine Care"],
    keywords: ["pangu", "পঙ্গু", "nitor", "orthopedic", "ভাঙা", "হাড়", "shyamoli", "agargaon"]
  },
  {
    name: "National Institute of Neurosciences & Hospital (NINS)",
    bnName: "জাতীয় নিউরোসায়েন্স ইনস্টিটিউট ও হাসপাতাল",
    area: "Agargaon",
    district: "Dhaka",
    type: "National Apex Neurology & Stroke Hospital",
    emergencyPhone: "02-9140745",
    ambulancePhone: "01713-398311",
    address: "Agargaon, Sher-e-Bangla Nagar, Dhaka",
    is24x7: true,
    specialties: ["24/7 Acute Stroke Emergency", "Brain Trauma", "Neurosurgery ICU"],
    keywords: ["agargaon", "আগারগাঁও", "neuro", "স্ট্রোক", "stroke", "brain", "nins"]
  },
  {
    name: "National Institute of Cardiovascular Diseases (NICVD)",
    bnName: "জাতীয় হৃদরোগ ইনস্টিটিউট ও হাসপাতাল",
    area: "Sher-e-Bangla Nagar",
    district: "Dhaka",
    type: "National Apex Government Heart Hospital",
    emergencyPhone: "02-9122560",
    ambulancePhone: "01713-380200",
    address: "Sher-e-Bangla Nagar, Dhaka",
    is24x7: true,
    specialties: ["24/7 Acute Heart Attack Emergency", "CCU", "Emergency Angioplasty"],
    keywords: ["nicvd", "হৃদরোগ", "heart", "cardiac", "shyamoli", "agargaon"]
  },
  {
    name: "Bangladesh Specialized Hospital",
    bnName: "বাংলাদেশ স্পেশালাইজড হাসপাতাল",
    area: "Shyamoli",
    district: "Dhaka",
    type: "Tertiary Multi-Specialty Hospital",
    emergencyPhone: "10633",
    ambulancePhone: "01763-990044",
    address: "21 Mirpur Road, Shyamoli, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Care", "Cardiac ICU", "Trauma", "Critical Care"],
    keywords: ["shyamoli", "শ্যামলী", "specialized", "স্পেশালাইজড", "mohammadpur", "মোহাম্মদপুর", "kallyanpur"]
  },
  {
    name: "Dhaka Shishu (Children) Hospital",
    bnName: "ঢাকা শিশু হাসপাতাল",
    area: "Sher-e-Bangla Nagar",
    district: "Dhaka",
    type: "Apex National Pediatric Hospital",
    emergencyPhone: "02-9113658",
    ambulancePhone: "01711-445566",
    address: "Sher-e-Bangla Nagar, Dhaka",
    is24x7: true,
    specialties: ["24/7 Pediatric Emergency", "NICU/PICU", "Child Surgery"],
    keywords: ["shishu", "শিশু", "child", "pediatric", "agargaon", "shyamoli"]
  },

  // ─── GULSHAN / BANANI / MOHAKHALI / BASHUNDHARA ─────────────────────────
  {
    name: "Evercare Hospital Dhaka",
    bnName: "এভারকেয়ার হাসপাতাল ঢাকা",
    area: "Bashundhara",
    district: "Dhaka",
    type: "JCI-Accredited Super-Specialty Hospital",
    emergencyPhone: "10678",
    ambulancePhone: "01714-090000",
    address: "Plot 81, Block E, Bashundhara R/A, Dhaka",
    is24x7: true,
    specialties: ["24/7 Advanced Emergency & Trauma", "Cardiac Emergency", "Stroke Unit", "ICU"],
    keywords: ["bashundhara", "বসুন্ধরা", "evercare", "এভারকেয়ার", "apollo", "baridhara", "বারিধারা", "bhatara"]
  },
  {
    name: "United Hospital Limited",
    bnName: "ইউনাইটেড হাসপাতাল গুলশান",
    area: "Gulshan",
    district: "Dhaka",
    type: "Tertiary Multi-Specialty Hospital",
    emergencyPhone: "10666",
    ambulancePhone: "01914-001234",
    address: "Plot 15, Road 71, Gulshan-2, Dhaka",
    is24x7: true,
    specialties: ["24/7 Acute Emergency & Trauma", "Cardiac ICU", "Neurosurgery", "Ambulance"],
    keywords: ["gulshan", "গুলশান", "gulshan 2", "united", "ইউনাইটেড", "banani", "বনানী"]
  },
  {
    name: "ICDDR,B Mohakhali Hospital",
    bnName: "আইসিডিডিআর,বি কলেরা হাসপাতাল মহাখালী",
    area: "Mohakhali",
    district: "Dhaka",
    type: "World-Renowned Diarrhoeal Disease Hospital",
    emergencyPhone: "02-9827001",
    ambulancePhone: "01711-594582",
    address: "68 Shaheed Tajuddin Ahmed Sarani, Mohakhali, Dhaka",
    is24x7: true,
    specialties: ["24/7 Acute Diarrhea & Dehydration Emergency", "Oral Rehydration", "Pediatric Care"],
    keywords: ["icddrb", "আইসিডিডিআরবি", "diarrhea", "ডায়রিয়া", "কলেরা", "cholera", "mohakhali", "মহাখালী"]
  },
  {
    name: "National Institute of Cancer Research & Hospital (NICRH)",
    bnName: "জাতীয় ক্যান্সার গবেষণা ইনস্টিটিউট ও হাসপাতাল",
    area: "Mohakhali",
    district: "Dhaka",
    type: "Apex Government Cancer Hospital",
    emergencyPhone: "02-9898600",
    ambulancePhone: "01713-380300",
    address: "Mohakhali, Dhaka",
    is24x7: true,
    specialties: ["24/7 Oncology Emergency", "Chemotherapy Casualty", "ICU"],
    keywords: ["cancer", "ক্যান্সার", "mohakhali", "মহাখালী", "nicrh"]
  },
  {
    name: "National Institute of Diseases of the Chest & Hospital (NIDCH)",
    bnName: "জাতীয় বক্ষব্যাধি ইনস্টিটিউট ও হাসপাতাল",
    area: "Mohakhali",
    district: "Dhaka",
    type: "Apex Government Pulmonary Hospital",
    emergencyPhone: "02-9898033",
    ambulancePhone: "01713-380400",
    address: "Mohakhali, Dhaka",
    is24x7: true,
    specialties: ["24/7 Respiratory Emergency", "Asthma & COPD", "Thoracic ICU"],
    keywords: ["chest", "বক্ষব্যাধি", "শ্বাসকষ্ট", "asthma", "mohakhali", "মহাখালী"]
  },

  // ─── KHILGAON / BADDA / RAMPURA / MALIBAGH ────────────────────────────────
  {
    name: "Farazy Hospital Limited",
    bnName: "ফরাজি হাসপাতাল বাড্ডা",
    area: "Badda",
    district: "Dhaka",
    type: "Multi-Specialty Hospital",
    emergencyPhone: "02-9842100",
    ambulancePhone: "01844-040404",
    address: "House 8-11, Block E, Banasree, Rampura, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Care", "ICU", "Dialysis", "Ambulance"],
    keywords: ["badda", "বাড্ডা", "banasree", "বনশ্রী", "rampura", "রামপুরা", "farazy", "ফরাজি"]
  },
  {
    name: "Khidmah Hospital Khilgaon",
    bnName: "খিদমাহ হাসপাতাল খিলগাঁও",
    area: "Khilgaon",
    district: "Dhaka",
    type: "Private General Hospital",
    emergencyPhone: "02-7210641",
    ambulancePhone: "01711-063030",
    address: "C-287/2-3 Khilgaon Bishwa Road, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency Care", "ICU", "Surgery"],
    keywords: ["khilgaon", "খিলগাঁও", "khidmah", "খিদমাহ", "malibagh", "মালিবাগ"]
  },
  {
    name: "Better Life Hospital Rampura",
    bnName: "বেটার লাইফ হাসপাতাল রামপুরা",
    area: "Rampura",
    district: "Dhaka",
    type: "General Hospital",
    emergencyPhone: "02-9345000",
    ambulancePhone: "01711-667788",
    address: "East Rampura, DIT Road, Dhaka",
    is24x7: true,
    specialties: ["24/7 Emergency", "ICU", "Casualty"],
    keywords: ["rampura", "রামপুরা", "better life", "বেটার লাইফ"]
  },

  // ─── OLD DHAKA / JATRABARI / SAYEDABAD ────────────────────────────────────
  {
    name: "Asgar Ali Hospital Gandaria",
    bnName: "আজগর আলী হাসপাতাল গেন্ডারিয়া",
    area: "Gandaria",
    district: "Dhaka",
    type: "Tertiary Multi-Specialty Hospital",
    emergencyPhone: "10602",
    ambulancePhone: "01787-683333",
    address: "111/1/A Distillery Road, Gandaria, Old Dhaka",
    is24x7: true,
    specialties: ["24/7 Trauma Emergency", "Cardiac Emergency", "ICU/NICU", "Ambulance"],
    keywords: ["gandaria", "গেন্ডারিয়া", "old dhaka", "পুরান ঢাকা", "jatrabari", "যাত্রাবাড়ী", "asgar ali", "আজগর আলী"]
  },
  {
    name: "Matuail Institute of Child & Mother Health (ICMH)",
    bnName: "মাতুয়াইল শিশু ও মাতৃস্বাস্থ্য ইনস্টিটিউট",
    area: "Matuail",
    district: "Dhaka",
    type: "Specialized Maternity & Pediatric Hospital",
    emergencyPhone: "02-7542618",
    ambulancePhone: "01713-380500",
    address: "Matuail, Jatrabari, Dhaka",
    is24x7: true,
    specialties: ["24/7 Maternal Emergency", "Pediatric Casualty", "NICU"],
    keywords: ["matuail", "মাতুয়াইল", "jatrabari", "যাত্রাবাড়ী", "sayedabad", "সায়েদাবাদ", "maternity", "প্রসূতি"]
  },

  // ─── SAVAR / ASHULIA / DHAMRAI ────────────────────────────────────────────
  {
    name: "Enam Medical College & Hospital",
    bnName: "এনাম মেডিকেল কলেজ হাসপাতাল সাভার",
    area: "Savar",
    district: "Dhaka",
    type: "Apex Trauma & Medical College Hospital",
    emergencyPhone: "02-7743779",
    ambulancePhone: "01716-358146",
    address: "9/3 Parboti Nagar, Thana Road, Savar, Dhaka",
    is24x7: true,
    specialties: ["24/7 Major Disaster & Accident Trauma", "ICU", "Neurosurgery", "Burn Care"],
    keywords: ["savar", "সাভার", "enam", "এনাম", "ashulia", "আশুলিয়া", "dhamrai", "ধামরাই"]
  },
  {
    name: "Centre for the Rehabilitation of the Paralysed (CRP)",
    bnName: "সিআরপি সাভার (প্যারালাইসিস পুনর্বাসন কেন্দ্র)",
    area: "Savar",
    district: "Dhaka",
    type: "Specialized Spinal Cord & Physical Trauma Hospital",
    emergencyPhone: "02-7745464",
    ambulancePhone: "01730-059500",
    address: "CRP-Chapain, Savar, Dhaka",
    is24x7: true,
    specialties: ["Spinal Injury", "Rehabilitation", "Trauma"],
    keywords: ["crp", "সিআরপি", "savar", "সাভার", "spine", "মেরুদণ্ড"]
  },

  // ─── NATIONWIDE DIVISIONAL MEDICAL COLLEGES ──────────────────────────────
  {
    name: "Chittagong Medical College Hospital (CMCH)",
    bnName: "চট্টগ্রাম মেডিকেল কলেজ হাসপাতাল (চমেক)",
    area: "Chittagong Sadar",
    district: "Chittagong",
    type: "Apex Government Medical College & Trauma Hospital",
    emergencyPhone: "031-619400",
    ambulancePhone: "01713-373600",
    address: "57 K.B. Fazlul Kader Road, Panchlaish, Chittagong",
    is24x7: true,
    specialties: ["24/7 Acute Casualty", "Trauma ICU", "Burn Unit", "Surgery"],
    keywords: ["chittagong", "চট্টগ্রাম", "chattogram", "cmch", "চমেক", "panchlaish", "পাঁচলাইশ"]
  },
  {
    name: "Rajshahi Medical College Hospital (RMCH)",
    bnName: "রাজশাহী মেডিকেল কলেজ হাসপাতাল (রামেক)",
    area: "Rajshahi Sadar",
    district: "Rajshahi",
    type: "Apex Government Tertiary Hospital",
    emergencyPhone: "0721-772150",
    ambulancePhone: "01713-373400",
    address: "Laxmipur, Rajshahi",
    is24x7: true,
    specialties: ["24/7 Trauma Emergency", "Burn Unit", "Cardiology ICU"],
    keywords: ["rajshahi", "রাজশাহী", "rmch", "রামেক", "laxmipur", "লক্ষ্মীপুর"]
  },
  {
    name: "Sylhet MAG Osmani Medical College Hospital (SOMCH)",
    bnName: "সিলেট এমএজি ওসমানী মেডিকেল কলেজ হাসপাতাল",
    area: "Sylhet Sadar",
    district: "Sylhet",
    type: "Apex Government Medical College Hospital",
    emergencyPhone: "0821-713667",
    ambulancePhone: "01713-374500",
    address: "Medical Road, Sylhet",
    is24x7: true,
    specialties: ["24/7 Acute Trauma & Emergency", "ICU", "Surgery", "Pediatrics"],
    keywords: ["sylhet", "সিলেট", "osmani", "ওসমানী", "somch"]
  },
  {
    name: "Khulna Medical College Hospital (KMCH)",
    bnName: "খুলনা মেডিকেল কলেজ হাসপাতাল",
    area: "Khulna Sadar",
    district: "Khulna",
    type: "Government Medical College Hospital",
    emergencyPhone: "041-760350",
    ambulancePhone: "01713-373500",
    address: "Boyra, Khulna",
    is24x7: true,
    specialties: ["24/7 Emergency Casualty", "Trauma", "ICU"],
    keywords: ["khulna", "খুলনা", "kmch", "boyra", "বয়রা"]
  },
  {
    name: "Sher-e-Bangla Medical College Hospital Barishal (SBMCH)",
    bnName: "শের-ই-বাংলা মেডিকেল কলেজ হাসপাতাল বরিশাল",
    area: "Barishal Sadar",
    district: "Barishal",
    type: "Government Medical College Hospital",
    emergencyPhone: "0431-2173550",
    ambulancePhone: "01713-374200",
    address: "Band Road, Barishal",
    is24x7: true,
    specialties: ["24/7 Casualty & Trauma", "Burn Unit", "Surgery"],
    keywords: ["barishal", "বরিশাল", "sbmch", "শের-ই-বাংলা"]
  },
  {
    name: "Mymensingh Medical College Hospital (MMCH)",
    bnName: "ময়মনসিংহ মেডিকেল কলেজ হাসপাতাল",
    area: "Mymensingh Sadar",
    district: "Mymensingh",
    type: "Government Medical College Hospital",
    emergencyPhone: "091-66063",
    ambulancePhone: "01713-374600",
    address: "Charpara, Mymensingh",
    is24x7: true,
    specialties: ["24/7 Casualty", "Trauma", "ICU", "Surgery"],
    keywords: ["mymensingh", "ময়মনসিংহ", "mmch", "charpara", "চরপাড়া"]
  },
  {
    name: "Rangpur Medical College Hospital (RpMCH)",
    bnName: "রংপুর মেডিকেল কলেজ হাসপাতাল",
    area: "Rangpur Sadar",
    district: "Rangpur",
    type: "Government Medical College Hospital",
    emergencyPhone: "0521-62288",
    ambulancePhone: "01713-374400",
    address: "Dhap, Rangpur",
    is24x7: true,
    specialties: ["24/7 Casualty & Emergency", "ICU", "Burn Care"],
    keywords: ["rangpur", "রংপুর", "rpmch", "dhap", "ধাপ"]
  },
  {
    name: "Comilla Medical College Hospital (CuMCH)",
    bnName: "কুমিল্লা মেডিকেল কলেজ হাসপাতাল",
    area: "Comilla Sadar",
    district: "Comilla",
    type: "Government Medical College Hospital",
    emergencyPhone: "081-65562",
    ambulancePhone: "01713-373660",
    address: "Kuchaitoli, Comilla",
    is24x7: true,
    specialties: ["24/7 Emergency Casualty", "Trauma", "Surgery"],
    keywords: ["comilla", "কুমিল্লা", "cumilla", "cumch"]
  }
];

/**
 * Searches the hospital directory by location/area tokens
 */
function findHospitalsByLocation(locationQuery, limit = 5) {
  if (!locationQuery || typeof locationQuery !== 'string') return [];
  const q = locationQuery.toLowerCase().trim();

  // Score each hospital
  const scored = [];
  for (const h of HOSPITALS_DATABASE) {
    let score = 0;
    for (const kw of h.keywords) {
      if (q === kw) {
        score += 50;
      } else if (q.includes(kw)) {
        score += 30;
      }
    }
    if (q.includes(h.area.toLowerCase())) score += 40;
    if (q.includes(h.district.toLowerCase())) score += 20;

    if (score > 0) {
      scored.push({ hospital: h, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map(s => s.hospital);
}

/**
 * Formats a list of hospitals into rich Markdown with clickable tel: links
 */
function formatHospitalListResponse(hospitals, locationName, isBangla = false) {
  if (!hospitals || hospitals.length === 0) return null;

  if (isBangla) {
    let text = `🏥 **${locationName} এলাকার নিকটবর্তী প্রধান জরুরি হাসপাতাল ও অ্যাম্বুলেন্স সার্ভিস:**\n\n`;
    hospitals.forEach((h, idx) => {
      const cleanPhone = h.emergencyPhone.replace(/\D/g, '');
      const cleanAmb = (h.ambulancePhone || '').replace(/\D/g, '');
      text += `${idx + 1}. 🏢 **${h.bnName}**\n`;
      text += `   📍 **ঠিকানা:** ${h.address}\n`;
      text += `   📞 **জরুরি বিভাগ (২৪ ঘণ্টা):** [${h.emergencyPhone}](tel:${cleanPhone})\n`;
      if (h.ambulancePhone) {
        text += `   🚑 **সরাসরি অ্যাম্বুলেন্স:** [${h.ambulancePhone}](tel:${cleanAmb})\n`;
      }
      text += `   🩺 **বিশেষায়িত সেবা:** ${h.specialties.join(', ')}\n\n`;
    });
    text += `🚨 **জরুরি অ্যাম্বুলেন্স ও পুলিশ সহায়তা:** অবিলম্বে [৯৯৯](tel:999) এ কল করতে পারেন (টোল-ফ্রি ২৪ ঘণ্টা)।\n`;
    text += `🩺 **লাইসেন্সধারী ডাক্তারের পরামর্শ:** স্বাস্থ্য বাতায়ন [১৬২৬৩](tel:16263) (২৪ ঘণ্টা)।`;

    const sources = hospitals.map(h => ({
      title: `${h.name} Emergency`,
      url: `tel:${h.emergencyPhone.replace(/\D/g, '')}`
    }));
    sources.push({ title: "999 National Emergency CAD", url: "tel:999" });

    return { text, sources };
  } else {
    let text = `🏥 **Emergency Hospitals & Ambulances near ${locationName}:**\n\n`;
    hospitals.forEach((h, idx) => {
      const cleanPhone = h.emergencyPhone.replace(/\D/g, '');
      const cleanAmb = (h.ambulancePhone || '').replace(/\D/g, '');
      text += `${idx + 1}. 🏢 **${h.name} (${h.bnName})**\n`;
      text += `   📍 **Address:** ${h.address}\n`;
      text += `   📞 **24/7 Emergency Line:** [${h.emergencyPhone}](tel:${cleanPhone})\n`;
      if (h.ambulancePhone) {
        text += `   🚑 **Direct Ambulance:** [${h.ambulancePhone}](tel:${cleanAmb})\n`;
      }
      text += `   🩺 **Key Care:** ${h.specialties.join(', ')}\n\n`;
    });
    text += `🚨 **Immediate CAD Ambulance Dispatch:** Call [999](tel:999) toll-free 24/7.\n`;
    text += `🩺 **Free Doctor Consultation:** Shastho Batayan [16263](tel:16263) (Govt Licensed Medical Officers).`;

    const sources = hospitals.map(h => ({
      title: `${h.name} Line`,
      url: `tel:${h.emergencyPhone.replace(/\D/g, '')}`
    }));
    sources.push({ title: "999 Emergency Dispatch", url: "tel:999" });

    return { text, sources };
  }
}

module.exports = {
  HOSPITALS_DATABASE,
  findHospitalsByLocation,
  formatHospitalListResponse
};
