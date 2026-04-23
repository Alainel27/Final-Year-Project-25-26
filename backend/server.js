require("dotenv").config();
//importing the required modules
//express creates the web server
const express = require("express");
//cors allows frontend to communicate with the backend
const cors = require("cors");
//allows for DNS lookups
const dns = require("dns").promises;
//creating the server
const app = express();
//for railway
const path = require("path");

app.use(express.static(path.join(__dirname, "../frontend")));

app.get("/", (req,res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
})
//cors() allows requests from the frontend
app.use(cors());
//parsefunction
function parseDMARC(record) {
  if (!record) return null;

  const parts = record.split(';').map(p => p.trim());
  const obj = {};

  parts.forEach(part => {
    const[key, value] = part.split('=');
    if(key && value) {
      obj[key] = value;
    }
  });
  return obj;
}

function getDmarcStatus(parsed) {
  if(!parsed) {
    return {
      policy: "None",
      subdomainPolicy: "None",
      reporting: "Disabled",
      risk: "High (No Records)"
    };
  }

  let risk = "Unknown";

  if (parsed.p === "none") {
    risk = "Medium (Monitoring Only, No Enforcement)";
  } else if (parsed.p === "quarantine") {
    risk = "Moderate (Emails to Spam)";
  }else if (parsed.p === "reject"){
    risk = "Low (Strong Protection)"
  }

  return {
    policy: parsed.p || "Not Set",
    subdomainPolicy: parsed.sp || "Not set",
    reporting: parsed.rua ? "Enabled" : "Disabled",
    risk
  };
}


function calculateEmailSecurityScore(spfRecord, dmarcParsed, dkim){
  let score = 0;
  if (spfRecord) {
    if(spfRecord.includes("-all")) {
      score += 40;
    }else if (spfRecord.includes("~all")){
      score +=25;
    }else{
      score += 10;
    }
  }

  if (dmarcParsed) {
    if(dmarcParsed.p ==="reject") {
      score += 40;
    }else if (dmarcParsed.p === "quarantine") {
      score += 25;
    }else if (dmarcParsed.p === "none") {
      score += 10;
    }
  }

  if (dmarcParsed && dmarcParsed.rua) {
    score += 20;
  }

  if(dkim) {
    score += 20;
  }

  return Math.min(score, 100);
}

function getSecurityIssues(spfRecord, dmarcParsed,dkim) {
  const issues = []

  if (!spfRecord) {
    issues.push("No SPF Record Found");
  }else if (spfRecord.includes("+all")) {
    issues.push("SPF allows all");
  }

  if(!dmarcParsed) {
    issues.push("No Dmarc Record Found");
  }else if (dmarcParsed.p === "none") {
    issues.push("Dmarc Not Enforced");
  }
  
  if(!dkim) {
    issues.push("No DKIM detected")
  } 

  return issues;
}

function emailSpoofAttack(spfRecord, dmarcParsed) {
  let spoofable = false;
  let inboxChance = "Unknown";
  let outcome = "Unknown";

  if (!dmarcParsed || dmarcParsed.p === "none" || !spfRecord) {
    spoofable = true;
  }

  if (dmarcParsed?.p === "reject") {
    inboxChance = "No.";
    outcome = "Blocked.";
  }else if (dmarcParsed?.p === "quarantine"){
    inboxChance = "Unlikely.";
    outcome = "Spam folder.";
  }else {
    inboxChance = "Possible.";
    outcome = "Delivered or spam folder."
  }

  return {
    spoofable: spoofable ? "Yes." : "No.",
    inboxChance,
    outcome
  };
}

function detectMailProvider(mxRecords, spfRecord) {
  let providers = [];

  const mxString = (mxRecords || []).map(mx=>mx.exchange).join(" ").toLowerCase();
  const spf = (spfRecord || "").toLowerCase();

  //Outlook
  if (mxString.includes("outlook") || mxString.includes("protection.outlook.com") || spf.includes("spf.protection.outlook.com")){
    providers.push("Mircosoft 365 (Outlook)")
  }

  //Google
  if (mxString.includes("google.com") || spf.includes("_spf.google.com") || mxString.includes("gmail-smtp-in.1.google.com") || mxString.includes("googlemail.com")){
    providers.push("Google Workspace / Gmail")
  }
  

  //Yahoo
  if (
    mxString.includes("yahoodns.net") ||
    spf.includes("yahoo.com")
  ) {
    providers.push("Yahoo Mail");
  }



  return providers.length > 0 ? providers :["Unknown"];

}


function calculateOverallSecurityScore({
  emailScore,
  mxRecords,
  nsRecords,
  issues
}) {
  let score =0;

  score += emailScore * 0.6;

  if(mxRecords && mxRecords.length > 0){
    score += 15;
  }else{
    score -= 10;
  }

  //At least two ns servers
  if (nsRecords && nsRecords.length >= 2) {
    score += 10;
  }else {
    score -= 5;
  }

  if(issues && issues.length >0) {
    score -= issues.length * 5;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

async function detectDkim(domain) {
  const selectors = ["default", "selector1", "selector2", "google"];
  for (const selector of selectors) {
    try{
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const joined = records.map(r => r.join("")).join("");
      if (joined) {
        return {
          found:true,
          selector,
          record: joined
        };
      }
    }catch{}
  }
  return {
    found: false,
    selector: null,
    record: null
  }
}


app.get("/analyse", async (req, res) => {
  //allows URL inputs. It reads the URL example would be /analyse?query=google.com
  const query = req.query.query;

 

  //input validation
  if (!query) {
    return res.status(400).json({ error: "No Query Provided" });
  }

  try {
    const address = await dns.lookup(query)

    //empty variables to store the different DNS record types
    let mxRecords = [];//mail servers
    let nsRecords = [];//name servers
    let soa = null;//doamin authority info
    let hostnames = [];// hostname
    let txtRecords = [];// txt records
    let dmarc = null;
    let spfRecord = null;


    //fill in catches with error handling later
    //individual lookups so if one fails then then the system wont crash everything.
    try{
      mxRecords = await dns.resolveMx(query);
    } catch {}

    try{
      nsRecords = await dns.resolveNs(query);
    } catch{}

    try{
      soa = await dns.resolveSoa(query);
    } catch{}

    try {
      hostnames = await dns.reverse(address.address);
    } catch{}

    try{
      txtRecords = await dns.resolveTxt(query);
    } catch{}

    if (txtRecords && txtRecords.length > 0) {
      spfRecord = txtRecords.map(r => r.join(''))
      .find(r => r.startsWith('v=spf1'));
    }

    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${query}`);

      dmarc = dmarcRecords
        .map(r => r.join(''))
        .find(r => r.startsWith('v=DMARC1'));
    } catch {
      dmarc = null
    }

    const dkimResults = await detectDkim(query);
    let dkim = dkimResults.record;

    const parsedDmarc = parseDMARC(dmarc);
    const dmarcStatus = getDmarcStatus(parsedDmarc);
    const emailScore = calculateEmailSecurityScore(spfRecord, parsedDmarc, dkim)
    const issues = getSecurityIssues(spfRecord, parsedDmarc, dkim);
    const spoofAttack = emailSpoofAttack(spfRecord, parsedDmarc);
    const detectedProviders = detectMailProvider(mxRecords, spfRecord);
    const overallScore = calculateOverallSecurityScore({emailScore,mxRecords,nsRecords,issues});

    //response returned as JSON 
    res.json({
      query,
      ip: address.address,
      mxRecords,
      nsRecords,
      soa,
      hostnames,
      txtRecords,
      dmarc,
      dmarcStatus,
      emailScore,
      issues,
      dkim,
      dkimResult: dkimResults,
      spfRecord,
      spoofAttack,
      detectedProviders,
      overallScore
    });


    //error handling. If an error happens it logs it into the terminal such as a DNS failure
  } catch (err) {
    console.error("DNS error:", err);
    res.status(500).json({ error: "DNS query failed", details: err.message });
  }
});

const OpenAI = require("openai");
const { error } = require("console");

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

app.post("/ai-summary", express.json(),async(req, res) =>{
  try{
    const data = req.body;

    const prompt = `
    Analyse the following data and provide: A short summary of the domain security, the key risk with the digital domain and recommendations.
    Give a short overview of the digital domain, then give a numbered list of the security issues and then give recommendations.
    Please make the summary short and simple to read.
    Only use text, do not use headings, Do not use bold texts and make it numbered to make it easier to read.

    I want you to also be aware that the DKIM analyser may not be able to pick all the records

    
    Data:
    ${JSON.stringify(data, null, 2)}
    `;
      const response = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          {role:"system", content: "You are an OSINT Expert."},
          {role:"user", content: prompt}
        ]
     });

    const summary = response.choices[0].message.content;

    res.json({ summary});

  } catch(err){
    console.error(err);
    res.status(500).json({ error: "AI Failed"});
  }
});

//Runs the server on port 3001
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
