//importing the required modules
//express creates the web server
const express = require("express");
//cors allows frontend to communicate with the backend
const cors = require("cors");
//allows for DNS lookups
const dns = require("dns").promises;
//creating the server
const app = express();
//cors() allows requests from the frontend
app.use(cors());

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


function calculateEmailSecurityScore(spfRecord, dmarcParsed){
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

  return Math.min(score, 100);
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

    const parsedDmarc = parseDMARC(dmarc);
    const dmarcStatus = getDmarcStatus(parsedDmarc);
    const emailScore = calculateEmailSecurityScore(spfRecord, parsedDmarc)

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
      emailScore
    });


    //error handling. If an error happens it logs it into the terminal such as a DNS failure
  } catch (err) {
    console.error("DNS error:", err);
    res.status(500).json({ error: "DNS query failed", details: err.message });
  }
});

//Runs the server on port 3001
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});