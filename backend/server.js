//only for the OPENAI_API_KEY
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

//express to serve files from the frontend folder
app.use(express.static(path.join(__dirname, "../frontend")));

//sends to index.html
app.get("/", (req,res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
})

//cors() allows requests from the frontend
app.use(cors());

//parsefunction
//function used to put the DMARC record into useful parts
function parseDMARC(record) {
  //if there is no DMARC then it will return null
  if (!record) return null;

  //this line splits the DMARC at each ;
  const parts = record.split(';').map(p => p.trim());
  //An empty object to store the DMARC values
  const obj = {};

  //Loops through every DMARC part
  parts.forEach(part => {
    //and then splits each part into a key and value
    //for example if the DMARC policy is "p=reject" it would be "p" and "reject"
    const[key, value] = part.split('=');
    //if they both exist 
    if(key && value) {
      //it gets saved into the object
      obj[key] = value;
    }
  });
  //returns the parsed DMARC Object
  return obj;
}

//this function converts the DMARC record into a readable security status
function getDmarcStatus(parsed) {
  //if it is empty then it will display that there is nothing and risky
  if(!parsed) {
    return {
      policy: "None",
      subdomainPolicy: "None",
      reporting: "Disabled",
      risk: "High (No Records)"
    };
  }

  //risk value set to unknown
  let risk = "Unknown";

  //if the DMARC policy is set to none
  if (parsed.p === "none") {
    //it displays that it is set to monitoring only
    risk = "Medium (Monitoring Only, No Enforcement)";
  //If it is set to quarantine
  } else if (parsed.p === "quarantine") {
    //displays this
    risk = "Moderate (Emails to Spam)";
    //id reject then the risk is set to low
  }else if (parsed.p === "reject"){
    risk = "Low (Strong Protection)"
  }

  //returns the final status
  return {
    policy: parsed.p || "Not Set",
    subdomainPolicy: parsed.sp || "Not set",
    reporting: parsed.rua ? "Enabled" : "Disabled",
    risk
  };
}

//calculates a score out of a 100 with all the avaialable data pulled from the site
function calculateEmailSecurityScore(spfRecord, dmarcParsed){
  //score is set to 0 orginally
  let score = 0;
  //checks if it exists
  if (spfRecord) {
    //if the spf is set to -all then it is giving 40
    //-all means that the all addresses not listed in the SPF record are not authorized and should be rejected
    if(spfRecord.includes("-all")) {
      score += 40;
      //~all states that all unlisted emails should be marked as insecure or spam
    }else if (spfRecord.includes("~all")){
      score +=25;
      //and if there is nothing it is giving 10
    }else{
      score += 10;
    }
  }


  //checks if it exists
  if (dmarcParsed) {
    //40 if it is set to reject
    if(dmarcParsed.p ==="reject") {
      score += 40;
      //25 if it is set to quarantine
    }else if (dmarcParsed.p === "quarantine") {
      score += 25;
      //10 if it is set to none
    }else if (dmarcParsed.p === "none") {
      score += 10;
    }
  }

  //20 if the DMARC has reporting enabled
  if (dmarcParsed && dmarcParsed.rua) {
    score += 20;
  }

  //returns the score and it caps at 100
  return Math.min(score, 100);
}

//function for all the ecurity issues in the DMARC and SPF
function getSecurityIssues(spfRecord, dmarcParsed) {
  //empty array
  const issues = []

  //if there is no spf then it will add this
  if (!spfRecord) {
    issues.push("No SPF Record Found");
    //issue if the spif is set to +all
    //+all allows all senders
  }else if (spfRecord.includes("+all")) {
    issues.push("SPF allows all");
  }

  //if no DMARC is found 
  if(!dmarcParsed) {
    issues.push("No Dmarc Record Found");
    //another issue if the DMARC is set to none
  }else if (dmarcParsed.p === "none") {
    issues.push("Dmarc Not Enforced");
  }

//returns the list of issues
  return issues;
}

//this function checks if a attack may spoof emails from the domain
function emailSpoofAttack(spfRecord, dmarcParsed) {
  //the defualt values
  let spoofable = false;
  let inboxChance = "Unknown";
  let outcome = "Unknown";


//if there is no DMARC or a weak DMARC or if there is no SPF
  if (!dmarcParsed || dmarcParsed.p === "none" || !spfRecord) {
    //then it will likely to get spoofed
    spoofable = true;
  }

  //if the DMARC policy is set to reject 
  //the ?. will check the DMARC safely 
  if (dmarcParsed?.p === "reject") {
    inboxChance = "No.";
    outcome = "Blocked.";
    //if the DMARC is set to Quarantine
  }else if (dmarcParsed?.p === "quarantine"){
    inboxChance = "Unlikely.";
    outcome = "Spam folder.";
  }else {
    //if nothing then yes it is possible
    inboxChance = "Possible.";
    outcome = "Delivered or spam folder."
  }

  //returns the results
  return {
    spoofable: spoofable ? "Yes." : "No.",
    inboxChance,
    outcome
  };
}


//this function detects the email provders from the MX records and the SPF records. It detects the three common email providers which are yahoo, outlook and gmail
function detectMailProvider(mxRecords, spfRecord) {
  //empty array
  let providers = [];

  //takes all the mxrecords and extracts them then joins them 
  const mxString = (mxRecords || []).map(mx=>mx.exchange).join(" ").toLowerCase();
  //gets the spf and makes them lowercase
  const spf = (spfRecord || "").toLowerCase();

  //the following lines looks at the mail providers and the common notifers that they exist in the mx records
  //Outlook
  if (mxString.includes("outlook") || mxString.includes("protection.outlook.com") || spf.includes("spf.protection.outlook.com")){
    providers.push("Microsoft 365 (Outlook)")
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

  //if the providers were found they are returned and if they arent then it will return unknown
  return providers.length > 0 ? providers :["Unknown"];

}


//calculates the overall security score using everything in the previous functions
function calculateOverallSecurityScore({
  emailScore,
  mxRecords,
  nsRecords,
  issues
}) {
  //set at 0
  let score =0;

  //the email score will make up 60% of the score
  score += emailScore * 0.6;

  //adds a point if the MX records exist
  if(mxRecords && mxRecords.length > 0){
    score += 15;
  }else{
    score -= 10;
  }

  //adds a point if the ns records exist and if there is atleast 2
  //two name servers should be minimum in any domain
  if (nsRecords && nsRecords.length >= 2) {
    score += 10;
  }else {
    score -= 5;
  }

  //subracts 5 points per each security issue in the previous funciton
  if(issues && issues.length >0) {
    score -= issues.length * 5;
  }

  //rounds the score and keeps it between 0 and 100
  return Math.max(0, Math.min(100, Math.round(score)));
}


//creates the GET route /analyse used in analysing the domain
app.get("/analyse", async (req, res) => {
  //allows URL inputs. It reads the URL example would be /analyse?query=google.com
  const query = req.query.query;

 

  //input validation
  if (!query) {
    return res.status(400).json({ error: "No Query Provided" });
  }

  
  try {
    //lookup the IP address of the domain
    const address = await dns.lookup(query)

    //empty variables to store the different DNS record types
    let mxRecords = [];//mail servers
    let nsRecords = [];//name servers
    let soa = null;//doamin authority info
    let hostnames = [];// hostname
    let txtRecords = [];// txt records
    let dmarc = null;//DMARC
    let spfRecord = null;//SPF

    //individual lookups so if one fails then then the system wont crash everything.
    //these lines of code tries to get the lookups of the domain
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
      //uses the IP address to find the hostnames
      hostnames = await dns.reverse(address.address);
    } catch{}

    try{
      txtRecords = await dns.resolveTxt(query);
    } catch{}

    //gets the SPF from the TXT record
    if (txtRecords && txtRecords.length > 0) {
      spfRecord = txtRecords.map(r => r.join(''))
      .find(r => r.startsWith('v=spf1'));
    }

    //looks at the TXT of _dmarc to find the DMARC record
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${query}`);

      //finds the DMARC
      dmarc = dmarcRecords
        .map(r => r.join(''))
        .find(r => r.startsWith('v=DMARC1'));
    } catch {
      //if there is no DMARC
      dmarc = null
    }


    //The security functions
    const parsedDmarc = parseDMARC(dmarc);
    const dmarcStatus = getDmarcStatus(parsedDmarc);
    const emailScore = calculateEmailSecurityScore(spfRecord, parsedDmarc)
    const issues = getSecurityIssues(spfRecord, parsedDmarc);
    const spoofAttack = emailSpoofAttack(spfRecord, parsedDmarc);
    const detectedProviders = detectMailProvider(mxRecords, spfRecord);
    const overallScore = calculateOverallSecurityScore({emailScore,mxRecords,nsRecords,issues});

    //response returned as JSON 
    res.json({
      //sends the final results back to the frontend
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

//OPENAI API setup
//importing all the OpoenAI library

const OpenAI = require("openai");
const { error } = require("console");

//OpenAI cleint using the API key in the .env file
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

//creates a POST route called /ai-summary
//express allows the backend to read the JSON sent from the frontend
app.post("/ai-summary", express.json(),async(req, res) =>{
  try{
    //gets the domain analysis data from the request
    const data = req.body;

    //The prompt used that will be sent to the AI model
    //I set the prompt to give a short overview, give a numbered list of the security issues and then give recommendations
    //the ${} converts the data into a JSON that the ai can read
    const prompt = `
    Analyse the following data and provide: A short summary of the domain security, the key risk with the digital domain and recommendations.
    Give a short overview of the digital domain, then give a numbered list of the security issues and then give recommendations.
    Please make the summary short and simple to read.
    Only use text, do not use headings, Do not use bold texts and make it numbered to make it easier to read.

    
    Data:
    ${JSON.stringify(data, null, 2)}
    `;
    //the request is sent to OpenAI
      const response = await openai.chat.completions.create({
        //this AI model was chosing as it is doesnt require alot of tokens per use 
        model: "gpt-4o-mini",
        //the system will tell an AI what role to follow
        messages: [
          {role:"system", content: "You are an OSINT Expert."},
          //the user message contains the prompt and data above
          {role:"user", content: prompt}
        ]
     });

     //The generated AI summary is sent back
    const summary = response.choices[0].message.content;

    //the summary is sent back to the frontend
    res.json({ summary});

    //if the AI fails then it lgos the error and gives an error response
  } catch(err){
    console.error(err);
    res.status(500).json({ error: "AI Failed"});
  }
});

//starting the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
