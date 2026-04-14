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

    //response returned as JSON 
    res.json({
      query,
      ip: address.address,
      mxRecords,
      nsRecords,
      soa,
      hostnames,
      txtRecords
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