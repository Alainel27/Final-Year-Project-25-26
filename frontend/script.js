function showTab(tabId){
    document.getElementById("scanner").style.display = "none";
    document.getElementById("info").style.display = "none";

    document.getElementById(tabId).style.display = "block";
}




//function to analyse the domains
function analyseDomain() {

    //Get user input
    const domain = document.getElementById('domainInput').value;

    //validation if input is empty
    if (!domain) {
        alert('Please enter a domain');
        return;
    }

    //loading message
    document.getElementById('result').textContent = "Scanning...";

    const baseURL = "https://final-year-project-25-26-production.up.railway.app";
    //baseURL
    //send the request to the backend
    fetch(`${baseURL}/analyse?query=${encodeURIComponent(domain)}`)

        //response into JSON
        .then(response => response.json())
        .then(data => {

            //output string 
            let output = `DOMAIN ANALYSIS\n`;
            output += `Domain: ${data.query}\n`;
            output += `IP Address: ${data.ip}\n`;

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //MX Records
            //checks if the mxRecords exist
            output += "\nMX RECORDS\n";
            if (data.mxRecords && data.mxRecords.length > 0) {
                data.mxRecords.forEach(mx => {
                    output += `Priority: ${mx.priority}, Exchange: ${mx.exchange}\n`;
                });
            } else {
                //if there is none
                output += "No MX records found.\n";
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //NS Records
            output += "\nNAME SERVERS\n";
            if (data.nsRecords && data.nsRecords.length > 0) {
                data.nsRecords.forEach(ns => {
                    output += `${ns}\n`;
                });
            } else {
                output += "No NS records found.\n";
            }
            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //SOA Record
            output += "\nSOA RECORD\n";
            if (data.soa) {
                output += `Primary NS: ${data.soa.nsname}\n`;
                output += `Admin: ${data.soa.hostmaster}\n`;
            } else {

                output += "No SOA Found.\n";
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //Reverse DNS
            output += "\nREVERSE DNS\n";
            if (data.hostnames && data.hostnames.length > 0) {
                data.hostnames.forEach(h => {
                    output += `${h}\n`;
                });
            } else {
                output += "No reverse DNS found.\n";

            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //TXT Records
            output += "\nTXT Records\n";
            output += "<details><summary>Show TXT Records</summary>\n";
            if (data.txtRecords && data.txtRecords.length > 0) {
            data.txtRecords.forEach(txt => {
                output += `${txt.join('')}<br>`;
                });
            } else {
                output += "No TXT Records Found<br>";
            }

            output += "</details>\n";

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            output += "\nDetected Mail Providers\n";

            if(data.detectedProviders  && data.detectedProviders.length > 0) {
                data.detectedProviders.forEach(p => {
                    output += `- ${p}\n`;
                });
            }else {
                output += "No providers detected\n";
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";
  
            
            output += "\nDMARC STATUS\n";

            if (data.dmarcStatus) {
                output += `Policy: ${data.dmarcStatus.policy}\n`;
                output += `subdomain Policy: ${data.dmarcStatus.subdomainPolicy}\n`;
                output += `Reporting: ${data.dmarcStatus.reporting}\n`;
                output += `Risk: ${data.dmarcStatus.risk}\n`;
            }else {
                output += "No Dmarc Found"
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

               output += "\nEmail Authentication";
               output += "\nDmarc, SPF and DKIM records:\n";

            output += `SPF Record: ${data.spfRecord || "Not Found"}\n`;
            output += `DMARC Record: ${data.dmarc || "Not Found"}\n`;
            if (data.dkimResult && data.dkimResult.found) {
                output += `DKIM Found (selector: ${data.dkimResult.selector})\n`;
            }else {
                output += `DKIM Not detected from common selectors\n`
            }


            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";




            output += "\nEmail Security Score\n"
            let rating = "";
            if (data.emailScore >= 80) {
                rating = "Strong";
            } else if (data.emailScore >=50) {
                rating = "Moderate";
            }else {
                rating = "Weak";
            }
            output += `Rating: ${rating}\n`;
            output += `Score: ${data.emailScore}/100\n`


            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";


            output += "\nSecurity Issues\n";

            if (data.issues && data.issues.length > 0) {
                data.issues.forEach(issue => {
                    output += `${issue}\n`;
                });
            }else {
                output += "\nNo Major Issues Found\n"
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";


            output += "\nEmail Security Rating\n"

            if (data.spoofAttack) {
                output += `- Can attackers spoof emails? ${data.spoofAttack.spoofable}\n`;
                output += `- Will spoofed emails reach the inbox? ${data.spoofAttack.inboxChance}\n`;
                output += `- Likely outcome: ${data.spoofAttack.outcome}\n`;

            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            output += "\nOverall Security Rating\n";

            let overallRating = "";
            if(data.overallScore >= 80) {
                overallRating = "Strong";
            }else if (data.overallScore >= 50) {
                overallRating = "Moderate";
            } else {
                overallRating = "Weak";
            }

            output += `Rating ${overallRating}\n`;
            output += `Score: ${data.overallScore}/100\n`


            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";




            //display the results
            document.getElementById('result').innerHTML = output;

            document.getElementById("aiSummary").textContent = "Generating AI Summary..."

            fetch(`${baseURL}/ai-summary`,{
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            })
            .then(res => res.json())
            .then(ai => {
                document.getElementById("aiSummary").textContent = ai.summary;
            })
            .catch(() => {
                document.getElementById("aiSummary").textContent = "AI analysis failed.";
            });

        })
        //error handling
        .catch(error => {
            document.getElementById('result').textContent = "Error: " + error;
        });
}


window.onload = function() {
    document.getElementById("infoContent").innerHTML = `

    <h2>What is OSINT</h2>
    <p>Open-Source Intelligence is the practice of passively collecting, analysing and producing actionable intelligence from publicly available sources.
    <br>
    In the context of digital forensics and cyber-security,
    it mainly involves collecting data from internet sources which are publicly available to identify threats along with vulnerabilities in digital domains.
    </p>


    <h3> IP Address </h3>
    <p>
    An IP (Internet Protocol) address serves as a unique numerical label that is assigned to the server hosting a website for a domain.
    <br>
    They are necessary as they allow the computer to identify, locate and communicate with the specific server where the website files are stored.
    <br>
    In the context of OSINT, IP addresses are crucial because they act as digital fingerprints which allow investigators to map infrastructure,
    uncover hidden relations between websites and track malicious actors.
    </p>

    <h3> MX Records (Mail Exchange) </h3>
    <p>
    Mx (Mail Exchange) records are a type of DNS (Domain Name System) record that assigns the mail servers responsible for receiving email messages on behalf of a domain name.
    <br>
    In OSINT and reconnaissance, MX records are extremely valuable as they allow the mapping of an organisation's digital infrastructure,
    identifying email providers and discovering potential security weaknesses without direct interaction with the target network.
    </p>

    <h3> NS records (Name server) </h3>
    <p>
    NS records are an important type of DNS record that designates which DNS servers are authoritative for a domain.
    <br>
    They direct internet traffic to the specific servers as they define which servers are responsible for managing the domain's DNS.
    <br>
    In OSINT they are crucial as they reveal critical infrastructure details, hosting providers and potential security weaknesses of a target organisation.
    <br> 
    </p>
    
    <h3> TXT Records </h3>
    <p>
    TXT records are a type of DNS that allows domain admins to insert arbitrary text into their DNS settings.
    <br>
    In OSINT investigations, they often reveal critical information about an organisation's infrastructure. 
    They often provide passive intelligence as they can be gathered without direct interaction.
    <br>
    </p>

    <h3> SOA (Start of Authority) Records </h3>
    <p>
    The SOA record is a type of DNS record that contains essential administrative and technical information about a domain.
    It includes information such as parties involved, primary nameserver and update frequency
    <br>
    In OSINT it is important as they provide data about how a domain is managed, which helps to reveal the infrastructure owner or any security misconfigurations.
    </p>

    <h3> SPF Records (Sender Policy Framework) </h3>
    <p>
    A SPF record is a type of DNS TXT record that lists all the servers authorised to send emails from a particular domain.
    <br>
    In OSINT, it is important as they help give an idea of an organisation's email security and validation of the email during an investigation.
    </p>

    <h3> DMARC (Domain-Based Message Authentication, Reporting and Conformance) </h3>
    <p>
    DMARC is a DNS TXT record that acts as an email authentication policy. It guides mail servers how to handle emails that fail SPF or DKIM checks.
    <br>
    It is important in OSINT as it reveals a domain's security posture and it can showcase how an organisation handles phishing or spoofing.
    </p>

    <h3> DKIM (DomainKeys Identified Mail) </h3>
    <p>
    DKIM is an email authentication method that adds a cryptographic signature to emails, that allows receiving servers to verify that the email was authorized by the domain owner
    and that the content within has not been altered.
    <br>
    In OSINT it is vital as to is a way of verifying email legitimacy and email infrastructure.
    </p>

    <h3> Why Does This Matter </h3>
    <p>
    These are records are valuable for OSINT investigations as they help map an organisations infrastructure. If these records are misconfigured, an attacker can spoof emails, send phishing emails and collect valuable information to attack an organisation.
    <br>
    </p>


    `
}