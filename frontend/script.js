//FRONTEND CODE FOR THE WEBSITE
//The function allows the users to go through the two different tabs in the website.
//The scanner tab holds the analyser and the AI overview and the information tab holds info on the OSINT functions
//The function hides both the tabs and then shows only the one requested
function showTab(tabId){
    //The line finds the HTML element with the scanner ID and then it hides it
    document.getElementById("scanner").style.display = "none";
    //This does the same but for the information tab
    document.getElementById("info").style.display = "none";
    //This line finds the element IF that matches with the value and shows it
    document.getElementById(tabId).style.display = "block";
}


//This is the main function in the project
//It runs when the user clicks the Analyse button
function analyseDomain() {

    //This line reads the user input with the ID domainInput
    const domain = document.getElementById('domainInput').value;

    //Validation if input is empty
    //This checks if the user wrote anything into the input  
    if (!domain) {
        alert('Please enter a domain');
        return;
    }

    //This line showcases a loading message to the user so they can see that the scanner has started
    //textContent as it is just showing plain text
    document.getElementById('result').textContent = "Scanning...";

    //This const stores the address of the deployed website from railway
    const baseURL = "https://final-year-project-25-26-production.up.railway.app";

    //This line sends the request to /analyse
    //the fetch() sends an HTTP request to the URL
    //The previous const domain is used in this
    //the encodeURIComponent makes the input safe to put in the URL so it does end in a failure
    fetch(`${baseURL}/analyse?query=${encodeURIComponent(domain)}`)

        //This line converts the response into a JSON
        //so the .then handles the result of the fetch onces it completes
        //The response is the result of the request
        //the response.json() parses the response as JSON
        .then(response => response.json())
        //the server fetched data is then handled
        .then(data => {

            //A variable called output is created and it will hold all of the text that will be shown to the user
            let output = `DOMAIN ANALYSIS\n`;
            //Adding the analysed domain and IP address to the output
            //the ${} is used to reference the variables in the server.js within the string
            output += `Domain: ${data.query}\n`;
            output += `IP Address: ${data.ip}\n`;

            //Breakpoint Lines are used to visually divide the lines
            output += "\n-----------------------------------------------------------------\n";

            //MX Records
            //checks if the mxRecords exist
            output += "\nMX RECORDS\n";
            //this line checks if the MX reocrds exist and if there is at least one present
            if (data.mxRecords && data.mxRecords.length > 0) {
                //loops through the MX records and displays the priority and mail server
                data.mxRecords.forEach(mx => {
                    output += `Priority: ${mx.priority}, Exchange: ${mx.exchange}\n`;
                });
            } else {
                //If there is no MX records then it will display this message
                output += "No MX records found.\n";
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //NS Records
            output += "\nNAME SERVERS\n";
            //checks if the NS records exist and if there is at least one present
            if (data.nsRecords && data.nsRecords.length > 0) {
                //if there is then it will loop through them and display them
                data.nsRecords.forEach(ns => {
                    output += `${ns}\n`;
                });
            } else {
                //If there is no NS records then it will display this message
                output += "No NS records found.\n";
            }
            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //SOA Record
            output += "\nSOA RECORD\n";
            //checks if it exists
            if (data.soa) {
                //if it does exist then it will display them
                output += `Primary NS: ${data.soa.nsname}\n`;
                output += `Admin: ${data.soa.hostmaster}\n`;
            } else {
                //if not then it will display this
                output += "No SOA Found.\n";
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //Reverse DNS
            output += "\nREVERSE DNS\n";
            //checks if they exist and if there is at least one
            if (data.hostnames && data.hostnames.length > 0) {
                //if there is then it will loop through them and display them
                data.hostnames.forEach(h => {
                    output += `${h}\n`;
                });
            } else {
                //if there is none then it will display this
                output += "No reverse DNS found.\n";

            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            //TXT Records
            output += "\nTXT Records\n";
            //uses <details> because this section is collasible in the website as it ussually provides to much information
            output += "<details><summary>Show TXT Records</summary>\n";
            //checks if they exist and if there is atleast one
            if (data.txtRecords && data.txtRecords.length > 0) {
                //if there is then it will loop through them and display them all
            data.txtRecords.forEach(txt => {
                //the join('') combines parts of the TXT into one string
                output += `${txt.join('')}<br>`;
                });
            } else {
                //if there is none then it will display this
                output += "No TXT Records Found<br>";
            }
            //closes the collapsible section
            output += "</details>\n";

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            output += "\nDetected Mail Providers\n";

            //checks if it exists and if there is more than one
            if(data.detectedProviders  && data.detectedProviders.length > 0) {
                //loops through them and displays them all
                data.detectedProviders.forEach(p => {
                    output += `- ${p}\n`;
                });
            }else {
                output += "No providers detected\n";
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";
  
            
            output += "\nDMARC STATUS\n";

            //checks if the dmarc exists
            if (data.dmarcStatus) {
                //displays it all
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
               output += "\nDMARC and SPF:\n";

               //displays the DMARC AND SPF in full and if the records dont exist it will display "not found"
            output += `SPF Record: ${data.spfRecord || "Not Found"}\n`;
            output += `DMARC Record: ${data.dmarc || "Not Found"}\n`;


            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";




            output += "\nEmail Security Score\n"
            //empty variable for the rating
            let rating = "";
            //the code here checks the value of the emailScore Numeric value then converts them into a rating such 
            if (data.emailScore >= 80) {
                rating = "Strong";
            } else if (data.emailScore >=50) {
                rating = "Moderate";
            }else {
                rating = "Weak";
            }
            //displays the rating
            output += `Rating: ${rating}\n`;
            output += `Score: ${data.emailScore}/100\n`


            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";


            output += "\nSecurity Issues\n";

            //checks if they exist 
            if (data.issues && data.issues.length > 0) {
                //displays each issiue
                data.issues.forEach(issue => {
                    output += `${issue}\n`;
                });
            }else {
                output += "\nNo Major Issues Found\n"
            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";


            output += "\nEmail Security Rating\n"
            //checks if it exists
            if (data.spoofAttack) {
                //displays all of the information
                output += `- Can attackers spoof emails? ${data.spoofAttack.spoofable}\n`;
                output += `- Will spoofed emails reach the inbox? ${data.spoofAttack.inboxChance}\n`;
                output += `- Likely outcome: ${data.spoofAttack.outcome}\n`;

            }

            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";

            output += "\nOverall Security Rating\n";

            //empty variable for the overallRating
            let overallRating = "";
            //Takes the numberic value of the score from the function and then gives it a word rating
            if(data.overallScore >= 80) {
                overallRating = "Strong";
            }else if (data.overallScore >= 50) {
                overallRating = "Moderate";
            } else {
                overallRating = "Weak";
            }

            //displays both the rating and the score
            output += `Rating ${overallRating}\n`;
            output += `Score: ${data.overallScore}/100\n`


            //Breakpoint Line
            output += "\n-----------------------------------------------------------------\n";




            //display the final results
            document.getElementById('result').innerHTML = output;

            //AI SUMMARY

            //Loading message for the AI summary
            document.getElementById("aiSummary").textContent = "Generating AI Summary..."

            //Sends a request to the backend but for the /ai-summary
            fetch(`${baseURL}/ai-summary`,{
                //POST as the data is sent to a server
                method: "POST",
                //The data sent is JSON
                headers: {
                    "Content-Type": "application/json"
                },
                //Gets the data and converts it to JSON
                body: JSON.stringify(data)
            })
            //AI summary response is turned into a JSON
            .then(res => res.json())
            //Displays the results
            .then(ai => {
                document.getElementById("aiSummary").textContent = ai.summary;
            })
            //err message if the AI summary fails
            .catch(() => {
                document.getElementById("aiSummary").textContent = "AI analysis failed.";
            });

        })
        //error handling for the main scan
        .catch(error => {
            document.getElementById('result').textContent = "Error: " + error;
        });
}


//For the Information Tab, windows.onload runs from the start
window.onload = function() {
    //
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

    <h3> Reverse DNS </h3>
    <p>
    Reverse DNS involves querying the DNS to determine the hostname associated with a specific IP address.
    <br>
    It is important in OSINT as it provides infrastructure reconnaissance. An investigator can use the hostname to find all other domains linked to that infrastructure using reverse DNS.

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