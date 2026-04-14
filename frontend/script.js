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

    //send the request to the backend
    fetch(`http://localhost:3001/analyse?query=${encodeURIComponent(domain)}`)

        //response into JSON
        .then(response => response.json())
        .then(data => {

            //output string 
            let output = `DOMAIN ANALYSIS\n`;
            output += `Domain: ${data.query}\n`;
            output += `IP Address: ${data.ip}\n\n`;

            //MX Records
            //checks if the mxRecords exist
            output += "MX RECORDS\n";
            if (data.mxRecords && data.mxRecords.length > 0) {
                data.mxRecords.forEach(mx => {
                    output += `Priority: ${mx.priority}, Exchange: ${mx.exchange}\n`;
                });
            } else {
                //if there is none
                output += "No MX records found.\n";
            }

            //NS Records
            output += "\nNAME SERVERS\n";
            if (data.nsRecords && data.nsRecords.length > 0) {
                data.nsRecords.forEach(ns => {
                    output += `${ns}\n`;
                });
            } else {
                output += "No NS records found.\n";
            }

            //SOA Record
            output += "\nSOA RECORD\n";
            if (data.soa) {
                output += `Primary NS: ${data.soa.nsname}\n`;
                output += `Admin: ${data.soa.hostmaster}\n`;
            } else {

                output += "No SOA Found.\n";
            }

            //Reverse DNS
            output += "\nREVERSE DNS\n";
            if (data.hostnames && data.hostnames.length > 0) {
                data.hostnames.forEach(h => {
                    output += `${h}\n`;
                });
            } else {
                output += "No reverse DNS found.\n";

            }

            //TXT Records
            output += "\nTXT RECORDS\n";
            if (data.txtRecords && data.txtRecords.length > 0) {
                data.txtRecords.forEach(txt => {
                    output += `${txt.join('')}\n`;
                });
                
            } else {
                output += "No TXT records found.\n";
            }

            //display the results
            document.getElementById('result').textContent = output;
        })
        //error handling
        .catch(error => {
            document.getElementById('result').textContent = "Error: " + error;
        });
}