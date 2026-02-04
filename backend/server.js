//Importing the Libs
//express is the Node.js web framework to create the server and cors allows the website to call the backend
const express = require("express");
const cors = require("cors");

//creates the application 
const app = express()

//allows cors to every request, allows GET, POST and requests to the frontend
app.use(cors());

//defining the /analyse toute
app.get("/analyse", (req, res)=> {
    //reading the query parameter
    const query = req.query.query;

    //Input Validation
    //if the user sends no query then it will return the error message
    if(!query) {
        return res.status(400).json({ error: "No Query Provided"});

    }

    //Stimulated Results this is a placeholder
    const fakeResults = {
        query: query,
        ip: "8.8.8.8",
        riskScore: Math.floor(Math.random() * 100)
        
    };
    //sending the results back to the frontend
    res.json(fakeResults);
});

//starting the server
app.listen(3000, () => {
    console.log("backend running on http://localhost:3000");
});



