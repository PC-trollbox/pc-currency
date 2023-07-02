const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const secret = "This is test, change me. Should be secret (duh!)";
const usernames = [ "tester" ];
const APIBase = "http://localhost:4599/api/";
const crypto = require("crypto");

app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(bodyParser.json());

app.post("/outNetworkTransactionRecieve", function(req, res) {
	if (!req.body.recipient) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.money) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.token) return res.status(400).send("Incomplete transaction structure.");
	if (req.body.currencySecret != secret) return res.status(403).send("Incoming request is not authenticated.");
	if (!usernames.includes(req.body.recipient)) return res.status(404).send("Recipient does not exist.");
	if (parseFloat(req.body.money) < 0) return res.status(400).send("Invalid transaction amount.");
	if (isNaN(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	if (!isFinite(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	let transaction = {
		sender: "REMOTE-PCCURRENCY-" + req.body.sender,
		recipient: req.body.recipient,
		money: req.body.money,
		timestamp: Date.now(),
		token: "REMOTE-" + req.body.token,
		description: req.body.description
	}
	console.log(transaction);
	res.send("OK");
});

/*
	fetch(APIBase + "outNetworkTransactionSend", {
		method: "POST",
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			sender: "tester",
			recipient: "PC",
			money: 1,
			timestamp: Date.now(),
			token: crypto.randomBytes(32).toString("hex"),
			description: "Just some money.",
			currencySecret: secret
		})
	});
*/

app.listen(4600, function() {
	console.log("Listening on port 4600");
});