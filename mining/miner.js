const readline = require("readline/promises");
const worker_threads = require("worker_threads");
const mineutils = require("./mineutils");
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
let line = "";
let writeLine = () => process.stdout.write("\r" + line + " ".repeat(Math.max(process.stdout.columns - line.length, 0)));
let minedTimes = 0;
let secondsPerMineAvg = [];
let avg = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;

async function logon(url) {
    console.log("TO USE THIS MINER, YOU NEED TO FIND THE LOGON COOKIE.");
    console.log("IT CAN BE FOUND BY TYPING 'document.cookie' IN YOUR BROWSER.");
    console.log("THE TOKEN IS AFTER THE 'token=' STRING.");
    console.log("DO NOT SHARE THIS TOKEN WITH ANYONE.");
    let token = await rl.question("Input cookie token: ");
    console.clear();
    console.log("Validating cookie token...");
    let username = await fetch(url + "api/username", paramToken(token));
    if (!username.ok) {
        console.log("Wrong token!");
        return logon(url);
    }
    username = await username.json();
    console.log("Username:\t" + username);
    let workers;
    while (true) {
        let workers_user = await rl.question("Workers:\t");
        if (workers_user <= 0) {
            console.log("Be realistic!");
            continue;
        }
        workers = workers_user;
        break;
    }
    console.log("Starting the mining process...");
    for (let i = 0; i < workers; i++) {
        let worker = new worker_threads.Worker(__filename);
        worker.postMessage({ token, url, workerID: i });
        let spm1 = Date.now();
        worker.on("message", function() {
            spm1 = Date.now() - spm1;
            spm1 = spm1 / 1000;
            secondsPerMineAvg.push(spm1);
            spm1 = Date.now();
            minedTimes++;
            line = "Mined " + minedTimes + " times. Currently done by worker" + i + ". Seconds/crack: " + avg(secondsPerMineAvg).toFixed(2) + " (" + (1 / avg(secondsPerMineAvg)).toFixed(2) + " c/sec)";
            writeLine();
        });
    }
    console.log("Mining in Progress...");
}

async function beforeLogon() {
    let url = await rl.question("Input the main PCCurrency URL: ");
    try {
        url = new URL(url);
    } catch {
        console.log("A syntax error occurred. The URL is invalid.");
        return beforeLogon()
    }
    if (url.protocol != "https:") console.log("It's recommended to use HTTPS.");
    url = url.protocol + "//" + url.hostname + ":" + url.port + "/";
    logon(url);
}

function paramToken(token) {
    return {
        headers: {
            cookie: "token=" + token
        }
    };
}

async function worker() {
    let port = worker_threads.parentPort;
    port.once("message", async function(data) {
        let { url, workerID, token } = data;
        while (true) {
            let task = await fetch(url + "api/task?thread=" + workerID, paramToken(token));
            task = await task.json();
            let mined = mineutils.mine(task.data, task.difficulty, workerID);
            await fetch(url + "api/task?code=" + mined + "&thread=" + workerID, paramToken(token));
            port.postMessage("mined");
        }
    });
}

if (worker_threads.isMainThread) beforeLogon();
else worker();