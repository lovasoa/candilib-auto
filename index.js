const fs = require('fs');
const fetch = require('node-fetch');
const { google } = require('googleapis');
const jwt_decode = require("jwt-decode");
const uuid = require("uuid");

require('dotenv').config()

// If modifying these scopes, delete token.json.
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

const CANDILIB_URL = 'https://beta.interieur.gouv.fr/candilib'
const CANDILIB_HEADERS = {
    "Content-Type": "application/json",
    "X-REQUEST-ID": uuid.v4(),
    "X-CLIENT-ID": uuid.v4(), // Pas la peine de mettre une version. Bug bien pratique : https://github.com/LAB-MI/candilibV2/blob/master/server/src/routes/middlewares/verify-user.js#L18 
};

const CENTRES_EXAM_PREFERES = ["94", "93", "92"];

async function main() {
    // Load client secrets from a local file.
    const credentials = JSON.parse(process.env.CREDENTIALS);
    // Authorize a client with credentials, then call the Gmail API.
    const auth = await authorize(credentials);
    let token = await findTokenInMail(auth);
    while (!token) {
        await sendCandilibEmail();
        console.log("Attente de la réception du mail de candilib");
        await sleep(1000 * 30);
        token = await findTokenInMail(auth);
    }
    const decoded_token = jwt_decode(token);
    console.log(`Token candilib trouvé. Bienvenue ${decoded_token.prenom} :)`,);
    const identified_headers = {
        ...CANDILIB_HEADERS,
        "X-USER-ID": decoded_token.id,
        "Authorization": "Bearer " + token
    }
    let total = 0;
    for await (const { count, centre } of examCentres(identified_headers)) {
        console.log(`${count} places à ${centre.nom} (${centre.geoDepartement})`);
        total += count;
    }
    console.log(`${total} places disponibles.`);
    if (total === 0) console.log("Évidemment :'(");
}

/**
 * Create an OAuth2 client with the given credentials,
 * @param {Object} credentials The authorization client credentials.
 * @param {function} callback The callback to call with the authorized client.
 */
async function authorize(credentials) {
    const { client_secret, client_id, redirect_uris } = credentials.installed;
    const oAuth2Client = new google.auth.OAuth2(
        client_id, client_secret, redirect_uris[0]);
    oAuth2Client.setCredentials(JSON.parse(process.env.TOKEN));
    return oAuth2Client
}

async function sleep(time_ms) {
    return new Promise(resolve => setTimeout(resolve, time_ms));
}

/**
 * Trouve le dernier mail de candilib
 *
 * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
 */
async function findTokenInMail(auth) {
    console.log("Recherche d'un mail de candilib");
    const gmail = google.gmail({ version: 'v1', auth });
    const response = await gmail.users.messages.list({
        userId: 'me',
        q: [
            'from:(noreply@interieur.gouv.fr)',
            'subject:(Validation de votre inscription à Candilib)',
            'after:' + (new Date()).toISOString().split('T')[0]
        ].join(' '),
        maxResults: 1,
    });
    if (response.data.resultSizeEstimate === 0) {
        console.log('Aucun message de candilib trouvé');
        return null;
    }
    const msg_id = response.data.messages[0].id;
    const raw_body = (await gmail.users.messages.get({
        userId: 'me',
        id: msg_id,
    })).data.payload.parts[0].body.data;
    const body = Buffer.from(raw_body, 'base64').toString('utf8');
    const token = body.match(/candilib\/candidat\?token=([\w\d\.=\-]+)/)[1];
    return token;
}

async function sendCandilibEmail() {
    console.log("demande à candilib d'envoi d'un token par email");
    const r = await fetch(CANDILIB_URL + "/api/v2/auth/candidat/magic-link", {
        "headers": CANDILIB_HEADERS,
        "body": JSON.stringify({ "email": "pere.jobs+permis@gmail.com" }),
        "method": "POST",
    });
    if (!r.status !== 200) {
        console.log("Erreur lors de l'envoi de l'email de candidilib");
        throw new Error("erreur candilib: " + await r.text())
    }
    const result = await r.json();
    if (!result.success) {
        console.log("Erreur lors de l'envoi du mail de candilib");
        console.log(result);
        throw new Error("erreur candilib" + result.message);
    }
}


/**
 * 
 * @param {Object} headers 
 */
async function* examCentres(headers) {
    const r = await fetch(CANDILIB_URL + "/api/v2/candidat/departements", { headers });
    if (r.status !== 200) throw new Error("erreur candilib: " + await r.text());
    const j = await r.json();
    if (!j.success) throw new Error(JSON.stringify(j));
    const centres = j.geoDepartementsInfos.map(d => d.geoDepartement);
    const centres_ordered = [
        ...CENTRES_EXAM_PREFERES.filter(c => centres.includes(c)),
        ...centres.filter(c => !CENTRES_EXAM_PREFERES.includes(c))
    ];
    for (c of centres_ordered) {
        for (const centre of await centresInDept(headers, c)) {
            yield centre;
        }
        await sleep(300);
    }
}

/**
 * 
 * @typedef {{
 *  idList:string[],
 *  _id:string,
 *  geoloc:{coordinates:[number,number],type:"Point"},
 *  adresse:string,
 *  geoDepartement:string,
 *  nom:string
 * }} Centre
 * @param {Object} headers 
 * @param {string} dept 
 * @returns {Promise<{centre:Centre,count:number}[]>}
 */
async function centresInDept(headers, dept) {
    console.log("Recherche de centres dans le " + dept);
    const centres_url = new URL(CANDILIB_URL + "/api/v2/candidat/centres");
    centres_url.searchParams.append("departement", dept);
    centres_url.searchParams.append("end", new Date(Date.now() + 4 * 31 * 24 * 3600 * 1000).toISOString());
    const req_centres = await fetch(centres_url, { headers });
    if (req_centres.status !== 200) throw new Error("erreur candilib: " + await req_centres.text());
    return await req_centres.json();
}

main()