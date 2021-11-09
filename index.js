const fetch = require('node-fetch');
const { google } = require('googleapis');
const jwt_decode = require("jwt-decode");
const uuid = require("uuid");
const readline = require("readline");

require('dotenv').config()
process.env.TZ = "Europe/Paris"; // Les temps candilib sont en heure française

// If modifying these scopes, delete token.json.
const SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send'
];

const CANDILIB_URL = 'https://beta.interieur.gouv.fr/candilib'
const CANDILIB_HEADERS = {
    "Content-Type": "application/json",
    "X-REQUEST-ID": uuid.v4(),
    "X-CLIENT-ID": uuid.v4(), // Pas la peine de mettre une version. Bug bien pratique : https://github.com/LAB-MI/candilibV2/blob/master/server/src/routes/middlewares/verify-user.js#L18 
};

const CENTRES_EXAM_PREFERES = ["94", "93", "92"];

async function main() {
    if (!process.env.CREDENTIALS) {
        console.log("variables d'environnement CREDENTIALS manquante");
        process.exit(1);
    }

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
    const depts = await examCentresDepartements(identified_headers);
    await attendreCreneau(decoded_token);
    const centres = await getCentres(depts, identified_headers);
    console.log(`${centres.length} centres avec des places disponibles.`);
    if (!centres.length) console.log("Évidemment :'(");
    await sendMail(auth, token, centres);
    console.log("Fini.");
}

async function attendreCreneau(decoded_token) {
    const date = new Date();
    date.setHours(12);
    date.setMinutes(10 * decoded_token.candidatStatus);
    date.setSeconds(0);
    date.setMilliseconds(0);
    const sleepTime = date.getTime() - Date.now();
    if (sleepTime < 0) return;
    console.log(`Sleeping ${(sleepTime / 1000).toFixed()} seconds until ${date.toLocaleString()}`);
    await sleep(sleepTime);
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
    if (!process.env.TOKEN) await missingGoogleToken(oAuth2Client);
    const token_json = JSON.parse(process.env.TOKEN);
    const scopes = token_json.scope.split(' ');
    if (!SCOPES.every(s => scopes.includes(s))) await missingGoogleToken(oAuth2Client);
    oAuth2Client.setCredentials(token_json);
    return oAuth2Client
}

/**
 * 
 * @param {import("google-auth-library").OAuth2Client} oAuth2Client
 */
async function missingGoogleToken(oAuth2Client) {
    const url = oAuth2Client.generateAuthUrl({ access_type: 'offline', scope: SCOPES, });
    console.log(`Vous pouvez maintenant vous connecter à votre compte Google avec le lien suivant : ${url}`);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const code = await new Promise(a => rl.question('Please paste the authentication code: ', a));
    const { tokens } = await oAuth2Client.getToken(code);
    console.log(`\nToken reçu, ajoutez la variable d'environnement\n\nTOKEN='${JSON.stringify(tokens)}'`);
    oAuth2Client.setCredentials(tokens);
    process.exit(1);
}

async function sleep(time_ms) {
    return new Promise(resolve => setTimeout(resolve, time_ms));
}

/**
 * Trouve le dernier mail de candilib
 *
 * @param {OAuth2Client} auth An authorized OAuth2 client.
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
    if (r.status !== 200) {
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
 * @returns {Promise<string[]>}
 */
async function examCentresDepartements(headers) {
    const r = await fetch(CANDILIB_URL + "/api/v2/candidat/departements", { headers });
    if (r.status !== 200) throw new Error("erreur candilib: " + await r.text());
    const j = await r.json();
    if (!j.success) throw new Error(JSON.stringify(j));
    const depts = j.geoDepartementsInfos.map(d => d.geoDepartement);
    const depts_ordered = [
        ...CENTRES_EXAM_PREFERES.filter(c => depts.includes(c)),
        ...depts.filter(c => !CENTRES_EXAM_PREFERES.includes(c))
    ];
    return depts_ordered
}

/**
 * 
 * @param {string[]} depts 
 * @param {Object} identified_headers 
 * @returns {Promise<Centre[]>}
 */
async function getCentres(depts, identified_headers) {
    const result = [];
    for (const dept of depts) {
        for (const { count, centre } of await centresInDept(identified_headers, dept)) {
            if (count > 0) result.push(centre);
            console.log(`${count} places disponibles à ${centre.nom} (${dept})`);
        }
        await sleep(200);
    }
    return result
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

/**
 * Envoi un mail avec les résultats
 *
 * @param {import('google-auth-library').OAuth2Client} auth An authorized OAuth2 client.
 * @param {string} token
 * @param {Centre[]} centres
 */
async function sendMail(auth, token, centres) {
    const gmail = google.gmail({ version: 'v1', auth });
    const my_profile = await gmail.users.getProfile({ userId: 'me' });
    const me = my_profile.data.emailAddress;
    const total = centres.length;
    const subject = `[${new Date().toISOString().split('T')[0]}] ${total} places disponibles sur candilib`;
    const body = centres.length
        ? `<p>
            Les centres suivants ont des places : <ul>\n${centres.map(c => (
            `  <li>`
            + `  <a href="${CANDILIB_URL}/candidat/${c.geoDepartement}/${c.nom}/undefinedMonth/undefinedDay/selection/selection-place?token=${token}">`
            + `    ${c.nom} (${c.geoDepartement})`
            + `  </a>`
            + `</li>`)
        )
            .join('\n')
        }</ul>
        </p>

        <p>
         <a href="${CANDILIB_URL}/candidat?token=${token}">Interface principale de candilib.</a>
        </p>`
        : `<p>Aucun centre n'a de place.</p>`;
    console.log(`Envoi du mail à ${me}`);
    await gmail.users.messages.send({
        userId: 'me',
        requestBody: {
            raw: makeBody(me, me, subject, body),
        }
    });
}

function makeBody(to, from, subject, message) {
    var str = [
        "Content-Type: text/html; charset=\"UTF-8\"\n",
        "MIME-Version: 1.0\n",
        "Content-Transfer-Encoding: 7bit\n",
        "to: ", to, "\n",
        "from: ", from, "\n",
        "subject: ", subject, "\n\n",
        message
    ].join('');

    var encodedMail = Buffer.from(str).toString("base64").replace(/\+/g, '-').replace(/\//g, '_');
    return encodedMail;
}

main()