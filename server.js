import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createAgent } from '@veramo/core'
import { KeyManager } from '@veramo/key-manager'
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
import { Entities, KeyStore, DIDStore, PrivateKeyStore, DataStore, migrations } from '@veramo/data-store'
import { DataSource } from 'typeorm'
import { DIDManager } from '@veramo/did-manager'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
import { WebDIDProvider } from '@veramo/did-provider-web'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { CredentialIssuerLD, LdDefaultContexts, VeramoEd25519Signature2020, VeramoEcdsaSecp256k1RecoverySignature2020 } from '@veramo/credential-ld'
import { bytesToBase58, bytesToMultibase, hexToBytes } from '@veramo/utils'
import express from 'express'
import cors from 'cors'
import sqlite3 from 'sqlite3'
import * as yaml from 'js-yaml'
import openBadgeContext from './context-3.0.3.json' assert { type: 'json' }

const CREDENTIALS_DB_FILE = 'credentials.db'

const credentialListPath = '/credentials'
const credentialPath = '/credential'
const svgPath = '/svg'
const oid4vcPath = '/openid'
const credentialType = "OpenBadgeCredential"

const badgeContexts = {}
badgeContexts['https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'] = openBadgeContext
badgeContexts['https://purl.imsglobal.org/spec/ob/v3p0/extensions.json'] = {
  "@context": {
    "id": "@id",
    "type": "@type",
    "1EdTechJsonSchemaValidator2019": "https://purl.imsglobal.org/spec/vccs/v1p0/context.json#1EdTechJsonSchemaValidator2019",
    "1EdTechRevocationList": "https://purl.imsglobal.org/spec/vcrl/v1p0/context.json#1EdTechRevocationList",
    "1EdTechCredentialRefresh": "https://purl.imsglobal.org/spec/vccr/v1p0/context.json#1EdTechCredentialRefresh"
  }
}

const configFile = './agent.yml'
const configString = readFileSync(configFile, 'utf8')
const config = yaml.load(configString);

const httpPort = parseInt(config.constants.port)

const baseUrl = config.constants.baseUrl.replace(/\/$/, '')  // omit trailing slash
const [scheme, empty, host, ...pathParts] = baseUrl.split('/')
let path = ''
if (pathParts.length) {
  path = `/${pathParts.join('/')}`
}

const keyTypes = {
  Secp256k1: 'EcdsaSecp256k1VerificationKey2019',
  Secp256r1: 'EcdsaSecp256r1VerificationKey2019',
  Ed25519: 'Ed25519VerificationKey2020',
  X25519: 'X25519KeyAgreementKey2019',
  Bls12381G1: 'Bls12381G1Key2020',
  Bls12381G2: 'Bls12381G2Key2020',
}

// init credential DB
let db = new sqlite3.Database(CREDENTIALS_DB_FILE, (err) => {
  if (err) {
    console.error(err.message)
  }
  console.log(`Connected to the database '${CREDENTIALS_DB_FILE}'.`)
  const create = `CREATE TABLE IF NOT EXISTS credential (
    id varchar(512) PRIMARY KEY,
    data TEXT
  )`
  db.run(create);
})

const dbConnection = new DataSource({
  type: 'sqlite',
  database: config.constants.databaseFile,
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ['debug', 'error', 'info', 'warn'],
  entities: Entities,
}).initialize()

const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(config.constants.dbEncryptionKey))),
      },
    }),
    new DataStore({dbConnection}),
    new DIDManager({
      store: new DIDStore(dbConnection),
      defaultProvider: 'did:web',
      providers: {
        'did:web': new WebDIDProvider({defaultKms: 'local'}),
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...webDidResolver(),
      }),
    }),
    new CredentialPlugin(),
    new CredentialIssuerLD({
      contextMaps: [LdDefaultContexts, badgeContexts],
      suites: [
        new VeramoEd25519Signature2020(),
      ]
    })
  ]
})

async function createDID(alias) {
  const identifier = await agent.didManagerCreate({ alias: alias }).catch(console.error)
  console.log(`New did ${alias} created`)
  const edKey = await agent.keyManagerCreate({ kms: 'local', type: 'Ed25519' })
  await agent.didManagerAddKey({ did: identifier.did, key: edKey }).catch(console.error)
  identifier.keys.push(edKey)
  return identifier
}

async function getMyDid() {
  let alias = [host, ...pathParts].join(':')
  let identifier
  const dids = await agent.didManagerFind({ alias: alias })
  if (dids.length > 0) {
    identifier = dids[0]
  }
  else {
    identifier = await createDID(alias).catch(console.error)
  }
  return { alias, identifier}
}

async function getDidDocument(req, res) {
  const {alias, identifier} = await getMyDid()
  const contexts = new Set(['https://www.w3.org/ns/did/v1'])
  const verificationMethods = []
  const authentications = []
  const assertionMethods = []
  const didDoc = {
    "@context": [...contexts],
    "id": `did:web:${alias}`,
    "verificationMethod": [],
    "authentication": [],
    "assertionMethod": [],
    "keyAgreement": [],
    "service": identifier.services
  }
  for (const key of identifier.keys) {
    const keyId = `did:web:${alias}#${key.kid}`
    didDoc.verificationMethod.push({
      "id": keyId,
      "type": keyTypes[key.type],
      "controller": `did:web:${alias}`,
      "publicKeyHex": key.publicKeyHex
    })
    if (key.type == 'X25519') {
      didDoc.keyAgreement.push(keyId)
    }
    else {
      didDoc.authentication.push(keyId)
      didDoc.assertionMethod.push(keyId)
    }
    // from https://github.com/decentralized-identity/veramo/blob/d89a4dd403942445e1262eabd34be88afa5f9685/packages/remote-server/src/web-did-doc-router.ts#L44C3-L110C4
    switch (didDoc.verificationMethod.at(-1).type) {
      case 'EcdsaSecp256k1VerificationKey2019':
      case 'EcdsaSecp256k1RecoveryMethod2020':
        contexts.add('https://w3id.org/security/v2')
        contexts.add('https://w3id.org/security/suites/secp256k1recovery-2020/v2')
        break
      case 'Ed25519VerificationKey2018':
        contexts.add('https://w3id.org/security/suites/ed25519-2018/v1')
        didDoc.verificationMethod.at(-1).publicKeyBase58 = bytesToBase58(hexToBytes(key.publicKeyHex))
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'X25519KeyAgreementKey2019':
        contexts.add('https://w3id.org/security/suites/x25519-2019/v1')
        didDoc.verificationMethod.at(-1).publicKeyBase58 = bytesToBase58(hexToBytes(key.publicKeyHex))
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'Ed25519VerificationKey2020':
        contexts.add('https://w3id.org/security/suites/ed25519-2020/v1')
        didDoc.verificationMethod.at(-1).publicKeyMultibase = bytesToMultibase(hexToBytes(key.publicKeyHex), 'Ed25519')
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'X25519KeyAgreementKey2020':
        contexts.add('https://w3id.org/security/suites/x25519-2020/v1')
        didDoc.verificationMethod.at(-1).publicKeyMultibase = bytesToMultibase(hexToBytes(key.publicKeyHex), 'X25519')
        delete(didDoc.verificationMethod.at(-1).publicKeyHex)
        break
      case 'EcdsaSecp256r1VerificationKey2019':
        contexts.add('https://w3id.org/security/v2')
        break
      case 'Bls12381G1Key2020':
      case 'Bls12381G2Key2020':
        contexts.add('https://w3id.org/security/bbs/v1')
        break
      default:
        break
    }
  }
  didDoc['@context'] = [...contexts]
  res.json(didDoc)
}

async function db_get(query) {
  return new Promise(function(resolve,reject){
    db.get(query, function(err,row){
      if(err){return reject(err);}
      resolve(row);
    });
  });
}

function getName(object, lang) {
  if (object[lang]) return object[lang]
  return object['fi']
}

async function getVerifiableCredential(id, format) {
  const {alias, identifier} = await getMyDid()
  // id can be either a long URL identifier or a row identifier
  const where = id.includes('http') ? `id = '${id}'` : `rowId = ${id}`
  const select = `SELECT * FROM credential WHERE ${where}`    
  // console.log(select)
  const row = await db_get(select)
  if (!row) {
    throw new Error(`Tunnisteella ${id} ei löytynyt todisteita.`)
  }
  // console.log(row.data)
  const credential = JSON.parse(row.data)
  const vc = await agent.createVerifiableCredential({
    credential: credential,
    proofFormat: format,
    save: false
  })
  return vc
}

function createOffer(id, name) {
  const authCode = [encodeURIComponent(name), encodeURIComponent(id)].join('/')
  const offer = {
    "credential_issuer": [baseUrl, authCode].join('/'),
    "credential_configuration_ids": [
      credentialType,
    ],
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        // "pre-authorized_code": id,
        "pre-authorized_code": authCode,
      }
      /*
        "authorization_code": {
        "issuer_state": id
      }
*/
    }
  }
  // console.log(offer)
  return offer
}

const app = express()
app.set('trust proxy', 1)
app.use(cors())
app.use(express.urlencoded({ extended: true }))
app.get(/^\/(.*)\.(png|ico|html)/, (req, res) => {
  console.log(req.method, req.url, req.params[0])
  res.sendFile(new URL(`./${req.params[0]}.${req.params[1]}`, import.meta.url).pathname)
})

app.get('/', async (req, res) => {
  console.log(req.method, req.url)
  res.sendFile(new URL('./index.html', import.meta.url).pathname)
})

app.get('/manifest.json', async (req, res) => {
  console.log(req.method, req.url)
  res.sendFile(new URL('./manifest.json', import.meta.url).pathname)
})

const didDocPath = path.length == 0 ? '/.well-known/did.json' : `${path}/did.json`
app.get(didDocPath, getDidDocument)
app.get('/did.json', getDidDocument) // hack for Open Badges 3.0 Verifier that doesn't know .well-known

app.get(credentialListPath, async (req, res) => {
  console.log(req.method, req.url)
  const url = req.query.url.replace('koski/opinnot', 'koski/api/opinnot')
  const lang = req.query.lang || 'fi'
  const {alias, identifier} = await getMyDid()
  const response = await fetch(url).catch(e => {
    const error = {
      "code": 404,
      "message": `Opintosuorituksia ei löytynyt osoitteella ${url}`,
      "details": e
    }
    res.status(error.code).json(error)
    console.warn(error)
  })
  if (!response) return false
  const obj = await response.json().catch(e => {
    const error = {
      "code": 500,
      "message": `Osoitteen ${url} tiedot eivät olleet JSON-muodossa.`,
      "details": e
    }
    res.status(error.code).json(error)
    console.warn(error)
  })
  if (!obj) return false
  const stmt = db.prepare("REPLACE INTO credential (id, data) VALUES (?, ?);")
  const person = obj['henkilö']
  if (!person) {
    console.error('Ei henkilöä!')
    console.log(obj)
  }
  const subject = person.oid
  const schools = obj.opiskeluoikeudet
  if (schools.length < 1) {
    const error = {
      "code": 404,
      "message": `Opintosuorituksista ${url} ei löytynyt yhtään opiskeluoikeutta.`,
      "details": e
    }
    res.status(error.code).send(`<p class="error">${error}</p>`)
    console.warn(error)
    return false
  }
  const credentialPromises = []
  schools.forEach(school => {
    const creator = {
      "id": null,
      "type": "Profile",
      "name": null,
    }
    let issuanceDate = null
    if (school?.oppilaitos?.oid) {
      creator.id = school.oppilaitos.oid
    }
    if (school?.oppilaitos?.nimi) {
      creator.name = getName(school.oppilaitos.nimi, lang)
    }
    if (school?.koulutustoimija?.oid) {
      creator.id = school.koulutustoimija.oid
    }
    if (school?.koulutustoimija?.nimi?.fi) {
      creator.name = getName(school.koulutustoimija.nimi, lang)
    }
    if (school['päättymispäivä']) {
      issuanceDate = school['päättymispäivä']
    }
    let fieldOfStudy = ''
    for (const jakso of school?.tila?.opiskeluoikeusjaksot) {
      if (jakso?.tila?.nimi?.fi == 'valmistunut') {
        issuanceDate = jakso.alku
      }
      if (jakso?.nimi?.fi) {
        fieldOfStudy = getName(jakso.nimi, lang)
      }
    }
    school.suoritukset.forEach(a => {
      const achievement = {
        "id": null,
        "type": "Achievement",
        "achievementType": "Achievement",
        "creator": JSON.parse(JSON.stringify(creator)), // create a copy
        "criteria": {
          "narrative": ""
        },
        "description": null,
        "fieldOfStudy": "",
        "name": null
      }
      if (fieldOfStudy) {
        achievement.fieldOfStudy = fieldOfStudy
      }
      if (school['lisätiedot'] && school['lisätiedot'].virtaOpiskeluoikeudenTyyppi) {
        const type = school['lisätiedot'].virtaOpiskeluoikeudenTyyppi
        switch (type.koodiarvo) {
          case '1':
            achievement.achievementType = 'BachelorDegree'
            break
          case '3':
            achievement.achievementType = 'MasterDegree'
            break
        }
      }
      if (a.koulusivistyskieli && a.koulusivistyskieli[0]?.nimi?.fi) {
        achievement.tag = getName(a.koulusivistyskieli[0].nimi, lang)
      }
      if (school?.tyyppi?.nimi?.fi) {
        achievement.description = getName(school.tyyppi.nimi, lang)
      }
      if (school?.tyyppi?.lyhytNimi?.fi) {
        achievement.description = getName(school.tyyppi.lyhytNimi, lang)
      }
      if (a.koulutusmoduuli?.tunniste?.lyhytNimi?.fi) {
        achievement.name = getName(a.koulutusmoduuli.tunniste.lyhytNimi, lang)
      }
      if (a.koulutusmoduuli?.tunniste?.nimi?.fi) {
        achievement.name = getName(a.koulutusmoduuli.tunniste.nimi, lang)
      }
      if (a.koulutusmoduuli?.virtaNimi?.fi) {
        achievement.fieldOfStudy = getName(a.koulutusmoduuli.virtaNimi, lang)
      }
      if (a.koulutusmoduuli?.nimi?.fi) {
        achievement.fieldOfStudy = getName(a.koulutusmoduuli.nimi, lang)
      }
      if (a.koulutusmoduuli?.lyhytNimi?.fi) {
        achievement.fieldOfStudy = getName(a.koulutusmoduuli.lyhytNimi, lang)
      }
      if (a.vahvistus && a.vahvistus['päivä']) {
        issuanceDate = a.vahvistus['päivä']
      }
      if (a.vahvistus && a.vahvistus['myöntäjäorganisaatio']?.oid) {
        achievement.creator.id = a.vahvistus['myöntäjäorganisaatio'].oid
      }
      if (a.vahvistus && a.vahvistus['myöntäjäOrganisaatio']?.oid) {
        achievement.creator.id = a.vahvistus['myöntäjäOrganisaatio'].oid
      }
      if (a.vahvistus && a.vahvistus['myöntäjäorganisaatio']?.oppilaitosnumero?.nimi?.fi) {
        achievement.creator.name = getName(a.vahvistus['myöntäjäorganisaatio'].oppilaitosnumero.nimi, lang)
      }
      if (a.vahvistus && a.vahvistus['myöntäjäOrganisaatio']?.nimi?.fi) {
        achievement.creator.name = getName(a.vahvistus['myöntäjäOrganisaatio'].nimi, lang)
      }
      if (a.luokittelu?.nimi?.fi) {
        achievement.criteria.narrative = getName(a.luokittelu.nimi, lang)
      }
      else {
        achievement.criteria.narrative = achievement.description
      }
      if (a.koulutusmoduuli?.tunniste?.koodiarvo) {
        achievement.id = [
          achievement.creator.id,
          a.koulutusmoduuli.tunniste.koodiarvo,
          subject,
          issuanceDate
        ].join('/')
      }
      issuanceDate = new Date(issuanceDate).toISOString()
      creator.id = `https://${alias}/${creator.id}`
      achievement.creator.id = `https://${alias}/${achievement.creator.id}`
      achievement.id = `https://${alias}/${achievement.id}`
      const issuer = {
        // signing all credentials with our own did but using the name of the original issuer
        // TODO: create DIDs for all schools
        id: identifier.did,
        name: achievement.creator.name,
        type: "Profile"
      }
      const credential = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
          "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json"
        ],
        "id": achievement.id,
        "type": ["VerifiableCredential", credentialType],
        // "name": achievement.name,
        "credentialSubject": {
          "id": achievement.id,
          "type": "AchievementSubject",
          "achievement": achievement
        },
        "issuer": issuer,
        "issuanceDate": issuanceDate,
        // "credentialSchema": [
        //   {
        //     "id": "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
        //     "type": "1EdTechJsonSchemaValidator2019"
        //   }
        // ]
      }
      if (person.etunimet && person.sukunimi) {
        const hash = createHash('sha256')
        const salt = alias
        const salted = `${person.etunimet} ${person.sukunimi}${salt}`
        const hashed = hash.update(salted).digest('hex')
        credential.credentialSubject.identifier = [
          {
            "type": "IdentityObject",
            "hashed": true,
            "identityHash": `sha256$${hashed}`,
            "identityType": "ext:name",
            "salt": salt
          }
        ]
      }
      const promise = new Promise((resolve, reject) => {
        stmt.run(achievement.id, JSON.stringify(credential), function(err) {
          if (err) reject(err)
          const rowId = this.lastID
          const file = achievement.id.split('/').at(-1)
          const offer = createOffer(rowId, file)
          console.log(JSON.stringify(offer, null, 2))
          console.log(`Expecting request to ${offer.credential_issuer}/.well-known/openid-credential-issuer`)
          const offerLink = 'openid-credential-offer://?credential_offer_uri=' + encodeURIComponent(`${offer.credential_issuer}/credential-offer.json`)
          const alternateOffer = 'openid-credential-offer://?credential_offer=' + encodeURIComponent(JSON.stringify(offer))
          const li = `<li class="${achievement.achievementType}"><a href="${credentialPath}?id=${encodeURIComponent(achievement.id)}">` +
                     `<span class="card"><img src="${svgPath}?id=${encodeURIComponent(achievement.id)}" alt="${achievement.name}" /></span></a>` +
                     `<span class="download"><span lang="fi">Lataa</span> <span lang="en">Download</span> <span lang="sv">Ladda ned</span>: ` +
                     `<a download="${file}.svg" href="${svgPath}?id=${encodeURIComponent(achievement.id)}">SVG</a> ` +
                     `<a download="${file}.json" href="${credentialPath}?id=${encodeURIComponent(achievement.id)}">JSON</a> ` +
                     `<a class="oid4vci" href="${offerLink}" data-offer="${alternateOffer}"><span lang="fi">lompakkoon</span> <span lang="en">to wallet</span> <span lang="sv">till plånboken</span></a>` +
                     `</span></li>`
          resolve(li)
        })
      })
      credentialPromises.push(promise)
    })
  })
  let html = '<ul>'
  await Promise.all(credentialPromises).then(results => {
    html += results.join(' ')
  })
  html += '</ul>'
  res.send(html)
})

app.get(credentialPath, async (req, res) => {
  console.log(req.method, req.url)
  const fmt = 'lds'
  if (req.query.format == 'jwt') {
    const fmt = req.query.format
  }
  const vc = await getVerifiableCredential(req.query.id, fmt).catch(e => {
    res.status(404).json(e)
    throw new Error(e)
  })
  res.setHeader('Content-Type', 'application/ld+json').json(vc)
})

app.get(svgPath, async (req, res) => {
  console.log(req.method, req.url)
  const vc = await getVerifiableCredential(req.query.id, 'lds').catch(e => {
    res.status(404).json(e)
  })
  if (!vc) return false
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:openbadges="https://purl.imsglobal.org/ob/v3p0" viewBox="0 0 856 549.8">
    <openbadges:credential>
      <![CDATA[
${JSON.stringify(vc, null, 2)}
      ]]>
    </openbadges:credential>
    <defs>
      <linearGradient id="findy-card" x1="0" x2="0" y1="0" y2="1" gradientTransform="rotate(16)">
       <stop offset="0%" stop-color="#0a00be" />
       <stop offset="100%" stop-color="#41ebff" />
      </linearGradient>
    </defs>
    <style type="text/css">
     .card {
      fill: url(#findy-card);
     }
     foreignObject {
      position: relative;
     }
     p {
      color: white;
      font-family: Helvetica,Verdana,Arial,sans-serif;
     }
     .achievement {
      font-size: 36pt;
     }
     .fieldOfStudy {
      font-size: 24pt;
     }
     .issuer {
      color: #0d0342;
      font-size: 18pt;
      /*
      position: absolute;
      bottom: 0;
      */
     }
    </style>
    <rect class="card" x="0" y="0" width="856" height="549.8" rx="31" ry="31" />
    <foreignObject x="75" y="25" width="706" height="225">
      <p xmlns="http://www.w3.org/1999/xhtml" class="achievement ModernText">${vc?.credentialSubject?.achievement?.name}</p>
    </foreignObject>
    <foreignObject x="75" y="250" width="706" height="150">
      <p xmlns="http://www.w3.org/1999/xhtml" class="fieldOfStudy ModernText">${vc?.credentialSubject?.achievement?.fieldOfStudy}</p>
    </foreignObject>
    <foreignObject x="75" y="450" width="706" height="100">
      <p xmlns="http://www.w3.org/1999/xhtml" class="issuer ModernText">${vc?.issuer?.name}</p>
    </foreignObject>
  </svg>`
  res.setHeader('Content-Type', 'image/svg+xml').send(svg)
})

app.get('/:name/:id/credential-offer.json', async (req, res) => {
  console.log(req.method, req.url)
  console.log(req.params)
  const id  = req.params.id
  const name  = req.params.name
  const offer = createOffer(id, name)
  console.log(JSON.stringify(offer, null, 2))
  console.log(`Expecting request to ${offer.credential_issuer}/.well-known/openid-credential-issuer`)
  res.json(offer)
})

app.get('/:name/:id/.well-known/oauth-authorization-server', async (req, res) => {
  console.log(req.method, req.url)
  const id  = req.params.id
  const name  = req.params.name
  const meta = {
    "issuer": [baseUrl, encodeURIComponent(name), encodeURIComponent(id)].join('/'),
    "token_endpoint": `${baseUrl}/token`,
    "response_types_supported": [
      "token"
    ]
  }
  console.log(JSON.stringify(meta, null, 2))
  res.json(meta)
})

app.get('/:name/:id/.well-known/openid-credential-issuer', async (req, res) => {
  console.log(req.method, req.url)
  console.log(req.params)
  const id  = req.params.id
  const name  = req.params.name
  console.log(req.headers)
  const meta = {
    "credential_issuer": [baseUrl, encodeURIComponent(name), encodeURIComponent(id)].join('/'),
    "credential_endpoint": `${baseUrl}${oid4vcPath}`,
    "credential_identifiers_supported": true,
    "display": [
      {
        "name": "Findynet Study Credential demo",
        "locale": "en-US",
        "logo": {
          "uri": `${baseUrl}/favicon.png`
        }
      },
      {
        "name": "Findynetin Opintopolku-todistedemo",
        "locale": "fi-FI",
        "logo": {
          "uri": `${baseUrl}/favicon.png`
        }
      },
      {
        "name": "Findynets Min Studieinfo-bevisdemo",
        "locale": "sv-SE",
        "logo": {
          "uri": `${baseUrl}/favicon.png`
        }
      }
    ],
    "credential_configurations_supported": {}
  }
  meta.credential_configurations_supported[credentialType] = {
    "format": "ldp_vc",
    // "credential_signing_alg_values_supported": [
    //   "Ed25519Signature2020"
    // ],
    "credential_definition":{
      "type": [
        "VerifiableCredential",
        credentialType
      ],
      // "credentialSubject": {
      // }
    },
    "display": [
      {
        "name": "My Studyinfo credential",
        "locale": "en-US",
        "logo": {
          "uri": `${baseUrl}/favicon.png`
        }
      },
      {
        "name": "Opintopolkutodiste",
        "locale": "fi-FI",
        "logo": {
          "uri": `${baseUrl}/favicon.png`
        }
      },
      {
        "name": "Min Studieinfo-bevis",
        "locale": "sv-SE",
        "logo": {
          "uri": `${baseUrl}/favicon.png`
        }
      }
    ],
  }
  console.log(JSON.stringify(meta, null, 2))
  res.json(meta)
})

app.get('/authorize', async (req, res) => {
  console.log(req.method, req.url)
  // const id = req.query.issuer_state
  const uri = req.query.redirect_uri
  const loc = uri + (uri.includes('?') ? '&' : '?') +
              `code=${encodeURIComponent(authCode)}`
  res.redirect(302, loc)
})

app.post('/token', async (req, res) => {
  console.log(req.method, req.url)
  console.log(req.body)
  const json = {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
    "token_type": "bearer",
    "expires_in": 86400,
  }
  if (req.body.pre-authorized_code) {
    const id = req.body.pre-authorized_code
    json.authorization_details = [
      {
        "type": "openid_credential",
        "credential_configuration_id": credentialType,
        "credential_identifiers": [ id ]
      }
    ]
  }
  res.setHeader('Cache-Control', 'no-store').json(json)
})

app.post('/:name/:id/token', async (req, res) => {
  console.log(req.method, req.url)
  console.log(req.body)
  const json = {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
    "token_type": "bearer",
    "expires_in": 86400,
  }
  if (req.body.pre-authorized_code) {
    const id = req.body.pre-authorized_code
    json.authorization_details = [
      {
        "type": "openid_credential",
        "credential_configuration_id": credentialType,
        "credential_identifiers": [ id ]
      }
    ]
  }
  res.setHeader('Cache-Control', 'no-store').json(json)
})

app.post(`/:name/:id/${oid4vcPath}`, async (req, res) => {
  const vc = await getVerifiableCredential(id, fmt).catch(e => {
    res.status(404).json(e)
    throw new Error(e)
  })
  res.json({"credential": vc})
})

app.post(oid4vcPath, async (req, res) => {
  console.log(req.method, req.url)
  console.log(req.body)
/*
  const vc = await getVerifiableCredential(req.query.id, 'lds').catch(e => {
    res.status(404).json(e)
  })
  let id = ''
  const format = req.body.format
  let fmt = 'lds'
  if (format.includes('jwt')) {
    fmt = 'jwt'
  }
*/
  const fmt = 'lds'
  if (req.body.credential_identifier) {
    id = req.body.credential_identifier
  }
  const vc = await getVerifiableCredential(id, fmt).catch(e => {
    res.status(404).json(e)
    throw new Error(e)
  })
  res.json({"credential": vc})
})

const server = app.listen(httpPort, (err) => {
  if (err) { console.error(err) }
  console.log(`Server running on port ${httpPort}, public address ${baseUrl}`)
})
