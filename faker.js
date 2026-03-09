/**
 * faker.js — Lightweight fake data generator, no dependencies.
 * Supports: {{faker.name}}, {{faker.email}}, {{faker.uuid}}, etc.
 */

const firstNames = ['Anderson','Maria','Carlos','Ana','Pedro','Julia','Lucas','Beatriz','Rafael','Camila','Felipe','Larissa','Gustavo','Leticia','Bruno','Fernanda','Diego','Gabriela','Rodrigo','Mariana'];
const lastNames  = ['Silva','Santos','Oliveira','Souza','Costa','Pereira','Carvalho','Ferreira','Rodrigues','Lima','Almeida','Nascimento','Araujo','Martins','Gomes','Barbosa','Ribeiro','Rocha','Cardoso','Correia'];
const domains    = ['gmail.com','hotmail.com','outlook.com','yahoo.com','empresa.com.br','corp.io','mail.dev'];
const companies  = ['TechCorp','DataSoft','CloudBase','DevMind','BitFlow','SkyAPI','NetGroup','CodeLab','AppWorks','PixelDev'];
const cities     = ['São Paulo','Rio de Janeiro','Belo Horizonte','Porto Alegre','Curitiba','Salvador','Fortaleza','Recife','Manaus','Brasília'];
const streets    = ['Av. Paulista','Rua Augusta','Rua da Consolação','Av. Brasil','Rua das Flores','Av. Atlântica','Rua XV de Novembro','Av. Faria Lima'];
const statuses   = ['active','inactive','pending','suspended'];
const colors     = ['red','blue','green','yellow','purple','orange','pink','black','white'];
const loremWords = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua'.split(' ');

let _seed = Date.now();
function rand(n) { _seed = (_seed * 1664525 + 1013904223) & 0xffffffff; return Math.abs(_seed) % n; }
function pick(arr) { return arr[rand(arr.length)]; }
function randInt(min, max) { return min + rand(max - min + 1); }
function pad(n, len=2) { return String(n).padStart(len,'0'); }

const generators = {
  // Names
  'faker.name':        () => `${pick(firstNames)} ${pick(lastNames)}`,
  'faker.firstName':   () => pick(firstNames),
  'faker.lastName':    () => pick(lastNames),
  'faker.fullName':    () => `${pick(firstNames)} ${pick(lastNames)}`,

  // Contact
  'faker.email':       () => {
    const u = pick(firstNames).toLowerCase() + '.' + pick(lastNames).toLowerCase() + rand(99);
    return `${u}@${pick(domains)}`;
  },
  'faker.phone':       () => `(${randInt(11,99)}) 9${randInt(1000,9999)}-${randInt(1000,9999)}`,
  'faker.username':    () => pick(firstNames).toLowerCase() + rand(999),

  // IDs
  'faker.uuid':        () => {
    const h = () => Math.floor(Math.random()*0x100).toString(16).padStart(2,'0');
    return `${h()}${h()}${h()}${h()}-${h()}${h()}-4${h().slice(1)}-${(Math.floor(Math.random()*4)+8).toString(16)}${h().slice(1)}-${h()}${h()}${h()}${h()}${h()}${h()}`;
  },
  'faker.id':          () => String(randInt(1, 99999)),
  'faker.shortId':     () => Math.random().toString(36).slice(2,8).toUpperCase(),

  // Numbers
  'faker.number':      () => randInt(1, 1000),
  'faker.price':       () => (randInt(1,999) + rand(100)/100).toFixed(2),
  'faker.age':         () => randInt(18, 80),
  'faker.rating':      () => (randInt(1,4) + rand(10)/10).toFixed(1),
  'faker.quantity':    () => randInt(1, 100),
  'faker.percentage':  () => randInt(0, 100),

  // Dates
  'faker.date':        () => {
    const d = new Date(Date.now() - rand(365*3)*86400000);
    return d.toISOString().split('T')[0];
  },
  'faker.datetime':    () => new Date(Date.now() - rand(365)*86400000).toISOString(),
  'faker.timestamp':   () => Date.now() - rand(1000000),
  'faker.futureDate':  () => new Date(Date.now() + rand(365)*86400000).toISOString().split('T')[0],

  // Location
  'faker.city':        () => pick(cities),
  'faker.street':      () => `${pick(streets)}, ${randInt(1,999)}`,
  'faker.cep':         () => `${randInt(10000,99999)}-${pad(rand(999),3)}`,
  'faker.country':     () => 'Brasil',

  // Business
  'faker.company':     () => pick(companies),
  'faker.status':      () => pick(statuses),
  'faker.color':       () => pick(colors),
  'faker.url':         () => `https://api.${pick(companies).toLowerCase()}.com/${pick(['v1','v2'])}/resource`,
  'faker.ipAddress':   () => `${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}`,
  'faker.boolean':     () => rand(2) === 1,
  'faker.lorem':       () => Array.from({length: randInt(5,12)}, () => pick(loremWords)).join(' '),
  'faker.word':        () => pick(loremWords),

  // Brazilian
  'faker.cpf':         () => {
    const d = Array.from({length:9}, () => rand(9));
    return `${d.slice(0,3).join('')}.${d.slice(3,6).join('')}.${d.slice(6,9).join('')}-${rand(9)}${rand(9)}`;
  },
  'faker.cnpj':        () => `${randInt(10,99)}.${randInt(100,999)}.${randInt(100,999)}/0001-${pad(rand(99),2)}`,
};

/**
 * Process a template string or object, replacing {{faker.xxx}} placeholders.
 * Supports: generate(template, count) to produce N objects.
 */
function processTemplate(template) {
  if (typeof template === 'string') {
    return template.replace(/\{\{([^}]+)\}\}/g, (_, key) => {
      const gen = generators[key.trim()];
      return gen ? gen() : _;
    });
  }
  if (typeof template === 'object' && template !== null) {
    if (Array.isArray(template)) return template.map(processTemplate);
    const result = {};
    for (const [k, v] of Object.entries(template)) {
      result[processTemplate(k)] = processTemplate(v);
    }
    return result;
  }
  return template;
}

function generate(template, count = 1) {
  const results = [];
  for (let i = 0; i < count; i++) {
    results.push(processTemplate(JSON.parse(JSON.stringify(template))));
  }
  return count === 1 ? results[0] : results;
}

module.exports = { generate, processTemplate, generators, listKeys: () => Object.keys(generators) };
