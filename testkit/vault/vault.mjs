// Тестовое хранилище на тестовом Prosody (testkit/prosody) для сквозных проверок клиентов:
// xmpp.js, ядро в WASM, учетная запись и движок из ядра. Работает от имени alice@vault.test.
//   node vault.mjs setup  - создает учетную запись в PEP и публикует первую запись
//   node vault.mjs add [JSON] - разблокирует хранилище мастер-паролем и добавляет запись; JSON - поля записи
//   node vault.mjs list   - разблокирует хранилище и выводит записи
//   node vault.mjs passwd - меняет мастер-пароль на NEW_MASTER_PASSWORD
//   node vault.mjs delete-account - удаляет узел учетной записи, записи остаются (потеря узла)
//   node vault.mjs foreign - заменяет учетную запись новой с MASTER_PASSWORD и удаляет записи (чужая учетная запись)
//   node vault.mjs key-id - выводит отпечаток учетной записи на сервере
//   node vault.mjs max-items [N] - выводит лимит записей узла хранилища, с N - меняет его
// Мастер-пароль задается переменной MASTER_PASSWORD. В checkout ядра нужна сборка WASM для Node: bindings/build.sh wasm.
import { client, xml } from "@xmpp/client";
import { createRequire } from "node:module";
import { PepAdapter, fetchAccount, publishAccount } from "./pep-adapter.mjs";

const require = createRequire(import.meta.url);
const core = require("@inkov-dev/inkvault-core-wasm/node");

const SERVICE = "ws://127.0.0.1:15280/xmpp-websocket";
const NS_VAULT = "urn:inkvault:vault:0";
const MASTER_PASSWORD = process.env.MASTER_PASSWORD ?? "correct horse battery staple";
const NEW_MASTER_PASSWORD = process.env.NEW_MASTER_PASSWORD ?? "new horse battery staple";

const NS_OWNER = "http://jabber.org/protocol/pubsub#owner";

async function deleteNode(xmpp, node) {
  try {
    await xmpp.iqCaller.request(xml("iq", { type: "set" }, xml("pubsub", { xmlns: NS_OWNER }, xml("delete", { node }))));
  } catch (err) {
    if (err.condition !== "item-not-found") throw err;
  }
}

const plain = (record) => Object.fromEntries(Object.entries(record.fields).map(([name, field]) => [name, field.value]));

async function setup(xmpp) {
  const account = core.VaultAccount.create(MASTER_PASSWORD, Date.now());
  await publishAccount(xmpp, xml, account.accountJson());
  console.log(`vault: учетная запись хранилища создана, vault ${JSON.parse(account.vaults())[0].id}`);
  return account;
}

async function unlock(xmpp) {
  const json = await fetchAccount(xmpp, xml);
  if (!json) throw new Error("учетной записи хранилища на сервере нет, нужен setup");
  const account = core.VaultAccount.unlock(json, MASTER_PASSWORD);
  console.log(`vault: хранилище ${JSON.parse(account.vaults())[0].id} разблокировано`);
  return account;
}

// Движок личного хранилища поверх PEP: подключение загружает узел и отправляет неотправленное
async function open(xmpp, account) {
  const [{ id }] = JSON.parse(account.vaults());
  const engine = account.openVault(id, NS_VAULT, core.generateNodeId(), core.defaultMaxItems());
  const adapter = new PepAdapter({
    xmpp,
    xml,
    engine,
    onEvent: (e) => e.event === "warning" && console.log(`vault: предупреждение ${e.kind}: ${e.detail}`),
    onError: (err) => console.error(`vault: ${err.message}`),
  });
  await adapter.connected();
  return adapter;
}

async function add(adapter, fields) {
  const output = await adapter.apply(adapter.engine.create("login", JSON.stringify(fields), Date.now()));
  console.log(`vault: опубликована запись ${output.item_id} (${fields.name}), неотправленных изменений: ${adapter.engine.pending()}`);
}

const command = process.argv[2];
const xmpp = client({ service: SERVICE, domain: "vault.test", username: "alice", password: "secret", resource: `testkit-${command}` });
xmpp.on("error", (err) => console.error(`vault: ${err.message}`));
await xmpp.start();
try {
  if (command === "setup") {
    await add(await open(xmpp, await setup(xmpp)), { name: "github.com", username: "alice", password: "Xk7#pQ2v" });
  } else if (command === "add") {
    const fields = process.argv[3] ? JSON.parse(process.argv[3]) : { name: "prod-db", username: "postgres", password: "s3cr3t-Db" };
    await add(await open(xmpp, await unlock(xmpp)), fields);
  } else if (command === "list") {
    const adapter = await open(xmpp, await unlock(xmpp));
    const records = JSON.parse(adapter.engine.records());
    for (const { id, record } of records) console.log(`vault: ${id} ${JSON.stringify(plain(record))}`);
    console.log(`vault: записей ${records.length}`);
  } else if (command === "passwd") {
    const account = await unlock(xmpp);
    await publishAccount(xmpp, xml, account.changePassword(MASTER_PASSWORD, NEW_MASTER_PASSWORD));
    console.log("vault: мастер-пароль изменен, учетная запись опубликована");
  } else if (command === "delete-account") {
    await deleteNode(xmpp, "urn:inkvault:account:0");
    console.log("vault: узел учетной записи удален");
  } else if (command === "foreign") {
    const account = core.VaultAccount.create(MASTER_PASSWORD, Date.now());
    await deleteNode(xmpp, NS_VAULT);
    await publishAccount(xmpp, xml, account.accountJson());
    console.log(`vault: на сервере новая учетная запись ${JSON.parse(account.accountJson()).key_id}`);
  } else if (command === "max-items") {
    const adapter = await open(xmpp, await unlock(xmpp));
    if (process.argv[3]) await adapter.apply(adapter.engine.setMaxItems(Number(process.argv[3])));
    console.log(`vault: лимит узла ${adapter.engine.maxItems()}`);
  } else if (command === "key-id") {
    const json = await fetchAccount(xmpp, xml);
    console.log(`vault: отпечаток ${json ? JSON.parse(json).key_id : "нет"}`);
  } else {
    throw new Error("команда: setup, add, list, passwd, delete-account, foreign, key-id или max-items");
  }
} finally {
  await xmpp.stop();
}
