// Адаптер PEP для движка синхронизации из ядра (VaultSync): исполняет команды движка через
// xmpp.js и передает ему ответы сервера и уведомления. Работает в Node и в браузере:
// клиент xmpp.js, построитель xml и движок передаются снаружи.

const NS_PUBSUB = "http://jabber.org/protocol/pubsub";
const NS_OWNER = "http://jabber.org/protocol/pubsub#owner";
const NS_EVENT = "http://jabber.org/protocol/pubsub#event";
const NS_DATA = "jabber:x:data";
const NS_VAULT = "urn:inkvault:vault:0";
const NS_ACCOUNT = "urn:inkvault:account:0";

function form(xml, formType, fields) {
  return xml(
    "x",
    { xmlns: NS_DATA, type: "submit" },
    xml("field", { var: "FORM_TYPE", type: "hidden" }, xml("value", {}, formType)),
    ...Object.entries(fields).map(([name, value]) => xml("field", { var: name }, xml("value", {}, String(value)))),
  );
}

// Параметры узла хранилища: при расхождении с ними сервер отклоняет публикацию
const nodeOptions = (maxItems) => ({
  "pubsub#access_model": "whitelist",
  "pubsub#persist_items": "true",
  "pubsub#max_items": maxItems,
});

function entryOf(item) {
  const entry = item.getChild("entry", NS_VAULT);
  return entry ? { id: item.attrs.id, key_version: Number(entry.attrs.key), ciphertext: entry.text() } : null;
}

// Специфичное условие PubSub (precondition-not-met) важнее общего (conflict); текст сервера объясняет причину
function errorCondition(err) {
  const condition = err.application?.name ?? err.condition ?? String(err.message ?? err);
  return err.text ? `${condition}: ${err.text}` : condition;
}

/** Учетная запись из узла PEP (JSON из ядра) или null, если узла еще нет. Нужна до создания движка. */
export async function fetchAccount(xmpp, xml) {
  let response;
  try {
    response = await xmpp.iqCaller.request(xml("iq", { type: "get" }, xml("pubsub", { xmlns: NS_PUBSUB }, xml("items", { node: NS_ACCOUNT }))));
  } catch (err) {
    if (err.condition === "item-not-found") return null;
    throw err;
  }
  const account = response.getChild("pubsub", NS_PUBSUB)?.getChild("items")?.getChild("item")?.getChild("account", NS_ACCOUNT);
  return account ? account.text() : null;
}

export async function publishAccount(xmpp, xml, accountJson) {
  const publish = xml("publish", { node: NS_ACCOUNT }, xml("item", { id: "current" }, xml("account", { xmlns: NS_ACCOUNT, v: "1" }, accountJson)));
  const options = xml("publish-options", {}, form(xml, "http://jabber.org/protocol/pubsub#publish-options", nodeOptions(1)));
  await xmpp.iqCaller.request(xml("iq", { type: "set" }, xml("pubsub", { xmlns: NS_PUBSUB }, publish, options)));
}

export class PepAdapter {
  // onApplied вызывается после каждой обработки результата движка: удобное место сохранить снимок
  constructor({ xmpp, xml, engine, node = NS_VAULT, now = () => Date.now(), onEvent = () => {}, onError = () => {}, onApplied = () => {} }) {
    Object.assign(this, { xmpp, xml, engine, node, now, onEvent, onError, onApplied });
    xmpp.on("stanza", (stanza) => this.#onStanza(stanza));
  }

  async connected(resumed = false, maxStanzaBytes = undefined) {
    return this.apply(this.engine.connected(resumed, maxStanzaBytes));
  }

  /** Обрабатывает результат вызова движка: события отдает в onEvent, команды исполняет по очереди. */
  async apply(outputJson) {
    const output = JSON.parse(outputJson);
    for (const event of output.events) this.onEvent(event);
    for (const command of output.commands) await this.#execute(command);
    this.onApplied();
    return output;
  }

  async #execute(command) {
    switch (command.op) {
      case "fetch_config":
        return this.apply(this.engine.configFetched(command.request, await this.#nodeMaxItems(command.node)));
      case "fetch_all":
        return this.apply(this.engine.itemsFetched(JSON.stringify(await this.#fetch(command.node)), this.now()));
      case "publish":
        return this.apply(this.engine.publishResult(command.request, await this.#publish(command)));
      case "configure_node":
        return this.apply(this.engine.configureResult(command.request, await this.#configure(command)));
      default:
        throw new Error(`неизвестная команда движка: ${command.op}`);
    }
  }

  // max_items из настроек узла (запрос владельца); undefined - узла нет или настройки не прочитались
  async #nodeMaxItems(node) {
    const { xml } = this;
    try {
      const response = await this.xmpp.iqCaller.request(xml("iq", { type: "get" }, xml("pubsub", { xmlns: NS_OWNER }, xml("configure", { node }))));
      const fields = response.getChild("pubsub", NS_OWNER)?.getChild("configure")?.getChild("x", NS_DATA)?.getChildren("field") ?? [];
      const value = Number(fields.find((f) => f.attrs.var === "pubsub#max_items")?.getChildText("value"));
      return Number.isInteger(value) && value > 0 ? value : undefined;
    } catch (err) {
      if (err.condition !== "item-not-found") this.onError(err);
      return undefined;
    }
  }

  async #fetch(node) {
    const { xml } = this;
    let response;
    try {
      response = await this.xmpp.iqCaller.request(xml("iq", { type: "get" }, xml("pubsub", { xmlns: NS_PUBSUB }, xml("items", { node }))));
    } catch (err) {
      // узла еще нет: учетная запись без записей
      if (err.condition === "item-not-found") return [];
      throw err;
    }
    return response.getChild("pubsub", NS_PUBSUB).getChild("items").getChildren("item").map(entryOf).filter(Boolean);
  }

  async #publish({ node, max_items: maxItems, item }) {
    const { xml } = this;
    const entry = xml("entry", { xmlns: NS_VAULT, v: "1", key: String(item.key_version) }, item.ciphertext);
    const publish = xml("publish", { node }, xml("item", { id: item.id }, entry));
    const options = xml("publish-options", {}, form(xml, "http://jabber.org/protocol/pubsub#publish-options", nodeOptions(maxItems)));
    try {
      await this.xmpp.iqCaller.request(xml("iq", { type: "set" }, xml("pubsub", { xmlns: NS_PUBSUB }, publish, options)));
      return undefined;
    } catch (err) {
      return errorCondition(err);
    }
  }

  async #configure({ node, max_items: maxItems }) {
    const { xml } = this;
    const configure = xml("configure", { node }, form(xml, "http://jabber.org/protocol/pubsub#node_config", nodeOptions(maxItems)));
    try {
      await this.xmpp.iqCaller.request(xml("iq", { type: "set" }, xml("pubsub", { xmlns: NS_OWNER }, configure)));
      return true;
    } catch (err) {
      this.onError(err);
      return false;
    }
  }

  #onStanza(stanza) {
    const items = stanza.is("message") && stanza.getChild("event", NS_EVENT)?.getChild("items");
    if (!items || items.attrs.node !== this.node) return;
    for (const item of items.getChildren("item")) {
      const entry = entryOf(item);
      if (entry) this.apply(this.engine.itemNotified(JSON.stringify(entry), this.now())).catch(this.onError);
    }
  }
}
