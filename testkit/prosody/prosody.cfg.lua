-- Тестовый сервер для сквозных проверок клиентов. Только для локального запуска: без TLS.
-- Хранилище, ограничение скорости и сторонние модули как в рабочей установке Prosody на Fedora 44.

plugin_paths = { "/usr/local/lib/prosody/modules" }

modules_enabled = {
    "disco";
    "roster";
    "saslauth";
    "pep";
    "smacks";
    "limits";
    "ping";
    "websocket";
    "sasl2";
    "sasl2_bind2";
    "sasl2_sm";
    "sasl2_fast";
}

allow_registration = false
c2s_require_encryption = false
authentication = "internal_hashed"

storage = "sql"
sql = {
    driver = "SQLite3";
    database = "prosody.sqlite";
}

limits = {
    c2s = {
        rate = "10kb/s";
    };
}

-- Учетная запись для замеров без ограничения скорости
unlimited_jids = { "fast@vault.test" }

-- WebSocket без TLS Prosody считает небезопасным и не дает по нему войти
http_ports = { 5280 }
http_interfaces = { "*" }
consider_websocket_secure = true

log = {
    { levels = { min = "info" }, to = "console" };
}

-- pep_max_items по умолчанию (256)
VirtualHost "default.test"

VirtualHost "vault.test"
    pep_max_items = 10000
