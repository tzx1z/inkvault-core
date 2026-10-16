#!/bin/sh
set -eu

# пользователи регистрируются только в новой базе: повторная регистрация меняет пароль, а после смены
# пароля Prosody отзывает токены FAST, и перезапуск сервера выглядел бы для клиентов как отзыв входа
if [ ! -f /var/lib/prosody/prosody.sqlite ]; then
    for jid in alice@vault.test bob@vault.test fast@vault.test alice@default.test; do
        prosodyctl register "${jid%@*}" "${jid#*@}" secret
    done
fi

exec prosody -F
