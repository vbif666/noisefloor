#!/bin/sh
# Самоподписанный сертификат для веб-панели: панель отдаётся только по HTTPS.
# У сервера по голому IP публичного сертификата нет, поэтому выпускаем свой и
# храним в томе данных.
#
# Срок - TLS_CERT_DAYS (по умолчанию 365 дней). Если до конца осталось меньше
# TLS_RENEW_DAYS (по умолчанию 30), сертификат перевыпускается С ТЕМ ЖЕ КЛЮЧОМ:
# каскад на соседней панели запоминает отпечаток ключа, поэтому плановый
# перевыпуск его не ломает. Скрипт безопасно вызывать сколько угодно раз -
# сертификат меняется только когда пора.
#
# Свой сертификат (не с CN=noisefloor) можно подложить в те же файлы - его
# скрипт не трогает, только предупреждает о скором истечении.
set -eu
dir="$1"
days="${TLS_CERT_DAYS:-365}"
renew_days="${TLS_RENEW_DAYS:-30}"
cert="$dir/cert.pem"
key="$dir/key.pem"
mkdir -p "$dir"
umask 077

ours() {
    openssl x509 -in "$cert" -noout -subject 2>/dev/null | grep -q 'CN *= *noisefloor'
}

if [ -s "$cert" ] && [ -s "$key" ]; then
    if openssl x509 -in "$cert" -noout -checkend $((renew_days * 86400)) >/dev/null 2>&1; then
        exit 0
    fi
    if ! ours; then
        echo "[tls] внимание: ваш сертификат $cert истекает менее чем через $renew_days дн. - замените его"
        exit 0
    fi
    action="перевыпущен (ключ прежний)"
else
    action="выпущен"
fi

if [ ! -s "$key" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$key.tmp" 2>/dev/null
    mv "$key.tmp" "$key"
fi

san="DNS:localhost,IP:127.0.0.1"
if [ -n "${PUBLIC_HOST:-}" ]; then
    case "$PUBLIC_HOST" in
        *[!0-9.]*) case "$PUBLIC_HOST" in *:*) san="$san,IP:$PUBLIC_HOST" ;; *) san="$san,DNS:$PUBLIC_HOST" ;; esac ;;
        *) san="$san,IP:$PUBLIC_HOST" ;;
    esac
fi

# Пишем во временный файл и подменяем атомарно: работающий сервер в момент
# перечитывания не увидит недописанный сертификат.
openssl req -x509 -new -key "$key" -sha256 -days "$days" \
    -subj "/CN=noisefloor" -addext "subjectAltName=$san" \
    -out "$cert.tmp" 2>/dev/null
mv "$cert.tmp" "$cert"
echo "[tls] сертификат $action: $cert, действует до $(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
