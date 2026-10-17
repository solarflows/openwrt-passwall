#!/bin/sh
CONFIG=passwall
dir="$1"
status="$2"
manager="$3"
force="$4"

rules_backup="/tmp/passwall_rules_backup_$$"
[ -d "/etc/passwall/rules" ] && cp -a "/etc/passwall/rules" "$rules_backup"

if [ "$manager" = apk ]; then
	extra=""
	[ "$force" = 1 ] && extra="--force-reinstall --force-overwrite"
	apk add --allow-untrusted $extra "$dir/luci-app-${CONFIG}.apk" "$dir/luci-i18n-${CONFIG}-zh-cn.apk"
	result=$?
else
	extra=""
	[ "$force" = 1 ] && extra="--force-reinstall"
	opkg install $extra "$dir/luci-app-${CONFIG}.ipk" "$dir/luci-i18n-${CONFIG}-zh-cn.ipk"
	result=$?
fi

if [ -d "$rules_backup" ]; then
	mkdir -p "/etc/passwall/rules"
	for bf in "$rules_backup"/*; do
		[ -f "$bf" ] || continue
		bname=$(basename "$bf")
		if [ ! -f "/etc/passwall/rules/$bname" ] || ([ ! -s "/etc/passwall/rules/$bname" ] && [ -s "$bf" ]); then
			cp -f "$bf" "/etc/passwall/rules/$bname"
		elif [ -f "/usr/share/passwall/rules/$bname" ] && cmp -s "/etc/passwall/rules/$bname" "/usr/share/passwall/rules/$bname" && ! cmp -s "$bf" "/usr/share/passwall/rules/$bname"; then
			cp -f "$bf" "/etc/passwall/rules/$bname"
		fi
	done
	rm -rf "$rules_backup"
fi

rm -rf "$dir"
if [ "$result" = 0 ]; then
	rm -f "/tmp/etc/${CONFIG}_tmp/${CONFIG}_version" /tmp/luci-indexcache /tmp/luci-indexcache.*
	if [ -x /etc/init.d/rpcd ]; then
		/etc/init.d/rpcd reload >/dev/null 2>&1
	fi
	if [ -x /etc/init.d/uhttpd ]; then
		/etc/init.d/uhttpd reload >/dev/null 2>&1
	fi
fi
[ "$result" = 0 ] && echo '{"code":0}' > "$status" || echo '{"code":1}' > "$status"
(sleep 60; rm -f "$status") >/dev/null 2>&1 &
