#!/bin/bash
certbot run --force-renewal --must-staple --test-cert --non-interactive --webroot --agree-tos -w /var/www/acme --redirect --hsts -d tbrowder.net -d mail.tbrowder.new -d www.tbrowder.net -d ns1.tbrowder.net -d ns2.tbrowder.net -d juvat2.tbrowder.net
