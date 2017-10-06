#!/bin/bash
certbot run --force-renewal --must-staple --test-cert --non-interactive --webroot --agree-tos -w /var/www/acme --redirect --hsts -d mygnus.com -d www.mygnus.com
