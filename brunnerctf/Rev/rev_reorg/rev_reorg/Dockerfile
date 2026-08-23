FROM nginx:1.31.3-alpine

COPY default.conf       /etc/nginx/conf.d/default.conf
COPY reorg-bands.conf   /etc/nginx/reorg-bands.conf
COPY reorg-ledger.conf  /etc/nginx/reorg-ledger.conf
COPY reorg-sales.conf   /etc/nginx/reorg-sales.conf
COPY reorg-legal.conf   /etc/nginx/reorg-legal.conf
COPY reorg-ops.conf     /etc/nginx/reorg-ops.conf

EXPOSE 80
