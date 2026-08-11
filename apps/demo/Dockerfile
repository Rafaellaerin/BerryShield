FROM nginx:1.27-alpine
COPY apps/demo/index.html /usr/share/nginx/html/index.html
COPY packages/browser-sdk/dist /usr/share/nginx/html/sdk
COPY crates/probe-wasm/dist/probe.wasm /usr/share/nginx/html/probe.wasm
COPY apps/demo/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
