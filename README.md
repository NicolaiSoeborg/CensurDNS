# CensurDNS

git clone --recurse-submodules ...

## CoreDNS

Build hardened Coredns with sqlite plugin:

```
cd coredns-src/plugin && ln -s ../../sqlite/ && cd ../
export COREDNS_PLUGINS=rrl:github.com/coredns/rrl/plugins/rrl,sqlite:sqlite
go get github.com/coredns/rrl/plugins/rrl
make gen
make CGO_ENABLED=1 BUILDOPTS='-tags "sqlite_app_armor sqlite_omit_load_extension sqlite_secure_delete"'
```

Now copy it to project folder: `cp ./coredns ../ && cd ..`

And run it: `./coredns -conf ./Corefile`

## Mgmt (py)

Make a virtualenv.  Pip install `fastapi` and `uvicorn`

Install caddy and make a `reverse_proxy localhost:8000`
