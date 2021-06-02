k6 privatebin performance test extension
========================================
This extension can be used to generate a privatebin encrypted paste.

## build
to build k6 with this extension, type:

```shell-session
$ xk6 build v0.32.0 --with github.com/binxio/xk6-privatebin
```

## run
to run a test with this extension, type:

```shell-session
$ ./k6 run -i 1 test.js
```
