fargo
==================

fargo(Fast cARGO) is simple file copy daemon with HTTP.

# Install

```
go get github.com/netmarkjp/fargo
```

# Usage

## Start server

```
./fargo
```

## Push file to server

1.get token

```
curl http://fargo.example.com:1236/token
```

2.push file

```
curl -F file=@somefile http://fargo.example.com:1236/push/<TOKEN>
```

## Get file from server

```
curl -OJ http://fargo.example.com:1236/get/<TOKEN>
```

# Specification

- Listen address/port is ``0.0.0.0:1236`` by default.
    - can change with env ``ADDR`` *feature*
- username/password for ``/token`` is ``fargo`` / ``fargo`` by default. *feature*
    - can change with env ``FARGO_USER`` and ``FARGO_PASSWORD`` *feature*
- File store directory is ``/tmp`` by default.
    - can change with env ``STORE_DIR`` *feature*
- ``TOKEN`` is UUIDv4
- ``TOKEN`` is expired in 5 min by default.
    - can change with env ``TOKEN_TTL`` (min) *feature*
- If get file fail, locked 30 seconds from same IP by default.
- Pushed file will delete in 60 min by default.
    - can change with env ``FILE_TTL`` (min) *feature*

