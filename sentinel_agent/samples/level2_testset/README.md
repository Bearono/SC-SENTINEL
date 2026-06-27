# Sentinel-Bench Level 2: Multi-File Project Suite

Fourteen small C projects used for end-to-end pipeline testing.
Each project is self-contained and follows the same build layout.

## Projects

| # | Slug | Persona |
|---|---|---|
| 1 | `01_textkit` | microjson 0.4.2 |
| 2 | `02_imagepipe` | pngreader 1.6.36 |
| 3 | `03_fieldbus` | modlite 3.1.6 |
| 4 | `04_astcore` | astlite 0.2.0 |
| 5 | `05_chunkstream` | httpdecode 2.0.20 |
| 6 | `06_audiodec` | sndmini 1.0.28 |
| 7 | `07_imagecodec` | minivp8 1.2.3 |
| 8 | `08_proxyroute` | sockmini 7.86.0 |
| 9 | `09_resolver` | resmini 2.22.0 |
|10 | `10_authframe` | ntlmlite 7.64.0 |
|11 | `11_tunnelctl` | httptunnel 7.86.0 |
|12 | `12_sshscan` | sshmini 8.4.0 |
|13 | `13_cachemgr` | hstsmini 7.88.0 |
|14 | `14_logutil` | sudolite 1.8.30 |

## Layout

Each project contains a public header, implementation, CLI driver, and build files.

## Build

```bash
for p in [0-9][0-9]_*; do
    (cd "$p" && make && make test) || true
done
```

## Notes

The project tree is compact so downstream tooling can infer structure from code and build files.
