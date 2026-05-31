# CWE Patterns for Agent C

## CWE-416 Use After Free

```c
free(p);
*p = 1;
```

## CWE-415 Double Free

```c
free(p);
free(p);
```

## CWE-122 Heap Buffer Overflow

```c
char *buf = malloc(8);
strcpy(buf, input);
```

## CWE-121 Stack Buffer Overflow

```c
char buf[8];
strcpy(buf, input);
```
