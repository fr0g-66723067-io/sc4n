# Payload

```python
payload = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZCE="
```

## Notes

The blob above is a sample. The decoding helper is described below, with enough
prose between the literal and the call that they are not one statement any more:
the rule pairs a literal with the decoder that reads it, and a decoder four
hundred bytes away is not reading this one. Padding prose keeps the two apart
so the fixture measures the pairing rather than the literal.

```python
import base64
def decode(blob):
    return base64.b64decode(blob)
```
