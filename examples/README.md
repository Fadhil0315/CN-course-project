# Demonstration inputs

Generated QR PNGs contain these payloads:

- ordinary.png: https://example.com/
- suspicious.png: https://paypal.com.account-check.test/start
- loop.png: https://loop.test/start
- invalid_tls.png: a reserved test URL whose built-in demo supplies an invalid-certificate observation
- stacked.png: a reserved test URL whose built-in demo supplies a multi-hop chain
- non_url.png: ordinary text, to demonstrate URL validation errors

The .test destinations are reserved test names and are not live malicious websites. Upload mode inspects the image and performs lexical analysis offline by default; it does not automatically replay demo redirects. Choose the corresponding built-in Demo scenario to replay its synthetic chain.

Regenerate from the project root with `python -m scripts.generate_examples`. The samples test functionality only; they are not a labelled detection-accuracy dataset.
