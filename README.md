The important steps that this shows are

1. Online phase:
    1. Calling a canister method.
    2. Storing SIGNED reply to a file.

2. Offline phase:
    1. Loading signed reply from the file.
    2. Verifying signature of signed reply.
    3. Parsing reply.

# Expiry

Suppose you hack in the following changes:

1. Put a 5 second gap between the online and offline phases, and

2. Change the value of `a_very_long_time` to 1 ns

Then, you will get a `CertificateOutdated`. This reflects the fact that canister
method replies EXPIRE. This means that if you want to save a signed canister
method reply to a file, so it can be read later, you need to increase the expiry
of ic_agent::Agent to "infinity" in order to get successful verification (modulo
expiry) of the sign canister method reply that you saved to the file.

# References

Closes [NNS1-4289].

[NNS1-4289]: https://dfinity.atlassian.net/browse/NNS1-4289
