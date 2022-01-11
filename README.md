# Suricata Extras in Rust

So far this is an implementation of `suricatasc` in Rust, with a separated out
Suricata client library.

The idea here is to make somthing suitable that can be included in the main
Suricata repository to replace the current Python requirement.

## Workspace Members

- suricata-client: A minimal implementation of a Suricata socket client.
- suricatasc: An implementation of `suricatasc` in Rust making use of
  `suricata-client`.