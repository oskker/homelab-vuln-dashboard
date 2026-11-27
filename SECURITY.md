# Security policy

## Reporting a problem

Please report security issues privately through GitHub: open the **Security** tab of this
repository and choose **Report a vulnerability**. Do not open a public issue for
something that could put users at risk.

Include what you found, how to reproduce it, and what an attacker could do with it.
This is a personal project, so replies can take a few days.

## Scope

In scope:

- The report parsers, the GMP client, the API and the dashboard in this repository.
- The AI triage guards described in [docs/threat-model.md](docs/threat-model.md),
  including ways to make scan content change the model's instructions or get model
  output rendered as markup.

Out of scope:

- Findings in the scanners or models this project talks to (OpenVAS and the other
  Greenbone components, Nessus, Ollama). Report those to their maintainers.
- Attacks that need administrator access to the computer the dashboard runs on.

## Design assumptions

The dashboard has no login. It is built to listen on `127.0.0.1` only, and so is the
Greenbone web interface that runs next to it. Do not
publish it on a network interface or put it behind a public reverse proxy.
