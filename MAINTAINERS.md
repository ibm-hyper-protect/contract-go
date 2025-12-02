# Maintainers

This document lists the maintainers of the `contract-go` project, their roles, and responsibilities.

## Current Maintainers

| Name      | GitHub Handle | Role          | Email | Focus Areas |
|-----------|---------------|---------------|-------|-------------|
| Sashwat K | [@Sashwat-K](https://github.com/Sashwat-K) | Lead Maintainer | Sashwat.K@ibm.com | Overall project direction, releases, core features |
| Vikas Sharma | [@vikas-sharma24](https://github.com/vikas-sharma24) | Maintainer | Vikas.Sharma24@ibm.com | Releases and core features |

## Roles and Responsibilities

### Lead Maintainer

The Lead Maintainer is responsible for:

- **Project Direction**
  - Setting the technical direction and roadmap
  - Making final decisions on major architectural changes
  - Coordinating with IBM Hyper Protect team

- **Release Management**
  - Managing release schedules and versioning
  - Creating and publishing releases
  - Maintaining the changelog

- **Code Review**
  - Reviewing and approving pull requests
  - Ensuring code quality and consistency
  - Mentoring contributors

- **Community Management**
  - Responding to issues and discussions
  - Moderating community interactions
  - Enforcing the Code of Conduct

- **Security**
  - Responding to security reports
  - Coordinating security fixes and disclosures
  - Managing security advisories

### Maintainer Responsibilities

All maintainers are expected to:

1. **Be Responsive**
   - Respond to issues and pull requests in a timely manner
   - Acknowledge security reports within 3 business days

2. **Maintain Quality**
   - Review code thoroughly before merging
   - Ensure tests pass and coverage is maintained
   - Follow the project's coding standards

3. **Support Contributors**
   - Provide constructive feedback on contributions
   - Help contributors improve their pull requests
   - Recognize and appreciate community contributions

4. **Uphold Standards**
   - Enforce the Code of Conduct
   - Maintain professional and respectful communication
   - Lead by example in code and community interactions

5. **Stay Informed**
   - Keep up with issues and discussions
   - Monitor security advisories for dependencies
   - Stay current with Go and IBM Hyper Protect ecosystem changes

## Becoming a Maintainer

We welcome community members who demonstrate consistent, high-quality contributions to become maintainers. The path to maintainership typically involves:

1. **Consistent Contributions**
   - Multiple merged pull requests
   - High-quality code and documentation
   - Helpful issue triage and support

2. **Community Engagement**
   - Active participation in discussions
   - Helping other contributors
   - Demonstrating deep understanding of the project

3. **Alignment with Project Values**
   - Following the Code of Conduct
   - Supporting the project's goals and direction
   - Collaborative and professional interactions

### Nomination Process

1. An existing maintainer nominates a contributor
2. The nomination is discussed among current maintainers
3. Consensus is reached (all maintainers must agree)
4. The nominee is invited to become a maintainer
5. Upon acceptance, the new maintainer is added to this document

## Emeritus Maintainers

Maintainers who have stepped down or moved to emeritus status are recognized here for their contributions:

_No emeritus maintainers at this time._

## Contact

### For General Questions

- Open an issue on [GitHub](https://github.com/ibm-hyper-protect/contract-go/issues)
- Start a discussion in [GitHub Discussions](https://github.com/ibm-hyper-protect/contract-go/discussions)

### For Security Issues

- Follow the [Security Policy](SECURITY.md)
- **Do not** open public issues for security vulnerabilities
- Report via [GitHub Security Advisories](https://github.com/ibm-hyper-protect/contract-go/security)

### For Code of Conduct Issues

- Contact the maintainers directly via GitHub
- Email will be added when available

## Decision Making

### Regular Decisions

For regular project decisions (features, bug fixes, documentation):

1. Proposed via GitHub issues or pull requests
2. Discussed in issue/PR comments
3. Maintainers review and provide feedback
4. Consensus is preferred; Lead Maintainer makes final call if needed

### Major Decisions

For major decisions (breaking changes, architectural changes, new major features):

1. Proposed via GitHub issue with detailed RFC (Request for Comments)
2. Community discussion period (minimum 1 week)
3. Maintainer review and discussion
4. Final decision by consensus among maintainers
5. Lead Maintainer makes final call if consensus cannot be reached

### Conflict Resolution

If conflicts arise:

1. Attempt to reach consensus through discussion
2. Seek input from community and other maintainers
3. If unresolved, Lead Maintainer makes the final decision
4. Decision is documented with reasoning

## Maintainer Guidelines

### Code Review Guidelines

When reviewing code:

- **Be Constructive** - Provide specific, actionable feedback
- **Be Timely** - Respond within a reasonable timeframe (ideally within 3 days)
- **Be Thorough** - Check for correctness, security, performance, and style
- **Be Respectful** - Remember there's a person behind the code
- **Approve or Request Changes** - Clearly communicate your decision

### Merging Pull Requests

Before merging:

- [ ] All CI checks pass
- [ ] At least one maintainer approval
- [ ] No unresolved review comments
- [ ] Proper commit message format
- [ ] Documentation updated if needed
- [ ] Tests added or updated

### Release Process

1. Update version in `go.mod`
2. Update `CHANGELOG.md`
3. Create release tag following semantic versioning
4. Publish release on GitHub
5. Announce in relevant channels

## Acknowledgments

This project exists thanks to all the contributors and maintainers, past and present. We appreciate everyone who helps make `contract-go` better!
