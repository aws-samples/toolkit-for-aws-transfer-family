## Toolkit for AWS Transfer Family

This repo contains a collection of tools and solutions to help with common use cases when working with AWS Transfer Family. 
This toolkit aims to provide reusable components and examples to simplify setting up AWS Transfer Family for common scenarios.

## Solution List

| Name | Location | Description |
| ---- | -------- | ----------- |
| Custom Identity Provider | [/solutions/custom-idp](https://github.com/aws-samples/toolkit-for-aws-transfer-family/solutions/custom-idp) | There are several examples of custom identity providers for AWS Transfer in AWS blog posts an documentation, but there have been no standard patterns for implementing a custom provider that accounts for details including logging and where to store the additional session metadata needed for AWS Transfer, such as the `HomeDirectoryDetails`. This solution provides a reusable foundation for implementing custom identity providers with granular per-user session configuration, and decouples the identity provider authentication logic from the reusable logic that builds a configuration that is returned to AWS Transfer to complete authentication and establish settings for the session. | 


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

